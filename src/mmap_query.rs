//! Query and lookup methods for [`MmapBlockIndex`](crate::mmap_index::MmapBlockIndex).

use crate::error::{Error, Result};
use crate::filter::{ByteFilter, NgramFilter};
use crate::index::CandidateRange;
use crate::mmap_index::MmapBlockIndex;
use crate::mmap_write::{ByteHistogramRef, NgramBloomRef};

impl MmapBlockIndex<'_> {
    /// Query candidate blocks directly from the serialized histograms/blooms.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, ByteFilter, MmapBlockIndex, NgramFilter};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(b"secret").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bf = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    /// let nf = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    /// let candidates = mmap.candidate_blocks(&bf, &nf);
    /// assert!(!candidates.is_empty());
    /// ```
    #[must_use]
    pub fn candidate_blocks(
        &self,
        byte_filter: &ByteFilter,
        ngram_filter: &NgramFilter,
    ) -> Vec<CandidateRange> {
        let paired_compact = byte_filter.compact_requirements();
        let paired_ngrams = ngram_filter.pattern_ngrams();
        let is_paired = paired_compact.len() == paired_ngrams.len();
        let use_exact = self
            .block_metas
            .first()
            .is_some_and(|meta| self.block_bloom(*meta).uses_exact_pairs());

        let block_count = self.block_metas.len();
        if block_count == 0 {
            return Vec::new();
        }

        let window_blocks = ngram_filter
            .max_pattern_bytes()
            .div_ceil(self.block_size)
            .max(1)
            .saturating_add(1)
            .min(block_count);
        let mut seen = vec![false; block_count];

        for index in 0..block_count {
            let block_meta = self.block_metas[index];
            let histogram = self.block_histogram(block_meta.offset);
            let bloom = self.block_bloom(block_meta);

            let single_match = if is_paired {
                if use_exact {
                    paired_compact
                        .iter()
                        .zip(paired_ngrams)
                        .any(|(required_bytes, ngrams)| {
                            required_bytes.iter().all(|&b| histogram.count(b) > 0)
                                && ngrams.iter().all(|&(first, second)| {
                                    bloom.maybe_contains_exact(first, second)
                                })
                        })
                } else {
                    paired_compact
                        .iter()
                        .zip(paired_ngrams)
                        .any(|(required_bytes, ngrams)| {
                            required_bytes.iter().all(|&b| histogram.count(b) > 0)
                                && ngrams.iter().all(|&(first, second)| {
                                    bloom.maybe_contains_bloom(first, second)
                                })
                        })
                }
            } else {
                byte_filter_matches_histogram(byte_filter, histogram)
                    && ngram_filter_matches_bloom(ngram_filter, bloom)
            };

            if single_match {
                seen[index] = true;
                continue;
            }

            if index == 0 {
                continue;
            }

            let prev_meta = self.block_metas[index - 1];
            let prev_histogram = self.block_histogram(prev_meta.offset);
            let prev_bloom = self.block_bloom(prev_meta);

            let pair_match = if is_paired {
                if use_exact {
                    paired_compact
                        .iter()
                        .zip(paired_ngrams)
                        .any(|(required_bytes, ngrams)| {
                            required_bytes
                                .iter()
                                .all(|&b| histogram.count(b) > 0 || prev_histogram.count(b) > 0)
                                && ngrams.iter().all(|&(first, second)| {
                                    bloom.maybe_contains_exact(first, second)
                                        || prev_bloom.maybe_contains_exact(first, second)
                                })
                        })
                } else {
                    paired_compact
                        .iter()
                        .zip(paired_ngrams)
                        .any(|(required_bytes, ngrams)| {
                            required_bytes
                                .iter()
                                .all(|&b| histogram.count(b) > 0 || prev_histogram.count(b) > 0)
                                && ngrams.iter().all(|&(first, second)| {
                                    bloom.maybe_contains_bloom(first, second)
                                        || prev_bloom.maybe_contains_bloom(first, second)
                                })
                        })
                }
            } else {
                byte_filter_matches_histogram_pair(byte_filter, prev_histogram, histogram)
                    && ngram_filter_matches_bloom_pair(ngram_filter, prev_bloom, bloom)
            };

            if pair_match {
                seen[index - 1] = true;
                seen[index] = true;
                continue;
            }

            // Multi-block window fallback for patterns spanning 3+ blocks
            let earliest_start = index.saturating_sub(window_blocks - 1);
            for window_start in earliest_start..index.saturating_sub(1) {
                let end = index + 1;
                let h_refs: Vec<_> = (window_start..end)
                    .map(|i| self.block_histogram(self.block_metas[i].offset))
                    .collect();
                let b_refs: Vec<_> = (window_start..end)
                    .map(|i| self.block_bloom(self.block_metas[i]))
                    .collect();

                let multi_match =
                    if is_paired {
                        if use_exact {
                            paired_compact.iter().zip(paired_ngrams).any(
                                |(required_bytes, ngrams)| {
                                    required_bytes
                                        .iter()
                                        .all(|&b| h_refs.iter().any(|h| h.count(b) > 0))
                                        && ngrams.iter().all(|&(first, second)| {
                                            b_refs.iter().any(|bloom| {
                                                bloom.maybe_contains_exact(first, second)
                                            })
                                        })
                                },
                            )
                        } else {
                            paired_compact.iter().zip(paired_ngrams).any(
                                |(required_bytes, ngrams)| {
                                    required_bytes
                                        .iter()
                                        .all(|&b| h_refs.iter().any(|h| h.count(b) > 0))
                                        && ngrams.iter().all(|&(first, second)| {
                                            b_refs.iter().any(|bloom| {
                                                bloom.maybe_contains_bloom(first, second)
                                            })
                                        })
                                },
                            )
                        }
                    } else {
                        byte_filter_matches_histogram_multi(byte_filter, &h_refs)
                            && ngram_filter_matches_bloom_multi(ngram_filter, &b_refs)
                    };

                if multi_match {
                    for item in seen.iter_mut().take(end).skip(window_start) {
                        *item = true;
                    }
                    break;
                }
            }
        }

        // Boundary safety: if block i matches and block i-1 contains any pattern
        // elements, a pattern might span the boundary.
        for index in 1..block_count {
            if seen[index] && !seen[index - 1] {
                let prev_meta = self.block_metas[index - 1];
                let prev_histogram = self.block_histogram(prev_meta.offset);
                let prev_bloom = self.block_bloom(prev_meta);
                let has_any = if is_paired {
                    if use_exact {
                        paired_compact.iter().zip(paired_ngrams).any(|(required_bytes, ngrams)| {
                            required_bytes.iter().any(|&b| prev_histogram.count(b) > 0)
                                || ngrams.iter().any(|&(first, second)| {
                                    prev_bloom.maybe_contains_exact(first, second)
                                })
                        })
                    } else {
                        paired_compact.iter().zip(paired_ngrams).any(|(required_bytes, ngrams)| {
                            required_bytes.iter().any(|&b| prev_histogram.count(b) > 0)
                                || ngrams.iter().any(|&(first, second)| {
                                    prev_bloom.maybe_contains_bloom(first, second)
                                })
                        })
                    }
                } else {
                    byte_filter
                        .compact_requirements()
                        .iter()
                        .any(|required_bytes| {
                            required_bytes.iter().any(|&b| prev_histogram.count(b) > 0)
                        })
                        || (!ngram_filter.union_ngrams().is_empty()
                            && prev_bloom.maybe_contains_any(ngram_filter.union_ngrams()))
                };
                if has_any {
                    seen[index - 1] = true;
                }
            }
        }

        let mut results = Vec::new();
        for (index, is_seen) in seen.into_iter().enumerate() {
            if is_seen {
                if let Some(c) = self.candidate_for_index(index) {
                    results.push(c);
                }
            }
        }
        crate::BlockIndex::merge_adjacent(&results)
    }

    /// Get the byte histogram for a block. Deprecated; use `try_histogram` to avoid errors on out of bounds.
    #[must_use]
    #[deprecated(since = "0.2.0", note = "use `try_histogram` instead to avoid panics")]
    pub fn histogram(&self, block_id: usize) -> ByteHistogramRef<'_> {
        self.try_histogram(block_id).unwrap_or(ByteHistogramRef {
            data: &[0; crate::index::SERIALIZED_HISTOGRAM_LEN],
        })
    }

    /// Access one block histogram without deserializing the whole index.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidBlockId` if `block_id` is out of range.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(b"hello").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let hist = mmap.try_histogram(0).unwrap();
    /// assert_eq!(hist.count(b'h'), 1);
    /// ```
    pub fn try_histogram(&self, block_id: usize) -> Result<ByteHistogramRef<'_>> {
        let offset = self
            .block_offsets
            .get(block_id)
            .copied()
            .ok_or(Error::InvalidBlockId {
                block_id,
                block_count: self.block_count,
            })?;
        Ok(self.block_histogram(offset))
    }

    /// Get the bloom filter for a block. Deprecated; use `try_bloom` to avoid errors on out of bounds.
    #[must_use]
    #[deprecated(since = "0.2.0", note = "use `try_bloom` instead to avoid panics")]
    pub fn bloom(&self, block_id: usize) -> NgramBloomRef<'_> {
        self.try_bloom(block_id).unwrap_or(NgramBloomRef {
            bloom_data: &[],
            exact_pairs_data: None,
            num_bits: 0,
        })
    }

    /// Access one block bloom filter without deserializing the whole index.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidBlockId` if `block_id` is out of range.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_bloom(b'a', b'b'));
    /// ```
    pub fn try_bloom(&self, block_id: usize) -> Result<NgramBloomRef<'_>> {
        let block_meta = *self
            .block_metas
            .get(block_id)
            .ok_or(Error::InvalidBlockId {
                block_id,
                block_count: self.block_count,
            })?;
        Ok(self.block_bloom(block_meta))
    }
}

fn byte_filter_matches_histogram(filter: &ByteFilter, histogram: ByteHistogramRef<'_>) -> bool {
    if filter.compact_requirements().is_empty() {
        return false;
    }

    filter
        .compact_requirements()
        .iter()
        .any(|required_bytes| required_bytes.iter().all(|&byte| histogram.count(byte) > 0))
}

fn byte_filter_matches_histogram_pair(
    filter: &ByteFilter,
    h1: ByteHistogramRef<'_>,
    h2: ByteHistogramRef<'_>,
) -> bool {
    let requirements = filter.compact_requirements();
    if requirements.is_empty() {
        return false;
    }
    requirements.iter().any(|required_bytes| {
        required_bytes
            .iter()
            .all(|&b| h1.count(b) > 0 || h2.count(b) > 0)
    })
}

fn byte_filter_matches_histogram_multi(
    filter: &ByteFilter,
    histograms: &[ByteHistogramRef<'_>],
) -> bool {
    let requirements = filter.compact_requirements();
    if requirements.is_empty() {
        return false;
    }
    requirements.iter().any(|required_bytes| {
        required_bytes
            .iter()
            .all(|&b| histograms.iter().any(|h| h.count(b) > 0))
    })
}

fn ngram_filter_matches_bloom_pair(
    filter: &NgramFilter,
    b1: NgramBloomRef<'_>,
    b2: NgramBloomRef<'_>,
) -> bool {
    let ngrams_list = filter.pattern_ngrams();
    if ngrams_list.is_empty() {
        return false;
    }

    if b1.uses_exact_pairs() && b2.uses_exact_pairs() {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                b1.maybe_contains_exact(first, second) || b2.maybe_contains_exact(first, second)
            })
        })
    } else {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                b1.maybe_contains_bloom(first, second) || b2.maybe_contains_bloom(first, second)
            })
        })
    }
}

fn ngram_filter_matches_bloom_multi(filter: &NgramFilter, blooms: &[NgramBloomRef<'_>]) -> bool {
    let ngrams_list = filter.pattern_ngrams();
    if ngrams_list.is_empty() {
        return false;
    }

    let use_exact = blooms.first().is_some_and(NgramBloomRef::uses_exact_pairs);
    if use_exact {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                blooms
                    .iter()
                    .any(|bloom| bloom.maybe_contains_exact(first, second))
            })
        })
    } else {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                blooms
                    .iter()
                    .any(|bloom| bloom.maybe_contains_bloom(first, second))
            })
        })
    }
}

fn ngram_filter_matches_bloom(filter: &NgramFilter, bloom: NgramBloomRef<'_>) -> bool {
    if filter.pattern_ngrams().is_empty() {
        return false;
    }

    // Fast early rejection: same rules as `NgramFilter::matches_bloom` (see filter.rs).
    let any_pattern_has_no_ngrams = filter
        .pattern_ngrams()
        .iter()
        .any(Vec::is_empty);
    let union_ngrams = filter.union_ngrams();
    if !any_pattern_has_no_ngrams
        && !union_ngrams.is_empty()
        && !bloom.maybe_contains_any(union_ngrams)
    {
        return false;
    }

    if bloom.uses_exact_pairs() {
        filter.pattern_ngrams().iter().any(|ngrams| {
            ngrams
                .iter()
                .all(|&(first, second)| bloom.maybe_contains_exact(first, second))
        })
    } else {
        filter.pattern_ngrams().iter().any(|ngrams| {
            ngrams
                .iter()
                .all(|&(first, second)| bloom.maybe_contains_bloom(first, second))
        })
    }
}
