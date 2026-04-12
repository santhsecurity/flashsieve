use super::BlockIndex;
use crate::bloom::NgramBloom;
use crate::filter::{ByteFilter, NgramFilter};

/// A range of bytes identified as a candidate for pattern matching.
///
/// Returned by query methods on [`BlockIndex`]. Adjacent ranges can be
/// merged using [`BlockIndex::merge_adjacent`] to reduce fragmentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRange {
    /// Byte offset of the candidate range.
    pub offset: usize,
    /// Length of the candidate range in bytes.
    pub length: usize,
}

impl BlockIndex {
    /// Query using byte-level filtering.
    ///
    /// Returns one range per indexed block that satisfies the byte filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, ByteFilter};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"secret").unwrap();
    /// let filter = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    /// let candidates = index.candidate_blocks_byte(&filter);
    /// assert!(!candidates.is_empty());
    /// ```
    #[must_use]
    pub fn candidate_blocks_byte(&self, filter: &ByteFilter) -> Vec<CandidateRange> {
        let block_count = self.histograms.len();
        let mut seen = vec![false; block_count];
        for index in 0..block_count {
            let h = &self.histograms[index];
            if filter.matches_histogram(h) {
                seen[index] = true;
                continue;
            }
            if index > 0 && filter.matches_histogram_pair(&self.histograms[index - 1], h) {
                seen[index - 1] = true;
                seen[index] = true;
            }
        }
        // Boundary safety: if block i matches and block i-1 contains any required
        // bytes, a pattern might span the boundary.
        for index in 1..block_count {
            if seen[index]
                && !seen[index - 1]
                && filter.has_any_required_byte(&self.histograms[index - 1])
            {
                seen[index - 1] = true;
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
        Self::merge_adjacent(&results)
    }

    /// Query using n-gram filtering.
    ///
    /// Returns one range per indexed block that satisfies the n-gram filter,
    /// checking adjacent blocks to prevent false negatives at block boundaries.
    /// Patterns spanning more than two blocks are handled by sliding-window
    /// checks sized from the longest pattern length.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, NgramFilter};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"secret").unwrap();
    /// let filter = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    /// let candidates = index.candidate_blocks_ngram(&filter);
    /// assert!(!candidates.is_empty());
    /// ```
    #[must_use]
    pub fn candidate_blocks_ngram(&self, filter: &NgramFilter) -> Vec<CandidateRange> {
        let block_count = self.blooms.len();
        if block_count == 0 {
            return Vec::new();
        }

        // A pattern of length L can span at most ceil(L / block_size) + 1 blocks
        // when it starts near a boundary. We check windows of this size.
        let window_blocks = filter
            .max_pattern_bytes()
            .div_ceil(self.block_size)
            .max(1)
            .saturating_add(1)
            .min(block_count);
        let mut seen = vec![false; block_count];

        for index in 0..block_count {
            // Single block match
            if filter.matches_bloom(&self.blooms[index]) {
                seen[index] = true;
                continue;
            }

            if index == 0 {
                continue;
            }

            // Pair match with previous block
            if filter.matches_bloom_pair(&self.blooms[index - 1], &self.blooms[index]) {
                seen[index - 1] = true;
                seen[index] = true;
                continue;
            }

            // Multi-block window fallback for patterns spanning 3+ blocks
            let earliest_start = index.saturating_sub(window_blocks - 1);
            for window_start in earliest_start..index.saturating_sub(1) {
                let end = index + 1;
                if filter.matches_bloom_multi(&self.blooms[window_start..end]) {
                    for item in seen.iter_mut().take(end).skip(window_start) {
                        *item = true;
                    }
                    break;
                }
            }
        }

        // Boundary safety: if block i matches and block i-1 contains any pattern
        // n-grams, a pattern might span the boundary.
        let union = filter.union_ngrams();
        if !union.is_empty() {
            for index in 1..block_count {
                if seen[index]
                    && !seen[index - 1]
                    && self.blooms[index - 1].maybe_contains_any(union)
                {
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
        Self::merge_adjacent(&results)
    }

    /// Query using byte and n-gram filtering.
    ///
    /// When both filters were built from the same pattern list length, this
    /// keeps per-pattern byte and n-gram requirements paired to avoid
    /// cross-pattern false positives.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"secret").unwrap();
    /// let byte_filter = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    /// let ngram_filter = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    /// let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
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
        // Hoist the exact-pairs check outside the per-block loop — all blocks
        // in an index use the same bloom_bits, so this is constant.
        let use_exact = self
            .blooms
            .first()
            .is_some_and(NgramBloom::uses_exact_pairs);

        let block_count = self.histograms.len();
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
            let histogram = &self.histograms[index];
            let bloom = &self.blooms[index];

            // Single block match
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
                byte_filter.matches_histogram(histogram) && ngram_filter.matches_bloom(bloom)
            };

            if single_match {
                seen[index] = true;
                continue;
            }

            if index == 0 {
                continue;
            }

            let prev_histogram = &self.histograms[index - 1];
            let prev_bloom = &self.blooms[index - 1];

            // Pair match with previous block
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
                byte_filter.matches_histogram_pair(prev_histogram, histogram)
                    && ngram_filter.matches_bloom_pair(prev_bloom, bloom)
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
                let h_slice = &self.histograms[window_start..end];
                let b_slice = &self.blooms[window_start..end];

                let multi_match =
                    if is_paired {
                        if use_exact {
                            paired_compact.iter().zip(paired_ngrams).any(
                                |(required_bytes, ngrams)| {
                                    required_bytes
                                        .iter()
                                        .all(|&b| h_slice.iter().any(|h| h.count(b) > 0))
                                        && ngrams.iter().all(|&(first, second)| {
                                            b_slice.iter().any(|bloom| {
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
                                        .all(|&b| h_slice.iter().any(|h| h.count(b) > 0))
                                        && ngrams.iter().all(|&(first, second)| {
                                            b_slice.iter().any(|bloom| {
                                                bloom.maybe_contains_bloom(first, second)
                                            })
                                        })
                                },
                            )
                        }
                    } else {
                        byte_filter.matches_histogram_multi(h_slice)
                            && ngram_filter.matches_bloom_multi(b_slice)
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
                let prev_histogram = &self.histograms[index - 1];
                let prev_bloom = &self.blooms[index - 1];
                let has_any =
                    if is_paired {
                        if use_exact {
                            paired_compact.iter().zip(paired_ngrams).any(
                                |(required_bytes, ngrams)| {
                                    required_bytes.iter().any(|&b| prev_histogram.count(b) > 0)
                                        || ngrams.iter().any(|&(first, second)| {
                                            prev_bloom.maybe_contains_exact(first, second)
                                        })
                                },
                            )
                        } else {
                            paired_compact.iter().zip(paired_ngrams).any(
                                |(required_bytes, ngrams)| {
                                    required_bytes.iter().any(|&b| prev_histogram.count(b) > 0)
                                        || ngrams.iter().any(|&(first, second)| {
                                            prev_bloom.maybe_contains_bloom(first, second)
                                        })
                                },
                            )
                        }
                    } else {
                        byte_filter.has_any_required_byte(prev_histogram)
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
        Self::merge_adjacent(&results)
    }

    /// Merge adjacent candidate ranges into contiguous regions.
    ///
    /// The input is expected to be sorted by `offset`.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndex, CandidateRange};
    ///
    /// let ranges = vec![
    ///     CandidateRange { offset: 0, length: 256 },
    ///     CandidateRange { offset: 256, length: 256 },
    /// ];
    /// let merged = BlockIndex::merge_adjacent(&ranges);
    /// assert_eq!(merged.len(), 1);
    /// assert_eq!(merged[0].length, 512);
    /// ```
    #[must_use]
    pub fn merge_adjacent(ranges: &[CandidateRange]) -> Vec<CandidateRange> {
        let mut iter = ranges.iter().copied();
        let Some(mut current) = iter.next() else {
            return Vec::new();
        };

        let mut merged = Vec::with_capacity(ranges.len());
        for range in iter {
            if current.offset.checked_add(current.length) == Some(range.offset) {
                current.length = current.length.saturating_add(range.length);
            } else if current.offset == range.offset && current.length == range.length {
                // Ignore identical duplicates
            } else {
                merged.push(current);
                current = range;
            }
        }
        merged.push(current);
        merged
    }

    /// Return the percentage of total data covered by candidate ranges.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, ByteFilter};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(&[0u8; 512]).unwrap();
    /// let filter = ByteFilter::from_patterns(&[b"x".as_slice()]);
    /// let candidates = index.candidate_blocks_byte(&filter);
    /// let selectivity = index.selectivity(&candidates);
    /// assert!(selectivity >= 0.0 && selectivity <= 1.0);
    /// ```
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn selectivity(&self, ranges: &[CandidateRange]) -> f64 {
        if self.total_len == 0 {
            return 0.0;
        }

        let covered = ranges.iter().map(|range| range.length).sum::<usize>();
        covered as f64 / self.total_len as f64
    }

    pub(super) fn candidate_for_index(&self, index: usize) -> Option<CandidateRange> {
        let offset = index.checked_mul(self.block_size)?;
        let remaining = self.total_len.saturating_sub(offset);
        let length = remaining.min(self.block_size);
        if length == 0 {
            return None;
        }
        Some(CandidateRange { offset, length })
    }
}
