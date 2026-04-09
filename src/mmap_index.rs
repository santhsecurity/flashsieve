//! Zero-parse block index access over serialized bytes.
//!
//! This module provides [`MmapBlockIndex`], a read-only view over the
//! serialized block-index wire format. It validates the header and block
//! layout once, then serves histogram and bloom queries directly from the
//! backing byte slice without heap-deserializing per-block summaries.

// EXACT_PAIR_WORDS is used via EXACT_PAIR_TABLE_SIZE from index module
use crate::error::{Error, Result};
use crate::filter::{ByteFilter, NgramFilter};
use crate::index::{
    parse_serialized_index_header, read_u64_le_checked, CandidateRange, EXACT_PAIR_TABLE_SIZE,
    MIN_SERIALIZED_BLOCK_LEN, SERIALIZED_BLOOM_HEADER_LEN, SERIALIZED_HISTOGRAM_LEN,
};

const SERIALIZED_HEADER_LEN: usize = 4 + 4 + 8 + 8 + 8;

/// Magic marker for exact-pair table presence.
const EXACT_PAIR_MARKER_PRESENT: u64 = crate::bloom::NgramBloom::exact_pair_magic();
/// A read-only view over a serialized [`BlockIndex`](crate::BlockIndex).
///
/// Construct from bytes that already contain a persisted flashsieve index,
/// such as a memory-mapped file.
///
/// # Example
///
/// ```
/// use flashsieve::{BlockIndexBuilder, ByteFilter, MmapBlockIndex, NgramFilter};
///
/// let bytes = BlockIndexBuilder::new()
///     .block_size(256)
///     .bloom_bits(1024)
///     .build(b"secret token")?
///     .to_bytes();
/// let mmap_index = MmapBlockIndex::from_slice(&bytes)?;
/// let byte_filter = ByteFilter::from_patterns(&[b"secret".as_slice()]);
/// let ngram_filter = NgramFilter::from_patterns(&[b"secret".as_slice()]);
///
/// assert_eq!(mmap_index.candidate_blocks(&byte_filter, &ngram_filter).len(), 1);
/// # Ok::<(), flashsieve::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct MmapBlockIndex<'a> {
    data: &'a [u8],
    block_size: usize,
    total_len: usize,
    block_count: usize,
    block_offsets: Vec<usize>,
    block_metas: Vec<BlockMeta>,
}

/// Per-block metadata for mmap access including exact-pair table offset.
#[derive(Clone, Copy, Debug)]
struct BlockMeta {
    offset: usize,
    exact_pairs_offset: Option<usize>,
}

impl<'a> MmapBlockIndex<'a> {
    /// Create a validated mmap-backed index view from serialized bytes.
    ///
    /// The backing data is borrowed directly. Histogram counts and bloom words
    /// remain in-place in the serialized region.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as
    /// [`BlockIndex::from_bytes_checked`](crate::BlockIndex::from_bytes_checked)
    /// when the header, checksum, or per-block layout is invalid.
    pub fn from_slice(data: &'a [u8]) -> Result<Self> {
        let header = parse_serialized_index_header(data)?;
        let mut offset = SERIALIZED_HEADER_LEN;
        let mut block_offsets = Vec::with_capacity(header.block_count);
        let mut block_metas = Vec::with_capacity(header.block_count);

        for block_index in 0..header.block_count {
            let block_start = offset;
            let is_truncated = match block_start.checked_add(MIN_SERIALIZED_BLOCK_LEN) {
                Some(end) => end > header.payload_end,
                None => true,
            };
            if is_truncated {
                return Err(Error::TruncatedBlock { block_index });
            }

            offset += SERIALIZED_HISTOGRAM_LEN;

            let num_bits_raw = read_u64_le_checked(&data[..header.payload_end], &mut offset)
                .map_err(|_| Error::TruncatedBlock { block_index })?;
            let has_exact_pairs = (num_bits_raw & 0x8000_0000_0000_0000) != 0;
            let num_bits =
                usize::try_from(num_bits_raw & !0x8000_0000_0000_0000).unwrap_or(usize::MAX);

            let word_count = usize::try_from(
                read_u64_le_checked(&data[..header.payload_end], &mut offset)
                    .map_err(|_| Error::TruncatedBlock { block_index })?,
            )
            .unwrap_or(usize::MAX);

            let required_bytes = word_count
                .checked_mul(std::mem::size_of::<u64>())
                .ok_or(Error::TruncatedBlock { block_index })?;
            let bloom_end = offset
                .checked_add(required_bytes)
                .ok_or(Error::TruncatedBlock { block_index })?;
            if bloom_end > header.payload_end {
                return Err(Error::TruncatedBlock { block_index });
            }
            if num_bits == 0 {
                return Err(Error::TruncatedBlock { block_index });
            }
            if !num_bits.is_power_of_two() {
                return Err(Error::TruncatedBlock { block_index });
            }
            if word_count < num_bits.div_ceil(64) {
                return Err(Error::TruncatedBlock { block_index });
            }

            offset = bloom_end;

            // Check for exact-pair table
            let exact_pairs_offset: Option<usize> = if has_exact_pairs {
                if offset + 8 > header.payload_end {
                    return Err(Error::TruncatedBlock { block_index });
                }
                let marker = u64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                if marker != EXACT_PAIR_MARKER_PRESENT {
                    return Err(Error::TruncatedBlock { block_index });
                }
                offset += 8;

                if offset + EXACT_PAIR_TABLE_SIZE > header.payload_end {
                    return Err(Error::TruncatedBlock { block_index });
                }
                let pairs_offset = offset;
                offset += EXACT_PAIR_TABLE_SIZE;
                Some(pairs_offset)
            } else {
                None
            };

            block_offsets.push(block_start);
            block_metas.push(BlockMeta {
                offset: block_start,
                exact_pairs_offset,
            });
        }

        Ok(Self {
            data,
            block_size: header.block_size,
            total_len: header.total_len,
            block_count: header.block_count,
            block_offsets: block_metas.iter().map(|m| m.offset).collect(),
            block_metas,
        })
    }

    /// Return the configured block size.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(b"x").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// assert_eq!(mmap.block_size(), 256);
    /// ```
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Return the number of indexed blocks.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(&[0u8; 512]).unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// assert_eq!(mmap.block_count(), 2);
    /// ```
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.block_count
    }

    /// Return the total indexed byte length.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(b"hello").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// assert_eq!(mmap.total_data_length(), 5);
    /// ```
    #[must_use]
    pub fn total_data_length(&self) -> usize {
        self.total_len
    }

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
            .saturating_add(1);
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
    pub fn histogram(&self, block_id: usize) -> ByteHistogramRef<'a> {
        self.try_histogram(block_id).unwrap_or(ByteHistogramRef {
            data: &[0; SERIALIZED_HISTOGRAM_LEN],
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
    pub fn try_histogram(&self, block_id: usize) -> Result<ByteHistogramRef<'a>> {
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
    pub fn bloom(&self, block_id: usize) -> NgramBloomRef<'a> {
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
    pub fn try_bloom(&self, block_id: usize) -> Result<NgramBloomRef<'a>> {
        let block_meta = *self
            .block_metas
            .get(block_id)
            .ok_or(Error::InvalidBlockId {
                block_id,
                block_count: self.block_count,
            })?;
        Ok(self.block_bloom(block_meta))
    }

    fn candidate_for_index(&self, index: usize) -> Option<CandidateRange> {
        let offset = index.checked_mul(self.block_size)?;
        let remaining = self.total_len.saturating_sub(offset);
        let length = remaining.min(self.block_size);
        if length == 0 {
            return None;
        }
        Some(CandidateRange { offset, length })
    }

    fn block_histogram(&self, block_offset: usize) -> ByteHistogramRef<'a> {
        ByteHistogramRef {
            data: &self.data[block_offset..block_offset + SERIALIZED_HISTOGRAM_LEN],
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn block_bloom(&self, block_meta: BlockMeta) -> NgramBloomRef<'a> {
        let bloom_header_offset = block_meta.offset + SERIALIZED_HISTOGRAM_LEN;
        let num_bits_raw = read_u64_le(
            &self.data[bloom_header_offset..bloom_header_offset + std::mem::size_of::<u64>()],
        );
        let num_bits = (num_bits_raw & !0x8000_0000_0000_0000) as usize;
        let word_count = read_u64_le(
            &self.data[bloom_header_offset + std::mem::size_of::<u64>()
                ..bloom_header_offset + SERIALIZED_BLOOM_HEADER_LEN],
        ) as usize;
        let data_offset = bloom_header_offset + SERIALIZED_BLOOM_HEADER_LEN;
        let data_len = word_count * std::mem::size_of::<u64>();

        NgramBloomRef {
            bloom_data: &self.data[data_offset..data_offset + data_len],
            exact_pairs_data: block_meta
                .exact_pairs_offset
                .map(|offset| &self.data[offset..offset + EXACT_PAIR_TABLE_SIZE]),
            num_bits,
        }
    }
}

/// A zero-parse histogram view into serialized block-index bytes.
///
/// The serialized format stores histogram counts as 256 little-endian `u32`
/// values. This reference reads those counts in-place on demand.
#[derive(Clone, Copy, Debug)]
pub struct ByteHistogramRef<'a> {
    data: &'a [u8],
}

impl ByteHistogramRef<'_> {
    /// Return the occurrence count for one byte value.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(b"hello").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let hist = mmap.try_histogram(0).unwrap();
    /// assert_eq!(hist.count(b'l'), 2);
    /// ```
    #[must_use]
    pub fn count(&self, byte: u8) -> u32 {
        let offset = usize::from(byte) * std::mem::size_of::<u32>();
        u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    #[cfg(test)]
    fn to_owned(self) -> ByteHistogram {
        let mut counts = [0_u32; 256];
        for byte in u8::MIN..=u8::MAX {
            counts[usize::from(byte)] = self.count(byte);
        }
        ByteHistogram::from_raw_counts(counts)
    }
}

/// A zero-parse bloom-filter view into serialized block-index bytes.
///
/// The serialized format stores bloom words as little-endian `u64` values.
/// When exact-pair tables are present in the serialized data, they are
/// used for exact 2-byte n-gram queries.
#[derive(Clone, Copy, Debug)]
pub struct NgramBloomRef<'a> {
    bloom_data: &'a [u8],
    exact_pairs_data: Option<&'a [u8]>,
    num_bits: usize,
}

impl NgramBloomRef<'_> {
    /// Return the serialized bloom bit count.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"x").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert_eq!(bloom.num_bits(), 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Test a 2-byte n-gram against the exact-pair path when available.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(4096).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_exact(b'a', b'b'));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn maybe_contains_exact(&self, first: u8, second: u8) -> bool {
        if let Some(exact_pairs) = self.exact_pairs_data {
            let pair = (usize::from(first) << 8) | usize::from(second);
            let word_index = pair >> 6;
            let bit_offset = pair & 63;
            let offset = word_index * std::mem::size_of::<u64>();
            let word = u64::from_le_bytes([
                exact_pairs[offset],
                exact_pairs[offset + 1],
                exact_pairs[offset + 2],
                exact_pairs[offset + 3],
                exact_pairs[offset + 4],
                exact_pairs[offset + 5],
                exact_pairs[offset + 6],
                exact_pairs[offset + 7],
            ]);
            return (word & (1_u64 << bit_offset)) != 0;
        }

        // Fall back to bloom filter if no exact-pair table
        self.maybe_contains_bloom(first, second)
    }

    /// Test a 2-byte n-gram against the serialized bloom filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_bloom(b'a', b'b'));
    /// ```
    #[must_use]
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn maybe_contains_bloom(&self, first: u8, second: u8) -> bool {
        let (h1, h2) = hash_pair(first, second);
        let mask = (self.num_bits as u64).wrapping_sub(1);
        let idx0 = (h1 & mask) as usize;
        let idx1 = (h1.wrapping_add(h2) & mask) as usize;
        let idx2 = (h1.wrapping_add(h2.wrapping_mul(2)) & mask) as usize;
        self.bit_is_set(idx0) && self.bit_is_set(idx1) && self.bit_is_set(idx2)
    }

    /// Batch check multiple n-grams with OR semantics.
    ///
    /// Returns `true` if ANY n-gram is present. Optimized for internet-scale
    /// workloads where early rejection based on union n-grams is critical.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_any(&[(b'x', b'y'), (b'a', b'b')]));
    /// ```
    #[must_use]
    #[inline]
    pub fn maybe_contains_any(&self, ngrams: &[(u8, u8)]) -> bool {
        if ngrams.is_empty() {
            return false;
        }
        if self.uses_exact_pairs() {
            ngrams.iter().any(|&(a, b)| self.maybe_contains_exact(a, b))
        } else {
            ngrams.iter().any(|&(a, b)| self.maybe_contains_bloom(a, b))
        }
    }

    /// Batch check multiple n-grams with AND semantics.
    ///
    /// Returns `true` only if ALL n-grams are present.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_all(&[(b'a', b'b')]));
    /// ```
    #[must_use]
    #[inline]
    pub fn maybe_contains_all(&self, ngrams: &[(u8, u8)]) -> bool {
        if ngrams.is_empty() {
            return true;
        }
        if self.uses_exact_pairs() {
            ngrams.iter().all(|&(a, b)| self.maybe_contains_exact(a, b))
        } else {
            ngrams.iter().all(|&(a, b)| self.maybe_contains_bloom(a, b))
        }
    }

    /// Returns true if this bloom filter has an exact-pair table.
    #[must_use]
    #[inline]
    fn uses_exact_pairs(&self) -> bool {
        self.exact_pairs_data.is_some()
    }

    fn bit_is_set(&self, bit_index: usize) -> bool {
        let word_index = bit_index / 64;
        let bit_offset = bit_index % 64;
        (self.bloom_word(word_index) & (1_u64 << bit_offset)) != 0
    }

    fn bloom_word(&self, word_index: usize) -> u64 {
        let offset = word_index * std::mem::size_of::<u64>();
        u64::from_le_bytes([
            self.bloom_data[offset],
            self.bloom_data[offset + 1],
            self.bloom_data[offset + 2],
            self.bloom_data[offset + 3],
            self.bloom_data[offset + 4],
            self.bloom_data[offset + 5],
            self.bloom_data[offset + 6],
            self.bloom_data[offset + 7],
        ])
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

    // Fast early rejection: check union n-grams first (O(union_size) vs O(patterns × ngrams))
    let union_ngrams = filter.union_ngrams();
    if !union_ngrams.is_empty() && !bloom.maybe_contains_any(union_ngrams) {
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

fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

use crate::bloom::hash::hash_pair;

#[cfg(test)]
use crate::histogram::ByteHistogram;

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::MmapBlockIndex;
    use crate::{BlockIndex, BlockIndexBuilder, ByteFilter, NgramFilter};

    #[test]
    fn mmap_candidate_blocks_match_heap_index() {
        let block_size = 256;
        let mut block_a = vec![b'x'; block_size];
        let mut block_b = vec![b'y'; block_size];
        let mut block_c = vec![b'z'; block_size];
        block_a[..6].copy_from_slice(b"secret");
        block_b[..5].copy_from_slice(b"token");
        block_c[..6].copy_from_slice(b"secret");

        let bytes = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(2048)
            .build_streaming([block_a, block_b, block_c].into_iter())
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let heap_index =
            BlockIndex::from_bytes_checked(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let mmap_index =
            MmapBlockIndex::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));

        for pattern in [
            b"secret".as_slice(),
            b"token".as_slice(),
            b"miss".as_slice(),
        ] {
            let byte_filter = ByteFilter::from_patterns(&[pattern]);
            let ngram_filter = NgramFilter::from_patterns(&[pattern]);
            assert_eq!(
                mmap_index.candidate_blocks(&byte_filter, &ngram_filter),
                heap_index.candidate_blocks(&byte_filter, &ngram_filter)
            );
        }
    }

    #[test]
    fn mmap_accessors_match_heap_index_contents() {
        let bytes = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(b"abacus secret token zebra")
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let heap_index =
            BlockIndex::from_bytes_checked(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let mmap_index =
            MmapBlockIndex::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));

        #[allow(clippy::unwrap_used)]
        let histogram = mmap_index.try_histogram(0).unwrap();
        for byte in [b'a', b's', b't', b'z', b'!'] {
            assert_eq!(
                histogram.count(byte),
                heap_index.histograms[0].count(byte),
                "byte {byte}"
            );
        }

        #[allow(clippy::unwrap_used)]
        let mmap_bloom = mmap_index.try_bloom(0).unwrap();
        let heap_bloom = &heap_index.blooms[0];
        for (first, second) in [(b'a', b'b'), (b's', b'e'), (b't', b'o'), (b'!', b'!')] {
            assert_eq!(
                mmap_bloom.maybe_contains_bloom(first, second),
                heap_bloom.maybe_contains_bloom(first, second)
            );
        }

        assert_eq!(
            histogram.to_owned().raw_counts(),
            heap_index.histograms[0].raw_counts()
        );
        assert_eq!(mmap_bloom.num_bits(), heap_bloom.raw_parts().0);
    }

    #[test]
    fn mmap_rejects_truncated_block_payload() {
        let mut bytes = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(b"secret token")
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        bytes.pop();

        assert!(MmapBlockIndex::from_slice(&bytes).is_err());
    }
}
