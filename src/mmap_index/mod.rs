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

mod query;
mod views;

pub use views::{ByteHistogramRef, NgramBloomRef};

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
    pub(super) data: &'a [u8],
    pub(super) block_size: usize,
    pub(super) total_len: usize,
    pub(super) block_count: usize,
    pub(super) block_offsets: Vec<usize>,
    pub(super) block_metas: Vec<BlockMeta>,
}

/// Per-block metadata for mmap access including exact-pair table offset.
#[derive(Clone, Copy, Debug)]
pub(super) struct BlockMeta {
    pub(super) offset: usize,
    pub(super) exact_pairs_offset: Option<usize>,
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
        query::candidate_blocks(self, byte_filter, ngram_filter)
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

    pub(super) fn candidate_for_index(&self, index: usize) -> Option<CandidateRange> {
        let offset = index.checked_mul(self.block_size)?;
        let remaining = self.total_len.saturating_sub(offset);
        let length = remaining.min(self.block_size);
        if length == 0 {
            return None;
        }
        Some(CandidateRange { offset, length })
    }

    pub(super) fn block_histogram(&self, block_offset: usize) -> ByteHistogramRef<'a> {
        ByteHistogramRef {
            data: &self.data[block_offset..block_offset + SERIALIZED_HISTOGRAM_LEN],
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn block_bloom(&self, block_meta: BlockMeta) -> NgramBloomRef<'a> {
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

pub(super) fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests;
