//! Zero-parse block index access over serialized bytes.
//!
//! This module provides [`MmapBlockIndex`], a read-only view over the
//! serialized block-index wire format. It validates the header and block
//! layout once, then serves histogram and bloom queries directly from the
//! backing byte slice without heap-deserializing per-block summaries.

use crate::error::{Error, Result};
use crate::index::{
    parse_serialized_index_header, read_u64_le_checked, CandidateRange, EXACT_PAIR_TABLE_SIZE,
    MIN_SERIALIZED_BLOCK_LEN, SERIALIZED_BLOOM_HEADER_LEN, SERIALIZED_HISTOGRAM_LEN,
};

pub use crate::mmap_write::{ByteHistogramRef, NgramBloomRef};

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
    pub(crate) data: &'a [u8],
    pub(crate) block_size: usize,
    pub(crate) total_len: usize,
    pub(crate) block_count: usize,
    pub(crate) block_offsets: Vec<usize>,
    pub(crate) block_metas: Vec<BlockMeta>,
}

/// Per-block metadata for mmap access including exact-pair table offset.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BlockMeta {
    pub(crate) offset: usize,
    pub(crate) exact_pairs_offset: Option<usize>,
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

    pub(crate) fn candidate_for_index(&self, index: usize) -> Option<CandidateRange> {
        let offset = index.checked_mul(self.block_size)?;
        let remaining = self.total_len.saturating_sub(offset);
        let length = remaining.min(self.block_size);
        if length == 0 {
            return None;
        }
        Some(CandidateRange { offset, length })
    }

    pub(crate) fn block_histogram(&self, block_offset: usize) -> ByteHistogramRef<'_> {
        ByteHistogramRef {
            data: &self.data[block_offset..block_offset + SERIALIZED_HISTOGRAM_LEN],
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn block_bloom(&self, block_meta: BlockMeta) -> NgramBloomRef<'_> {
        // SAFETY: `num_bits` and `word_count` were validated in `from_slice` to fit in `usize`.
        // The `as usize` casts below are therefore truncating already-verified values.
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

fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
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
