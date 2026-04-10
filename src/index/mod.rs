//! Block indexes and candidate range queries.
//!
//! This module provides [`BlockIndex`], a pre-computed index over blocked data
//! containing per-block byte histograms and n-gram bloom filters for fast
//! pre-filtering of pattern matching operations.
//!
//! # Serialization Wire Format
//!
//! The binary serialization format (version 2) is designed for portability
//! and integrity verification:
//!
//! ```text
//! Offset  Size  Field                    Description
//! ─────────────────────────────────────────────────────────────
//! 0       4     magic                    "FSBX" (0x46 0x53 0x42 0x58)
//! 4       4     version                  Format version (2)
//! 5       8     block_size               Block size in bytes (u64 LE)
//! 13      8     total_len                Total data length in bytes (u64 LE)
//! 21      8     block_count              Number of blocks (u64 LE)
//! 29      N     blocks[]                 Per-block data (see below)
//! N+29    4     crc32                    CRC-32 checksum (u32 LE)
//! ```
//!
//! ## Per-Block Layout
//!
//! ```text
//! Offset  Size  Field
//! ─────────────────────────────────────────────────────────────
//! 0       1024  histogram                256 x u32 LE counts
//! 1024    8     bloom_num_bits           Number of bloom bits (u64 LE)
//! 1032    8     bloom_word_count         Number of u64 words (u64 LE)
//! 1040    M     bloom_data               bloom_word_count x u64 LE
//! ```
//!
//! ## CRC-32 Calculation
//!
//! The CRC-32 is computed over all bytes from offset 0 to N+28 (everything
//! before the CRC field itself). Uses the standard ISO 3309 / ITU-T V.42
//! polynomial with a pre-computed lookup table for O(n) performance.
//!
//! - Polynomial: `0xEDB8_8320` (reversed)
//! - Initial value: `0xFFFF_FFFF`
//! - Final XOR: `0xFFFF_FFFF`
//!
//! The lookup table is computed at compile time using the bit-serial algorithm.
//!
//! # Version History
//!
//! - **Version 1**: Initial format, no CRC checksum
//! - **Version 2**: Added CRC-32 integrity check

use crate::bloom::NgramBloom;
use crate::histogram::ByteHistogram;

mod codec;
mod query;

pub(crate) use codec::{
    parse_serialized_index_header, read_u64_le_checked, EXACT_PAIR_TABLE_SIZE,
    MIN_SERIALIZED_BLOCK_LEN, SERIALIZED_BLOOM_HEADER_LEN, SERIALIZED_HISTOGRAM_LEN,
};
pub use query::CandidateRange;

/// A pre-computed index over blocked data for fast pre-filtering.
///
/// Contains per-block byte histograms and n-gram bloom filters.
/// Use [`BlockIndexBuilder`](crate::BlockIndexBuilder) to construct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockIndex {
    pub(crate) block_size: usize,
    pub(crate) bloom_bits: usize,
    pub(crate) total_len: usize,
    pub(crate) histograms: Vec<ByteHistogram>,
    pub(crate) blooms: Vec<NgramBloom>,
}

impl BlockIndex {
    /// Create a new block index from its component summaries.
    ///
    /// The caller is responsible for providing matching histogram and bloom
    /// counts, plus a `total_len` consistent with the represented data.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndex, ByteHistogram, NgramBloom};
    ///
    /// let hist = ByteHistogram::from_block(b"hello");
    /// let bloom = NgramBloom::from_block(b"hello", 1024).unwrap();
    /// let index = BlockIndex::new(256, 5, vec![hist], vec![bloom]);
    /// assert_eq!(index.block_count(), 1);
    /// ```
    #[must_use]
    pub fn new(
        block_size: usize,
        total_len: usize,
        histograms: Vec<ByteHistogram>,
        blooms: Vec<NgramBloom>,
    ) -> Self {
        let bloom_bits = blooms.first().map_or(0, |bloom| bloom.raw_parts().0);
        Self {
            block_size,
            bloom_bits,
            total_len,
            histograms,
            blooms,
        }
    }

    /// Return the configured block size.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let index = BlockIndexBuilder::new().block_size(512).build(b"hello").unwrap();
    /// assert_eq!(index.block_size(), 512);
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
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(&[0u8; 512]).unwrap();
    /// assert_eq!(index.block_count(), 2);
    /// ```
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.histograms.len()
    }

    /// Return the total indexed byte length.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"hello").unwrap();
    /// assert_eq!(index.total_data_length(), 5);
    /// ```
    #[must_use]
    pub fn total_data_length(&self) -> usize {
        self.total_len
    }

    /// Return statistics about the index size, FPR, and cache efficiency.
    ///
    /// Note: `avg_fpr_per_block` and `cache_efficiency` use `f64` and may lose
    /// precision for block counts or bloom sizes exceeding `2^53`.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"hello").unwrap();
    /// let stats = index.stats();
    /// assert!(stats.total_bytes_used > 0);
    /// ```
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn stats(&self) -> BlockIndexStats {
        let total_bytes_used = self.blooms.iter().map(|b| b.bits.len() * 8).sum::<usize>()
            + self.histograms.len() * 256 * 4;

        let avg_fpr_per_block = if self.blooms.is_empty() {
            0.0
        } else {
            self.blooms
                .iter()
                .map(crate::bloom::NgramBloom::estimated_false_positive_rate)
                .sum::<f64>()
                / (self.blooms.len() as f64)
        };

        let bytes_per_block = self.bloom_bits / 8;
        let cache_efficiency = if bytes_per_block == 0 {
            0.0
        } else {
            32768.0 / (bytes_per_block as f64)
        };

        BlockIndexStats {
            total_bytes_used,
            avg_fpr_per_block,
            cache_efficiency,
        }
    }
}

/// Statistics about a block index.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockIndexStats {
    /// Total bytes consumed by histograms and bloom filters.
    pub total_bytes_used: usize,
    /// Average estimated false positive rate across all blocks.
    pub avg_fpr_per_block: f64,
    /// Ratio of L1 cache size (assumed 32KB) to the bloom filter size per block.
    pub cache_efficiency: f64,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::BlockIndex;
    use crate::index::CandidateRange;
    use crate::{BlockIndexBuilder, ByteFilter, NgramFilter};
    use rand::rngs::StdRng;
    use rand::{Rng, RngCore, SeedableRng};

    fn make_data(block_size: usize) -> Vec<u8> {
        let mut data = vec![b'x'; block_size * 4];
        data[block_size..block_size + 6].copy_from_slice(b"secret");
        data[block_size * 3..block_size * 3 + 5].copy_from_slice(b"token");
        data
    }

    #[test]
    fn index_build_and_query_byte() {
        let block_size = 256;
        let data = make_data(block_size);
        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));

        let filter = ByteFilter::from_patterns(&[b"secret".as_slice()]);
        let candidates = index.candidate_blocks_byte(&filter);

        // Byte-filter boundary safety may include adjacent blocks, so we
        // only assert that the block containing the pattern is present.
        assert!(
            candidates.iter().any(|r| r.offset == block_size),
            "expected block 1 to be included, got {candidates:?}"
        );
    }

    #[test]
    fn index_build_and_query_ngram() {
        let block_size = 256;
        let data = make_data(block_size);
        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));

        let filter = NgramFilter::from_patterns(&[b"token".as_slice()]);
        let candidates = index.candidate_blocks_ngram(&filter);

        assert_eq!(
            candidates,
            vec![CandidateRange {
                offset: block_size * 3,
                length: block_size
            }]
        );
    }

    #[test]
    fn index_selectivity() {
        let block_size = 256;
        let mut data = vec![b'a'; block_size * 10];
        data[block_size * 7..block_size * 7 + 6].copy_from_slice(b"rarezz");

        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));
        let byte_filter = ByteFilter::from_patterns(&[b"rarezz".as_slice()]);
        let ngram_filter = NgramFilter::from_patterns(&[b"rarezz".as_slice()]);
        let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

        assert!(index.selectivity(&candidates) < 0.4);
    }

    #[test]
    fn index_no_false_negatives() {
        let block_size = 256;
        let mut rng = StdRng::seed_from_u64(0xB10C_1D3A);
        let mut data = vec![0_u8; block_size * 8];
        rng.fill_bytes(&mut data);

        let pattern = b"needle";
        let offsets = [10_usize, block_size + 32, block_size * 5 + 100];
        for &offset in &offsets {
            data[offset..offset + pattern.len()].copy_from_slice(pattern);
        }

        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));
        let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
        let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
        let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

        for &offset in &offsets {
            let expected_start = (offset / block_size) * block_size;
            assert!(candidates.iter().any(|range| expected_start >= range.offset
                && expected_start < range.offset + range.length));
        }
    }

    #[test]
    fn index_merge_adjacent() {
        let ranges = vec![
            CandidateRange {
                offset: 0,
                length: 256,
            },
            CandidateRange {
                offset: 256,
                length: 256,
            },
            CandidateRange {
                offset: 1024,
                length: 256,
            },
        ];

        assert_eq!(
            BlockIndex::merge_adjacent(&ranges),
            vec![
                CandidateRange {
                    offset: 0,
                    length: 512
                },
                CandidateRange {
                    offset: 1024,
                    length: 256
                }
            ]
        );
    }

    #[test]
    fn index_streaming_build() {
        let block_size = 256;
        let data = make_data(block_size);
        let builder = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(1024);
        let batch = builder
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));
        let streaming = builder
            .build_streaming(data.chunks(block_size).map(<[u8]>::to_vec))
            .unwrap_or_else(|error| panic!("{error}"));

        let filter = ByteFilter::from_patterns(&[b"secret".as_slice(), b"token".as_slice()]);
        assert_eq!(
            batch.candidate_blocks_byte(&filter),
            streaming.candidate_blocks_byte(&filter)
        );

        let ngram = NgramFilter::from_patterns(&[b"secret".as_slice(), b"token".as_slice()]);
        assert_eq!(
            batch.candidate_blocks(&filter, &ngram),
            streaming.candidate_blocks(&filter, &ngram)
        );
    }

    #[test]
    fn to_bytes_from_bytes_round_trip() {
        let block_size = 256;
        let data = make_data(block_size);
        let original = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(1024)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));

        let serialized = original.to_bytes();
        let deserialized =
            BlockIndex::from_bytes(&serialized).expect("round-trip deserialization must succeed");

        assert_eq!(original.block_size(), deserialized.block_size());
        assert_eq!(original.block_count(), deserialized.block_count());
        assert_eq!(
            original.total_data_length(),
            deserialized.total_data_length()
        );

        let byte_filter = ByteFilter::from_patterns(&[b"secret".as_slice()]);
        assert_eq!(
            original.candidate_blocks_byte(&byte_filter),
            deserialized.candidate_blocks_byte(&byte_filter),
        );

        let ngram_filter = NgramFilter::from_patterns(&[b"secret".as_slice()]);
        assert_eq!(
            original.candidate_blocks_ngram(&ngram_filter),
            deserialized.candidate_blocks_ngram(&ngram_filter),
        );
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let block_size = 256;
        let data = make_data(block_size);
        let original = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));

        let mut bad = original.to_bytes();
        bad[0] = b'X';
        assert!(BlockIndex::from_bytes(&bad).is_none());
    }

    #[test]
    fn from_bytes_rejects_truncated() {
        let block_size = 256;
        let data = make_data(block_size);
        let original = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));

        let serialized = original.to_bytes();
        let truncated = &serialized[..serialized.len() / 2];
        assert!(BlockIndex::from_bytes(truncated).is_none());
    }

    #[test]
    fn crc_detects_single_bit_flip() {
        let block_size = 256;
        let data = make_data(block_size);
        let original = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));

        let mut serialized = original.to_bytes();
        let flip_pos = serialized.len() / 2;
        serialized[flip_pos] ^= 0x01;

        let result = BlockIndex::from_bytes_checked(&serialized);
        assert!(result.is_err(), "CRC should detect bit flip");
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::Error::ChecksumMismatch { .. }),
            "expected ChecksumMismatch, got: {err}"
        );
    }

    #[test]
    fn crc_round_trip_succeeds() {
        let block_size = 256;
        let data = make_data(block_size);
        let original = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(1024)
            .build(&data)
            .unwrap_or_else(|error| panic!("{error}"));

        let serialized = original.to_bytes();
        let result = BlockIndex::from_bytes_checked(&serialized);
        assert!(
            result.is_ok(),
            "CRC round-trip should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn from_bytes_checked_invalid_magic_error() {
        let bad_data = b"XSIE\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let err = BlockIndex::from_bytes_checked(bad_data).unwrap_err();
        assert!(
            matches!(err, crate::Error::InvalidMagic { .. }),
            "expected InvalidMagic, got: {err}"
        );
    }

    #[test]
    fn from_bytes_checked_unsupported_version_error() {
        let mut bad_data = vec![0u8; 40];
        bad_data[0..4].copy_from_slice(b"FSBX");
        bad_data[4..8].copy_from_slice(&99u32.to_le_bytes());
        let err = BlockIndex::from_bytes_checked(&bad_data).unwrap_err();
        assert!(
            matches!(err, crate::Error::UnsupportedVersion { got: 99, .. }),
            "expected UnsupportedVersion(99), got: {err}"
        );
    }

    #[test]
    fn from_bytes_checked_truncated_header_error() {
        let err = BlockIndex::from_bytes_checked(b"FSBX").unwrap_err();
        assert!(
            matches!(err, crate::Error::TruncatedHeader { .. }),
            "expected TruncatedHeader, got: {err}"
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn from_bytes_arbitrary_input_never_panics() {
        let mut rng = StdRng::seed_from_u64(0xFEED_FACE);
        for _ in 0..10_000 {
            let len = rng.gen_range(0..2000);
            let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let _ = BlockIndex::from_bytes(&data);
            let _ = BlockIndex::from_bytes_checked(&data);
        }
    }

    #[test]
    fn block_index_stats() {
        let block_size = 256;
        let data = make_data(block_size);
        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();

        let stats = index.stats();
        assert!(stats.total_bytes_used > 0);
        assert!(stats.avg_fpr_per_block >= 0.0);
        assert!(stats.cache_efficiency > 0.0);
    }
}
