#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::naive_bytecount,
    clippy::panic,
    clippy::unwrap_used
)]
//! Property-based tests for flashsieve invariants.
//!
//! These tests verify fundamental invariants for the bloom filter, histogram,
//! and indexing logic across a wide range of random inputs.

use flashsieve::{
    BlockIndex, BlockIndexBuilder, ByteFilter, ByteHistogram, NgramBloom, NgramFilter,
};
use proptest::prelude::*;
use rand::{Rng, SeedableRng};

// ============================================================================
// Strategies
// ============================================================================

/// Strategy for generating blocks of data
fn block_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=2048)
}

/// Strategy for generating valid bloom filter sizes (power of two)
fn bloom_size_strategy() -> impl Strategy<Value = usize> {
    prop_oneof![
        64usize..=1024,
        1024usize..=8192,
        Just(65536), // Threshold for exact-pairs table
    ]
}

/// Strategy for generating random patterns
fn pattern_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

// ============================================================================
// Properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    /// 1. Bloom filter: zero false negatives.
    /// If pattern is in block, bloom.maybe_contains_pattern(pattern) MUST be true.
    #[test]
    fn bloom_zero_false_negatives(
        block in block_strategy(),
        size in bloom_size_strategy(),
    ) {
        let bloom = NgramBloom::from_block(&block, size).unwrap();

        // Every n-gram in the block must be found
        for window in block.windows(2) {
            prop_assert!(
                bloom.maybe_contains(window[0], window[1]),
                "False negative for n-gram ({}, {})", window[0], window[1]
            );
        }

        // Every pattern that is a subslice of the block must be found
        if block.len() >= 2 {
            // Test a few substrings to keep test time reasonable even with 10k cases
            let mut rng = rand::thread_rng();
            for _ in 0..10 {
                let start = rng.gen_range(0..block.len() - 1);
                let end = rng.gen_range(start + 1..=block.len());
                let pattern = &block[start..end];
                prop_assert!(
                    bloom.maybe_contains_pattern(pattern),
                    "False negative for pattern of length {} at offset {}",
                    pattern.len(), start
                );
            }
        }
    }

    /// 2. Serialization roundtrip: BlockIndex::from_bytes(index.to_bytes()) == original
    #[test]
    fn serialization_roundtrip(
        block_size in prop_oneof![Just(256usize), Just(512), Just(1024), Just(2048)],
        num_blocks in 1usize..=10,
        bloom_bits in bloom_size_strategy(),
    ) {
        let total_size = block_size * num_blocks;
        let mut data = vec![0u8; total_size];
        let mut rng = rand::thread_rng();
        rng.fill(&mut data[..]);

        let original = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(bloom_bits)
            .build(&data)
            .unwrap();

        let bytes = original.to_bytes();
        let recovered = BlockIndex::from_bytes_checked(&bytes).expect("Roundtrip deserialization failed");

        prop_assert_eq!(original, recovered, "Serialization roundtrip failed: deserialized index differs from original");
    }

    /// 3. CRC integrity: corrupting any byte in serialized data causes from_bytes to return Err.
    #[test]
    fn crc_integrity(
        block_size in Just(256usize),
        num_blocks in Just(2usize),
        bloom_bits in Just(1024usize),
        seed in any::<u64>(),
    ) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut data = vec![0u8; block_size * num_blocks];
        rng.fill(&mut data[..]);

        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(bloom_bits)
            .build(&data)
            .unwrap();

        let mut bytes = index.to_bytes();
        // Pick a random byte to flip
        let idx = rng.gen_range(0..bytes.len());
        bytes[idx] ^= 0x01; // Flip one bit

        let result = BlockIndex::from_bytes_checked(&bytes);

        // CORNER CASE: If we flipped a bit in a region that isn't checked by CRC
        // or if by astronomical chance the CRC matches (1 in 2^32), this might pass.
        // But our CRC covers the whole payload.
        prop_assert!(
            result.is_err(),
            "CRC failed to detect corruption at index {}/{}", idx, bytes.len()
        );
    }

    /// 4. Histogram accuracy: ByteHistogram::from_block(data).count(byte) == data.iter().filter(|&&b| b == byte).count()
    #[test]
    fn histogram_accuracy(
        data in block_strategy(),
    ) {
        let hist = ByteHistogram::from_block(&data);
        for b in 0..=255u8 {
            let expected = data.iter().filter(|&&x| x == b).count() as u32;
            prop_assert_eq!(
                hist.count(b),
                expected,
                "Incorrect count for byte {} (0x{:02x})", b, b
            );
        }
    }

    /// 5. Candidate ranges: if a pattern exists in block N, then candidates(pattern) MUST include block N.
    #[test]
    fn candidate_ranges_contain_matches(
        block_size in prop_oneof![Just(256usize), Just(512), Just(1024)],
        num_blocks in 1usize..=5,
        target_block_idx in 0usize..5,
        pattern in pattern_strategy(),
    ) {
        let target_block = target_block_idx % num_blocks;
        let mut all_data = vec![0u8; block_size * num_blocks];
        let mut rng = rand::thread_rng();
        rng.fill(&mut all_data[..]);

        // Ensure pattern fits in block
        let p = if pattern.len() > block_size {
            &pattern[..block_size]
        } else {
            &pattern[..]
        };

        // Insert pattern into target block at random offset
        let offset_in_block = rng.gen_range(0..=(block_size - p.len()));
        let start = target_block * block_size + offset_in_block;
        all_data[start..start + p.len()].copy_from_slice(p);

        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&all_data)
            .unwrap();

        let byte_filter = ByteFilter::from_patterns(&[p]);
        let ngram_filter = NgramFilter::from_patterns(&[p]);

        let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

        let expected_offset = target_block * block_size;
        prop_assert!(
            candidates.iter().any(|r| expected_offset >= r.offset && expected_offset < r.offset + r.length),
            "Block {} (offset {}) not found in candidates for pattern of length {}",
            target_block, expected_offset, p.len()
        );
    }

    /// 6. Builder consistency: building an index from N blocks produces exactly N blocks in the result.
    #[test]
    fn builder_consistency(
        block_size in prop_oneof![Just(256usize), Just(512), Just(1024)],
        num_blocks in 1usize..=20,
    ) {
        let data = vec![0u8; block_size * num_blocks];
        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&data)
            .unwrap();

        prop_assert_eq!(index.block_count(), num_blocks);
    }

    /// 7. Incremental consistency: appending a block then querying produces same results as building from scratch.
    #[test]
    fn incremental_consistency(
        block_size in prop_oneof![Just(256usize), Just(512), Just(1024)],
        initial_blocks in 1usize..=5,
        append_blocks in 1usize..=5,
        pattern in pattern_strategy(),
    ) {
        let mut all_data = vec![0u8; block_size * (initial_blocks + append_blocks)];
        let mut rng = rand::thread_rng();
        rng.fill(&mut all_data[..]);

        // Build from scratch
        let full_index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&all_data)
            .unwrap();

        // Build incrementally
        let mut incremental_index = BlockIndexBuilder::new()
            .block_size(block_size)
            .build(&all_data[..initial_blocks * block_size])
            .unwrap();

        for i in 0..append_blocks {
            let start = (initial_blocks + i) * block_size;
            let end = start + block_size;
            incremental_index.append_block(&all_data[start..end]).unwrap();
        }

        prop_assert_eq!(full_index.block_count(), incremental_index.block_count());
        prop_assert_eq!(full_index.total_data_length(), incremental_index.total_data_length());

        let byte_filter = ByteFilter::from_patterns(&[&pattern]);
        let ngram_filter = NgramFilter::from_patterns(&[&pattern]);

        let full_candidates = full_index.candidate_blocks(&byte_filter, &ngram_filter);
        let incremental_candidates = incremental_index.candidate_blocks(&byte_filter, &ngram_filter);

        prop_assert_eq!(
            full_candidates,
            incremental_candidates,
            "Incremental index produced different candidate blocks"
        );
    }
}
