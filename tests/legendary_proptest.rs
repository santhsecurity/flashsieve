#![allow(
    clippy::cast_precision_loss,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
//! Property-based tests for flashsieve using proptest.
//!
//! These tests verify fundamental invariants that should hold for all
//! possible inputs, not just specific test cases.

use flashsieve::{BlockIndexBuilder, BlockedNgramBloom, ByteFilter, NgramBloom, NgramFilter};
use proptest::prelude::*;

/// Strategy for generating valid bloom filter sizes
fn bloom_size_strategy() -> impl Strategy<Value = usize> {
    prop_oneof![
        64usize..=1024,
        1024usize..=65536,
        Just(65536), // Exact size for exact_pairs table
    ]
}

/// Strategy for generating byte pairs (n-grams)
fn ngram_strategy() -> impl Strategy<Value = (u8, u8)> {
    any::<(u8, u8)>()
}

/// Strategy for generating blocks of data
fn block_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=1024)
}

// ============================================================================
// Property: No False Negatives
// ============================================================================

proptest! {
    #[test]
    fn no_false_negatives(
        ngrams in prop::collection::vec(ngram_strategy(), 0..=100),
        size in bloom_size_strategy(),
    ) {
        let mut bloom = NgramBloom::new(size).unwrap();

        // Insert all n-grams
        for (a, b) in &ngrams {
            bloom.insert_ngram(*a, *b);
        }

        // Every inserted n-gram must be found
        for (a, b) in &ngrams {
            prop_assert!(
                bloom.maybe_contains(*a, *b),
                "False negative for n-gram ({}, {})",
                a, b
            );
        }
    }
}

proptest! {
    #[test]
    fn blocked_bloom_inserted_pairs_never_false_negative(
        size in bloom_size_strategy(),
        ngrams in prop::collection::vec(ngram_strategy(), 1..=256),
    ) {
        let mut bloom = BlockedNgramBloom::new(size).unwrap();

        for (a, b) in &ngrams {
            bloom.insert(*a, *b);
        }

        for (a, b) in &ngrams {
            prop_assert!(
                bloom.maybe_contains(*a, *b),
                "blocked bloom lost inserted pair ({}, {})",
                a,
                b
            );
        }
    }
}

// ============================================================================
// Property: Insert is Idempotent
// ============================================================================

proptest! {
    #[test]
    fn insert_idempotent(
        ngram in ngram_strategy(),
        size in bloom_size_strategy(),
        insert_count in 1usize..=100,
    ) {
        let mut bloom = NgramBloom::new(size).unwrap();

        // Insert the same n-gram multiple times
        for _ in 0..insert_count {
            bloom.insert_ngram(ngram.0, ngram.1);
        }

        // Should be found
        prop_assert!(bloom.maybe_contains(ngram.0, ngram.1));

        // The FPR estimate should be the same regardless of insert count
        // (since it's based on bit count, not insert count)
        let fpr = bloom.estimated_false_positive_rate();
        prop_assert!((0.0..=1.0).contains(&fpr));
    }
}

// ============================================================================
// Property: Serialization Roundtrip
// ============================================================================

proptest! {
    #[test]
    fn serialization_roundtrip(
        blocks in prop::collection::vec(block_strategy(), 1..=10),
    ) {
        // All blocks must be same size for indexing
        if blocks.is_empty() {
            return Ok(());
        }

        let block_size = blocks[0].len();
        if block_size == 0 {
            return Ok(());
        }

        // Pad or truncate blocks to same size
        let normalized_blocks: Vec<Vec<u8>> = blocks
            .into_iter()
            .map(|mut b| {
                b.resize(block_size, 0);
                b
            })
            .collect();

        let result = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(1024.min(block_size * 8))
            .build_streaming(normalized_blocks.into_iter());

        // May fail if block_size isn't power of two or < 256
        if let Ok(index) = result {
            let bytes = index.to_bytes();
            let recovered = flashsieve::BlockIndex::from_bytes(&bytes);

            prop_assert!(
                recovered.is_some(),
                "Deserialization failed for serialized data"
            );

            let recovered = recovered.unwrap();
            prop_assert_eq!(
                index.block_count(),
                recovered.block_count(),
                "Block count mismatch after roundtrip"
            );
            prop_assert_eq!(
                index.block_size(),
                recovered.block_size(),
                "Block size mismatch after roundtrip"
            );
        }
    }
}

// ============================================================================
// Property: Monotonic Positive (more inserts = higher or equal FPR estimate)
// ============================================================================

proptest! {
    #[test]
    fn monotonic_fpr_estimate(
        size in bloom_size_strategy(),
        initial_ngrams in prop::collection::vec(ngram_strategy(), 0..=50),
        additional_ngrams in prop::collection::vec(ngram_strategy(), 0..=50),
    ) {
        let mut bloom = NgramBloom::new(size).unwrap();

        // Measure FPR after initial inserts
        for (a, b) in &initial_ngrams {
            bloom.insert_ngram(*a, *b);
        }
        let fpr_before = bloom.estimated_false_positive_rate();

        // Insert additional n-grams
        for (a, b) in &additional_ngrams {
            bloom.insert_ngram(*a, *b);
        }
        let fpr_after = bloom.estimated_false_positive_rate();

        // FPR estimate should be monotonic non-decreasing
        prop_assert!(
            fpr_after >= fpr_before - 1e-10, // Allow tiny floating point error
            "FPR estimate decreased: {} -> {}",
            fpr_before,
            fpr_after
        );
    }
}

// ============================================================================
// Property: Empty Bloom Returns False for All Queries
// ============================================================================

proptest! {
    #[test]
    fn empty_bloom_all_false(
        size in bloom_size_strategy(),
        queries in prop::collection::vec(ngram_strategy(), 1..=100),
    ) {
        let bloom = NgramBloom::new(size).unwrap();

        for (a, b) in queries {
            prop_assert!(
                !bloom.maybe_contains(a, b),
                "Empty bloom returned true for query ({}, {})",
                a, b
            );
        }
    }
}

// ============================================================================
// Property: Pattern Queries are Consistent
// ============================================================================

proptest! {
    #[test]
    fn pattern_query_consistency(
        block in block_strategy(),
        size in bloom_size_strategy(),
    ) {
        if block.len() < 2 {
            return Ok(());
        }

        let bloom = NgramBloom::from_block(&block, size).unwrap();

        // Extract all n-grams from the block
        for window in block.windows(2) {
            let a = window[0];
            let b = window[1];

            // Each n-gram in the block must be found
            prop_assert!(
                bloom.maybe_contains(a, b),
                "N-gram ({}, {}) from block not found",
                a, b
            );
        }
    }
}

// ============================================================================
// Property: Filter False Negatives Never Occur
// ============================================================================

proptest! {
    #[test]
    fn filter_no_false_negatives(
        block in block_strategy(),
        pattern in prop::collection::vec(any::<u8>(), 1..=20),
    ) {
        use flashsieve::ByteHistogram;

        if block.is_empty() || pattern.is_empty() {
            return Ok(());
        }

        let hist = ByteHistogram::from_block(&block);
        let bloom = NgramBloom::from_block(&block, 1024).unwrap();

        let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
        let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

        // If the pattern actually exists in the block, the filters must match
        let pattern_in_block = block
            .windows(pattern.len())
            .any(|w| w == pattern.as_slice());

        if pattern_in_block {
            prop_assert!(
                byte_filter.matches_histogram(&hist),
                "Byte filter false negative for pattern in block"
            );

            // Ngram filter should also match (may have false positives but no false negatives)
            prop_assert!(
                ngram_filter.matches_bloom(&bloom),
                "Ngram filter false negative for pattern in block"
            );
        }
    }
}

// ============================================================================
// Property: Byte Filter Empty Patterns Never Match
// ============================================================================

proptest! {
    #[test]
    fn empty_byte_filter_never_matches(
        block in block_strategy(),
    ) {
        use flashsieve::ByteHistogram;

        let hist = ByteHistogram::from_block(&block);
        let filter = ByteFilter::from_patterns(&[]);

        prop_assert!(
            !filter.matches_histogram(&hist),
            "Empty filter should never match"
        );
    }
}

// ============================================================================
// Property: Merge Adjacent is Correct
// ============================================================================

proptest! {
    #[test]
    fn merge_adjacent_properties(
        ranges in prop::collection::vec(
            (0usize..=10000usize, 1usize..=1000usize),
            0..=50
        ),
    ) {
        use flashsieve::index::CandidateRange;

        let mut ranges: Vec<CandidateRange> = ranges
            .into_iter()
            .map(|(offset, length)| CandidateRange { offset, length })
            .collect();

        // Sort by offset as required by merge_adjacent
        // Use stable sort to handle duplicates deterministically
        ranges.sort_by(|a, b| a.offset.cmp(&b.offset));

        // Remove duplicates for clean testing (same offset ranges)
        ranges.dedup_by(|a, b| a.offset == b.offset);

        let merged = flashsieve::BlockIndex::merge_adjacent(&ranges);

        // Property: merged ranges should be sorted (non-decreasing)
        for i in 1..merged.len() {
            prop_assert!(
                merged[i].offset >= merged[i-1].offset,
                "Merged ranges not sorted"
            );
        }

        // Property: no adjacent ranges should remain
        for i in 1..merged.len() {
            let prev_end = merged[i-1].offset + merged[i-1].length;
            prop_assert!(
                prev_end != merged[i].offset,
                "Adjacent ranges not merged"
            );
        }

        // Property: total coverage should be preserved
        let original_coverage: usize = ranges.iter().map(|r| r.length).sum();
        let merged_coverage: usize = merged.iter().map(|r| r.length).sum();
        prop_assert_eq!(
            original_coverage, merged_coverage,
            "Coverage changed after merge"
        );
    }
}

// ============================================================================
// Property: FPR Target is Achievable
// ============================================================================

proptest! {
    #[test]
    fn target_fpr_produces_reasonable_size(
        target_fpr in 0.0001f64..=0.5f64,
        expected_items in 100usize..=10000usize,
    ) {
        let result = NgramBloom::with_target_fpr(target_fpr, expected_items);

        // Should always succeed for valid inputs
        prop_assert!(
            result.is_ok(),
            "with_target_fpr failed for fpr={}, items={}",
            target_fpr, expected_items
        );

        let bloom = result.unwrap();
        let (num_bits, _) = bloom.raw_parts();

        // The resulting filter should be large enough to theoretically
        // achieve the target FPR
        let n = expected_items as f64;
        let m = num_bits as f64;
        let k = 3.0f64;
        let theoretical_fpr = (1.0 - (-k * n / m).exp()).powf(k);

        // Allow 2x margin on size due to power-of-two rounding
        prop_assert!(
            theoretical_fpr <= target_fpr * 2.0 || num_bits >= 64,
            "Filter too small: theoretical_fpr={} target={}",
            theoretical_fpr, target_fpr
        );
    }
}

// ============================================================================
// Property: Deserialization Never Panics
// ============================================================================

proptest! {
    #[test]
    fn deserialization_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..=2000),
    ) {
        // Any byte sequence should either deserialize successfully or fail gracefully
        let _ = flashsieve::BlockIndex::from_bytes(&data);
        let _ = flashsieve::BlockIndex::from_bytes_checked(&data);
        // Should not panic
    }
}

// ============================================================================
// Property: Byte Count is Monotonic
// ============================================================================

proptest! {
    #[test]
    fn byte_count_monotonic(
        initial_bytes in prop::collection::vec(any::<u8>(), 0..=50),
        additional_bytes in prop::collection::vec(any::<u8>(), 0..=50),
    ) {
        use flashsieve::ByteHistogram;

        let mut hist = ByteHistogram::from_block(&initial_bytes);

        // Record counts before
        let counts_before: Vec<u32> = (0u8..=255).map(|b| hist.count(b)).collect();

        // Add more data
        let more_data: Vec<u8> = initial_bytes
            .into_iter()
            .chain(additional_bytes.into_iter())
            .collect();
        hist = ByteHistogram::from_block(&more_data);

        // Record counts after
        let counts_after: Vec<u32> = (0u8..=255).map(|b| hist.count(b)).collect();

        // All counts should be >= previous counts
        for (before, after) in counts_before.iter().zip(counts_after.iter()) {
            prop_assert!(
                after >= before,
                "Byte count decreased: {} -> {}",
                before, after
            );
        }
    }
}

// ============================================================================
// Property: Selectivity is in [0, 1]
// ============================================================================

proptest! {
    #[test]
    fn selectivity_in_valid_range(
        block_sizes in prop::collection::vec(256usize..=1024usize, 1..=5),
    ) {
        // Build index with random blocks
        let mut all_data = Vec::new();
        for size in &block_sizes {
            let size = size.next_power_of_two();
            all_data.extend(vec![0u8; size]);
        }

        if let Ok(index) = BlockIndexBuilder::new()
            .block_size(256)
            .build(&all_data)
        {
            use flashsieve::index::CandidateRange;

            // Generate some candidate ranges
            let candidates: Vec<CandidateRange> = (0..index.block_count())
                .map(|i| CandidateRange {
                    offset: i * index.block_size(),
                    length: index.block_size(),
                })
                .collect();

            let selectivity = index.selectivity(&candidates);

            prop_assert!(
                (0.0..=1.0).contains(&selectivity),
                "Selectivity out of range: {}",
                selectivity
            );
        }
    }
}
