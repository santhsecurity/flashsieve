#![allow(clippy::pedantic)]

//! Adversarial tests for exact-pairs at block boundaries — Jules missed these.
//!
//! These tests verify that patterns at block boundaries are correctly found
//! when exact-pairs is enabled (num_bits >= EXACT_PAIR_THRESHOLD_BITS).

#![allow(
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::unwrap_used
)]

use flashsieve::{BlockIndexBuilder, ByteFilter, MmapBlockIndex, NgramBloom, NgramFilter};

const EXACT_PAIR_THRESHOLD_BITS: usize = 4096;

/// CRITICAL: Verifies that exact-pairs bloom filters correctly handle patterns
/// at block boundaries. A false negative here means data loss at scale.
#[test]
fn exact_pairs_pattern_at_block_boundary_found() {
    let block_size = 256;
    // Pattern "XY" at positions 254-255 (end of block 0, start of block 1)
    let mut data = vec![b'a'; block_size * 2];
    data[254] = b'X';
    data[255] = b'Y';

    // Build with large bloom_bits to enable exact_pairs
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192) // >= EXACT_PAIR_THRESHOLD_BITS (4096)
        .build(&data)
        .expect("valid index");

    // Query for n-gram at the boundary
    let filter = NgramFilter::from_patterns(&[b"XY".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&filter);

    // CRITICAL: Pattern must be found in at least one block
    let found_block_0 = candidates.iter().any(|r| r.offset == 0);
    let found_block_1 = candidates.iter().any(|r| r.offset == block_size);

    assert!(
        found_block_0 || found_block_1,
        "CRITICAL FINDING: Pattern at block boundary not found! \
         This is a FALSE NEGATIVE at internet scale. \
         Pattern XY at positions 254-255 should be found."
    );
}

/// Tests cross-boundary n-gram where first byte is in block 0,
/// second byte is in block 1.
#[test]
fn exact_pairs_cross_boundary_ngram_found() {
    let block_size = 256;
    // n-gram "YZ" at positions 255-256 spans blocks 0 and 1
    let mut data = vec![b'a'; block_size * 2];
    data[255] = b'Y'; // Last byte of block 0
    data[256] = b'Z'; // First byte of block 1

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    let filter = NgramFilter::from_patterns(&[b"YZ".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&filter);

    // Cross-boundary n-gram should trigger the matches_bloom_pair logic
    assert!(
        !candidates.is_empty(),
        "Cross-boundary n-gram YZ (pos 255-256) should be found"
    );
}

/// Verifies that exact_pairs produces ZERO false positives for 2-byte pairs.
/// With exact_pairs enabled, maybe_contains_exact should be exact (no FPR).
#[test]
fn exact_pairs_zero_false_positives_for_pairs() {
    // Use minimum size for exact_pairs
    let mut bloom = NgramBloom::new(EXACT_PAIR_THRESHOLD_BITS).expect("valid bloom");

    // Insert a specific set of n-grams
    let inserted: &[(u8, u8)] = &[(b'a', b'b'), (b'c', b'd'), (b'e', b'f')];
    for (a, b) in inserted {
        bloom.insert_ngram(*a, *b);
    }

    // Verify all inserted pairs are found (no false negatives)
    for (a, b) in inserted {
        assert!(
            bloom.maybe_contains(*a, *b),
            "Inserted pair ({}, {}) should be found",
            *a as char,
            *b as char
        );
    }

    // Verify non-inserted pairs are NOT found (no false positives)
    // With exact_pairs, we should have ZERO false positives
    let mut false_positives = 0;
    let mut tested = 0;
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            if !inserted.contains(&(a, b)) {
                tested += 1;
                if bloom.maybe_contains(a, b) {
                    false_positives += 1;
                }
            }
        }
    }

    // Note: With exact_pairs enabled, we expect ZERO false positives
    // However, the current implementation may fall back to bloom-only
    // if exact_pairs table is not properly initialized
    assert_eq!(
        false_positives, 0,
        "CRITICAL: exact_pairs should produce ZERO false positives for 2-byte pairs, \
         got {} false positives out of {} tested",
        false_positives, tested
    );
}

/// Tests paired byte + ngram filter at block boundaries with exact-pairs.
#[test]
fn exact_pairs_paired_filter_at_boundary() {
    let block_size = 256;
    let mut data = vec![b'a'; block_size * 2];
    // Pattern at boundary: "needle" at positions 250-256
    data[250..256].copy_from_slice(b"needle");

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    let byte_filter = ByteFilter::from_patterns(&[b"needle".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"needle".as_slice()]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    assert!(
        !candidates.is_empty(),
        "Paired filter should find pattern at block boundary"
    );
}

/// FINDING 1 DEMONSTRATION: MmapBlockIndex never reports exact_pairs availability.
/// This test documents the bug where MmapBlockIndex always uses bloom-only path.
#[test]
fn mmap_vs_heap_exact_pairs_behavior() {
    let block_size = 256;
    let data = vec![b'x'; block_size * 4];

    // Build with large bloom_bits to enable exact_pairs
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    // Serialize and mmap
    let bytes = index.to_bytes();
    let mmap = MmapBlockIndex::from_slice(&bytes).expect("valid mmap");

    // Query both indexes with the same pattern
    let pattern = b"xy";
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    let heap_candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    let mmap_candidates = mmap.candidate_blocks(&byte_filter, &ngram_filter);

    // The results should be exactly the same, and both should correctly reject
    // the pattern because exact_pairs is enabled and "xy" is not present.
    assert!(
        heap_candidates.is_empty(),
        "heap should reject absent pattern"
    );
    assert!(
        mmap_candidates.is_empty(),
        "mmap should reject absent pattern"
    );
}

/// Tests that exact-pairs bloom filters handle all 65536 possible pairs.
#[test]
fn exact_pairs_all_65536_pairs() {
    let mut bloom = NgramBloom::new(EXACT_PAIR_THRESHOLD_BITS * 2).expect("valid bloom");

    // Insert all possible 2-byte n-grams
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            bloom.insert_ngram(a, b);
        }
    }

    // Verify all are found
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            assert!(
                bloom.maybe_contains(a, b),
                "False negative for pair ({}, {})",
                a,
                b
            );
        }
    }
}

/// Tests exact-pairs with single-byte pattern (no n-grams).
#[test]
fn exact_pairs_single_byte_pattern() {
    let block_size = 256;
    let mut data = vec![b'a'; block_size * 2];
    data[255] = b'X'; // Last byte of block 0

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    // Single byte pattern has no n-grams, so ngram filter matches everything
    let filter = NgramFilter::from_patterns(&[b"X".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&filter);

    // Should return all blocks (no n-gram filter applied)
    // This is expected behavior — ngram filter doesn't filter single-byte patterns
    assert!(!candidates.is_empty());
}

/// Tests exact-pairs with empty pattern.
#[test]
fn exact_pairs_empty_pattern() {
    let block_size = 256;
    let data = vec![b'a'; block_size * 2];

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    // Empty pattern has no n-grams
    let filter = NgramFilter::from_patterns(&[b"".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&filter);

    // Empty pattern behavior — should not panic
    let _ = candidates;
}

/// Tests patterns fully contained within a single block.
#[test]
fn exact_pairs_pattern_within_single_block() {
    let block_size = 256;
    let mut data = vec![b'a'; block_size * 4];

    // Pattern fully in block 1
    data[300..310].copy_from_slice(b"SECRETKEY=");

    // Pattern fully in block 2
    data[550..560].copy_from_slice(b"API_TOKEN=");

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    // Find SECRETKEY= in block 1
    let filter1 = NgramFilter::from_patterns(&[b"SECRETKEY=".as_slice()]);
    let candidates1 = index.candidate_blocks_ngram(&filter1);
    assert!(
        candidates1.iter().any(|r| r.offset == block_size),
        "Should find SECRETKEY= in block 1"
    );

    // Find API_TOKEN= in block 2
    let filter2 = NgramFilter::from_patterns(&[b"API_TOKEN=".as_slice()]);
    let candidates2 = index.candidate_blocks_ngram(&filter2);
    assert!(
        candidates2.iter().any(|r| r.offset == block_size * 2),
        "Should find API_TOKEN= in block 2"
    );
}

/// Tests that exact-pairs correctly rejects patterns not in data.
#[test]
fn exact_pairs_correctly_rejects_absent_patterns() {
    let block_size = 256;
    let data = vec![b'a'; block_size * 2];
    // Data contains only 'a' characters

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    // Pattern with characters not in data
    let filter = NgramFilter::from_patterns(&[b"XYZ".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&filter);

    // With exact_pairs, we expect zero false positives
    assert!(
        candidates.is_empty(),
        "exact_pairs should correctly reject absent patterns with zero false positives"
    );
}

/// Tests multiple queries on same index with different patterns.
#[test]
fn exact_pairs_multiple_queries_same_index() {
    let block_size = 256;
    let mut data = vec![b'a'; block_size * 2];
    data[100..106].copy_from_slice(b"SECRET");
    data[300..306].copy_from_slice(b"TOKEN=");

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .expect("valid index");

    // Query 1: SECRET
    let filter1 = NgramFilter::from_patterns(&[b"SECRET".as_slice()]);
    let candidates1 = index.candidate_blocks_ngram(&filter1);
    assert!(candidates1.iter().any(|r| r.offset == 0));

    // Query 2: TOKEN=
    let filter2 = NgramFilter::from_patterns(&[b"TOKEN=".as_slice()]);
    let candidates2 = index.candidate_blocks_ngram(&filter2);
    assert!(candidates2.iter().any(|r| r.offset == block_size));

    // Query 3: Neither (combined)
    let filter3 = NgramFilter::from_patterns(&[b"SECRET".as_slice(), b"TOKEN=".as_slice()]);
    let candidates3 = index.candidate_blocks_ngram(&filter3);
    // Adjacent blocks get merged, so we expect 1 range covering both blocks
    assert_eq!(candidates3.len(), 1);
    assert_eq!(candidates3[0].length, block_size * 2); // Covers both blocks
}
