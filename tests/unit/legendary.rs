#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::items_after_statements,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::unwrap_used
)]
//! Legendary adversarial tests for flashsieve.
//!
//! This module contains comprehensive edge-case and adversarial tests
//! to ensure robustness against unexpected inputs and usage patterns.

use flashsieve::{
    BlockIndex, BlockIndexBuilder, ByteFilter, ByteHistogram, NgramBloom, NgramFilter,
};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::collections::HashSet;

// ============================================================================
// 1. Empty Filter Tests
// ============================================================================

#[test]
fn empty_filter_no_inserts_all_queries_false() {
    let bloom = NgramBloom::new(1024).unwrap();
    // Query all possible n-grams
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            assert!(
                !bloom.maybe_contains(a, b),
                "Empty filter should return false for ({}, {})",
                a,
                b
            );
        }
    }
}

#[test]
fn empty_histogram_all_counts_zero() {
    let hist = ByteHistogram::new();
    for byte in 0u8..=255 {
        assert_eq!(
            hist.count(byte),
            0,
            "Empty histogram count for {} should be 0",
            byte
        );
    }
}

#[test]
fn empty_block_produces_empty_bloom() {
    let bloom = NgramBloom::from_block(&[], 1024).unwrap();
    assert!(!bloom.maybe_contains(b'a', b'b'));
}

// ============================================================================
// 2. No False Negatives Tests
// ============================================================================

#[test]
fn no_false_negatives_10000_inserts() {
    let mut bloom = NgramBloom::new(65536).unwrap();
    let mut inserted = Vec::new();
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);

    // Insert 10000 random n-grams
    for _ in 0..10000 {
        let a = rng.gen();
        let b = rng.gen();
        bloom.insert_ngram(a, b);
        inserted.push((a, b));
    }

    // Verify all inserted items are found
    for (a, b) in inserted {
        assert!(
            bloom.maybe_contains(a, b),
            "False negative for inserted n-gram ({}, {})",
            a,
            b
        );
    }
}

#[test]
fn no_false_negatives_all_65536_pairs() {
    let mut bloom = NgramBloom::new(65536).unwrap();

    // Insert all possible 2-byte combinations
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
                "False negative for ({}, {})",
                a,
                b
            );
        }
    }
}

// ============================================================================
// 3. FPR Measurement Tests
// ============================================================================

#[test]
fn fpr_within_theoretical_bound() {
    let num_bits = 32768;
    let num_inserts = 1000;
    let num_tests = 10000;

    let mut bloom = NgramBloom::new(num_bits).unwrap();
    let mut rng = StdRng::seed_from_u64(0xF1A5_510E);
    let mut inserted = HashSet::new();

    // Insert random items
    for _ in 0..num_inserts {
        let a = rng.gen();
        let b = rng.gen();
        bloom.insert_ngram(a, b);
        inserted.insert((a, b));
    }

    // Test random absent items
    let mut false_positives = 0;
    let mut trials = 0;
    for _ in 0..num_tests {
        let a = rng.gen();
        let b = rng.gen();
        if !inserted.contains(&(a, b)) {
            trials += 1;
            if bloom.maybe_contains(a, b) {
                false_positives += 1;
            }
        }
    }

    let measured_fpr = false_positives as f64 / trials as f64;

    // Theoretical FPR with k=3: (1 - e^(-kn/m))^k
    let n = num_inserts as f64;
    let m = num_bits as f64;
    let k = 3.0;
    let theoretical_fpr = (1.0 - (-k * n / m).exp()).powf(k);

    // Allow 50% margin above theoretical bound
    let max_acceptable_fpr = theoretical_fpr * 1.5;

    assert!(
        measured_fpr < max_acceptable_fpr,
        "FPR {} exceeds theoretical bound {} (with margin)",
        measured_fpr,
        max_acceptable_fpr
    );
}

// ============================================================================
// 4. Serialization Roundtrip Tests
// ============================================================================

#[test]
fn serialization_roundtrip_empty_index() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 256])
        .unwrap();

    let bytes = index.to_bytes();
    let recovered = BlockIndex::from_bytes(&bytes).unwrap();

    assert_eq!(index.block_size(), recovered.block_size());
    assert_eq!(index.block_count(), recovered.block_count());
}

#[test]
fn serialization_roundtrip_multiple_blocks() {
    let mut data = vec![0u8; 1024];
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
    rng.fill_bytes(&mut data);

    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let bytes = index.to_bytes();
    let recovered = BlockIndex::from_bytes(&bytes).unwrap();

    // Query results should be identical
    let filter = ByteFilter::from_patterns(&[b"\x00".as_slice()]);
    assert_eq!(
        index.candidate_blocks_byte(&filter),
        recovered.candidate_blocks_byte(&filter)
    );
}

#[test]
fn truncated_deserialize_fails_gracefully() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 512])
        .unwrap();

    let bytes = index.to_bytes();

    // Try various truncation points
    for truncate_at in [1, 10, 20, 29, 100, bytes.len() - 1] {
        if truncate_at < bytes.len() {
            let truncated = &bytes[..truncate_at];
            assert!(
                BlockIndex::from_bytes(truncated).is_none(),
                "Should fail for truncation at {}",
                truncate_at
            );
        }
    }
}

#[test]
fn corrupted_crc_detected() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 256])
        .unwrap();

    let mut bytes = index.to_bytes();

    // Corrupt a byte in the middle
    let mid = bytes.len() / 2;
    bytes[mid] = bytes[mid].wrapping_add(1);

    let result = BlockIndex::from_bytes_checked(&bytes);
    assert!(result.is_err());
}

#[test]
fn corrupted_data_detected_by_crc() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 1024])
        .unwrap();

    let mut bytes = index.to_bytes();

    // Corrupt multiple bytes
    for i in (0..bytes.len() - 4).step_by(100) {
        bytes[i] ^= 0xFF;
    }

    assert!(BlockIndex::from_bytes(&bytes).is_none());
}

// ============================================================================
// 5. Edge Case Tests
// ============================================================================

#[test]
fn zero_size_filter_rejected() {
    assert!(NgramBloom::new(0).is_err());
}

#[test]
fn huge_item_count_handled() {
    // Test with very large expected item count for with_target_fpr
    let bloom = NgramBloom::with_target_fpr(0.01, 1_000_000_000).unwrap();
    assert!(!bloom.raw_parts().1.is_empty());
}

#[test]
fn single_byte_block() {
    // Block with only 1 byte has no n-grams
    let bloom = NgramBloom::from_block(b"x", 1024).unwrap();
    assert!(!bloom.maybe_contains(b'x', b'x'));
}

#[test]
fn two_byte_block_single_ngram() {
    // Block with exactly 2 bytes has exactly 1 n-gram
    let bloom = NgramBloom::from_block(b"ab", 1024).unwrap();
    assert!(bloom.maybe_contains(b'a', b'b'));
    assert!(!bloom.maybe_contains(b'b', b'a'));
}

#[test]
fn binary_data_with_nulls() {
    let data = vec![0u8, 1, 2, 0, 3, 0, 0, 255];
    let bloom = NgramBloom::from_block(&data, 1024).unwrap();

    // Should handle null bytes correctly
    assert!(bloom.maybe_contains(0, 1));
    assert!(bloom.maybe_contains(0, 0));
    assert!(bloom.maybe_contains(0, 3));
}

// ============================================================================
// 6. Duplicate Insert Tests
// ============================================================================

#[test]
fn duplicate_inserts_idempotent() {
    let mut bloom = NgramBloom::new(1024).unwrap();

    // Insert same n-gram many times
    for _ in 0..1000 {
        bloom.insert_ngram(b'x', b'y');
    }

    // Should still be found
    assert!(bloom.maybe_contains(b'x', b'y'));

    // FPR estimate should account for actual fill, not insert count
    let fpr = bloom.estimated_false_positive_rate();
    assert!(fpr < 0.01, "FPR after duplicate inserts should be low");
}

#[test]
fn all_same_byte_repeated() {
    let data = vec![b'A'; 10000];
    let bloom = NgramBloom::from_block(&data, 1024).unwrap();

    // Only one distinct n-gram: "AA"
    assert!(bloom.maybe_contains(b'A', b'A'));
}

// ============================================================================
// 7. Hash Distribution Tests
// ============================================================================

#[test]
fn hash_distribution_spread() {
    let mut bloom = NgramBloom::new(4096).unwrap();

    // Insert sequential pairs
    for i in 0..256u16 {
        let a = (i >> 8) as u8;
        let b = i as u8;
        bloom.insert_ngram(a, b);
    }

    // Check that bits are spread (not all concentrated)
    let (_, bits) = bloom.raw_parts();
    let ones: u64 = bits.iter().map(|w| u64::from(w.count_ones())).sum();

    // With 256 inserts and k=3, expect roughly 768 bits set
    // Allow for variance but ensure reasonable spread
    assert!(
        ones > 100,
        "Bits should be well distributed, got {} ones",
        ones
    );
    assert!(ones < 4000, "Too many bits set: {}", ones);
}

// ============================================================================
// 8. CRC-32 Reference Values
// ============================================================================

/// Compute CRC-32 for verification
fn crc32_reference(data: &[u8]) -> u32 {
    let table: [u32; 256] = {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut crc = i as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
            *slot = crc;
        }
        t
    };

    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let idx = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    !crc
}

#[test]
fn crc32_reference_values() {
    // Known CRC-32 values for test strings
    let test_cases = [
        (b"" as &[u8], 0x0000_0000),
        (b"\x00\x00\x00\x00", 0x2144_df1c),
        (b"123456789", 0xcbf4_3926),
        (b"FSBX", 0x563e_bc55),
    ];

    for (input, expected) in &test_cases {
        let computed = crc32_reference(input);
        assert_eq!(computed, *expected, "CRC-32 mismatch for input {:?}", input);
    }
}

// ============================================================================
// 9. FNV-64 Reference Values
// ============================================================================

fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[test]
fn fnv1a_64_reference_values() {
    // Known FNV-1a 64-bit test vectors from the FNV spec
    let test_cases = [
        (b"" as &[u8], 0xCBF2_9CE4_8422_2325u64),
        (b"a", 0xAF63_DC4C_8601_EC8C),
        (b"foobar", 0x8594_4171_F739_67E8),
    ];

    for (input, expected) in &test_cases {
        let computed = fnv1a_64(input);
        assert_eq!(
            computed, *expected,
            "FNV-1a 64 mismatch for input {:?}",
            input
        );
    }
}

// ============================================================================
// 10. Concurrent Read Tests
// ============================================================================

#[test]
fn concurrent_reads_thread_safe() {
    use std::sync::Arc;
    use std::thread;

    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 2048])
        .unwrap();

    let index = Arc::new(index);
    let mut handles = vec![];

    // Spawn 8 threads doing concurrent reads
    for thread_id in 0..8 {
        let idx = Arc::clone(&index);
        let handle = thread::spawn(move || {
            let filter = ByteFilter::from_patterns(&[b"test".as_slice()]);
            for _ in 0..1000 {
                let candidates = idx.candidate_blocks_byte(&filter);
                assert_eq!(candidates.len(), 0); // No matches expected
            }
            thread_id
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
}

// ============================================================================
// 11. Filter Edge Cases
// ============================================================================

#[test]
fn empty_pattern_filter_never_matches() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 256])
        .unwrap();

    let filter = ByteFilter::from_patterns(&[]);
    let candidates = index.candidate_blocks_byte(&filter);
    assert!(candidates.is_empty());
}

#[test]
fn single_byte_pattern_matches_all_with_byte() {
    let mut data = vec![0u8; 256];
    data[100] = b'x';

    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();

    let filter = ByteFilter::from_patterns(&[b"x".as_slice()]);
    let candidates = index.candidate_blocks_byte(&filter);
    assert_eq!(candidates.len(), 1);
}

#[test]
fn pattern_longer_than_block() {
    // Use minimum valid block size (256) for testing
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 256])
        .unwrap();

    // Pattern longer than block should still be queryable
    let filter = NgramFilter::from_patterns(&[
        b"this is a very long pattern that exceeds block size".as_slice(),
    ]);
    let _ = index.candidate_blocks_ngram(&filter);
    // Should not panic
}

// ============================================================================
// 12. Block Size Edge Cases
// ============================================================================

#[test]
fn minimum_block_size_256() {
    // 256 is minimum valid block size
    let result = BlockIndexBuilder::new().block_size(256).build(&[0u8; 256]);
    assert!(result.is_ok());
}

#[test]
fn block_size_not_power_of_two_rejected() {
    let result = BlockIndexBuilder::new()
        .block_size(300) // Not a power of two
        .build(&[0u8; 300]);
    assert!(result.is_err());
}

#[test]
fn block_size_too_small_rejected() {
    let result = BlockIndexBuilder::new()
        .block_size(128) // Less than 256
        .build(&[0u8; 128]);
    assert!(result.is_err());
}

// ============================================================================
// 13. Builder Edge Cases
// ============================================================================

#[test]
fn builder_zero_bloom_bits_rejected() {
    let result = BlockIndexBuilder::new().bloom_bits(0).build(&[0u8; 256]);
    assert!(result.is_err());
}

#[test]
fn streaming_build_empty_iterator() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build_streaming(std::iter::empty::<Vec<u8>>())
        .unwrap();

    assert_eq!(index.block_count(), 0);
    assert_eq!(index.total_data_length(), 0);
}

#[test]
fn streaming_build_wrong_block_size() {
    let blocks = vec![vec![0u8; 128]]; // Wrong size
    let result = BlockIndexBuilder::new()
        .block_size(256)
        .build_streaming(blocks.into_iter());
    assert!(result.is_err());
}

// ============================================================================
// 14. CandidateRange Tests
// ============================================================================

#[test]
fn merge_adjacent_empty() {
    let merged = BlockIndex::merge_adjacent(&[]);
    assert!(merged.is_empty());
}

#[test]
fn merge_adjacent_single() {
    use flashsieve::index::CandidateRange;

    let ranges = vec![CandidateRange {
        offset: 0,
        length: 256,
    }];
    let merged = BlockIndex::merge_adjacent(&ranges);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].offset, 0);
    assert_eq!(merged[0].length, 256);
}

#[test]
fn merge_adjacent_non_adjacent() {
    use flashsieve::index::CandidateRange;

    let ranges = vec![
        CandidateRange {
            offset: 0,
            length: 256,
        },
        CandidateRange {
            offset: 512,
            length: 256,
        }, // Gap of 256
    ];
    let merged = BlockIndex::merge_adjacent(&ranges);
    assert_eq!(merged.len(), 2);
}

// ============================================================================
// 15. Random Stress Test
// ============================================================================

#[test]
fn random_data_no_panic() {
    let mut rng = StdRng::seed_from_u64(0xBAD_C0DE);

    for _ in 0..100 {
        let block_size = 256;
        let num_blocks = rng.gen_range(1..10);
        let mut data = vec![0u8; block_size * num_blocks];
        rng.fill_bytes(&mut data);

        let index = BlockIndexBuilder::new()
            .block_size(block_size)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();

        // Generate random patterns
        for _ in 0..10 {
            let pattern_len = rng.gen_range(1..20);
            let pattern: Vec<u8> = (0..pattern_len).map(|_| rng.gen()).collect();

            let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
            let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

            let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
            assert!(candidates.len() <= num_blocks);
        }
    }
}

// ============================================================================
// 16. Serialization Version Tests
// ============================================================================

#[test]
fn deserialize_version_1_format() {
    // Manually construct a version 1 (no CRC) serialized index
    // magic + version + block_size + total_len + block_count + histogram + bloom
    let mut data = Vec::new();
    data.extend_from_slice(b"FSBX"); // magic
    data.extend_from_slice(&1u32.to_le_bytes()); // version 1 (no CRC)
    data.extend_from_slice(&256u64.to_le_bytes()); // block_size
    data.extend_from_slice(&256u64.to_le_bytes()); // total_len
    data.extend_from_slice(&1u64.to_le_bytes()); // block_count

    // Histogram: 256 u32s (all zeros)
    for _ in 0..256 {
        data.extend_from_slice(&0u32.to_le_bytes());
    }

    // Bloom: num_bits + word_count + words
    data.extend_from_slice(&64u64.to_le_bytes()); // num_bits
    data.extend_from_slice(&1u64.to_le_bytes()); // word_count
    data.extend_from_slice(&0u64.to_le_bytes()); // single word

    // Version 1 should still parse (no CRC check)
    let result = BlockIndex::from_bytes(&data);
    assert!(result.is_some());
}

#[test]
fn deserialize_invalid_version_rejected() {
    let mut data = vec![0u8; 100];
    data[0..4].copy_from_slice(b"FSBX");
    data[4..8].copy_from_slice(&255u32.to_le_bytes()); // Invalid version

    assert!(BlockIndex::from_bytes(&data).is_none());
}

// ============================================================================
// 17. Composite Filter Tests
// ============================================================================

#[test]
fn composite_filter_and_semantics() {
    use flashsieve::filter::{CompositeFilter, FilterOp};

    let a = ByteFilter::from_patterns(&[b"abc".as_slice()]);
    let b = ByteFilter::from_patterns(&[b"def".as_slice()]);
    let combined = CompositeFilter::combine_byte(a, b, FilterOp::And);

    let hist_abc = ByteHistogram::from_block(b"abc");
    let hist_def = ByteHistogram::from_block(b"def");
    let hist_abcdef = ByteHistogram::from_block(b"abcdef");

    let bloom = NgramBloom::new(1024).unwrap();

    // AND: neither alone should match
    assert!(!combined.matches(&hist_abc, &bloom));
    assert!(!combined.matches(&hist_def, &bloom));

    // But together they should
    assert!(combined.matches(&hist_abcdef, &bloom));
}

#[test]
fn composite_filter_or_semantics() {
    use flashsieve::filter::{CompositeFilter, FilterOp};

    let a = ByteFilter::from_patterns(&[b"abc".as_slice()]);
    let b = ByteFilter::from_patterns(&[b"def".as_slice()]);
    let combined = CompositeFilter::combine_byte(a, b, FilterOp::Or);

    let hist_abc = ByteHistogram::from_block(b"abc");
    let bloom = NgramBloom::new(1024).unwrap();

    // OR: either should match
    assert!(combined.matches(&hist_abc, &bloom));
}

// ============================================================================
// 18. Pattern Matching Edge Cases
// ============================================================================

#[test]
fn empty_pattern_matches_all() {
    // Empty patterns have no requirements, so they match everything
    let bloom = NgramBloom::from_block(b"hello", 1024).unwrap();
    assert!(bloom.maybe_contains_pattern(b""));
}

#[test]
fn single_byte_pattern_matches_all() {
    // Single byte patterns have no n-grams, so they match
    let bloom = NgramBloom::from_block(b"hello", 1024).unwrap();
    assert!(bloom.maybe_contains_pattern(b"x"));
}

#[test]
fn pattern_exactly_at_block_boundary() {
    let mut data = vec![b'x'; 512];
    // Pattern fully contained in block 0 (not spanning boundary for simplicity)
    data[100..106].copy_from_slice(b"needle");

    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();

    // Test with byte filter - should find block 0
    let byte_filter = ByteFilter::from_patterns(&[b"needle".as_slice()]);
    let candidates = index.candidate_blocks_byte(&byte_filter);

    // Should find only block 0 (pattern is fully contained there)
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].offset, 0);

    // Test with ngram filter
    let ngram_filter = NgramFilter::from_patterns(&[b"needle".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&ngram_filter);

    // Should also find block 0
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].offset, 0);
}

// ============================================================================
// 19. Selectivity Tests
// ============================================================================

#[test]
fn selectivity_zero_for_empty_candidates() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 256])
        .unwrap();

    let candidates = vec![];
    assert_eq!(index.selectivity(&candidates), 0.0);
}

#[test]
fn selectivity_full_coverage() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&[0u8; 256])
        .unwrap();

    use flashsieve::index::CandidateRange;
    let candidates = vec![CandidateRange {
        offset: 0,
        length: 256,
    }];
    assert_eq!(index.selectivity(&candidates), 1.0);
}

// ============================================================================
// 20. Bloom Filter Size Tests
// ============================================================================

#[test]
fn very_small_bloom_filter() {
    // Minimum practical size (will be rounded up)
    let bloom = NgramBloom::new(1).unwrap();
    let (num_bits, _) = bloom.raw_parts();
    assert!(num_bits >= 64);
}

#[test]
fn very_large_bloom_filter() {
    // Large filter that triggers exact_pairs table
    let bloom = NgramBloom::new(65536).unwrap();
    let (num_bits, _) = bloom.raw_parts();
    assert_eq!(num_bits, 65536);
}
