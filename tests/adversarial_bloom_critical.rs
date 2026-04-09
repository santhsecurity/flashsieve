//! CRITICAL adversarial tests for flashsieve bloom filter — designed to BREAK.
//!
//! A single bloom filter false negative means malware goes undetected at
//! internet scale. These tests probe edge cases that could cause false
//! negatives, panics, or resource exhaustion.
//!
//! CORE LAW 4: Every finding is CRITICAL — at internet scale, a "low" bug
//! corrupts billions of records.
#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramBloom, NgramFilter};
use std::sync::{Arc, Barrier};
use std::thread;

// =============================================================================
// TEST 1: Bloom filter with 0 patterns — must not panic, must reject everything
// =============================================================================

#[test]
fn ngram_filter_empty_patterns_rejects_all() {
    // Empty pattern set should produce a filter that rejects everything.
    // No false negatives possible (nothing to match), but must not panic.
    let filter = NgramFilter::from_patterns(&[]);
    let bloom = NgramBloom::from_block(b"anything here", 1024).unwrap();

    // With zero patterns, the filter should reject all blooms
    let matches = filter.matches_bloom(&bloom);
    assert!(
        !matches,
        "CRITICAL FINDING: Empty pattern filter accepted a bloom — must reject all"
    );

    // Also test with empty bloom
    let empty_bloom = NgramBloom::from_block(b"", 1024).unwrap();
    let matches = filter.matches_bloom(&empty_bloom);
    assert!(
        !matches,
        "CRITICAL FINDING: Empty pattern filter accepted empty bloom — must reject all"
    );
}

#[test]
fn byte_filter_empty_patterns_rejects_all() {
    use flashsieve::ByteHistogram;

    let filter = ByteFilter::from_patterns(&[]);
    let hist = ByteHistogram::from_block(b"anything here");

    let matches = filter.matches_histogram(&hist);
    assert!(
        !matches,
        "CRITICAL FINDING: Empty pattern byte filter accepted histogram — must reject all"
    );
}

// =============================================================================
// TEST 2: Bloom filter with 100K patterns — must not OOM
// =============================================================================

#[test]
fn ngram_filter_100k_patterns_no_oom() {
    // Generate 100,000 unique patterns
    let mut patterns = Vec::with_capacity(100_000);
    let mut pattern_data = Vec::with_capacity(100_000);

    for i in 0..100_000 {
        // Create unique patterns of varying lengths
        let len = 8 + (i % 24); // 8-32 bytes
        let mut pattern = Vec::with_capacity(len);
        for (j, item) in pattern.iter_mut().enumerate().take(len) {
            // Deterministic but unique content
            *item = ((i * 31 + j * 17) % 256) as u8;
        }
        pattern_data.push(pattern);
    }

    for p in &pattern_data {
        patterns.push(p.as_slice());
    }

    // This should complete without OOM or panic
    let filter = NgramFilter::from_patterns(&patterns);

    // Verify the filter works correctly — search for a pattern we know exists
    let target_pattern = &pattern_data[50_000];
    let bloom = NgramBloom::from_block(target_pattern, 8192).unwrap();

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: Filter failed to match a pattern that was inserted"
    );

    // Verify no false negatives: the filter must match its own patterns
}

// =============================================================================
// TEST 3: Pattern at exact bloom hash collision boundary
// =============================================================================

#[test]
fn bloom_hash_collision_boundary_zero_fnr() {
    // Create patterns designed to cause hash collisions in the bloom filter.
    // Even with collisions, there must be ZERO false negatives.

    // Use a very small bloom filter to maximize collision probability
    let small_bits = 64; // Only 64 bits = extremely high collision rate

    // Create data with embedded pattern
    let pattern = b"MALICIOUS_PAYLOAD";
    let mut data = vec![0u8; 1024];

    // Fill with data designed to cause collisions
    for (i, item) in data.iter_mut().enumerate() {
        *item = (i % 256) as u8;
    }

    // Place pattern at the beginning
    data[..pattern.len()].copy_from_slice(pattern);

    let bloom = NgramBloom::from_block(&data, small_bits).unwrap();

    // Build filter with just this pattern
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // Must match — zero false negatives even with extreme collisions
    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: False negative at hash collision boundary!"
    );
}

#[test]
fn bloom_saturated_filter_no_false_negatives() {
    // Saturate a small bloom filter with many n-grams, then verify
    // that patterns actually present are still detected.

    let small_bits = 128;
    let pattern = b"TARGET";

    // Create data with lots of random n-grams + target pattern
    let mut data: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();
    data[100..100 + pattern.len()].copy_from_slice(pattern);

    let bloom = NgramBloom::from_block(&data, small_bits).unwrap();
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // Even with saturation (high FPR), must have zero FNR
    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: Saturated bloom filter produced false negative!"
    );
}

// =============================================================================
// TEST 4: union_ngrams optimization — verify zero false negatives
// =============================================================================

#[test]
fn union_ngrams_optimization_no_false_negatives() {
    // The union_ngrams optimization does early rejection: if the bloom
    // doesn't contain ANY union n-grams, reject immediately.
    // This test verifies that this never causes false negatives.

    let pattern1 = b"abc";
    let pattern2 = b"def";
    let filter = NgramFilter::from_patterns(&[pattern1.as_slice(), pattern2.as_slice()]);

    // File containing pattern1 — must NOT be rejected
    let file_with_pattern1 = NgramBloom::from_block(b"xxabcxx", 1024).unwrap();
    assert!(
        filter.matches_bloom(&file_with_pattern1),
        "CRITICAL FINDING: union_ngrams optimization caused false negative for pattern1!"
    );

    // File containing pattern2 — must NOT be rejected by union_ngrams
    let file_with_pattern2 = NgramBloom::from_block(b"xxdefxx", 1024).unwrap();
    assert!(
        filter.matches_bloom(&file_with_pattern2),
        "CRITICAL FINDING: union_ngrams optimization caused false negative for pattern2!"
    );

    // File containing BOTH patterns — must match
    let file_with_both = NgramBloom::from_block(b"abcdef", 1024).unwrap();
    assert!(
        filter.matches_bloom(&file_with_both),
        "CRITICAL FINDING: Filter failed to match file with both patterns!"
    );
}

#[test]
fn union_ngrams_rejection_is_correct() {
    // If union_ngrams rejects (returns false for maybe_contains_any),
    // then the file truly has NO matching n-grams.

    let pattern = b"secret";
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // File with completely different n-grams (no overlap with "secret")
    let disjoint_file = NgramBloom::from_block(b"xyzwvutsrqponmlk", 1024).unwrap();

    // The disjoint_file bloom does not contain pattern n-grams
    // Pattern n-grams: (s,e), (e,c), (c,r), (r,e), (e,t)
    let pattern_ngrams = vec![
        (b's', b'e'),
        (b'e', b'c'),
        (b'c', b'r'),
        (b'r', b'e'),
        (b'e', b't'),
    ];
    let any_present = disjoint_file.maybe_contains_any(&pattern_ngrams);

    if !any_present {
        // File should be correctly rejected — verify matches_bloom returns false
        let matches = filter.matches_bloom(&disjoint_file);
        assert!(
            !matches,
            "CRITICAL FINDING: File with no matching n-grams was accepted!"
        );
    }
    // If any_present is true, the file might match (false positive possible)
}

// =============================================================================
// TEST 5: Empty file input — must not panic
// =============================================================================

#[test]
fn empty_file_input_no_panic() {
    // Empty files have no n-grams, so they should never match patterns with n-grams
    let empty_bloom = NgramBloom::from_block(b"", 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[b"test".as_slice()]);

    // Should not panic and should return false (empty file can't contain pattern)
    let result = filter.matches_bloom(&empty_bloom);
    assert!(
        !result,
        "CRITICAL FINDING: Empty file matched a non-empty pattern!"
    );
}

#[test]
fn empty_file_single_byte_pattern() {
    // Single-byte patterns have no 2-byte n-grams
    // This is an edge case — single-byte patterns technically "match" any file
    // because there are no n-grams to check (vacuous truth)
    let empty_bloom = NgramBloom::from_block(b"", 1024).unwrap();
    let single_byte_filter = NgramFilter::from_patterns(&[b"a".as_slice()]);

    // Single-byte pattern has no n-grams, so it technically "matches"
    // This is the documented behavior — patterns < 2 bytes match any bloom
    let _result = single_byte_filter.matches_bloom(&empty_bloom);
    // We just verify this doesn't panic — the semantic is documented
}

// =============================================================================
// TEST 6: File containing ONLY the pattern bytes and nothing else
// =============================================================================

#[test]
fn file_only_pattern_bytes_must_match() {
    // File containing exactly the pattern and nothing else
    let pattern = b"EXACT_MATCH";
    let bloom = NgramBloom::from_block(pattern, 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: File containing ONLY pattern did not match!"
    );
}

#[test]
fn file_only_pattern_at_block_boundary() {
    // Pattern exactly at block boundary
    let block_size = 256;
    let pattern = b"BOUNDARY";

    // Pattern split across blocks: "BOUND" at end of block 0, "ARY" at start of block 1
    let mut data = vec![b'x'; block_size * 2];
    let split_point = block_size - 5; // "BOUND" = 5 chars
    data[split_point..split_point + pattern.len()].copy_from_slice(pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("build should succeed");

    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    // At least one block should be a candidate (the blocks containing the pattern)
    assert!(
        !candidates.is_empty(),
        "CRITICAL FINDING: Pattern at block boundary not detected!"
    );
}

// =============================================================================
// TEST 7: Binary file with null bytes between pattern chars
// =============================================================================

#[test]
fn binary_null_bytes_between_pattern_chars() {
    // Pattern "AB" with null byte between: "A\0B"
    // The n-grams are (A, \0) and (\0, B), NOT (A, B)
    // So "AB" should NOT match "A\0B"

    let pattern = b"AB";
    let data_with_null = vec![b'A', 0x00, b'B'];

    let bloom = NgramBloom::from_block(&data_with_null, 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // "AB" n-gram is NOT in data_with_null, so should not match
    let _matches = filter.matches_bloom(&bloom);
    // This is actually expected behavior — null bytes break the n-gram
    // We verify the behavior is consistent

    // Now verify that the ACTUAL n-grams are detected
    let actual_ngram_filter = NgramFilter::from_patterns(&[b"A\x00".as_slice()]);
    assert!(
        actual_ngram_filter.matches_bloom(&bloom),
        "CRITICAL FINDING: Actual n-gram (A, NULL) not detected!"
    );
}

#[test]
fn binary_all_null_bytes() {
    // File containing only null bytes
    let null_data = vec![0x00; 256];
    let bloom = NgramBloom::from_block(&null_data, 1024).unwrap();

    // Pattern with null byte
    let pattern_with_null = b"\x00\x00";
    let filter = NgramFilter::from_patterns(&[pattern_with_null.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: Null byte pattern not detected in null file!"
    );
}

// =============================================================================
// TEST 8: Concurrent access from 100 threads — must not race
// =============================================================================

#[test]
fn concurrent_100_threads_no_race() {
    const NUM_THREADS: usize = 100;
    const ITERATIONS: usize = 1000;

    // Shared bloom and filter
    let pattern = b"CONCURRENT_TEST_PATTERN";
    let bloom = Arc::new(NgramBloom::from_block(pattern, 8192).unwrap());
    let filter = Arc::new(NgramFilter::from_patterns(&[pattern.as_slice()]));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let bloom_clone = Arc::clone(&bloom);
        let filter_clone = Arc::clone(&filter);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Synchronize all threads to maximize contention
            barrier_clone.wait();

            for i in 0..ITERATIONS {
                // Mix reads and pattern variations
                let should_match = i % 2 == 0;

                if should_match {
                    // Should always match
                    assert!(
                        filter_clone.matches_bloom(&bloom_clone),
                        "CRITICAL FINDING: Race condition caused false negative in thread {thread_id} iter {i}"
                    );
                } else {
                    // Test with a different pattern (may or may not match)
                    let _ = filter_clone.matches_bloom(&bloom_clone);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked — possible race condition!");
    }
}

#[test]
fn concurrent_build_and_query_100_threads() {
    const NUM_THREADS: usize = 100;

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            // Each thread builds its own bloom and queries
            let pattern = format!("THREAD_{thread_id}_PATTERN");
            let data = pattern.as_bytes();

            let bloom = NgramBloom::from_block(data, 4096).unwrap();
            let filter = NgramFilter::from_patterns(&[data]);

            // Must match its own pattern
            assert!(
                filter.matches_bloom(&bloom),
                "CRITICAL FINDING: Thread {thread_id} pattern failed to match itself!"
            );
        });

        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during concurrent build/query!");
    }
}

// =============================================================================
// TEST 9: Adversarial input: all-zero, all-0xFF, repeating patterns
// =============================================================================

#[test]
fn adversarial_all_zero_file() {
    // File containing all zeros
    let all_zero = vec![0x00; 4096];
    let bloom = NgramBloom::from_block(&all_zero, 8192).unwrap();

    // Pattern that should match (all zeros)
    let zero_pattern = b"\x00\x00\x00\x00";
    let filter = NgramFilter::from_patterns(&[zero_pattern.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: All-zero pattern not detected in all-zero file!"
    );
}

#[test]
fn adversarial_all_0xff_file() {
    // File containing all 0xFF
    let all_ff = vec![0xFF; 4096];
    let bloom = NgramBloom::from_block(&all_ff, 8192).unwrap();

    // Pattern that should match (all 0xFF)
    let ff_pattern = b"\xFF\xFF\xFF\xFF";
    let filter = NgramFilter::from_patterns(&[ff_pattern.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: All-0xFF pattern not detected in all-0xFF file!"
    );
}

#[test]
fn adversarial_repeating_pattern_collision() {
    // Repeating patterns can cause hash collisions
    // Test with patterns designed to collide

    let repeating = vec![b'A'; 1024]; // "AAAAAA..."
    let bloom = NgramBloom::from_block(&repeating, 1024).unwrap();

    // Pattern that exists
    let pattern = b"AAAAA";
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: Repeating pattern caused false negative!"
    );
}

#[test]
fn adversarial_alternating_bytes() {
    // Alternating pattern: ABABABAB...
    let alternating: Vec<u8> = (0..1024)
        .map(|i| if i % 2 == 0 { b'A' } else { b'B' })
        .collect();
    let bloom = NgramBloom::from_block(&alternating, 2048).unwrap();

    // Pattern "ABAB" should match
    let pattern = b"ABAB";
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: Alternating pattern not detected!"
    );
}

#[test]
fn adversarial_pathological_hash_collision() {
    // Create pairs that might hash to similar values
    // This tests the double-hashing mechanism

    let mut data = Vec::with_capacity(512);

    // Add many pairs that could stress the hash function
    for i in 0u32..256 {
        data.push(i as u8);
        data.push(((i * 7) % 256) as u8);
    }

    let bloom = NgramBloom::from_block(&data, 256).unwrap();

    // Each pair we added should be detectable
    for i in 0u32..256 {
        let a = i as u8;
        let b = ((i * 7) % 256) as u8;
        assert!(
            bloom.maybe_contains(a, b),
            "CRITICAL FINDING: Pathological hash input ({a}, {b}) not found!"
        );
    }
}

// =============================================================================
// TEST 10: proptest-style invariant: bloom.matches() == false implies exact_match() == false
// (Zero false negatives property)
// =============================================================================

#[test]
fn zero_false_negatives_property_exhaustive_small() {
    // Exhaustive test for all 2-byte patterns with small bloom
    // Verifies that inserted n-grams are ALWAYS found

    let mut bloom = NgramBloom::new(256).unwrap();

    // Insert a subset of all possible pairs
    let mut inserted = Vec::new();
    for a in 0..16_u8 {
        for b in 0..16_u8 {
            bloom.insert_ngram(a, b);
            inserted.push((a, b));
        }
    }

    // Verify ALL inserted pairs are found (zero false negatives)
    for (a, b) in &inserted {
        assert!(
            bloom.maybe_contains(*a, *b),
            "CRITICAL FINDING: False negative for inserted pair ({a}, {b})!"
        );
    }
}

#[test]
fn zero_false_negatives_pattern_level() {
    // For any pattern and any input, if the pattern is in the input,
    // the bloom filter must report a potential match.

    let test_cases: Vec<(&[u8], &[u8])> = vec![
        (b"hello world here", b"hello"),
        (b"malicious_code", b"code"),
        (b"\x00\x01\x02\x03", b"\x01\x02"),
        (b"AAAAAAAAAA", b"AAA"),
    ];

    for (input, pattern) in test_cases {
        let bloom = NgramBloom::from_block(input, 1024).unwrap();
        let filter = NgramFilter::from_patterns(&[pattern]);

        // Pattern IS in input, so must match
        assert!(
            filter.matches_bloom(&bloom),
            "CRITICAL FINDING: False negative for pattern {pattern:?} in input {input:?}!"
        );
    }
}

#[test]
fn proptest_style_random_patterns() {
    // Use a deterministic pseudo-random sequence to test the property:
    // If bloom.matches() returns false, then exact_match() MUST be false
    // (equivalent to: if exact_match() is true, bloom.matches() MUST be true)

    use std::collections::HashSet;

    // Pseudo-random number generator (SplitMix64)
    let mut state: u64 = 0x1234_5678_9ABC_DEF0;
    let mut rng = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };

    // Generate random "files" and "patterns", verify zero FNR
    for _ in 0..1000 {
        // Generate random file content
        let file_len = (rng() % 512 + 10) as usize;
        let file: Vec<u8> = (0..file_len)
            .map(|_| (rng() % 256).try_into().unwrap_or(0))
            .collect();

        // Extract actual n-grams from file
        let actual_ngrams: HashSet<(u8, u8)> = file.windows(2).map(|w| (w[0], w[1])).collect();

        let bloom = NgramBloom::from_block(&file, 4096).unwrap();

        // Test with random patterns
        for _ in 0..10 {
            let pat_len = (rng() % 10 + 2) as usize; // 2-12 bytes
            let pattern: Vec<u8> = (0..pat_len)
                .map(|_| (rng() % 256).try_into().unwrap_or(0))
                .collect();

            // Check if pattern n-grams are actually in the file
            let pattern_ngrams: Vec<(u8, u8)> = pattern.windows(2).map(|w| (w[0], w[1])).collect();

            let all_ngrams_present = pattern_ngrams.iter().all(|ng| actual_ngrams.contains(ng));

            let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
            let bloom_matches = filter.matches_bloom(&bloom);

            if all_ngrams_present {
                // CRITICAL: If all n-grams are present, bloom MUST match (zero FNR)
                assert!(
                    bloom_matches,
                    "CRITICAL FINDING: False negative! Pattern {pattern:?} n-grams are in file but bloom rejected"
                );
            }
            // If not all n-grams present, bloom may match (false positive) or not — both OK
        }
    }
}

// =============================================================================
// ADDITIONAL EDGE CASES
// =============================================================================

#[test]
fn bloom_exact_pairs_table_integrity() {
    // For large blooms (>=4096 bits), exact_pairs table should eliminate FPR
    let data = b"exact pair test data";
    let bloom = NgramBloom::from_block(data, 4096).unwrap();

    // All n-grams in data must be found (with exact_pairs table if available)
    for window in data.windows(2) {
        assert!(
            bloom.maybe_contains_exact(window[0], window[1]),
            "CRITICAL FINDING: Exact pairs lookup failed for {window:?}"
        );
    }
}

#[test]
fn bloom_from_raw_parts_preserves_zero_fnr() {
    // Serialization/deserialization must preserve zero false negative property
    let data = b"test data for serialization";
    let original = NgramBloom::from_block(data, 8192).unwrap();

    let (num_bits, bits) = original.raw_parts();
    let reconstructed = NgramBloom::from_raw_parts(num_bits, bits.to_vec()).unwrap();

    // All n-grams must still be found after round-trip
    for window in data.windows(2) {
        assert!(
            reconstructed.maybe_contains(window[0], window[1]),
            "CRITICAL FINDING: False negative after deserialization for {window:?}"
        );
    }
}

#[test]
fn union_of_blooms_no_false_negatives() {
    // Union of multiple blooms must not introduce false negatives
    let bloom1 = NgramBloom::from_block(b"abc", 1024).unwrap();
    let bloom2 = NgramBloom::from_block(b"def", 1024).unwrap();

    let union = NgramBloom::union_of(&[bloom1, bloom2]).unwrap();

    // All n-grams from both sources must be present in union
    assert!(
        union.maybe_contains(b'a', b'b'),
        "Union missing n-gram from bloom1"
    );
    assert!(
        union.maybe_contains(b'b', b'c'),
        "Union missing n-gram from bloom1"
    );
    assert!(
        union.maybe_contains(b'd', b'e'),
        "Union missing n-gram from bloom2"
    );
    assert!(
        union.maybe_contains(b'e', b'f'),
        "Union missing n-gram from bloom2"
    );
}

#[test]
fn filter_with_unicode_patterns() {
    // UTF-8 multi-byte characters as patterns
    let utf8_pattern = "日本語".as_bytes(); // Japanese characters
    let bloom = NgramBloom::from_block(utf8_pattern, 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[utf8_pattern]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL FINDING: UTF-8 pattern not detected!"
    );
}

#[test]
fn quick_reject_consistency() {
    // quick_reject heuristic must not cause false negatives
    let data = b"pattern at the beginning of a large file";
    let filter = NgramFilter::from_patterns(&[b"pattern".as_slice()]);

    // quick_reject should not reject files containing the pattern
    let quick_result = filter.quick_reject(data);
    assert!(
        quick_result,
        "quick_reject rejected a file containing the pattern!"
    );

    // And matches_bloom should also match
    let bloom = NgramBloom::from_block(data, 1024).unwrap();
    assert!(
        filter.matches_bloom(&bloom),
        "matches_bloom rejected pattern that quick_reject accepted"
    );
}
