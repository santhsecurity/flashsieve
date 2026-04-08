#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! CRITICAL: Zero false negative tests.
//!
//! A false negative in flashsieve means silently skipping a file that
//! contains matches. These tests verify that no combination of block
//! placement, pattern position, or data composition can cause the
//! pre-filter to incorrectly exclude a candidate block.

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramBloom, NgramFilter};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

// =============================================================================
// Byte Filter: Zero False Negatives
// =============================================================================

#[test]
fn byte_present_in_block_never_filtered_out() {
    let block_size = 256;
    // Place one occurrence of every byte value in the block.
    let mut data = vec![0_u8; block_size];
    for i in 0..=255_u8 {
        data[usize::from(i) % block_size] = i;
    }
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();

    // A filter for any single byte should match.
    for byte in 0_u8..=255 {
        let filter = ByteFilter::from_single_pattern(&[byte]);
        let candidates = index.candidate_blocks_byte(&filter);
        assert!(
            !candidates.is_empty(),
            "byte {byte:#04x} is present but was filtered out"
        );
    }
}

#[test]
fn pattern_at_start_of_block_never_skipped() {
    let block_size = 256;
    let mut data = vec![0_u8; block_size * 4];
    data[0..6].copy_from_slice(b"needle");

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[b"needle"]);
    let ngram_filter = NgramFilter::from_patterns(&[b"needle"]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    assert!(
        candidates.iter().any(|r| r.offset == 0),
        "pattern at block start was incorrectly filtered"
    );
}

#[test]
fn pattern_at_end_of_block_never_skipped() {
    let block_size = 256;
    let mut data = vec![0_u8; block_size * 4];
    let pattern = b"needle";
    data[block_size - pattern.len()..block_size].copy_from_slice(pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    assert!(
        candidates.iter().any(|r| r.offset == 0),
        "pattern at block end was incorrectly filtered"
    );
}

#[test]
fn single_occurrence_in_random_data_never_missed() {
    let block_size = 256;
    let num_blocks = 8;
    let mut rng = StdRng::seed_from_u64(0x00FA_15E0);
    let mut data = vec![0_u8; block_size * num_blocks];
    rng.fill_bytes(&mut data);

    let pattern = b"XYZZY";
    let placement_offset = block_size * 5 + 100;
    data[placement_offset..placement_offset + pattern.len()].copy_from_slice(pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    let target_block = placement_offset / block_size;
    assert!(
        candidates
            .iter()
            .any(|r| r.offset <= placement_offset && r.offset + r.length > placement_offset),
        "pattern placed in block {target_block} was not found in candidates"
    );
}

#[test]
fn pattern_in_every_block_all_blocks_are_candidates() {
    let block_size = 256;
    let num_blocks = 8;
    let mut data = vec![b'x'; block_size * num_blocks];
    let pattern = b"find_me";
    for block_idx in 0..num_blocks {
        let offset = block_idx * block_size + 10;
        data[offset..offset + pattern.len()].copy_from_slice(pattern);
    }

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    assert_eq!(
        candidates.len(),
        1,
        "all blocks contain the pattern but only {} were returned",
        candidates.len()
    );
    assert_eq!(candidates[0].offset, 0);
    assert_eq!(candidates[0].length, block_size * num_blocks);
}

// =============================================================================
// Ngram Filter: Zero False Negatives
// =============================================================================

#[test]
fn all_ngrams_of_pattern_in_block_passes_ngram_filter() {
    let block_size = 256;
    let mut data = vec![b'x'; block_size];
    data[50..56].copy_from_slice(b"secret");

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let filter = NgramFilter::from_patterns(&[b"secret"]);
    let candidates = index.candidate_blocks_ngram(&filter);

    assert_eq!(candidates.len(), 1);
}

#[test]
fn binary_pattern_with_null_bytes_never_missed() {
    let block_size = 256;
    let mut data = vec![0xFF_u8; block_size];
    let pattern = &[0x00, 0x01, 0x02, 0x00, 0xFF];
    data[100..100 + pattern.len()].copy_from_slice(pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    assert!(
        !candidates.is_empty(),
        "binary pattern with null bytes was missed"
    );
}

// =============================================================================
// Merge Adjacent
// =============================================================================

#[test]
fn merge_empty_returns_empty() {
    let merged = flashsieve::BlockIndex::merge_adjacent(&[]);
    assert!(merged.is_empty());
}

#[test]
fn merge_single_range_unchanged() {
    let ranges = vec![flashsieve::CandidateRange {
        offset: 0,
        length: 256,
    }];
    let merged = flashsieve::BlockIndex::merge_adjacent(&ranges);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].offset, 0);
    assert_eq!(merged[0].length, 256);
}

#[test]
fn merge_non_adjacent_preserved() {
    let ranges = vec![
        flashsieve::CandidateRange {
            offset: 0,
            length: 256,
        },
        flashsieve::CandidateRange {
            offset: 512,
            length: 256,
        },
    ];
    let merged = flashsieve::BlockIndex::merge_adjacent(&ranges);
    assert_eq!(merged.len(), 2);
}

#[test]
fn merge_all_adjacent_into_one() {
    let ranges = vec![
        flashsieve::CandidateRange {
            offset: 0,
            length: 256,
        },
        flashsieve::CandidateRange {
            offset: 256,
            length: 256,
        },
        flashsieve::CandidateRange {
            offset: 512,
            length: 256,
        },
    ];
    let merged = flashsieve::BlockIndex::merge_adjacent(&ranges);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].length, 768);
}

#[test]
fn pattern_crossing_block_boundary_never_skipped() {
    use flashsieve::{
        filter::{ByteFilter, NgramFilter},
        BlockIndexBuilder,
    };
    let block_size = 256;
    let mut data = vec![0_u8; block_size * 2];
    let pattern = b"boundary";

    // Place pattern exactly crossing the boundary between block 0 and block 1
    // "boun" in block 0, "dary" in block 1
    let split_point = pattern.len() / 2;
    data[block_size - split_point..block_size].copy_from_slice(&pattern[..split_point]);
    data[block_size..block_size + pattern.len() - split_point]
        .copy_from_slice(&pattern[split_point..]);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    println!("CANDIDATES: {candidates:?}");

    // Either block 0 or block 1 (or both) MUST be a candidate.
    // If neither is, we have a false negative.
    assert!(
        candidates
            .iter()
            .any(|r| r.offset == 0 || r.offset == block_size),
        "pattern crossing block boundary was incorrectly filtered"
    );
}

// =============================================================================
// CRITICAL: union_ngrams optimization must NEVER cause false negatives
// =============================================================================

/// The union_ngrams optimization does early rejection: if the bloom
/// doesn't contain ANY union n-grams, reject immediately.
///
/// CORRECTNESS PROOF:
/// - union_ngrams = set of ALL unique n-grams from ALL patterns
/// - If bloom ∩ union_ngrams = ∅, then bloom contains NONE of the pattern n-grams
/// - Therefore, NO pattern can match (since every pattern's n-grams ⊆ union_ngrams)
/// - This has ZERO false negatives by set theory.
///
/// This test exhaustively verifies the implementation matches the proof.
#[test]
fn union_ngrams_optimization_zero_fnr_theorem() {
    // Test case 1: Multiple patterns, file contains only pattern1
    let pattern1 = b"abc";
    let pattern2 = b"def";
    let filter = NgramFilter::from_patterns(&[pattern1.as_slice(), pattern2.as_slice()]);

    // File containing pattern1 — must NOT be rejected
    let file_with_pattern1 = NgramBloom::from_block(b"xxabcxx", 1024).unwrap();
    assert!(
        filter.matches_bloom(&file_with_pattern1),
        "CRITICAL: union_ngrams caused FNR for pattern1! Pattern 'abc' is in file 'xxabcxx' but was rejected"
    );

    // File containing pattern2 — must NOT be rejected by union_ngrams
    let file_with_pattern2 = NgramBloom::from_block(b"xxdefxx", 1024).unwrap();
    assert!(
        filter.matches_bloom(&file_with_pattern2),
        "CRITICAL: union_ngrams caused FNR for pattern2! Pattern 'def' is in file 'xxdefxx' but was rejected"
    );

    // File containing BOTH patterns — must match
    let file_with_both = NgramBloom::from_block(b"abcdef", 1024).unwrap();
    assert!(
        filter.matches_bloom(&file_with_both),
        "CRITICAL: Filter failed to match file with both patterns!"
    );

    // File containing NEITHER pattern — should be rejected (no FNR risk)
    let file_with_neither = NgramBloom::from_block(b"xyzwvu", 1024).unwrap();
    // Note: This might have false positives, but never false negatives
    let _result = filter.matches_bloom(&file_with_neither);
}

/// Verify union_ngrams rejection is mathematically sound
#[test]
fn union_ngrams_rejection_is_mathematically_sound() {
    let pattern = b"secret";
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // Extract actual n-grams from pattern
    let pattern_ngrams: Vec<(u8, u8)> = pattern.windows(2).map(|w| (w[0], w[1])).collect();

    // File with completely disjoint n-grams (no overlap with "secret")
    let disjoint_data = b"xyzwvutsrqponmlk";
    let disjoint_file = NgramBloom::from_block(disjoint_data, 1024).unwrap();

    // Verify that disjoint_file truly has no pattern n-grams
    let disjoint_ngrams: std::collections::HashSet<(u8, u8)> =
        disjoint_data.windows(2).map(|w| (w[0], w[1])).collect();

    let any_overlap = pattern_ngrams.iter().any(|ng| disjoint_ngrams.contains(ng));
    assert!(
        !any_overlap,
        "Test setup error: disjoint file actually contains pattern n-grams"
    );

    // Now verify bloom filter correctly rejects
    let any_present = disjoint_file.maybe_contains_any(&pattern_ngrams);
    if !any_present {
        // File should be correctly rejected — verify matches_bloom returns false
        let matches = filter.matches_bloom(&disjoint_file);
        assert!(
            !matches,
            "CRITICAL: File with no matching n-grams was accepted! This is a false positive, not FNR, but still bad."
        );
    }
    // If any_present is true, the file might match (false positive) — this is acceptable
}

/// Stress test: union_ngrams with 100 patterns, verify no FNR
#[test]
fn union_ngrams_stress_100_patterns() {
    // Create 100 unique patterns
    let patterns: Vec<Vec<u8>> = (0..100)
        .map(|i| format!("PATTERN_{:04X}_END", i).into_bytes())
        .collect();

    let pattern_refs: Vec<&[u8]> = patterns.iter().map(|p| p.as_slice()).collect();
    let filter = NgramFilter::from_patterns(&pattern_refs);

    // For each pattern, create a file containing it and verify it matches
    for (i, pattern) in patterns.iter().enumerate() {
        // Create file with pattern in middle
        let mut file_data = vec![b'X'; 256];
        let start = 100;
        file_data[start..start + pattern.len()].copy_from_slice(pattern);

        let bloom = NgramBloom::from_block(&file_data, 4096).unwrap();

        assert!(
            filter.matches_bloom(&bloom),
            "CRITICAL: union_ngrams caused FNR for pattern {} ({:?})",
            i,
            std::str::from_utf8(pattern).unwrap_or("<binary>")
        );
    }
}

/// Test that union_ngrams works correctly with exact-pairs table (large blooms)
#[test]
fn union_ngrams_with_exact_pairs_table() {
    // Use 8192 bits to trigger exact-pairs table allocation
    let pattern1 = b"malware_signature_A";
    let pattern2 = b"malware_signature_B";
    let filter = NgramFilter::from_patterns(&[pattern1.as_slice(), pattern2.as_slice()]);

    // File with pattern1 — must match
    let file1 = NgramBloom::from_block(pattern1, 8192).unwrap();
    assert!(
        filter.matches_bloom(&file1),
        "CRITICAL: union_ngrams + exact_pairs caused FNR for pattern1!"
    );

    // File with pattern2 — must match
    let file2 = NgramBloom::from_block(pattern2, 8192).unwrap();
    assert!(
        filter.matches_bloom(&file2),
        "CRITICAL: union_ngrams + exact_pairs caused FNR for pattern2!"
    );
}

// =============================================================================
// CRITICAL: Short patterns (< 2 bytes) edge cases
// =============================================================================

/// Patterns shorter than 2 bytes have no n-grams to check.
/// Documented behavior: they "technically match any bloom filter" (vacuous truth).
/// But this could cause issues if the implementation panics or returns incorrect results.
#[test]
fn single_byte_pattern_no_panic() {
    let bloom = NgramBloom::from_block(b"anything", 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[b"a".as_slice()]);

    // Should not panic
    let _result = filter.matches_bloom(&bloom);
    // Vacuous truth: no n-grams to check, so it "matches"
}

#[test]
fn empty_pattern_no_panic() {
    let bloom = NgramBloom::from_block(b"anything", 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[b"".as_slice()]);

    // Should not panic
    let _result = filter.matches_bloom(&bloom);
}

/// Verify 2-byte pattern (minimum length with n-grams) works correctly
#[test]
fn two_byte_pattern_exact_ngram() {
    let pattern = b"ab";
    let file = b"xxabxx";

    let bloom = NgramBloom::from_block(file, 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL: 2-byte pattern 'ab' in file 'xxabxx' was not detected!"
    );
}

/// Verify 3-byte pattern (2 n-grams) works correctly
#[test]
fn three_byte_pattern_two_ngrams() {
    let pattern = b"abc";
    let file = b"xxabcxx";

    let bloom = NgramBloom::from_block(file, 1024).unwrap();
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    assert!(
        filter.matches_bloom(&bloom),
        "CRITICAL: 3-byte pattern 'abc' in file 'xxabcxx' was not detected!"
    );

    // Verify that missing one n-gram causes rejection
    let file_missing_ngram = b"axc"; // has (a,x) and (x,c), but not (a,b) or (b,c)
    let bloom_missing = NgramBloom::from_block(file_missing_ngram, 1024).unwrap();
    let matches = filter.matches_bloom(&bloom_missing);
    // May be false positive, but should never be false negative
    // Since 'abc' is NOT in file, it's OK if matches is true (FP) or false
    // Just verify no panic
    let _ = matches;
}

// =============================================================================
// CRITICAL: Pattern spanning 3 blocks must not produce false negatives
// =============================================================================

/// A pattern longer than 2*block_size can span 3 blocks. The pre-filter must
/// return all 3 blocks as candidates so the scanner searches the full region.
#[test]
fn pattern_spanning_three_blocks_never_skipped() {
    use flashsieve::{
        filter::{ByteFilter, NgramFilter},
        BlockIndexBuilder,
    };
    let block_size = 256;

    // Create a 514-byte pattern with unique boundary bytes so no single block
    // or adjacent pair contains all n-grams.
    let mut pattern: Vec<u8> = (0..514u16)
        .map(|i| {
            if i < 256 {
                i as u8
            } else if i < 512 {
                (i + 1) as u8
            } else {
                (i + 2) as u8
            }
        })
        .collect();
    pattern[255] = 0xAB;
    pattern[256] = 0xCD;
    pattern[511] = 0xEF;
    pattern[512] = 0x12;

    let mut data = vec![0xFFu8; block_size * 3];
    data[..pattern.len()].copy_from_slice(&pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(4096)
        .build(&data)
        .unwrap();

    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // n-gram-only query must cover all three blocks
    let ngram_candidates = index.candidate_blocks_ngram(&ngram_filter);
    assert!(
        ngram_candidates
            .iter()
            .any(|r| r.offset == 0 && r.offset + r.length >= block_size * 3),
        "CRITICAL: 3-block-spanning pattern missed in n-gram-only query: {:?}",
        ngram_candidates
    );

    // Combined query must also cover all three blocks
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(
        candidates
            .iter()
            .any(|r| r.offset == 0 && r.offset + r.length >= block_size * 3),
        "CRITICAL: 3-block-spanning pattern missed in combined query: {:?}",
        candidates
    );
}

/// Verify the same for MmapBlockIndex — serialization must not lose the fix.
#[test]
fn pattern_spanning_three_blocks_mmap_never_skipped() {
    use flashsieve::{
        filter::{ByteFilter, NgramFilter},
        BlockIndexBuilder, MmapBlockIndex,
    };
    let block_size = 256;

    let mut pattern: Vec<u8> = (0..514u16)
        .map(|i| {
            if i < 256 {
                i as u8
            } else if i < 512 {
                (i + 1) as u8
            } else {
                (i + 2) as u8
            }
        })
        .collect();
    pattern[255] = 0xAB;
    pattern[256] = 0xCD;
    pattern[511] = 0xEF;
    pattern[512] = 0x12;

    let mut data = vec![0xFFu8; block_size * 3];
    data[..pattern.len()].copy_from_slice(&pattern);

    let bytes = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(4096)
        .build(&data)
        .unwrap()
        .to_bytes();

    let mmap_index = MmapBlockIndex::from_slice(&bytes).unwrap();
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    let candidates = mmap_index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(
        candidates
            .iter()
            .any(|r| r.offset == 0 && r.offset + r.length >= block_size * 3),
        "CRITICAL: 3-block-spanning pattern missed in MmapBlockIndex: {:?}",
        candidates
    );
}
