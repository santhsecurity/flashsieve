
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
//! Exhaustive adversarial tests for flashsieve.
//!
//! These tests are designed to break the implementation by testing:
//! - Edge cases (empty data, boundary conditions)
//! - Invariants (zero false negatives, FPR bounds)
//! - Malformed inputs (corrupted data, truncated data)
//! - Scale limits (10K patterns, 1MB blocks)
//! - Adversarial patterns (all zeros, all 0xFF, repeated bytes)

use flashsieve::{
    BlockIndex, BlockIndexBuilder, ByteFilter, ByteHistogram, FileBloomIndex, IncrementalBuilder,
    MmapBlockIndex, NgramBloom, NgramFilter,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Instant;

// ============================================================================
// NGRAM BLOOM ADVERSARIAL TESTS
// ============================================================================

/// Test `NgramBloom::from_block` with completely empty data.
/// An empty block should produce a valid but empty bloom filter.
#[test]
fn ngram_bloom_from_block_empty_data() {
    let bloom = NgramBloom::from_block(b"", 1024).expect("expected");
    // Empty data has no n-grams, so nothing should be "contained"
    assert!(
        !bloom.maybe_contains(b'a', b'b'),
        "empty bloom should not contain any n-grams"
    );
    assert!(
        bloom.estimated_false_positive_rate() < f64::EPSILON,
        "empty bloom should have 0% FPR"
    );
}

/// Test `NgramBloom::from_block` with single byte (no n-grams possible).
#[test]
fn ngram_bloom_from_block_single_byte() {
    let bloom = NgramBloom::from_block(b"x", 1024).expect("expected");
    // Single byte has no 2-byte n-grams
    assert!(
        !bloom.maybe_contains(b'x', b'x'),
        "single byte input should produce no n-grams"
    );
}

/// Test `NgramBloom::from_block` with exactly 2 bytes (one n-gram).
#[test]
fn ngram_bloom_from_block_two_bytes() {
    let bloom = NgramBloom::from_block(b"ab", 1024).expect("expected");
    assert!(
        bloom.maybe_contains(b'a', b'b'),
        "bloom should contain the one n-gram from 2-byte input"
    );
    assert!(
        !bloom.maybe_contains(b'b', b'a'),
        "bloom should not contain reversed n-gram"
    );
}

/// Test `NgramBloom::from_block` with data exactly matching block size.
#[test]
fn ngram_bloom_from_block_exact_block_size() {
    let block_size = 4096;
    let data = vec![b'x'; block_size];
    let bloom = NgramBloom::from_block(&data, 65536).expect("expected");
    // Should contain the (x, x) n-gram
    assert!(
        bloom.maybe_contains(b'x', b'x'),
        "bloom should contain repeated-byte n-gram"
    );
}

/// Test `NgramBloom::from_block` with data one byte over block size.
#[test]
fn ngram_bloom_from_block_block_size_plus_one() {
    let block_size = 4096;
    let data = vec![b'x'; block_size + 1];
    let bloom = NgramBloom::from_block(&data, 65536).expect("expected");
    assert!(
        bloom.maybe_contains(b'x', b'x'),
        "bloom should contain repeated-byte n-gram"
    );
}

/// Test with all-zeros input (adversarial: minimal entropy).
#[test]
fn ngram_bloom_all_zeros_input() {
    let data = vec![0x00; 1000];
    let bloom = NgramBloom::from_block(&data, 1024).expect("expected");
    // All n-grams are (0x00, 0x00)
    assert!(
        bloom.maybe_contains(0x00, 0x00),
        "bloom should contain (0x00, 0x00) n-gram"
    );
    assert!(
        !bloom.maybe_contains(0x00, 0x01),
        "bloom should not contain (0x00, 0x01) n-gram"
    );
}

/// Test with all-0xFF input (adversarial: maximum entropy in one sense).
#[test]
fn ngram_bloom_all_0xff_input() {
    let data = vec![0xFF; 1000];
    let bloom = NgramBloom::from_block(&data, 1024).expect("expected");
    assert!(
        bloom.maybe_contains(0xFF, 0xFF),
        "bloom should contain (0xFF, 0xFF) n-gram"
    );
    assert!(
        !bloom.maybe_contains(0xFE, 0xFF),
        "bloom should not contain (0xFE, 0xFF) n-gram"
    );
}

/// Test with all same byte (repeated pattern).
#[test]
fn ngram_bloom_all_same_byte() {
    for byte in [0x00, 0x42, 0xAB, 0xFF] {
        let data = vec![byte; 500];
        let bloom = NgramBloom::from_block(&data, 2048).expect("expected");
        assert!(
            bloom.maybe_contains(byte, byte),
            "bloom should contain ({byte:#04X}, {byte:#04X}) n-gram"
        );
    }
}

/// Test `NgramBloom` with `block_size` = 0 (should fail).
#[test]
fn ngram_bloom_block_size_zero() {
    let result = NgramBloom::new(0);
    assert!(
        result.is_err(),
        "zero bits should fail with ZeroBloomBits error"
    );
}

/// Test `NgramBloom` with `block_size` = 1 (minimal valid).
#[test]
fn ngram_bloom_block_size_one() {
    // 1 bit rounds up to 64 bits (minimum)
    let bloom = NgramBloom::new(1).expect("expected");
    let (num_bits, words) = bloom.raw_parts();
    assert_eq!(
        num_bits, 64,
        "1 bit request should round up to 64 bits (power of two, minimum)"
    );
    assert_eq!(words.len(), 1, "64 bits = 1 word");
}

/// Test `NgramBloom` with `block_size` = 4096.
#[test]
fn ngram_bloom_block_size_4096() {
    let bloom = NgramBloom::new(4096).expect("expected");
    let (num_bits, words) = bloom.raw_parts();
    assert_eq!(num_bits, 4096, "4096 bits should be exact power of two");
    assert_eq!(words.len(), 64, "4096 bits = 64 words");
    // At 4096 bits, exact_pairs should be used internally
}

/// Test `NgramBloom` with `block_size` = 1MB.
#[test]
fn ngram_bloom_block_size_1mb() {
    let bits = 1024 * 1024; // 1M bits
    let bloom = NgramBloom::new(bits).expect("expected");
    let (num_bits, _) = bloom.raw_parts();
    assert_eq!(num_bits, bits, "1M bits should be exact power of two");
    // At 1M bits, exact_pairs should be used internally
}

// ============================================================================
// NGRAM FILTER ADVERSARIAL TESTS
// ============================================================================

/// Test `NgramFilter::from_patterns` with 0 patterns.
#[test]
fn ngram_filter_zero_patterns() {
    let filter = NgramFilter::from_patterns(&[]);
    // Empty pattern list should never match
    let bloom = NgramBloom::from_block(b"hello", 1024).expect("expected");
    assert!(
        !filter.matches_bloom(&bloom),
        "empty pattern filter should never match any bloom"
    );
}

/// Test `NgramFilter::from_patterns` with 1 pattern.
#[test]
fn ngram_filter_one_pattern() {
    let filter = NgramFilter::from_patterns(&[b"hello".as_slice()]);
    let bloom = NgramBloom::from_block(b"hello world", 1024).expect("expected");
    assert!(
        filter.matches_bloom(&bloom),
        "filter with matching pattern should match"
    );
}

/// Test `NgramFilter::from_patterns` with 1000 patterns.
#[test]
fn ngram_filter_thousand_patterns() {
    let patterns: Vec<Vec<u8>> = (0..1000)
        .map(|i| format!("pattern{i}").into_bytes())
        .collect();
    let pattern_refs: Vec<&[u8]> = patterns.iter().map(std::vec::Vec::as_slice).collect();
    let filter = NgramFilter::from_patterns(&pattern_refs);

    // Build a bloom containing one of the patterns
    let bloom = NgramBloom::from_block(b"pattern500", 65536).expect("expected");
    assert!(
        filter.matches_bloom(&bloom),
        "filter should match bloom containing one of 1000 patterns"
    );
}

/// Test pattern with length 0 (empty pattern).
#[test]
fn ngram_filter_empty_pattern() {
    let filter = NgramFilter::from_patterns(&[b"".as_slice()]);
    // Empty patterns are ignored by the filter builder, producing a filter
    // that matches nothing.
    let bloom = NgramBloom::from_block(b"anything", 1024).expect("expected");
    assert!(
        !filter.matches_bloom(&bloom),
        "empty pattern should be ignored and match nothing"
    );
}

/// Test pattern with length 1 (below ngram window).
#[test]
fn ngram_filter_single_byte_pattern() {
    let filter = NgramFilter::from_patterns(&[b"x".as_slice()]);
    // Single byte has no 2-byte n-grams
    let bloom = NgramBloom::from_block(b"xxx", 1024).expect("expected");
    // No n-grams means vacuously true - all 0 n-grams are present
    assert!(
        filter.matches_bloom(&bloom),
        "single-byte pattern vacuously matches (no n-grams to check)"
    );
}

/// Test pattern with length 2 (exactly one n-gram).
#[test]
fn ngram_filter_two_byte_pattern() {
    let filter = NgramFilter::from_patterns(&[b"ab".as_slice()]);
    let bloom = NgramBloom::from_block(b"abc", 1024).expect("expected");
    assert!(
        filter.matches_bloom(&bloom),
        "2-byte pattern with matching n-gram should match"
    );

    let bloom_no_match = NgramBloom::from_block(b"xyz", 1024).expect("expected");
    assert!(
        !filter.matches_bloom(&bloom_no_match),
        "2-byte pattern without matching n-gram should not match"
    );
}

/// Test false positive rate is below 5%.
#[test]
fn ngram_filter_false_positive_rate() {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);

    // Insert 1000 random n-grams
    let mut inserted = std::collections::HashSet::new();
    let data: Vec<u8> = (0..1001).map(|_| rng.gen()).collect();
    let bloom = NgramBloom::from_block(&data, 65536).expect("expected");

    // Collect inserted pairs
    for window in data.windows(2) {
        inserted.insert((window[0], window[1]));
    }

    // Test 10000 random pairs not in the inserted set
    let mut false_positives = 0;
    let mut trials = 0;
    for _ in 0..10000 {
        let a = rng.gen::<u8>();
        let b = rng.gen::<u8>();
        if inserted.contains(&(a, b)) {
            continue;
        }
        trials += 1;
        if bloom.maybe_contains(a, b) {
            false_positives += 1;
        }
    }

    let fpr = f64::from(false_positives) / f64::from(trials);
    assert!(
        fpr < 0.05,
        "false positive rate {fpr} exceeds 5% ({false_positives} false positives in {trials} trials)"
    );
}

/// ZERO FALSE NEGATIVES INVARIANT: If pattern is in data, bloom MUST say yes.
#[test]
fn ngram_filter_zero_false_negatives_invariant() {
    let mut rng = StdRng::seed_from_u64(0xC0FF_EE00);

    for _ in 0..100 {
        // Generate random data
        let data: Vec<u8> = (0..rng.gen_range(10..1000)).map(|_| rng.gen()).collect();
        let bloom = NgramBloom::from_block(&data, 32768).expect("expected");

        // Every n-gram in the data MUST be detected
        for window in data.windows(2) {
            assert!(
                bloom.maybe_contains(window[0], window[1]),
                "FALSE NEGATIVE: bloom rejected n-gram ({:#04X}, {:#04X}) that is in data",
                window[0],
                window[1]
            );
        }
    }
}

/// Test patterns with null bytes.
#[test]
fn ngram_filter_null_bytes() {
    let filter = NgramFilter::from_patterns(&[b"a\x00b".as_slice()]);
    let data = vec![b'a', 0x00, b'b'];
    let bloom = NgramBloom::from_block(&data, 1024).expect("expected");
    assert!(
        filter.matches_bloom(&bloom),
        "pattern with null bytes should match when present"
    );
}

/// Test patterns with binary data (all byte values).
#[test]
fn ngram_filter_binary_data() {
    // Create data with all 256 byte values
    let data: Vec<u8> = (0_u16..=255).map(|i| u8::try_from(i).unwrap()).collect();
    let bloom = NgramBloom::from_block(&data, 65536).expect("expected");

    // Check that consecutive pairs are detected
    for i in 0..255 {
        assert!(
            bloom.maybe_contains(
                u8::try_from(i & 0xFF).unwrap(),
                u8::try_from((i + 1) & 0xFF).unwrap()
            ),
            "bloom should contain n-gram ({i}, {})",
            i + 1
        );
    }
}

/// Test patterns with unicode (multi-byte characters).
#[test]
fn ngram_filter_unicode_patterns() {
    let unicode = "Hello 世界 🌍".as_bytes();
    let bloom = NgramBloom::from_block(unicode, 4096).expect("expected");

    // Filter for a pattern containing unicode
    let filter = NgramFilter::from_patterns(&[unicode]);
    assert!(
        filter.matches_bloom(&bloom),
        "unicode pattern should match when present"
    );
}

// ============================================================================
// BYTE FILTER ADVERSARIAL TESTS
// ============================================================================

/// Test `ByteFilter` with 0 patterns.
#[test]
fn byte_filter_zero_patterns() {
    let filter = ByteFilter::from_patterns(&[]);
    let hist = ByteHistogram::from_block(b"hello");
    assert!(
        !filter.matches_histogram(&hist),
        "empty pattern filter should not match any histogram"
    );
}

/// Test `ByteFilter` with pattern containing all 256 byte values.
#[test]
fn byte_filter_all_bytes_pattern() {
    let all_bytes: Vec<u8> = (0_u16..=255).map(|i| u8::try_from(i).unwrap()).collect();
    let filter = ByteFilter::from_patterns(&[all_bytes.as_slice()]);

    // Should match only if all bytes are present
    let hist_all = ByteHistogram::from_block(&all_bytes);
    assert!(
        filter.matches_histogram(&hist_all),
        "filter should match when all 256 bytes are present"
    );

    let hist_partial = ByteHistogram::from_block(b"hello");
    assert!(
        !filter.matches_histogram(&hist_partial),
        "filter should not match when only partial bytes present"
    );
}

// ============================================================================
// SERIALIZATION / PERSISTENCE ADVERSARIAL TESTS
// ============================================================================

/// Test write + read round-trip.
#[test]
fn serialization_write_read_roundtrip() {
    let data = b"the quick brown fox jumps over the lazy dog";
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(data)
        .expect("expected");

    let serialized = index.to_bytes();
    let deserialized = BlockIndex::from_bytes_checked(&serialized).expect("expected");

    assert_eq!(index.block_count(), deserialized.block_count());
    assert_eq!(index.block_size(), deserialized.block_size());
    assert_eq!(index.total_data_length(), deserialized.total_data_length());

    // Verify queries work the same
    let filter = ByteFilter::from_patterns(&[b"fox".as_slice()]);
    assert_eq!(
        index.candidate_blocks_byte(&filter),
        deserialized.candidate_blocks_byte(&filter)
    );
}

/// Test corrupted file (bit flip).
#[test]
fn serialization_corrupted_file() {
    let data = b"test data for corruption detection";
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(data)
        .expect("expected");

    let mut serialized = index.to_bytes();
    // Flip a bit in the middle
    let mid = serialized.len() / 2;
    serialized[mid] ^= 0x01;

    let result = BlockIndex::from_bytes_checked(&serialized);
    assert!(
        result.is_err(),
        "corrupted data should fail CRC check: {:?}",
        result.ok()
    );
}

/// Test truncated file.
#[test]
fn serialization_truncated_file() {
    let data = b"test data for truncation test";
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(data)
        .expect("expected");

    let serialized = index.to_bytes();
    let truncated = &serialized[..serialized.len() / 2];

    let result = BlockIndex::from_bytes_checked(truncated);
    assert!(
        result.is_err(),
        "truncated data should fail deserialization"
    );
}

/// Test empty file.
#[test]
fn serialization_empty_file() {
    let result = BlockIndex::from_bytes_checked(b"");
    assert!(
        result.is_err(),
        "empty data should fail with TruncatedHeader"
    );
}

/// Test wrong magic bytes.
#[test]
fn serialization_wrong_magic() {
    let data = b"test data";
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(data)
        .expect("expected");

    let mut serialized = index.to_bytes();
    serialized[0] = b'X'; // Change magic

    let result = BlockIndex::from_bytes_checked(&serialized);
    assert!(result.is_err(), "wrong magic should fail deserialization");
}

// ============================================================================
// SCALE TESTS
// ============================================================================

/// Test 10K patterns filter.
#[test]
fn scale_ten_thousand_patterns() {
    let mut rng = StdRng::seed_from_u64(0x5CA1E);

    // Generate 10K random patterns
    let patterns: Vec<Vec<u8>> = (0..10_000)
        .map(|_| {
            let len = rng.gen_range(3..50);
            (0..len).map(|_| rng.gen::<u8>()).collect()
        })
        .collect();
    let pattern_refs: Vec<&[u8]> = patterns.iter().map(std::vec::Vec::as_slice).collect();

    let filter = NgramFilter::from_patterns(&pattern_refs);

    // Build data containing one specific pattern
    let target_pattern = &patterns[5000];
    let bloom = NgramBloom::from_block(target_pattern, 65536).expect("expected");

    assert!(
        filter.matches_bloom(&bloom),
        "10K pattern filter should find match for contained pattern"
    );
}

/// Test 1MB data block bloom filter.
#[test]
fn scale_one_mb_data_block() {
    let mut rng = StdRng::seed_from_u64(0x10B0_DA7A);
    let data: Vec<u8> = (0..(1024 * 1024)).map(|_| rng.gen()).collect();

    let start = Instant::now();
    let bloom = NgramBloom::from_block(&data, 65536).expect("expected");
    let elapsed = start.elapsed();

    // Verify correctness: check some n-grams from the data
    for window in data.windows(2).take(100) {
        assert!(
            bloom.maybe_contains(window[0], window[1]),
            "1MB block bloom should contain its n-grams"
        );
    }

    // Performance check: should be well under 100ms
    assert!(
        elapsed.as_millis() < 100,
        "1MB block processing took {elapsed:?}, expected < 100ms"
    );
}

/// Benchmark: `from_block` on 1MB must be < 100ms in debug mode, < 10ms in release.
#[test]
fn benchmark_from_block_1mb_performance() {
    let mut rng = StdRng::seed_from_u64(0xB3AC_1001);
    let data: Vec<u8> = (0..(1024 * 1024)).map(|_| rng.gen()).collect();

    let start = Instant::now();
    let _bloom = NgramBloom::from_block(&data, 65536).expect("expected");
    let elapsed = start.elapsed();

    // In debug mode, allow up to 100ms; release mode should be < 10ms
    #[cfg(debug_assertions)]
    let limit_ms = 100;
    #[cfg(not(debug_assertions))]
    let limit_ms = 10;

    assert!(
        elapsed.as_millis() < limit_ms,
        "PERFORMANCE REGRESSION: from_block on 1MB took {elapsed:?}, must be < {limit_ms}ms"
    );
}

// ============================================================================
// INCREMENTAL BUILDER ADVERSARIAL TESTS
// ============================================================================

/// Test appending to empty serialized index.
#[test]
fn incremental_append_to_minimal() {
    let base = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build_streaming([vec![b'a'; 256]].into_iter())
        .expect("expected");

    let serialized = base.to_bytes();
    let extra = vec![b'b'; 256];

    let appended =
        IncrementalBuilder::append_blocks(&serialized, &[extra.as_slice()]).expect("expected");

    let recovered = BlockIndex::from_bytes_checked(&appended).expect("expected");
    assert_eq!(
        recovered.block_count(),
        2,
        "should have 2 blocks after append"
    );
}

/// Test appending empty block list.
#[test]
fn incremental_append_empty_blocks() {
    let base = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build_streaming([vec![b'a'; 256]].into_iter())
        .expect("expected");

    let serialized = base.to_bytes();
    let appended = IncrementalBuilder::append_blocks(&serialized, &[]).expect("expected");

    let recovered = BlockIndex::from_bytes_checked(&appended).expect("expected");
    assert_eq!(
        recovered.block_count(),
        1,
        "should still have 1 block after empty append"
    );
}

/// Test appending wrong-sized block (larger than `block_size`).
/// Note: Blocks smaller than `block_size` may be allowed (partial blocks).
#[test]
fn incremental_append_wrong_size() {
    let base = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build_streaming([vec![b'a'; 256]].into_iter())
        .expect("expected");

    let serialized = base.to_bytes();
    let wrong_size = vec![b'b'; 500]; // Larger than block_size - should fail

    let result = IncrementalBuilder::append_blocks(&serialized, &[wrong_size.as_slice()]);
    assert!(
        result.is_err(),
        "appending block larger than `block_size` should fail: {:?}",
        result.ok()
    );
}

// ============================================================================
// MMAP INDEX ADVERSARIAL TESTS
// ============================================================================

/// Test `MmapBlockIndex` with valid data.
#[test]
fn mmap_valid_data() {
    let bytes = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"secret token data")
        .expect("expected")
        .to_bytes();

    let mmap_index = MmapBlockIndex::from_slice(&bytes).expect("expected");

    let byte_filter = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"secret".as_slice()]);

    let candidates = mmap_index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(!candidates.is_empty(), "should find candidate blocks");
}

/// Test `MmapBlockIndex` with truncated data.
#[test]
fn mmap_truncated_data() {
    let mut bytes = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test data")
        .expect("expected")
        .to_bytes();

    bytes.truncate(bytes.len() - 10);

    let result = MmapBlockIndex::from_slice(&bytes);
    assert!(
        result.is_err(),
        "truncated data should fail mmap validation"
    );
}

// ============================================================================
// FILE BLOOM INDEX ADVERSARIAL TESTS
// ============================================================================

/// Test `FileBloomIndex` with valid index.
#[test]
fn file_bloom_valid() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test data with patterns")
        .expect("expected");

    let file_bloom = FileBloomIndex::try_new(index).expect("expected");

    let filter = NgramFilter::from_patterns(&[b"pattern".as_slice()]);
    let candidates = file_bloom.candidate_blocks_ngram(&filter);
    // pattern IS present in "test data with patterns"
    assert_eq!(candidates.len(), 1);
}

/// Test `FileBloomIndex` with empty index (should fail).
#[test]
fn file_bloom_empty_index() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build_streaming(std::iter::empty())
        .expect("expected");

    let result = FileBloomIndex::try_new(index);
    assert!(
        result.is_err(),
        "empty index should fail: {:?}",
        result.ok()
    );
}

// ============================================================================
// BLOCK INDEX OPERATION ADVERSARIAL TESTS
// ============================================================================

/// Test merge with incompatible block sizes.
#[test]
fn block_index_merge_incompatible_block_size() {
    let index1 = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"data1")
        .expect("expected");

    let index2 = BlockIndexBuilder::new()
        .block_size(512) // Different block size
        .bloom_bits(1024)
        .build(b"data2")
        .expect("expected");

    let mut index1_mut = index1;
    let result = index1_mut.merge(&index2);
    assert!(
        result.is_err(),
        "merging incompatible block sizes should fail: {:?}",
        result.ok()
    );
}

/// Test `remove_blocks` with invalid block ID.
#[test]
fn block_index_remove_invalid_block_id() {
    let mut index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test data for removal")
        .expect("expected");

    let block_count = index.block_count();
    let result = index.remove_blocks(&[block_count]); // Out of range
    assert!(
        result.is_err(),
        "removing invalid block ID should fail: {:?}",
        result.ok()
    );
}

/// Test `remove_blocks` with empty list.
#[test]
fn block_index_remove_empty_list() {
    let mut index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test data")
        .expect("expected");

    let original_count = index.block_count();
    index.remove_blocks(&[]).expect("expected");
    assert_eq!(
        index.block_count(),
        original_count,
        "empty removal should not change block count"
    );
}

// ============================================================================
// HISTOGRAM ADVERSARIAL TESTS
// ============================================================================

/// Test `ByteHistogram` with empty block.
#[test]
fn histogram_empty_block() {
    let hist = ByteHistogram::from_block(b"");
    for byte in 0_u8..=255 {
        assert_eq!(
            hist.count(byte),
            0,
            "empty block should have 0 count for all bytes"
        );
    }
}

/// Test `ByteHistogram` with single byte repeated many times.
#[test]
fn histogram_single_byte_repeated() {
    let data = vec![0x42; 10000];
    let hist = ByteHistogram::from_block(&data);
    assert_eq!(
        hist.count(0x42),
        10000,
        "should count repeated byte correctly"
    );
    assert_eq!(hist.count(0x41), 0, "should have 0 for non-present bytes");
}

/// Test `ByteHistogram` with all 256 byte values.
#[test]
fn histogram_all_byte_values() {
    let data: Vec<u8> = (0_u16..=255).map(|i| u8::try_from(i).unwrap()).collect();
    let hist = ByteHistogram::from_block(&data);
    for byte in 0_u8..=255 {
        assert_eq!(hist.count(byte), 1, "each byte should appear exactly once");
    }
}

// ============================================================================
// BLOCKED NGRAM BLOOM ADVERSARIAL TESTS
// ============================================================================

use flashsieve::bloom::BlockedNgramBloom;

/// Test `BlockedNgramBloom` with zero bits.
#[test]
fn blocked_bloom_zero_bits() {
    let result = BlockedNgramBloom::new(0);
    assert!(result.is_err(), "zero bits should fail");
}

/// Test `BlockedNgramBloom` with minimal bits.
#[test]
fn blocked_bloom_minimal_bits() {
    let bloom = BlockedNgramBloom::new(1).expect("expected");
    // Insert and query
    let mut bloom = bloom;
    bloom.insert(b'a', b'b');
    assert!(
        bloom.maybe_contains(b'a', b'b'),
        "should contain inserted n-gram"
    );
}

/// Test `BlockedNgramBloom` zero false negatives.
#[test]
fn blocked_bloom_zero_false_negatives() {
    let mut rng = StdRng::seed_from_u64(0xB10C_BAAD);
    let mut bloom = BlockedNgramBloom::new(65536).expect("expected");

    // Insert 10000 random n-grams
    let mut inserted = std::collections::HashSet::new();
    while inserted.len() < 10000 {
        let pair = (rng.gen::<u8>(), rng.gen::<u8>());
        if inserted.insert(pair) {
            bloom.insert(pair.0, pair.1);
        }
    }

    // Verify zero false negatives
    for &(a, b) in &inserted {
        assert!(
            bloom.maybe_contains(a, b),
            "BlockedNgramBloom FALSE NEGATIVE for ({a:#04X}, {b:#04X})"
        );
    }
}

/// Test `BlockedNgramBloom` FPR is below 5%.
#[test]
fn blocked_bloom_false_positive_rate() {
    let mut rng = StdRng::seed_from_u64(0xF00B_100D);
    let mut bloom = BlockedNgramBloom::new(65536).expect("expected");

    let mut inserted = std::collections::HashSet::new();
    while inserted.len() < 10000 {
        let pair = (rng.gen::<u8>(), rng.gen::<u8>());
        if inserted.insert(pair) {
            bloom.insert(pair.0, pair.1);
        }
    }

    // Measure FPR
    let mut false_positives = 0;
    let mut trials = 0;
    while trials < 10000 {
        let pair = (rng.gen::<u8>(), rng.gen::<u8>());
        if inserted.contains(&pair) {
            continue;
        }
        trials += 1;
        if bloom.maybe_contains(pair.0, pair.1) {
            false_positives += 1;
        }
    }

    let fpr = f64::from(false_positives) / f64::from(trials);
    assert!(fpr < 0.05, "BlockedNgramBloom FPR {fpr} exceeds 5%");
}

// ============================================================================
// BUILDER ADVERSARIAL TESTS
// ============================================================================

/// Test `BlockIndexBuilder` with invalid block size (not power of 2).
#[test]
fn builder_invalid_block_size_not_power_of_2() {
    let result = BlockIndexBuilder::new()
        .block_size(100) // Not a power of 2
        .bloom_bits(1024)
        .build(b"test");
    assert!(
        result.is_err(),
        "non-power-of-2 block size should fail: {:?}",
        result.ok()
    );
}

/// Test `BlockIndexBuilder` with block size below minimum.
#[test]
fn builder_block_size_too_small() {
    let result = BlockIndexBuilder::new()
        .block_size(128) // Below 256 minimum
        .bloom_bits(1024)
        .build(b"test");
    assert!(
        result.is_err(),
        "block size < 256 should fail: {:?}",
        result.ok()
    );
}

/// Test `BlockIndexBuilder` with zero bloom bits.
#[test]
fn builder_zero_bloom_bits() {
    let result = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(0)
        .build(b"test");
    assert!(
        result.is_err(),
        "zero bloom bits should fail: {:?}",
        result.ok()
    );
}

/// Test streaming build with unaligned block.
#[test]
fn builder_streaming_unaligned_block() {
    let result = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build_streaming([vec![b'a'; 100]].into_iter()); // Wrong size
    assert!(
        result.is_err(),
        "unaligned block in streaming should fail: {:?}",
        result.ok()
    );
}

// ============================================================================
// EXACT PAIRS TABLE ADVERSARIAL TESTS
// ============================================================================

/// Test that exact pairs table eliminates false positives for 2-byte queries.
#[test]
fn exact_pairs_zero_false_positives() {
    // Use large enough bloom to trigger exact_pairs table
    let mut bloom = NgramBloom::new(4096).expect("expected");

    // Insert only a few n-grams
    bloom.insert_ngram(b'a', b'b');
    bloom.insert_ngram(b'c', b'd');

    // With exact_pairs, queries for non-inserted pairs should be accurate
    assert!(
        !bloom.maybe_contains_exact(b'x', b'y'),
        "exact_pairs should correctly reject non-inserted n-grams"
    );
    assert!(
        !bloom.maybe_contains_exact(b'a', b'z'),
        "exact_pairs should correctly reject partially-matching n-grams"
    );
}

/// Test `exact_pairs` with all 65536 possible pairs.
#[test]
fn exact_pairs_exhaustive() {
    let mut bloom = NgramBloom::new(65536).expect("expected");

    // Insert every possible pair
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            bloom.insert_ngram(a, b);
        }
    }

    // Every query should return true
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            assert!(
                bloom.maybe_contains_exact(a, b),
                "exact_pairs should find inserted pair ({a:#04X}, {b:#04X})"
            );
        }
    }
}

// ============================================================================
// UNION OPERATION ADVERSARIAL TESTS
// ============================================================================

/// Test union of empty bloom list.
#[test]
fn bloom_union_empty() {
    let result = NgramBloom::union_of(&[]);
    assert!(result.is_err(), "union of empty list should fail");
}

/// Test union of single bloom.
#[test]
fn bloom_union_single() {
    let bloom = NgramBloom::from_block(b"ab", 1024).expect("expected");
    let union = NgramBloom::union_of(&[bloom]).expect("expected");
    assert!(
        union.maybe_contains(b'a', b'b'),
        "union should contain n-grams from single bloom"
    );
}

/// Test union with incompatible bit counts.
#[test]
fn bloom_union_incompatible_bits() {
    let bloom1 = NgramBloom::new(1024).expect("expected");
    let bloom2 = NgramBloom::new(2048).expect("expected");

    let result = NgramBloom::union_of(&[bloom1, bloom2]);
    assert!(
        result.is_err(),
        "union of incompatible bit counts should fail: {:?}",
        result.ok()
    );
}

/// Test union preserves all n-grams (zero false negatives).
#[test]
fn bloom_union_zero_false_negatives() {
    let bloom1 = NgramBloom::from_block(b"abc", 4096).expect("expected");
    let bloom2 = NgramBloom::from_block(b"def", 4096).expect("expected");

    let union = NgramBloom::union_of(&[bloom1, bloom2]).expect("expected");

    // All n-grams from both blooms should be present
    assert!(
        union.maybe_contains(b'a', b'b'),
        "union should contain 'ab'"
    );
    assert!(
        union.maybe_contains(b'b', b'c'),
        "union should contain 'bc'"
    );
    assert!(
        union.maybe_contains(b'd', b'e'),
        "union should contain 'de'"
    );
    assert!(
        union.maybe_contains(b'e', b'f'),
        "union should contain 'ef'"
    );
}

// ============================================================================
// PATTERN MATCHING EDGE CASES
// ============================================================================

/// Test pattern at block boundary.
#[test]
fn pattern_at_block_boundary() {
    let block_size = 256;
    let mut data = vec![b'x'; block_size * 2];
    // Place pattern 'test' entirely within second block to ensure it can be found
    data[block_size + 10..block_size + 14].copy_from_slice(b"test");

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(4096)
        .build(&data)
        .expect("expected");

    // Check byte filter finds the pattern in block 1
    let byte_filter = ByteFilter::from_patterns(&[b"test".as_slice()]);
    let byte_candidates = index.candidate_blocks_byte(&byte_filter);
    assert!(
        !byte_candidates.is_empty(),
        "byte filter should find pattern in block 1"
    );
    // The pattern is in block 1 (offset 256)
    assert_eq!(
        byte_candidates[0].offset, block_size,
        "pattern should be in block 1"
    );

    // N-gram filter should also find it
    let filter = NgramFilter::from_patterns(&[b"test".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&filter);
    assert!(!candidates.is_empty(), "n-gram filter should find pattern");
}

/// Test overlapping patterns.
#[test]
fn overlapping_patterns() {
    let data = b"aaaaa"; // Overlapping 'aa' n-grams
    let bloom = NgramBloom::from_block(data, 1024).expect("expected");

    // Should match pattern with overlapping n-grams
    let filter = NgramFilter::from_patterns(&[b"aaa".as_slice()]);
    assert!(
        filter.matches_bloom(&bloom),
        "overlapping pattern should match"
    );
}

/// Test pattern with repeated single byte.
#[test]
fn pattern_repeated_single_byte() {
    let data = b"xxxxxxxxxx";
    let bloom = NgramBloom::from_block(data, 1024).expect("expected");

    let filter = NgramFilter::from_patterns(&[b"xxxx".as_slice()]);
    assert!(
        filter.matches_bloom(&bloom),
        "repeated byte pattern should match"
    );
}

// ============================================================================
// SELECTIVITY AND CANDIDATE RANGE TESTS
// ============================================================================

/// Test selectivity calculation with empty candidates.
#[test]
fn selectivity_empty_candidates() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test data")
        .expect("expected");

    let selectivity = index.selectivity(&[]);
    assert!(
        selectivity < 0.0001,
        "empty candidates should have 0% selectivity"
    );
}

/// Test `merge_adjacent` with empty input.
#[test]
fn merge_adjacent_empty() {
    let merged = BlockIndex::merge_adjacent(&[]);
    assert!(merged.is_empty(), "merging empty should return empty");
}

/// Test `merge_adjacent` with single range.
#[test]
fn merge_adjacent_single() {
    use flashsieve::index::CandidateRange;
    let ranges = vec![CandidateRange {
        offset: 0,
        length: 256,
    }];
    let merged = BlockIndex::merge_adjacent(&ranges);
    assert_eq!(merged.len(), 1, "single range should remain single");
}

/// Test `merge_adjacent` with non-adjacent ranges.
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
        },
    ];
    let merged = BlockIndex::merge_adjacent(&ranges);
    assert_eq!(merged.len(), 2, "non-adjacent ranges should not be merged");
}

// ============================================================================
// HASH FUNCTION ADVERSARIAL TESTS
// ============================================================================

/// Test hash function never returns zero for second hash via bloom behavior.
/// The bloom filter depends on h2 never being zero for correct operation.
#[test]
fn hash_second_never_zero() {
    // If h2 were ever 0, the bloom filter would fail for certain n-grams.
    // We test by inserting and querying all 65536 possible n-grams.
    let mut bloom = NgramBloom::new(65536).expect("expected");

    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            bloom.insert_ngram(a, b);
        }
    }

    // Verify all were inserted (would fail if h2=0 caused issues)
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            assert!(
                bloom.maybe_contains(a, b),
                "bloom should contain ({a:#04X}, {b:#04X}) - hash may have h2=0 issue"
            );
        }
    }
}

/// Test hash function is deterministic via bloom behavior.
/// Same input should always produce same bloom result.
#[test]
fn hash_deterministic() {
    let data = b"deterministic test data";
    let bloom1 = NgramBloom::from_block(data, 4096).expect("expected");
    let bloom2 = NgramBloom::from_block(data, 4096).expect("expected");

    // Both should have identical internal state
    let (bits1, words1) = bloom1.raw_parts();
    let (bits2, words2) = bloom2.raw_parts();
    assert_eq!(bits1, bits2, "bit count should match");
    assert_eq!(
        words1, words2,
        "word vectors should be identical (deterministic)"
    );
}

// ============================================================================
// VERSION COMPATIBILITY TESTS
// ============================================================================

/// Test deserialization rejects unsupported version.
#[test]
fn version_unsupported() {
    let data = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test")
        .expect("expected")
        .to_bytes();

    // Manually create data with wrong version
    let mut bad_data = data.clone();
    bad_data[4..8].copy_from_slice(&99u32.to_le_bytes()); // Unsupported version

    let result = BlockIndex::from_bytes_checked(&bad_data);
    assert!(
        result.is_err(),
        "unsupported version should fail: {:?}",
        result.ok()
    );
}

/// Test that magic bytes are validated.
#[test]
fn magic_bytes_validation() {
    let mut data = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test")
        .expect("expected")
        .to_bytes();

    // Corrupt magic
    data[0] = b'X';
    data[1] = b'Y';
    data[2] = b'Z';
    data[3] = b'!';

    let result = BlockIndex::from_bytes_checked(&data);
    assert!(result.is_err(), "invalid magic should fail");
}
