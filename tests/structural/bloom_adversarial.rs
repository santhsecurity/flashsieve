#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! Adversarial tests for the bloom filter internals.
//!
//! These tests probe hash collision behavior, saturation limits,
//! false positive rate bounds, exact-pair tracking, and edge cases
//! with extreme byte values.

use flashsieve::NgramBloom;

// =============================================================================
// Insertion and Query Round-Trip
// =============================================================================

#[test]
fn insert_all_65536_ngrams_no_false_negative() {
    let mut bloom = NgramBloom::new(131_072).unwrap();
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            bloom.insert_ngram(a, b);
        }
    }
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            assert!(
                bloom.maybe_contains(a, b),
                "false negative for ngram ({a}, {b}) after full insertion"
            );
        }
    }
}

#[test]
fn single_insert_single_query() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0x41, 0x42);
    assert!(bloom.maybe_contains(0x41, 0x42));
}

#[test]
fn insert_same_ngram_twice_idempotent() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0x41, 0x42);
    bloom.insert_ngram(0x41, 0x42);
    assert!(bloom.maybe_contains(0x41, 0x42));
}

#[test]
fn query_without_insert_may_return_false() {
    let bloom = NgramBloom::new(4096).unwrap();
    // An empty bloom should return false for all queries.
    assert!(!bloom.maybe_contains(0x41, 0x42));
}

// =============================================================================
// Extreme Byte Values
// =============================================================================

#[test]
fn ngram_0x00_0x00_round_trip() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0x00, 0x00);
    assert!(bloom.maybe_contains(0x00, 0x00));
}

#[test]
fn ngram_0xff_0xff_round_trip() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0xFF, 0xFF);
    assert!(bloom.maybe_contains(0xFF, 0xFF));
}

#[test]
fn ngram_0x00_0xff_round_trip() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0x00, 0xFF);
    assert!(bloom.maybe_contains(0x00, 0xFF));
}

#[test]
fn ngram_0xff_0x00_round_trip() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0xFF, 0x00);
    assert!(bloom.maybe_contains(0xFF, 0x00));
}

// =============================================================================
// Saturation Behavior
// =============================================================================

#[test]
fn fully_saturated_bloom_all_queries_true() {
    // A very small bloom with many insertions becomes mostly saturated.
    let mut bloom = NgramBloom::new(64).unwrap();
    for a in 0_u8..=255 {
        bloom.insert_ngram(a, a);
    }
    // At 64 bits with 256 insertions × 3 hashes, FPR should be very high.
    let fpr = bloom.estimated_false_positive_rate();
    assert!(
        fpr > 0.5,
        "tiny bloom with 256 insertions should be heavily saturated, FPR: {fpr}"
    );
}

#[test]
fn estimated_fpr_zero_for_empty_bloom() {
    let bloom = NgramBloom::new(4096).unwrap();
    let fpr = bloom.estimated_false_positive_rate();
    assert!(
        fpr.abs() < f64::EPSILON,
        "empty bloom should have zero FPR, got: {fpr}"
    );
}

#[test]
fn estimated_fpr_increases_with_insertions() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    let fpr_0 = bloom.estimated_false_positive_rate();
    bloom.insert_ngram(0x41, 0x42);
    let fpr_1 = bloom.estimated_false_positive_rate();
    assert!(
        fpr_1 >= fpr_0,
        "FPR must not decrease after insertion: {fpr_0} -> {fpr_1}"
    );
}

#[test]
fn estimated_fpr_approaches_1_when_saturated() {
    let mut bloom = NgramBloom::new(64).unwrap();
    for a in 0_u8..=255 {
        for b in 0_u8..16 {
            bloom.insert_ngram(a, b);
        }
    }
    let fpr = bloom.estimated_false_positive_rate();
    assert!(
        fpr > 0.9,
        "heavily saturated bloom should have FPR near 1.0, got: {fpr}"
    );
}

// =============================================================================
// Pattern-Level Queries
// =============================================================================

#[test]
fn maybe_contains_pattern_empty_always_true() {
    let bloom = NgramBloom::new(4096).unwrap();
    assert!(bloom.maybe_contains_pattern(&[]));
}

#[test]
fn maybe_contains_pattern_single_byte_always_true() {
    let bloom = NgramBloom::new(4096).unwrap();
    assert!(bloom.maybe_contains_pattern(&[0x41]));
}

#[test]
fn maybe_contains_pattern_two_bytes_round_trip() {
    let bloom = NgramBloom::from_block(b"abcdef", 4096).unwrap();
    assert!(bloom.maybe_contains_pattern(b"ab"));
    assert!(bloom.maybe_contains_pattern(b"cd"));
    assert!(bloom.maybe_contains_pattern(b"ef"));
}

#[test]
fn maybe_contains_pattern_not_found() {
    let bloom = NgramBloom::from_block(b"abcdef", 4096).unwrap();
    assert!(!bloom.maybe_contains_pattern(b"zx"));
}

#[test]
fn maybe_contains_pattern_partial_match_rejected() {
    let bloom = NgramBloom::from_block(b"abcdef", 4096).unwrap();
    // "az" — 'a' is present, but ngram 'az' was never inserted.
    assert!(!bloom.maybe_contains_pattern(b"az"));
}

// =============================================================================
// Construction Errors
// =============================================================================

#[test]
fn zero_bits_rejected() {
    let result = NgramBloom::new(0);
    assert!(result.is_err());
}

#[test]
fn from_block_zero_bits_rejected() {
    let result = NgramBloom::from_block(b"data", 0);
    assert!(result.is_err());
}

#[test]
fn from_block_empty_data_produces_empty_bloom() {
    let bloom = NgramBloom::from_block(&[], 4096).unwrap();
    // No 2-byte windows means nothing inserted.
    assert!(!bloom.maybe_contains(0x41, 0x42));
}

#[test]
fn from_block_single_byte_data_produces_empty_bloom() {
    let bloom = NgramBloom::from_block(&[0x41], 4096).unwrap();
    // Single byte has no 2-byte window.
    assert!(!bloom.maybe_contains(0x41, 0x42));
}

// =============================================================================
// Exact Pair Mode (activated at >= 4096 bits)
// =============================================================================

#[test]
fn exact_pairs_no_false_positive_for_pair_lookup() {
    // With >= 4096 bits, exact_pairs mode is enabled, giving zero false positives.
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0x41, 0x42);
    // Only (0x41, 0x42) should return true; check a subset to verify.
    assert!(bloom.maybe_contains(0x41, 0x42));
    assert!(!bloom.maybe_contains(0x42, 0x41));
    assert!(!bloom.maybe_contains(0x00, 0x00));
}

#[test]
fn below_exact_pair_threshold_uses_bloom_only() {
    // With < 4096 bits (e.g., 2048), exact_pairs is None.
    let mut bloom = NgramBloom::new(2048).unwrap();
    bloom.insert_ngram(0x41, 0x42);
    assert!(bloom.maybe_contains(0x41, 0x42));
    // False positives are possible but not guaranteed.
}

#[test]
fn clone_preserves_exact_pairs() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(0x41, 0x42);
    let cloned = bloom.clone();
    assert!(cloned.maybe_contains(0x41, 0x42));
    assert!(!cloned.maybe_contains(0x43, 0x44));
}
