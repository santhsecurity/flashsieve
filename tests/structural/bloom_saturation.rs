#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! Bloom filter saturation and structural invariant tests.

use flashsieve::bloom::NgramBloom;

#[test]
fn saturated_bloom_has_no_false_negatives() {
    // Insert every possible 2-byte ngram into the bloom filter.
    // After saturation, EVERYTHING must test positive — zero false negatives.
    let mut bloom = NgramBloom::new(65536).unwrap();
    for a in 0..=u8::MAX {
        for b in 0..=u8::MAX {
            bloom.insert_ngram(a, b);
        }
    }
    // Any 2-byte query must hit — the filter is fully saturated.
    assert!(bloom.maybe_contains(0xDE, 0xAD));
    assert!(bloom.maybe_contains(0x00, 0x00));
    assert!(bloom.maybe_contains(0xFF, 0xFF));
}

#[test]
fn empty_bloom_rejects_everything() {
    let bloom = NgramBloom::new(4096).unwrap();
    // No insertions — everything should be rejected (no false positives
    // on an empty filter because no bits are set).
    assert!(!bloom.maybe_contains(b'A', b'B'));
    assert!(!bloom.maybe_contains(0, 0));
}

#[test]
fn single_insertion_is_detected() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(b'h', b'e');
    assert!(bloom.maybe_contains(b'h', b'e'));
}

#[test]
fn from_block_builds_correct_bloom() {
    let data = b"hello world";
    let bloom = NgramBloom::from_block(data, 4096).unwrap();
    // "he", "el", "ll", "lo", "o ", " w", "wo", "or", "rl", "ld" are all ngrams.
    assert!(bloom.maybe_contains(b'h', b'e'));
    assert!(bloom.maybe_contains(b'l', b'o'));
    assert!(bloom.maybe_contains(b'r', b'l'));
}

#[test]
fn estimated_fpr_increases_with_insertions() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    let fpr_empty = bloom.estimated_false_positive_rate();
    assert!(fpr_empty < 0.001, "empty bloom should have near-zero FPR");

    for i in 0..200_u16 {
        bloom.insert_ngram((i >> 8) as u8, (i & 0xFF) as u8);
    }
    let fpr_loaded = bloom.estimated_false_positive_rate();
    assert!(
        fpr_loaded > fpr_empty,
        "FPR must increase with insertions: empty={fpr_empty}, loaded={fpr_loaded}"
    );
}

#[test]
fn zero_size_bloom_is_rejected() {
    let result = NgramBloom::new(0);
    assert!(result.is_err(), "zero-bit bloom must be rejected");
}

#[test]
fn maybe_contains_pattern_checks_all_ngrams() {
    let data = b"abcdef";
    let bloom = NgramBloom::from_block(data, 4096).unwrap();
    // "abc" has ngrams "ab" and "bc" — both present.
    assert!(bloom.maybe_contains_pattern(b"abc"));
    // "xyz" has ngrams "xy" and "yz" — neither present (with high probability).
    // Can't assert false due to FPR, but this exercises the path.
    let _ = bloom.maybe_contains_pattern(b"xyz");
}
