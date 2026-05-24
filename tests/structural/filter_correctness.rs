#![allow(
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
//! Adversarial tests for ByteFilter and NgramFilter correctness.
//!
//! These tests verify that no filter configuration can produce a false
//! negative — a block containing a pattern must NEVER be filtered out.

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};

// =============================================================================
// ByteFilter Correctness
// =============================================================================

#[test]
fn byte_filter_required_byte_present_passes() {
    let filter = ByteFilter::from_patterns(&[b"abc"]);
    let histogram = flashsieve::ByteHistogram::from_block(b"abcdef");
    assert!(filter.matches_histogram(&histogram));
}

#[test]
fn byte_filter_required_byte_absent_rejects() {
    let filter = ByteFilter::from_patterns(&[b"xyz"]);
    let histogram = flashsieve::ByteHistogram::from_block(b"abcdef");
    assert!(!filter.matches_histogram(&histogram));
}

#[test]
fn byte_filter_empty_never_matches() {
    let filter = ByteFilter::new();
    let histogram = flashsieve::ByteHistogram::from_block(b"anything");
    assert!(!filter.matches_histogram(&histogram));
}

#[test]
fn byte_filter_single_byte_pattern() {
    let filter = ByteFilter::from_patterns(&[b"a"]);
    let histogram = flashsieve::ByteHistogram::from_block(b"a");
    assert!(filter.matches_histogram(&histogram));
}

#[test]
fn byte_filter_all_256_required_passes_full_data() {
    let data: Vec<u8> = (0_u8..=255).collect();
    let pattern: Vec<u8> = (0_u8..=255).collect();
    let filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let histogram = flashsieve::ByteHistogram::from_block(&data);
    assert!(filter.matches_histogram(&histogram));
}

#[test]
fn byte_filter_multi_pattern_any_match_passes() {
    let filter = ByteFilter::from_patterns(&[b"xyz", b"abc"]);
    let histogram = flashsieve::ByteHistogram::from_block(b"abc");
    // "abc" has all bytes for the "abc" pattern.
    assert!(filter.matches_histogram(&histogram));
}

#[test]
fn byte_filter_multi_pattern_none_match_rejects() {
    let filter = ByteFilter::from_patterns(&[b"xyz", b"qrs"]);
    let histogram = flashsieve::ByteHistogram::from_block(b"abcdef");
    assert!(!filter.matches_histogram(&histogram));
}

#[test]
fn byte_filter_required_count_accurate() {
    let filter = ByteFilter::from_patterns(&[b"aab"]);
    // "aab" has 2 unique bytes: 'a' and 'b'.
    assert_eq!(filter.required_count(), 2);
}

#[test]
fn byte_filter_default_is_empty() {
    let filter = ByteFilter::default();
    assert_eq!(filter.required_count(), 0);
}

// =============================================================================
// NgramFilter Correctness
// =============================================================================

#[test]
fn ngram_filter_required_ngram_present_passes() {
    let filter = NgramFilter::from_patterns(&[b"ab"]);
    let bloom = flashsieve::NgramBloom::from_block(b"abcdef", 4096).unwrap();
    assert!(filter.matches_bloom(&bloom));
}

#[test]
fn ngram_filter_required_ngram_absent_rejects() {
    let filter = NgramFilter::from_patterns(&[b"zx"]);
    let bloom = flashsieve::NgramBloom::from_block(b"abcdef", 4096).unwrap();
    assert!(!filter.matches_bloom(&bloom));
}

#[test]
fn ngram_filter_empty_patterns_never_matches() {
    let filter = NgramFilter::from_patterns(&[]);
    let bloom = flashsieve::NgramBloom::from_block(b"abcdef", 4096).unwrap();
    assert!(!filter.matches_bloom(&bloom));
}

#[test]
fn ngram_filter_single_byte_pattern_always_matches() {
    let filter = NgramFilter::from_patterns(&[b"a"]);
    let bloom = flashsieve::NgramBloom::from_block(b"xyz", 4096).unwrap();
    // Single byte pattern has no 2-byte ngrams → vacuously true.
    assert!(filter.matches_bloom(&bloom));
}

#[test]
fn ngram_filter_pattern_abc_requires_ab_and_bc() {
    let filter = NgramFilter::from_patterns(&[b"abc"]);
    let mut bloom = flashsieve::NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(b'a', b'b');
    // Missing "bc" ngram — should fail.
    assert!(!filter.matches_bloom(&bloom));
    bloom.insert_ngram(b'b', b'c');
    // Now both ngrams present.
    assert!(filter.matches_bloom(&bloom));
}

#[test]
fn ngram_filter_multi_pattern_any_match_passes() {
    let filter = NgramFilter::from_patterns(&[b"zx", b"ab"]);
    let bloom = flashsieve::NgramBloom::from_block(b"abcdef", 4096).unwrap();
    assert!(filter.matches_bloom(&bloom));
}

// =============================================================================
// Combined Filter (BlockIndex.candidate_blocks)
// =============================================================================

#[test]
fn combined_filter_byte_passes_ngram_rejects() {
    let block_size = 256;
    let data = vec![b'a'; block_size]; // only 'a', no 2-byte variety
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[b"a"]);
    let ngram_filter = NgramFilter::from_patterns(&[b"ab"]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    // Byte filter passes (block has 'a'), but ngram "ab" not present.
    assert!(candidates.is_empty());
}

#[test]
fn combined_filter_both_pass() {
    let block_size = 256;
    let mut data = vec![b'x'; block_size];
    data[0..6].copy_from_slice(b"secret");
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[b"secret"]);
    let ngram_filter = NgramFilter::from_patterns(&[b"secret"]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert_eq!(candidates.len(), 1);
}

#[test]
fn combined_filter_both_reject() {
    let block_size = 256;
    let data = vec![b'x'; block_size];
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[b"secret"]);
    let ngram_filter = NgramFilter::from_patterns(&[b"secret"]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(candidates.is_empty());
}
