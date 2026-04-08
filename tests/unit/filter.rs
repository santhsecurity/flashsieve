#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{ByteFilter, ByteHistogram, NgramBloom, NgramFilter};

#[test]
fn test_byte_filter_empty() {
    let filter = ByteFilter::from_patterns(&[]);
    let histogram = ByteHistogram::from_block(b"some data");
    assert!(!filter.matches_histogram(&histogram));
}

#[test]
fn test_byte_filter_single_pattern() {
    let patterns: &[&[u8]] = &[b"hello"];
    let filter = ByteFilter::from_patterns(patterns);

    let histogram_match = ByteHistogram::from_block(b"h e l l o world");
    assert!(filter.matches_histogram(&histogram_match));

    let histogram_miss = ByteHistogram::from_block(b"h e l o"); // missing second 'l'? 'l' is present, wait.
    assert!(filter.matches_histogram(&histogram_miss)); // "helo" contains all unique bytes of "hello"

    let histogram_fail = ByteHistogram::from_block(b"h l l o"); // missing 'e'
    assert!(!filter.matches_histogram(&histogram_fail));
}

#[test]
fn test_ngram_filter_empty() {
    let filter = NgramFilter::from_patterns(&[]);
    let bloom = NgramBloom::from_block(b"some data", 1024).unwrap();
    assert!(!filter.matches_bloom(&bloom));
}

#[test]
fn test_ngram_filter_single_pattern() {
    let patterns: &[&[u8]] = &[b"hello"];
    let filter = NgramFilter::from_patterns(patterns);

    let bloom_match = NgramBloom::from_block(b"hello world", 1024).unwrap();
    assert!(filter.matches_bloom(&bloom_match));

    let bloom_miss = NgramBloom::from_block(b"he llo", 1024).unwrap();
    assert!(!filter.matches_bloom(&bloom_miss));
}
