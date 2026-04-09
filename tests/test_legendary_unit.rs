#![allow(clippy::unwrap_used)]

use flashsieve::{
    BlockIndexBuilder, ByteFilter, ByteHistogram, CompositeFilter, FilterOp, NgramFilter,
};

#[test]
fn legendary_unit_block_index_builder_valid() {
    let builder = BlockIndexBuilder::new().block_size(1024).bloom_bits(2048);
    let data = vec![0x42; 1500];
    let index = builder.build(&data).unwrap();
    assert_eq!(index.block_size(), 1024);
    assert_eq!(index.block_count(), 2);
    assert_eq!(index.total_data_length(), 1500);
}

#[test]
fn legendary_unit_byte_filter_single_pattern() {
    let pattern = b"hello";
    let filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    assert_eq!(filter.required_count(), 4); // h, e, l, o

    let hist_match = ByteHistogram::from_block(b"hello world");
    assert!(filter.matches_histogram(&hist_match));

    let hist_miss = ByteHistogram::from_block(b"helo"); // missing 'l' x2 but unique count is met
    assert!(filter.matches_histogram(&hist_miss));

    let hist_fail = ByteHistogram::from_block(b"hell");
    assert!(!filter.matches_histogram(&hist_fail));
}

#[test]
fn legendary_unit_byte_filter_multi_pattern() {
    let filter = ByteFilter::from_patterns(&[b"abc".as_slice(), b"def".as_slice()]);
    let hist_abc = ByteHistogram::from_block(b"a_b_c");
    let hist_def = ByteHistogram::from_block(b"d_e_f");
    let hist_mix = ByteHistogram::from_block(b"a_b_d");

    assert!(filter.matches_histogram(&hist_abc));
    assert!(filter.matches_histogram(&hist_def));
    assert!(!filter.matches_histogram(&hist_mix));
}

#[test]
fn legendary_unit_ngram_filter_creation() {
    let filter = NgramFilter::from_patterns(&[b"test".as_slice()]);
    let bloom_match = flashsieve::NgramBloom::from_block(b"this is a test", 1024).unwrap();
    let bloom_miss = flashsieve::NgramBloom::from_block(b"this is a tes", 1024).unwrap();

    assert!(filter.matches_bloom(&bloom_match));
    // It's a bloom filter, so miss could still match (false positive), but we test the API contract
    // We don't assert miss fails strictly because of FPR, but for short strings and 1024 bits it usually fails.
    assert!(!filter.matches_bloom(&bloom_miss));
}

#[test]
fn legendary_unit_ngram_filter_short_pattern() {
    // Patterns < 2 bytes contribute no n-grams, matching ANY bloom.
    let filter = NgramFilter::from_patterns(&[b"a".as_slice()]);
    let bloom = flashsieve::NgramBloom::from_block(b"xyz", 1024).unwrap();
    assert!(filter.matches_bloom(&bloom));
}

#[test]
fn legendary_unit_composite_filter_and() {
    let bf = ByteFilter::from_patterns(&[b"a".as_slice()]);
    let nf = NgramFilter::from_patterns(&[b"ab".as_slice()]);
    let filter = CompositeFilter::combine(
        CompositeFilter::Byte(bf),
        CompositeFilter::Ngram(nf),
        FilterOp::And,
    );

    let hist_match = ByteHistogram::from_block(b"ab");
    let bloom_match = flashsieve::NgramBloom::from_block(b"ab", 1024).unwrap();

    assert!(filter.matches(&hist_match, &bloom_match));

    let hist_miss = ByteHistogram::from_block(b"a_");
    let bloom_miss = flashsieve::NgramBloom::from_block(b"a_", 1024).unwrap();

    // Wait, the filter is: Byte(a) AND Ngram(ab).
    // The hist_miss is "a_". Does it match Byte(a)? Yes, it has 'a'.
    // The bloom is `bloom_match` which is "ab". Does it match Ngram(ab)? Yes, it has "ab".
    // So filter.matches(&hist_miss, &bloom_match) returns TRUE because BOTH are true!
    // We want to test that it fails if ONE of them fails. Let's pass a failing bloom filter!
    assert!(!filter.matches(&hist_miss, &bloom_miss));
}

#[test]
fn legendary_unit_composite_filter_or() {
    let bf = ByteFilter::from_patterns(&[b"z".as_slice()]);
    let nf = NgramFilter::from_patterns(&[b"ab".as_slice()]);
    let filter = CompositeFilter::combine(
        CompositeFilter::Byte(bf),
        CompositeFilter::Ngram(nf),
        FilterOp::Or,
    );

    let hist_a = ByteHistogram::from_block(b"z");
    let bloom_a = flashsieve::NgramBloom::from_block(b"z", 1024).unwrap();
    assert!(filter.matches(&hist_a, &bloom_a));

    let hist_b = ByteHistogram::from_block(b"ab");
    let bloom_b = flashsieve::NgramBloom::from_block(b"ab", 1024).unwrap();
    assert!(filter.matches(&hist_b, &bloom_b));

    let hist_fail = ByteHistogram::from_block(b"xy");
    let bloom_fail = flashsieve::NgramBloom::from_block(b"xy", 1024).unwrap();
    assert!(!filter.matches(&hist_fail, &bloom_fail));
}
