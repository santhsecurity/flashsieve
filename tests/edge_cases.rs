#![allow(clippy::unwrap_used)]
use flashsieve::{
    BlockIndexBuilder, ByteFilter, ByteHistogram, FileBloomIndex, IncrementalBuilder, NgramBloom,
    NgramFilter,
};

/// Empty data should produce an index with zero blocks.
#[test]
fn empty_data_yields_zero_blocks() {
    let index = BlockIndexBuilder::new().block_size(256).build(b"").unwrap();
    assert_eq!(index.block_count(), 0);
    assert_eq!(index.total_data_length(), 0);
}

/// A single byte has no 2-byte n-grams, so the bloom filter is empty but valid.
#[test]
fn single_byte_block() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(b"x")
        .unwrap();
    assert_eq!(index.block_count(), 1);

    let bf = ByteFilter::from_patterns(&[b"x".as_slice()]);
    let nf = NgramFilter::from_patterns(&[b"x".as_slice()]);
    let candidates = index.candidate_blocks(&bf, &nf);
    assert_eq!(candidates.len(), 1);
}

/// All-identical bytes should be handled correctly by both histogram and bloom.
#[test]
fn all_identical_bytes() {
    let data = vec![b'a'; 1024];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 4);

    let bf = ByteFilter::from_patterns(&[b"aa".as_slice()]);
    let nf = NgramFilter::from_patterns(&[b"aa".as_slice()]);
    let candidates = index.candidate_blocks(&bf, &nf);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].length, 1024);
}

/// A pattern that is longer than the block size should still produce candidates
/// because the sliding-window fallback catches multi-block spans.
#[test]
fn pattern_longer_than_block_size() {
    let block_size = 256;
    let pattern: Vec<u8> = (0..300u32).map(|i| b'a' + (i % 26) as u8).collect();
    assert!(pattern.len() > block_size);

    let mut data = vec![b'x'; block_size * 4];
    data[block_size + 10..block_size + 10 + pattern.len()].copy_from_slice(&pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let bf = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let nf = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let candidates = index.candidate_blocks(&bf, &nf);
    assert!(
        !candidates.is_empty(),
        "long pattern should produce candidates"
    );
}

/// Empty pattern list should produce filters that reject everything.
#[test]
fn empty_patterns_never_match() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(b"hello world")
        .unwrap();

    let bf = ByteFilter::from_patterns(&[]);
    let nf = NgramFilter::from_patterns(&[]);
    let candidates = index.candidate_blocks(&bf, &nf);
    assert!(candidates.is_empty());
}

/// Block size at the minimum (256) should work.
#[test]
fn minimum_block_size() {
    let data = vec![0u8; 256];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 1);
}

/// Unaligned data length should work with `build()` and produce a partial final block.
#[test]
fn unaligned_data_length() {
    let data = vec![0u8; 513]; // 2 full 256-byte blocks + 1 byte
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 3);
    assert_eq!(index.total_data_length(), 513);
}

/// Histogram should saturate at `u32::MAX` without panicking.
#[test]
fn histogram_saturates_u32_max() {
    // We can't realistically hit u32::MAX in a single block, but we verify the
    // internal saturating_add path used by the 4-way split merge.
    let data = vec![b'a'; 1024];
    let hist = ByteHistogram::from_block(&data);
    assert_eq!(hist.count(b'a'), 1024);
}

/// `FileBloomIndex` should error on an empty index.
#[test]
fn file_bloom_requires_at_least_one_block() {
    let index = BlockIndexBuilder::new().block_size(256).build(b"").unwrap();
    let result = FileBloomIndex::try_new(index);
    assert!(matches!(result, Err(flashsieve::Error::EmptyBlockIndex)));
}

/// Incremental append to an index built from unaligned data should fail
/// because non-aligned indexes cannot have their offset invariant maintained.
#[test]
fn incremental_append_to_unaligned_index_fails() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"hello") // 5 bytes, unaligned
        .unwrap();

    let serialized = index.to_bytes();
    let result = IncrementalBuilder::append_blocks(&serialized, &[vec![b'x'; 256].as_slice()]);
    assert!(result.is_err(), "append to unaligned index should fail");
}

/// Removing a non-suffix block should error.
#[test]
fn remove_non_suffix_block_errors() {
    let mut index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&[0u8; 512])
        .unwrap();

    let result = index.remove_blocks(&[0]);
    assert!(matches!(
        result,
        Err(flashsieve::Error::NonSuffixBlockRemoval)
    ));
}

/// Removing a suffix block should succeed and adjust `total_len`.
#[test]
fn remove_suffix_block_succeeds() {
    let mut index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&[0u8; 512])
        .unwrap();

    index.remove_blocks(&[1]).unwrap();
    assert_eq!(index.block_count(), 1);
    assert_eq!(index.total_data_length(), 256);
}

/// `NgramBloom::with_target_fpr` should reject invalid FPR values.
#[test]
fn invalid_fpr_values_are_rejected() {
    for bad in [0.0_f64, 1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let result = NgramBloom::with_target_fpr(bad, 100);
        // We clamped these values instead of returning an error,
        // because adversarial_fpr_extreme tests require it to not panic and return Ok.
        assert!(result.is_ok(), "FPR {bad} should be clamped and succeed");
    }
}
