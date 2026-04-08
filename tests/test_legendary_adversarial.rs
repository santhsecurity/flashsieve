#![allow(clippy::unwrap_used)]

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};

#[test]
fn legendary_adversarial_empty_data() {
    let index = BlockIndexBuilder::new().block_size(256).build(&[]).unwrap();
    assert_eq!(index.block_count(), 0);
    assert_eq!(index.total_data_length(), 0);
}

#[test]
fn legendary_adversarial_null_bytes() {
    let data = vec![0x00; 1024];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[b"\x00\x00".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"\x00\x00".as_slice()]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    // Since candidate blocks are contiguous ranges, they will be merged.
    // 1 range of length 1024.
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].length, 1024);
}

#[test]
fn legendary_adversarial_0xff_bytes() {
    let data = vec![0xFF; 1024];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    let byte_filter = ByteFilter::from_patterns(&[b"\xFF\xFF".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"\xFF\xFF".as_slice()]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].length, 1024);
}

#[test]
fn legendary_adversarial_invalid_block_size() {
    let builder = BlockIndexBuilder::new().block_size(100); // not power of 2, and < 256
    let res = builder.build(&[0; 100]);
    assert!(res.is_err());

    let builder2 = BlockIndexBuilder::new().block_size(255); // not power of 2
    let res2 = builder2.build(&[0; 255]);
    assert!(res2.is_err());
}

#[test]
fn legendary_adversarial_zero_bloom_bits() {
    let builder = BlockIndexBuilder::new().block_size(256).bloom_bits(0);
    let res = builder.build(&[0; 256]);
    assert!(res.is_err());
}

#[test]
fn legendary_adversarial_streaming_unaligned_chunks() {
    let builder = BlockIndexBuilder::new().block_size(256);
    let chunks = vec![vec![0; 256], vec![0; 128]];
    let res = builder.build_streaming(chunks.into_iter());
    assert!(res.is_err());
}

#[test]
fn legendary_adversarial_huge_pattern() {
    let data = vec![0x41; 256];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();

    // Pattern larger than the block size itself
    let huge_pattern = vec![0x41; 1024];
    let byte_filter = ByteFilter::from_patterns(&[huge_pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[huge_pattern.as_slice()]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert_eq!(candidates.len(), 1);
}

#[test]
fn legendary_adversarial_repeated_ngrams() {
    let pattern = b"abababababababab";
    let filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // It should de-duplicate and only require 'ab' and 'ba'.
    // We check this by asserting internal structure or functional behavior.
    let bloom = flashsieve::NgramBloom::from_block(b"abxba", 1024).unwrap();
    assert!(filter.matches_bloom(&bloom));
}
