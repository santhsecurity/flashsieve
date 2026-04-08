#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, Error};

#[test]
fn test_builder_defaults() {
    // There's no getter for block_size, so we check it indirectly by building a block.
    // The defaults are 256 KiB and 65,536 bits per block.
    let index = BlockIndexBuilder::new().build(&vec![0xAA; 1024]).unwrap();
    assert_eq!(
        index.block_size(),
        262_144,
        "Default block size should be 256KB"
    );
}

#[test]
fn test_builder_custom_params() {
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .bloom_bits(2048)
        .build(&vec![0xAA; 1024])
        .unwrap();
    assert_eq!(index.block_size(), 1024);
}

#[test]
fn test_build_empty_data() {
    let builder = BlockIndexBuilder::new();
    let index = builder.build(&[]).expect("Should build empty index");
    assert_eq!(index.block_count(), 0);
    assert_eq!(index.total_data_length(), 0);
}

#[test]
fn test_build_single_block() {
    let data = vec![0xAA; 1024];
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&data)
        .expect("Should build single block");

    assert_eq!(index.block_count(), 1);
    assert_eq!(index.total_data_length(), 1024);
}

#[test]
fn test_build_multiple_blocks() {
    let data = vec![0xBB; 2500]; // 2 full blocks of 1024, 1 partial block of 452
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&data)
        .expect("Should build multiple blocks");

    assert_eq!(index.block_count(), 3);
    assert_eq!(index.total_data_length(), 2500);
}

#[test]
fn test_build_streaming_empty() {
    let blocks: Vec<Vec<u8>> = vec![];
    let index = BlockIndexBuilder::new()
        .build_streaming(blocks.into_iter())
        .expect("Should build empty streaming");
    assert_eq!(index.block_count(), 0);
}

#[test]
fn test_build_streaming_multiple_blocks() {
    let data1 = vec![0xCC; 1024];
    let data2 = vec![0xCC; 1024];
    let data3 = vec![0xCC; 452]; // Partial block

    // Using build() should handle unaligned correctly as it chunks it internally,
    // but build_streaming() expects the caller to either pad or handle the final block correctly,
    // or it rejects an incorrectly sized intermediate block? Let's check error:
    let blocks = vec![data1, data2, data3];
    let result = BlockIndexBuilder::new()
        .block_size(1024)
        .build_streaming(blocks.into_iter());

    assert!(matches!(result, Err(Error::UnalignedData { .. })));

    // Now pass exactly aligned blocks.
    let blocks_aligned = vec![vec![0xCC; 1024], vec![0xCC; 1024], vec![0xCC; 1024]];
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build_streaming(blocks_aligned.into_iter())
        .expect("Should build aligned blocks");

    assert_eq!(index.block_count(), 3);
    assert_eq!(index.total_data_length(), 3072);
}
