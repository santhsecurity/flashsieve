#![allow(
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
//! Adversarial tests for BlockIndexBuilder validation.

use flashsieve::BlockIndexBuilder;

// =============================================================================
// Block Size Validation
// =============================================================================

#[test]
fn block_size_0_rejected() {
    let result = BlockIndexBuilder::new().block_size(0).build(&[]);
    assert!(result.is_err());
}

#[test]
fn block_size_1_rejected() {
    let result = BlockIndexBuilder::new().block_size(1).build(&[0; 1]);
    assert!(result.is_err());
}

#[test]
fn block_size_128_rejected_below_minimum() {
    let result = BlockIndexBuilder::new().block_size(128).build(&[0; 128]);
    assert!(result.is_err());
}

#[test]
fn block_size_256_accepted() {
    let data = vec![0_u8; 256];
    let result = BlockIndexBuilder::new().block_size(256).build(&data);
    assert!(result.is_ok());
}

#[test]
fn block_size_not_power_of_two_rejected() {
    let result = BlockIndexBuilder::new().block_size(300).build(&[0; 300]);
    assert!(result.is_err());
}

#[test]
fn block_size_512_power_of_two_accepted() {
    let data = vec![0_u8; 512];
    let result = BlockIndexBuilder::new().block_size(512).build(&data);
    assert!(result.is_ok());
}

// =============================================================================
// Data Alignment Validation
// =============================================================================

#[test]
fn unaligned_data_builds_partial_final_block() {
    let data = vec![0_u8; 300]; // not aligned to 256
    let result = BlockIndexBuilder::new().block_size(256).build(&data);
    let index = result.unwrap();
    assert_eq!(index.block_count(), 2);
    assert_eq!(index.total_data_length(), data.len());
}

#[test]
fn empty_data_aligned_accepted() {
    let result = BlockIndexBuilder::new().block_size(256).build(&[]);
    assert!(result.is_ok());
}

#[test]
fn exactly_one_block_accepted() {
    let data = vec![0_u8; 256];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 1);
}

#[test]
fn exactly_four_blocks_accepted() {
    let data = vec![0_u8; 1024];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 4);
}

// =============================================================================
// Bloom Bits Validation
// =============================================================================

#[test]
fn bloom_bits_0_rejected() {
    let data = vec![0_u8; 256];
    let result = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(0)
        .build(&data);
    assert!(result.is_err());
}

#[test]
fn bloom_bits_1_accepted() {
    let data = vec![0_u8; 256];
    let result = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1)
        .build(&data);
    assert!(result.is_ok());
}

// =============================================================================
// Streaming Build Parity
// =============================================================================

#[test]
fn streaming_wrong_block_size_rejected() {
    let builder = BlockIndexBuilder::new().block_size(256);
    let blocks = vec![vec![0_u8; 128]]; // wrong size
    let result = builder.build_streaming(blocks.into_iter());
    assert!(result.is_err());
}

#[test]
fn streaming_empty_produces_zero_blocks() {
    let builder = BlockIndexBuilder::new().block_size(256);
    let index = builder
        .build_streaming(std::iter::empty::<Vec<u8>>())
        .unwrap();
    assert_eq!(index.block_count(), 0);
}

#[test]
fn streaming_matches_batch_for_same_data() {
    let block_size = 256;
    let data = vec![0x42_u8; block_size * 3];
    let builder = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024);

    let batch = builder.build(&data).unwrap();
    let streaming = builder
        .build_streaming(data.chunks(block_size).map(<[u8]>::to_vec))
        .unwrap();

    let filter = flashsieve::ByteFilter::from_single_pattern(&[0x42]);
    assert_eq!(
        batch.candidate_blocks_byte(&filter),
        streaming.candidate_blocks_byte(&filter)
    );
}

// =============================================================================
// Index Properties
// =============================================================================

#[test]
fn block_size_accessor() {
    let data = vec![0_u8; 512];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_size(), 256);
}

#[test]
fn total_data_length_accessor() {
    let data = vec![0_u8; 1024];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    assert_eq!(index.total_data_length(), 1024);
}

#[test]
fn selectivity_empty_ranges_is_zero() {
    let data = vec![0_u8; 256];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    let selectivity = index.selectivity(&[]);
    assert!(selectivity.abs() < f64::EPSILON);
}

#[test]
fn selectivity_full_coverage_is_one() {
    let data = vec![0_u8; 256];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .build(&data)
        .unwrap();
    let all_ranges =
        index.candidate_blocks_byte(&flashsieve::ByteFilter::from_single_pattern(&[0x00]));
    let selectivity = index.selectivity(&all_ranges);
    assert!((selectivity - 1.0).abs() < f64::EPSILON);
}

#[test]
fn default_builder_has_valid_defaults() {
    let builder = BlockIndexBuilder::default();
    // Default block size is 256KB, so we need 256KB of data.
    let data = vec![0_u8; 256 * 1024];
    let result = builder.build(&data);
    assert!(result.is_ok());
}
