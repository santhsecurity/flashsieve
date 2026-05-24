#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::BlockIndexBuilder;

#[test]
fn test_boundary_exact_block_size() {
    let data = vec![0xFF; 65536]; // exactly 64KB
    let index = BlockIndexBuilder::new()
        .block_size(65536)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 1);
}

#[test]
fn test_boundary_block_size_plus_one() {
    let data = vec![0xFF; 65537]; // exactly 64KB + 1 byte
    let index = BlockIndexBuilder::new()
        .block_size(65536)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 2);
}

#[test]
fn test_boundary_empty_input() {
    let data = vec![];
    let index = BlockIndexBuilder::new()
        .block_size(65536)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 0);
}
