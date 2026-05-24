#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, MmapBlockIndex};

#[test]
fn test_mmap_index_from_slice_basic() {
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&vec![0xAA; 1024])
        .unwrap();
    let serialized = index.to_bytes();

    let mmap_idx = MmapBlockIndex::from_slice(&serialized).unwrap();
    assert_eq!(mmap_idx.block_count(), 1);
    assert_eq!(mmap_idx.block_size(), 1024);
    assert_eq!(mmap_idx.total_data_length(), 1024);
}

#[test]
fn test_mmap_index_from_slice_invalid_file() {
    let bad_data = b"not an index";
    assert!(MmapBlockIndex::from_slice(bad_data).is_err());
}
