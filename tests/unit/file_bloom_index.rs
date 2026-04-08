#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, FileBloomIndex};
#[test]
fn test_file_bloom_index_basic() {
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&vec![0xAA; 1024])
        .unwrap();

    let file_idx = FileBloomIndex::try_new(index).unwrap();
    assert_eq!(file_idx.inner().block_count(), 1);
    assert_eq!(file_idx.inner().block_size(), 1024);
    assert_eq!(file_idx.inner().total_data_length(), 1024);

    assert!(file_idx.file_bloom().maybe_contains(0xAA, 0xAA));
}

#[test]
fn test_file_bloom_index_empty() {
    let index = BlockIndexBuilder::new().build(&[]).unwrap();
    assert!(FileBloomIndex::try_new(index).is_err());
}
