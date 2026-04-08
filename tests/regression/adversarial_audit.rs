#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndex, BlockIndexBuilder, Error, MmapBlockIndex, NgramBloom};

#[test]
fn test_malicious_word_count_is_rejected() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(64)
        .build_streaming([vec![b'A'; 256]].into_iter())
        .unwrap();
    let mut bytes = index.to_bytes();
    bytes[4] = 1; // Use version 1 to skip CRC checks

    let word_count_offset = 29 + 1024 + 8;
    // Set an enormous word count (u64::MAX)
    bytes[word_count_offset..word_count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());

    let result = BlockIndex::from_bytes_checked(&bytes);
    assert!(matches!(result, Err(Error::TruncatedBlock { .. })));
}

#[test]
fn test_mmap_index_word_count_rejected() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(64)
        .build_streaming([vec![b'A'; 256]].into_iter())
        .unwrap();
    let mut bytes = index.to_bytes();
    bytes[4] = 1; // Use version 1 to skip CRC checks

    let word_count_offset = 29 + 1024 + 8;
    // Set word_count < num_bits.div_ceil(64). num_bits is 64, so it needs 1.
    bytes[word_count_offset..word_count_offset + 8].copy_from_slice(&0u64.to_le_bytes());

    let result = MmapBlockIndex::from_slice(&bytes);
    assert!(matches!(result, Err(Error::TruncatedBlock { .. })));
}

#[test]
fn test_incremental_remove_blocks_total_len_recalculated() {
    let mut index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(64)
        .build(b"short") // 5 bytes, one partial block
        .unwrap();
    assert_eq!(index.total_data_length(), 5);
    index.remove_blocks(&[0]).unwrap();
    assert_eq!(index.total_data_length(), 0);
}

#[test]
fn test_incremental_append_partial_middle_rejected() {
    let mut index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(64)
        .build(b"short") // 5 bytes, partial block
        .unwrap();
    let result = index.append_block(b"more"); // try to append after partial
    assert!(matches!(result, Err(Error::UnalignedData { .. })));
}

#[test]
fn test_candidate_range_offset_overflow() {
    // block_size must be a power of two.
    let result = BlockIndexBuilder::new()
        .block_size(1 << 30) // valid large block size
        .bloom_bits(64)
        .build(vec![b'A'; 256].as_slice());
    assert!(result.is_ok());
}
