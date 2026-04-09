#![allow(clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, BlockIndex, MmapBlockIndex, NgramBloom, NgramFilter, ByteFilter};
use flashsieve::incremental_watch::{IncrementalWatch, WatchConfig};
use std::time::Duration;

#[test]
fn break_it_build_index_with_0_blocks() {
    let index = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(&[]).unwrap();
    assert_eq!(index.block_count(), 0);
}

#[test]
fn break_it_build_with_block_size_1() {
    let result = BlockIndexBuilder::new().block_size(1).bloom_bits(1024).build(b"a");
    assert!(result.is_err());
}

#[test]
fn break_it_bloom_filter_with_0_bits() {
    let result = NgramBloom::new(0);
    assert!(result.is_err());
}

#[test]
fn break_it_ngramfilter_with_empty_patterns() {
    let filter = NgramFilter::from_patterns(&[]);
    let bloom = NgramBloom::from_block(b"test", 1024).unwrap();
    assert!(!filter.matches_bloom(&bloom));
}

#[test]
fn break_it_candidate_blocks_on_empty_index() {
    let index = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(&[]).unwrap();
    let filter = ByteFilter::from_patterns(&[b"test".as_slice()]);
    let candidates = index.candidate_blocks_byte(&filter);
    assert!(candidates.is_empty());
}

#[test]
fn break_it_transport_round_trip_with_corrupt_crc() {
    let index = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"data").unwrap();
    let mut bytes = index.to_bytes();
    let len = bytes.len();
    bytes[len - 1] ^= 0xFF;
    let result = BlockIndex::from_bytes_checked(&bytes);
    assert!(result.is_err());
}

#[test]
fn break_it_incremental_watch_on_deleted_directory() {
    use tempfile::tempdir;
    let dir = tempdir().unwrap();
    let path = dir.path().to_path_buf();
    
    let config = WatchConfig {
        block_size: 256,
        bloom_bits: 1024,
        max_file_size: 1024 * 1024,
        poll_interval: Duration::from_secs(5),
    };
    
    let mut watcher = IncrementalWatch::new(&path, config);
    drop(dir); // Delete directory
    
    // Polling a deleted directory should ideally return no changes or an error.
    let _changes = watcher.poll();
}

#[test]
fn break_it_mmap_index_on_truncated_file() {
    let index = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"data").unwrap();
    let mut bytes = index.to_bytes();
    bytes.truncate(bytes.len() - 10);
    let result = MmapBlockIndex::from_slice(&bytes);
    assert!(result.is_err());
}
