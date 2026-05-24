#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
//! crash/concurrent tests for flashsieve.
//!
//! Tests for multiple threads building and saving separate indexes to the same directory.

use flashsieve::BlockIndexBuilder;
use std::fs;
use std::sync::Arc;
use std::thread;

#[test]
fn test_concurrent_index_building() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dir_path = Arc::new(temp_dir.path().to_path_buf());

    let mut handles = vec![];

    for i in 0..10 {
        let dir = Arc::clone(&dir_path);
        handles.push(thread::spawn(move || {
            let mut data = vec![0u8; 1024 * 64];
            data.fill((i % 256) as u8);

            let index = BlockIndexBuilder::new()
                .block_size(1024)
                .bloom_bits(1024)
                .build(&data)
                .expect("build failed");

            let bytes = index.to_bytes();

            let file_path = dir.join(format!("index_{i}.fsie"));
            fs::write(&file_path, bytes).unwrap();

            let read_bytes = fs::read(&file_path).unwrap();
            let loaded = flashsieve::BlockIndex::from_bytes_checked(&read_bytes).unwrap();

            assert_eq!(loaded.block_count(), 64);
            assert_eq!(loaded.block_size(), 1024);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // verify all files exist and are valid
    for i in 0..10 {
        let file_path = dir_path.join(format!("index_{i}.fsie"));
        let bytes = fs::read(&file_path).unwrap();
        assert!(flashsieve::BlockIndex::from_bytes_checked(&bytes).is_ok());
    }
}
