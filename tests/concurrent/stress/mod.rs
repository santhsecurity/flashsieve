#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn test_stress_concurrent_mmap_reads_with_barrier() {
    let data = vec![0x12; 1024 * 64];
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&data)
        .unwrap();
    let serialized = index.to_bytes();

    let mmap = MmapBlockIndex::from_slice(&serialized).unwrap();
    let num_threads = 100;
    let barrier = Arc::new(Barrier::new(num_threads));

    thread::scope(|s| {
        for i in 0..num_threads {
            let barrier_clone = Arc::clone(&barrier);
            let mmap_ref = &mmap;
            s.spawn(move || {
                barrier_clone.wait(); // Force simultaneous access

                // Read from various blocks based on thread ID
                let block_id = i % 64;
                let hist = mmap_ref.try_histogram(block_id).unwrap();
                assert_eq!(hist.count(0x12), 1024);

                let bloom = mmap_ref.try_bloom(block_id).unwrap();
                assert!(bloom.maybe_contains_bloom(0x12, 0x12));
            });
        }
    });
}
