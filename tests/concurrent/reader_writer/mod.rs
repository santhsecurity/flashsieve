#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
use std::thread;

#[test]
fn test_concurrent_reads_on_arc_index() {
    let data = vec![0xAB; 4096];
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&data)
        .unwrap();
    let serialized = index.to_bytes();

    // MmapBlockIndex has a lifetime tied to the slice.
    // Instead of Arc-ing the MmapBlockIndex across threads with a static bound,
    // we use thread::scope so we don't need 'static lifetimes.
    let mmap = MmapBlockIndex::from_slice(&serialized).unwrap();

    thread::scope(|s| {
        // Spawn 50 threads doing simultaneous reads
        for _ in 0..50 {
            let mmap_ref = &mmap;
            s.spawn(move || {
                for _ in 0..100 {
                    let bloom = mmap_ref.try_bloom(0).unwrap();
                    assert!(bloom.maybe_contains_bloom(0xAB, 0xAB));

                    let hist = mmap_ref.try_histogram(0).unwrap();
                    assert_eq!(hist.count(0xAB), 1024);
                }
            });
        }
    });
}
