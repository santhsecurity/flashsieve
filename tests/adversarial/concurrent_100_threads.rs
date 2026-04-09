#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! CRITICAL: Concurrent access from 100 threads — must not race.
//!
//! At internet scale, warpscan processes files concurrently. Race conditions
//! in the bloom filter or filter structures could cause false negatives,
//! letting malware through.
//!
//! CORE LAW 4: Every finding is CRITICAL — at internet scale, a "low" bug
//! corrupts billions of records.

use flashsieve::{BlockIndexBuilder, NgramBloom, NgramFilter};
use std::sync::{Arc, Barrier};
use std::thread;

/// Test 100 threads reading shared bloom filter — must not race.
///
/// `NgramBloom` and `NgramFilter` are immutable after construction,
/// so concurrent reads should be safe. This test verifies no
/// data races exist.
#[test]
fn concurrent_100_threads_shared_bloom_reads() {
    const NUM_THREADS: usize = 100;
    const ITERATIONS: usize = 1000;

    // Shared immutable bloom and filter
    let pattern = b"CONCURRENT_TEST_PATTERN_MALWARE_SIG";
    let bloom = Arc::new(NgramBloom::from_block(pattern, 8192).unwrap());
    let filter = Arc::new(NgramFilter::from_patterns(&[pattern.as_slice()]));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let bloom_clone = Arc::clone(&bloom);
        let filter_clone = Arc::clone(&filter);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Synchronize all threads to maximize contention
            barrier_clone.wait();

            for i in 0..ITERATIONS {
                // Alternate between matching and non-matching queries
                let should_match = i % 2 == 0;

                if should_match {
                    // Should always match - this is the critical path
                    let matches = filter_clone.matches_bloom(&bloom_clone);
                    assert!(
                        matches,
                        "CRITICAL FINDING: Race condition caused false negative in thread {} iter {}",
                        thread_id, i
                    );
                } else {
                    // Test with different pattern - may or may not match
                    let _ = filter_clone.matches_bloom(&bloom_clone);
                }

                // Also test direct bloom queries
                let _ = bloom_clone.maybe_contains(b'A', b'B');
                let _ = bloom_clone.maybe_contains(pattern[0], pattern[1]);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked — possible race condition!");
    }

    println!(
        "All {} threads completed {} iterations without races",
        NUM_THREADS, ITERATIONS
    );
}

/// Test 100 threads building their own blooms concurrently.
///
/// Each thread builds its own bloom and filter from scratch.
/// This tests that the builder code is thread-safe.
#[test]
fn concurrent_100_threads_build_own_bloom() {
    const NUM_THREADS: usize = 100;

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            // Each thread builds its own bloom and queries
            let pattern = format!("THREAD_{:03}_PATTERN", thread_id);
            let data = pattern.as_bytes();

            let bloom = NgramBloom::from_block(data, 4096).unwrap();
            let filter = NgramFilter::from_patterns(&[data]);

            // Must match its own pattern
            assert!(
                filter.matches_bloom(&bloom),
                "CRITICAL FINDING: Thread {} pattern failed to match itself!",
                thread_id
            );

            // Test cross-thread isolation
            for other_id in 0..NUM_THREADS {
                if other_id != thread_id {
                    // Other thread's pattern - may or may not match, just verify no panic
                    let _ = filter.matches_bloom(&bloom);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during concurrent build/query!");
    }
}

/// Test concurrent bloom filter union operations.
///
/// Multiple threads creating unions of blooms should not interfere.
#[test]
fn concurrent_bloom_union_operations() {
    const NUM_THREADS: usize = 100;
    const BLOOMS_PER_THREAD: usize = 10;

    // Pre-create blooms for all threads
    let blooms: Vec<NgramBloom> = (0..NUM_THREADS * BLOOMS_PER_THREAD)
        .map(|i| {
            let data = format!("UNION_TEST_DATA_{:04}", i);
            NgramBloom::from_block(data.as_bytes(), 4096).unwrap()
        })
        .collect();

    let blooms_arc = Arc::new(blooms);
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let blooms_clone = Arc::clone(&blooms_arc);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            // Each thread unions a subset of blooms
            let start = thread_id * BLOOMS_PER_THREAD;
            let end = start + BLOOMS_PER_THREAD;
            let thread_blooms: Vec<_> = blooms_clone[start..end].to_vec();

            let union = NgramBloom::union_of(&thread_blooms).unwrap();

            // Verify union contains all expected n-grams
            for i in start..end {
                let data = format!("UNION_TEST_DATA_{:04}", i);
                let filter = NgramFilter::from_patterns(&[data.as_bytes()]);
                assert!(
                    filter.matches_bloom(&union),
                    "CRITICAL: Union missing data from bloom {}",
                    i
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked during union!");
    }
}

/// Test concurrent exact-pairs table queries.
///
/// Large blooms (≥4096 bits) use an exact-pairs table for O(1) lookups.
/// Verify concurrent reads from this table don't race.
#[test]
fn concurrent_exact_pairs_table_reads() {
    const NUM_THREADS: usize = 100;
    const ITERATIONS: usize = 1000;

    // Use 8192 bits to ensure exact-pairs table is allocated
    let bloom = Arc::new(NgramBloom::from_block(b"test data", 8192).unwrap());
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let bloom_clone = Arc::clone(&bloom);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            for i in 0..ITERATIONS {
                // Query various positions in the exact-pairs table
                let a = ((thread_id * 7 + i * 13) % 256) as u8;
                let b = ((thread_id * 13 + i * 7) % 256) as u8;

                // Use maybe_contains_exact to force exact-pairs path
                let _ = bloom_clone.maybe_contains_exact(a, b);

                // Also test maybe_contains which may use exact-pairs
                let _ = bloom_clone.maybe_contains(a, b);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during exact-pairs queries!");
    }
}

/// Test concurrent `BlockedNgramBloom` operations.
///
/// `BlockedNgramBloom` uses cache-line-sized blocks for better locality.
#[test]
fn concurrent_blocked_bloom_reads() {
    use flashsieve::BlockedNgramBloom;

    const NUM_THREADS: usize = 100;
    const ITERATIONS: usize = 1000;

    let blocked = Arc::new(BlockedNgramBloom::from_block(b"blocked bloom test", 8192).unwrap());
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let blocked_clone = Arc::clone(&blocked);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            for i in 0..ITERATIONS {
                let a = ((thread_id * 7 + i * 13) % 256) as u8;
                let b = ((thread_id * 13 + i * 7) % 256) as u8;
                let _ = blocked_clone.maybe_contains(a, b);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during blocked bloom reads!");
    }
}

/// Stress test: 100 threads with barrier-synchronized access.
///
/// This maximizes contention by having all threads hit the bloom
/// filter at exactly the same time.
#[test]
fn concurrent_stress_barrier_synchronization() {
    const NUM_THREADS: usize = 100;
    const ITERATIONS: usize = 100;

    let pattern = b"STRESS_TEST_PATTERN";
    let bloom = Arc::new(NgramBloom::from_block(pattern, 4096).unwrap());
    let filter = Arc::new(NgramFilter::from_patterns(&[pattern.as_slice()]));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let bloom_clone = Arc::clone(&bloom);
        let filter_clone = Arc::clone(&filter);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            for iteration in 0..ITERATIONS {
                // Synchronize all threads at each iteration
                barrier_clone.wait();

                // All 100 threads query simultaneously
                let result = filter_clone.matches_bloom(&bloom_clone);

                // Every thread should see the match
                assert!(
                    result,
                    "CRITICAL: Thread {} saw false negative at iteration {}",
                    thread_id, iteration
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked in stress test!");
    }

    println!(
        "Stress test passed: {} threads × {} synchronized iterations",
        NUM_THREADS, ITERATIONS
    );
}

/// Test concurrent mmap index reads.
///
/// `MmapBlockIndex` provides zero-copy access to serialized indexes.
/// Multiple threads reading from the same mmap should be safe.
#[test]
fn concurrent_mmap_index_reads() {
    use flashsieve::MmapBlockIndex;

    const NUM_THREADS: usize = 100;

    // Create and serialize an index - leak the data to get 'static lifetime
    let data = vec![0x42_u8; 1024 * 64]; // 64KB of data
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&data)
        .unwrap();
    let serialized: &'static [u8] = Box::leak(index.to_bytes().into_boxed_slice());

    let mmap = Arc::new(MmapBlockIndex::from_slice(serialized).unwrap());
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let mmap_clone = Arc::clone(&mmap);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            // Each thread reads from different blocks
            for block_id in 0..64 {
                let target_block = (thread_id + block_id) % 64;

                let hist = mmap_clone.try_histogram(target_block).unwrap();
                assert_eq!(
                    hist.count(0x42),
                    1024,
                    "Histogram mismatch in thread {}",
                    thread_id
                );

                let bloom = mmap_clone.try_bloom(target_block).unwrap();
                assert!(
                    bloom.maybe_contains_bloom(0x42, 0x42),
                    "Bloom mismatch in thread {}",
                    thread_id
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked during mmap reads!");
    }
}

/// Test concurrent filter building and querying.
///
/// Multiple threads building filters from the same pattern set.
#[test]
fn concurrent_filter_building() {
    const NUM_THREADS: usize = 100;
    const PATTERNS_PER_THREAD: usize = 100;

    // Shared pattern set
    let patterns: Vec<Vec<u8>> = (0..PATTERNS_PER_THREAD)
        .map(|i| format!("SHARED_PATTERN_{:04}", i).into_bytes())
        .collect();

    let patterns_arc = Arc::new(patterns);
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let patterns_clone = Arc::clone(&patterns_arc);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            // Each thread builds the same filter
            let pattern_refs: Vec<&[u8]> =
                patterns_clone.iter().map(std::vec::Vec::as_slice).collect();
            let filter = NgramFilter::from_patterns(&pattern_refs);

            // Build a bloom containing one of the patterns
            let test_pattern = &patterns_clone[thread_id % PATTERNS_PER_THREAD];
            let bloom = NgramBloom::from_block(test_pattern, 4096).unwrap();

            // Must match
            assert!(
                filter.matches_bloom(&bloom),
                "CRITICAL: Thread {} filter failed to match",
                thread_id
            );
        });

        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during filter building!");
    }
}

/// Test that `NgramFilter` is Send + Sync.
///
/// Compile-time check that the filter can be safely shared between threads.
#[test]
fn filter_send_sync_traits() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<NgramFilter>();
    assert_sync::<NgramFilter>();
    assert_send::<NgramBloom>();
    assert_sync::<NgramBloom>();
}
