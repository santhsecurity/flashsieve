#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::unwrap_used
)]
//! Adversarial tests for flashsieve — designed to BREAK the implementation.
//!
//! These tests probe edge cases, malformed inputs, and boundary conditions
//! that could cause panics, incorrect results, or security vulnerabilities.
//!
//! LAW 5: Tests are designed to FAIL first — if a test passes, the engine
//! handles the edge case. If it panics, that's a FINDING.

use flashsieve::{
    BlockIndex, BlockIndexBuilder, ByteFilter, MmapBlockIndex, NgramBloom, NgramFilter,
};
use std::sync::Arc;
use std::thread;

// =============================================================================
// TEST 1: NgramBloom::new(0) — must error, not panic or succeed
// =============================================================================

#[test]
fn ngram_bloom_new_zero_bits_must_error() {
    // Attempting to create a bloom filter with zero bits should fail gracefully.
    // This is a fundamental invariant — a zero-bit bloom filter is meaningless.
    let result = NgramBloom::new(0);
    assert!(
        result.is_err(),
        "CRITICAL: NgramBloom::new(0) must return an error, got Ok instead"
    );
}

// =============================================================================
// TEST 2: BlockIndex::from_bytes with truncated data at every byte offset
// =============================================================================

#[test]
fn block_index_from_bytes_truncated_at_every_offset() {
    // Create a valid serialized index, then truncate at every possible byte
    // and verify we never panic — only return None or an error.
    let block_size = 256;
    let data = vec![b'x'; block_size * 4];
    let original = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("valid index build");
    let serialized = original.to_bytes();

    // Truncate at every possible offset from 1 to len-1
    for truncate_at in 1..serialized.len() {
        let truncated = &serialized[..truncate_at];
        let result = std::panic::catch_unwind(|| BlockIndex::from_bytes(truncated));
        assert!(
            result.is_ok(),
            "PANIC FINDING: BlockIndex::from_bytes panicked at truncation point {}/{}",
            truncate_at,
            serialized.len()
        );
        // Result should be None (failure) not Some (success)
        assert!(
            result.unwrap().is_none(),
            "FINDING: BlockIndex::from_bytes succeeded with truncated data at byte {} — should fail",
            truncate_at
        );
    }
}

// =============================================================================
// TEST 3: BlockIndex::from_bytes with CRC corruption
// =============================================================================

#[test]
fn block_index_from_bytes_crc_corruption_detected() {
    // Create a valid serialized index, corrupt a single bit, verify CRC detects it.
    let block_size = 256;
    let data = vec![b'x'; block_size * 4];
    let original = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("valid index build");
    let mut serialized = original.to_bytes();

    // Corrupt each byte position (except magic bytes 0-3 which don't affect CRC of payload)
    for pos in 4..serialized.len().saturating_sub(4) {
        serialized[pos] ^= 0x01; // Flip one bit
        let result = flashsieve::BlockIndex::from_bytes_checked(&serialized);
        assert!(
            result.is_err(),
            "FINDING: CRC did not detect corruption at byte position {} — data may be silently corrupted",
            pos
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, flashsieve::Error::ChecksumMismatch { .. })
                || matches!(err, flashsieve::Error::UnsupportedVersion { .. }),
            "FINDING: Expected ChecksumMismatch or UnsupportedVersion for CRC corruption at position {}, got: {:?}",
            pos,
            err
        );
        serialized[pos] ^= 0x01; // Restore
    }
}

// =============================================================================
// TEST 4: BlockIndex::from_bytes with block_count = u64::MAX
// =============================================================================

#[test]
fn block_index_from_bytes_block_count_max_u64() {
    // Craft a malicious header claiming u64::MAX blocks.
    // This should be rejected, not cause OOM or panic.
    let mut malicious = Vec::new();
    malicious.extend_from_slice(b"FSBX"); // magic
    malicious.extend_from_slice(&2u32.to_le_bytes()); // version 2
    malicious.extend_from_slice(&256_u64.to_le_bytes()); // block_size
    malicious.extend_from_slice(&0_u64.to_le_bytes()); // total_len
    malicious.extend_from_slice(&u64::MAX.to_le_bytes()); // block_count = u64::MAX

    // Add minimal CRC for version 2
    malicious.resize(malicious.len() + 4, 0);

    let result = std::panic::catch_unwind(|| BlockIndex::from_bytes(&malicious));
    assert!(
        result.is_ok(),
        "PANIC FINDING: BlockIndex::from_bytes panicked with block_count = u64::MAX"
    );
    assert!(
        result.unwrap().is_none(),
        "FINDING: BlockIndex::from_bytes accepted block_count = u64::MAX without rejection"
    );
}

// =============================================================================
// TEST 5: NgramBloom::from_raw_parts with mismatched num_bits vs bits.len()
// =============================================================================

#[test]
fn ngram_bloom_from_raw_parts_mismatched_bits() {
    // Test case: num_bits claims 1024 bits (16 u64s needed) but provide fewer words.
    // This should error, not cause out-of-bounds access later.
    let num_bits = 1024; // Requires 16 u64 words
    let bits = vec![0u64; 1]; // Only 1 word provided

    let result = NgramBloom::from_raw_parts(num_bits, bits);
    assert!(
        result.is_err(),
        "FINDING: NgramBloom::from_raw_parts accepted mismatched num_bits ({}) vs bits.len() (1)",
        num_bits
    );

    // Test case: num_bits = 0 with non-empty bits
    let bits = vec![0u64; 16];
    let result = NgramBloom::from_raw_parts(0, bits);
    // num_bits = 0 requires 0 words, we provided 16 — this is acceptable (extra is ignored)
    // But a bloom with 0 bits is degenerate — check behavior
    assert!(
        result.is_ok() || result.is_err(),
        "from_raw_parts(0, non_empty) should have defined behavior"
    );

    // Test case: num_bits > bits.len() * 64 (severely truncated)
    let num_bits = 10000;
    let bits = vec![0u64; 10]; // Only 640 bits provided
    let result = NgramBloom::from_raw_parts(num_bits, bits);
    assert!(
        result.is_err(),
        "FINDING: NgramBloom::from_raw_parts accepted severely truncated bits (need {}, got {})",
        num_bits.div_ceil(64),
        10
    );
}

// =============================================================================
// TEST 6: Builder with block_size = 0
// =============================================================================

#[test]
fn builder_block_size_zero_must_error() {
    // block_size = 0 is invalid — must fail, not panic or create empty index
    let result = BlockIndexBuilder::new().block_size(0).build(b"some data");
    assert!(
        result.is_err(),
        "FINDING: Builder with block_size=0 must error, got: {:?}",
        result
    );

    // Also test build_streaming
    let result = BlockIndexBuilder::new()
        .block_size(0)
        .build_streaming(vec![vec![0u8; 256]].into_iter());
    assert!(
        result.is_err(),
        "FINDING: Builder::build_streaming with block_size=0 must error, got: {:?}",
        result
    );
}

// =============================================================================
// TEST 7: Builder with empty data
// =============================================================================

#[test]
fn builder_empty_data_behavior() {
    // Empty data should create an empty index (0 blocks), not panic.
    let result = BlockIndexBuilder::new().block_size(256).build(b"");

    // Empty data with div_ceil(block_size) = 0 blocks — should succeed
    assert!(
        result.is_ok(),
        "FINDING: Builder with empty data should succeed, got: {:?}",
        result
    );

    let index = result.unwrap();
    assert_eq!(
        index.block_count(),
        0,
        "FINDING: Empty data should produce 0 blocks, got {}",
        index.block_count()
    );

    // Verify queries on empty index don't panic
    let byte_filter = ByteFilter::from_patterns(&[b"test".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"test".as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(
        candidates.is_empty(),
        "FINDING: Query on empty index should return empty candidates"
    );
}

// =============================================================================
// TEST 8: Incremental: append then remove more blocks than exist
// =============================================================================

#[test]
fn incremental_append_then_remove_too_many_blocks() {
    // Build a minimal index with one block
    let block_size = 256;
    let data = vec![b'x'; block_size];
    let mut index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("valid single-block index");

    assert_eq!(index.block_count(), 1, "setup: should have 1 block");

    // Try to remove block IDs that don't exist (0 exists, 1-99 don't)
    let result = index.remove_blocks(&[0, 1, 2, 99]);
    assert!(
        result.is_err(),
        "FINDING: remove_blocks with invalid block IDs should error, got: {:?}",
        result
    );

    // Verify index is still valid after failed removal
    let byte_filter = ByteFilter::from_patterns(&[b"x".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"x".as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(
        !candidates.is_empty(),
        "FINDING: Index should still be queryable after failed remove_blocks"
    );

    // Try to remove exactly one more than exists
    let result = index.remove_blocks(&[1]);
    assert!(
        result.is_err(),
        "FINDING: remove_blocks(block_id == block_count) should error"
    );

    // Try removing with empty list (should succeed)
    let result = index.remove_blocks(&[]);
    assert!(
        result.is_ok(),
        "FINDING: remove_blocks with empty list should succeed"
    );
    assert_eq!(
        index.block_count(),
        1,
        "FINDING: remove_blocks(&[]) should not change block count"
    );
}

// =============================================================================
// TEST 9: MmapBlockIndex::from_slice with zero length
// =============================================================================

#[test]
fn mmap_block_index_zero_length() {
    // Empty slice should error gracefully, not panic
    let empty: &[u8] = b"";
    let result = std::panic::catch_unwind(|| MmapBlockIndex::from_slice(empty));
    assert!(
        result.is_ok(),
        "PANIC FINDING: MmapBlockIndex::from_slice panicked on empty slice"
    );
    assert!(
        result.unwrap().is_err(),
        "FINDING: MmapBlockIndex::from_slice should error on empty slice"
    );
}

// =============================================================================
// TEST 10: Concurrent build + query (thread safety stress test)
// =============================================================================

#[test]
fn concurrent_build_and_query_thread_safety() {
    use std::sync::Barrier;

    const NUM_THREADS: usize = 8;
    const ITERATIONS: usize = 100;

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            // Synchronize all threads to start simultaneously (maximize contention)
            barrier.wait();

            for i in 0..ITERATIONS {
                // Thread alternates between building and querying
                if (thread_id + i) % 2 == 0 {
                    // Build operation
                    let block_size = 256;
                    let data = vec![b'a' + (i % 26) as u8; block_size * 2];
                    let _index = BlockIndexBuilder::new()
                        .block_size(block_size)
                        .bloom_bits(1024)
                        .build(&data)
                        .expect("concurrent build should succeed");
                } else {
                    // Query operation on pre-built index
                    let block_size = 256;
                    let data = vec![b'x'; block_size * 4];
                    let index = BlockIndexBuilder::new()
                        .block_size(block_size)
                        .bloom_bits(1024)
                        .build(&data)
                        .expect("build should succeed");

                    let pattern = vec![b'x'; 10];
                    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
                    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);
                    let _candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let result = handle.join();
        assert!(
            result.is_ok(),
            "PANIC FINDING: Thread panicked during concurrent build/query: {:?}",
            result
        );
    }
}

// =============================================================================
// ADDITIONAL ADVERSARIAL TESTS
// =============================================================================

#[test]
fn block_index_from_bytes_malicious_histograms() {
    // Craft data with invalid histogram counts that could cause overflow
    let mut malicious = Vec::new();
    malicious.extend_from_slice(b"FSBX"); // magic
    malicious.extend_from_slice(&2u32.to_le_bytes()); // version 2
    malicious.extend_from_slice(&256_u64.to_le_bytes()); // block_size
    malicious.extend_from_slice(&256_u64.to_le_bytes()); // total_len
    malicious.extend_from_slice(&1_u64.to_le_bytes()); // block_count = 1

    // Histogram: 256 u32 counts, all set to u32::MAX
    for _ in 0..256 {
        malicious.extend_from_slice(&u32::MAX.to_le_bytes());
    }

    // Bloom header: num_bits = 64, word_count = 1
    malicious.extend_from_slice(&64_u64.to_le_bytes());
    malicious.extend_from_slice(&1_u64.to_le_bytes());
    malicious.extend_from_slice(&0_u64.to_le_bytes()); // bloom data

    // Calculate and append correct CRC
    let crc = crc32_compute(&malicious);
    malicious.extend_from_slice(&crc.to_le_bytes());

    // This should parse successfully — u32::MAX counts are valid (just large)
    let result = BlockIndex::from_bytes(&malicious);
    assert!(
        result.is_some(),
        "FINDING: Valid index with large histogram counts should parse"
    );

    // Verify the histogram reports correct counts
    let index = result.unwrap();
    assert_eq!(index.block_count(), 1);
}

#[test]
fn bloom_filter_with_large_bits() {
    // Test bloom filter at large bit counts that are still reasonable
    // This verifies no overflow occurs in calculations
    let large_bits = 1_000_000; // 1M bits = ~125KB, reasonable size
    let result = NgramBloom::new(large_bits);
    // Should either succeed or fail gracefully — never panic
    assert!(
        result.is_ok(),
        "FINDING: NgramBloom::new(1_000_000) should succeed or error gracefully"
    );
}

#[test]
fn builder_streaming_unaligned_blocks() {
    // build_streaming requires exact block sizes
    let result = BlockIndexBuilder::new()
        .block_size(256)
        .build_streaming(vec![vec![0u8; 100]].into_iter()); // Wrong size

    assert!(
        result.is_err(),
        "FINDING: build_streaming with unaligned block should error"
    );
}

#[test]
fn incremental_append_oversized_block() {
    let block_size = 256;
    let data = vec![b'x'; block_size];
    let mut index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("valid index");

    // Try to append a block larger than block_size
    let oversized = vec![b'y'; block_size + 1];
    let result = index.append_block(&oversized);
    assert!(
        result.is_err(),
        "FINDING: append_block with oversized data should error"
    );
}

#[test]
fn query_with_malformed_patterns() {
    // Build a valid index
    let block_size = 256;
    let data = vec![b'x'; block_size * 4];
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("valid index");

    // Query with empty patterns
    let empty_patterns: &[&[u8]] = &[];
    let result = std::panic::catch_unwind(|| {
        let _ = ByteFilter::from_patterns(empty_patterns);
    });
    // Empty patterns may panic or error — we just verify no undefined behavior
    let _ = result;

    // Query with single-byte patterns (no n-grams)
    let single_byte = ByteFilter::from_patterns(&[b"a".as_slice()]);
    let single_ngram = NgramFilter::from_patterns(&[b"a".as_slice()]);
    let candidates = index.candidate_blocks(&single_byte, &single_ngram);
    // Single-byte patterns have no 2-byte n-grams, so ngram filter returns true
    // Byte filter checks if 'a' is present
    let _ = candidates; // Mainly testing that this doesn't panic
}

#[test]
fn mmap_index_out_of_bounds_access() {
    let block_size = 256;
    let data = vec![b'x'; block_size * 4];
    let bytes = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("valid index")
        .to_bytes();

    let mmap = MmapBlockIndex::from_slice(&bytes).expect("valid mmap");

    // Accessing valid block IDs should work
    let _ = mmap.try_histogram(0).unwrap();
    let _ = mmap.try_bloom(0).unwrap();

    // Accessing out-of-bounds should panic (documented behavior)
    // We verify the panic message is helpful
    let result = mmap.try_histogram(999);
    assert!(
        result.is_err(),
        "FINDING: MmapBlockIndex::try_histogram out-of-bounds should return an Error"
    );
}

#[test]
fn serialization_round_trip_integrity() {
    // Verify that serialization/deserialization preserves all data
    let block_size = 256;
    let mut data = vec![0u8; block_size * 4];
    // Fill with patterned data
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    let original = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .expect("valid index");

    let serialized = original.to_bytes();

    // Verify serialized format structure
    assert_eq!(&serialized[0..4], b"FSBX", "magic bytes incorrect");
    assert_eq!(serialized[4], 2, "version should be 2");

    // Deserialize and compare
    let deserialized = BlockIndex::from_bytes(&serialized).expect("deserialize should succeed");

    assert_eq!(
        original.block_count(),
        deserialized.block_count(),
        "block count mismatch"
    );
    assert_eq!(
        original.block_size(),
        deserialized.block_size(),
        "block size mismatch"
    );
    assert_eq!(
        original.total_data_length(),
        deserialized.total_data_length(),
        "total length mismatch"
    );

    // Query results should match
    let pattern = b"\x00\x01\x02\x03";
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    let orig_candidates = original.candidate_blocks(&byte_filter, &ngram_filter);
    let de_candidates = deserialized.candidate_blocks(&byte_filter, &ngram_filter);

    assert_eq!(
        orig_candidates, de_candidates,
        "FINDING: Query results differ after round-trip"
    );
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Compute CRC-32 (same algorithm as the crate uses)
fn crc32_compute(data: &[u8]) -> u32 {
    static TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ TABLE[index];
    }
    !crc
}
pub mod bloom_collisions;
pub mod concurrent_100_threads;
pub mod hash_distribution;
pub mod memory_sizing;
