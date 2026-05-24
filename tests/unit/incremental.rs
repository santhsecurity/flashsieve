#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, IncrementalBuilder, NgramFilter};

#[test]
fn test_incremental_append_blocks() {
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&vec![0xAA; 1024])
        .unwrap();
    let serialized = index.to_bytes();

    let block2 = vec![0xBB; 1024];
    let block3 = vec![0xCC; 1024];

    let new_serialized =
        IncrementalBuilder::append_blocks(&serialized, &[&block2, &block3]).unwrap();

    let new_index = flashsieve::BlockIndex::from_bytes_checked(&new_serialized).unwrap();
    assert_eq!(new_index.block_count(), 3);
    assert_eq!(new_index.total_data_length(), 3072);
}

#[test]
fn test_incremental_append_empty_blocks_list() {
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&vec![0xAA; 1024])
        .unwrap();
    let serialized = index.to_bytes();

    let new_serialized = IncrementalBuilder::append_blocks(&serialized, &[]).unwrap();
    let new_index = flashsieve::BlockIndex::from_bytes_checked(&new_serialized).unwrap();
    assert_eq!(new_index.block_count(), 1);
}

/// Test that append_blocks_with_boundary correctly handles the cross-boundary n-gram.
///
/// Issue: Without the boundary byte, patterns spanning the boundary between
/// old and new data may be missed (false negatives).
#[test]
fn test_incremental_append_with_boundary_byte() {
    // Create initial data ending with "XY"
    let block_size = 256;
    let mut block1 = vec![b'a'; block_size];
    block1[block_size - 2] = b'X';
    block1[block_size - 1] = b'Y';

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(4096) // Use large enough bits for exact-pair table
        .build(&block1)
        .unwrap();
    let serialized = index.to_bytes();

    // Create new block starting with "Z"
    let mut block2 = vec![b'b'; block_size];
    block2[0] = b'Z';

    // The ngram "YZ" spans the boundary (Y from block1, Z from block2).
    // Pattern "YZ" is just this one ngram.
    let pattern = b"YZ";
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    // Without boundary byte - the YZ ngram won't be in block2's bloom filter
    let appended_without = IncrementalBuilder::append_blocks(&serialized, &[&block2]).unwrap();
    let index_without = flashsieve::BlockIndex::from_bytes_checked(&appended_without).unwrap();
    let _candidates_without = index_without.candidate_blocks_ngram(&ngram_filter);

    // With boundary byte - YZ should be inserted into block2's bloom filter
    let last_byte_of_old = block1.last().copied(); // b'Y'
    let appended_with =
        IncrementalBuilder::append_blocks_with_boundary(&serialized, last_byte_of_old, &[&block2])
            .unwrap();
    let index_with = flashsieve::BlockIndex::from_bytes_checked(&appended_with).unwrap();
    let candidates_with = index_with.candidate_blocks_ngram(&ngram_filter);

    // Both should have 2 blocks
    assert_eq!(index_without.block_count(), 2);
    assert_eq!(index_with.block_count(), 2);

    // The key assertion: with boundary byte, block 1 should be a candidate
    // because YZ (where Y is from block1's last byte) is inserted into block2's bloom
    let found_in_block1 = candidates_with.iter().any(|r| r.offset == block_size);
    assert!(
        found_in_block1,
        "Boundary ngram YZ should be found in block 1"
    );
}

/// Test that mmap indexes preserve the exact-pair table through serialization.
///
/// Issue 2: MmapBlockIndex was losing the exact-pairs table on deserialization,
/// causing false negatives for 2-byte patterns.
#[test]
fn test_mmap_preserves_exact_pairs() {
    use flashsieve::{ByteFilter, MmapBlockIndex};

    let block_size = 256;
    // Create data with a specific 2-byte pattern
    let mut data = vec![b'a'; block_size];
    data[100] = b'X';
    data[101] = b'Y';

    // Build with large bloom_bits to enable exact_pairs
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192) // >= 4096 threshold for exact_pairs
        .build(&data)
        .unwrap();

    // Serialize and create mmap view
    let serialized = index.to_bytes();
    let mmap_index = MmapBlockIndex::from_slice(&serialized).unwrap();

    // Verify exact-pair table is accessible
    let bloom_ref = mmap_index.try_bloom(0).unwrap();

    // The exact-pair table should be present (since bloom_bits >= 4096)
    // and should correctly identify the XY pair
    assert!(
        bloom_ref.maybe_contains_exact(b'X', b'Y'),
        "Exact-pair table should find XY pattern that was inserted"
    );

    // A pattern that was NOT inserted should be correctly rejected
    assert!(
        !bloom_ref.maybe_contains_exact(b'Z', b'W'),
        "Exact-pair table should reject ZW pattern that was not inserted"
    );

    // Verify that candidate_blocks works correctly with exact-pairs
    let pattern = b"XY";
    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    let mmap_candidates = mmap_index.candidate_blocks(&byte_filter, &ngram_filter);
    let heap_candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    // Both should find the pattern
    assert!(
        !mmap_candidates.is_empty(),
        "Mmap index with exact-pairs should find XY pattern"
    );
    assert_eq!(
        mmap_candidates, heap_candidates,
        "Mmap and heap indexes should produce identical results"
    );
}
