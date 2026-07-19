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

/// Regression: after `remove_blocks` drops the trailing block, the cached
/// `last_byte` must not survive into the next `append_blocks`, or the new
/// block gets a bogus cross-boundary n-gram pairing its first byte with the
/// removed block's final byte.
///
/// Repro: index ends with block1's final byte 'X'; remove block1; append a
/// new block starting with 'Z'. With the stale-last_byte bug, ('X','Z') is
/// inserted into the appended block's exact-pair table even though 'X' is no
/// longer at any boundary. The exact-pair table is a full 65536-bit table
/// (no false positives for 2-byte pairs), so this assertion is deterministic.
#[test]
fn remove_then_append_does_not_insert_stale_boundary_ngram() {
    use flashsieve::MmapBlockIndex;

    let block_size = 256;
    // Two blocks: block0 = all 'a', block1 = all 'b' except a distinctive
    // final byte 'X'. bloom_bits >= 4096 enables the exact-pair table.
    let mut data = vec![b'a'; block_size * 2];
    for b in data[block_size..].iter_mut() {
        *b = b'b';
    }
    let last = data.len() - 1;
    data[last] = b'X';

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(4096)
        .build(&data)
        .unwrap();
    assert_eq!(index.block_count(), 2);

    // Drop the trailing block (block id 1). This makes the cached boundary
    // byte 'X' refer to removed data.
    let mut index = index;
    index.remove_blocks(&[1]).unwrap();
    assert_eq!(index.block_count(), 1);
    let serialized = index.to_bytes();

    // Append a new block starting with a distinctive byte 'Z'.
    let mut block2 = vec![b'c'; block_size];
    block2[0] = b'Z';
    let appended = IncrementalBuilder::append_blocks(&serialized, &[block2.as_slice()]).unwrap();

    let mmap = MmapBlockIndex::from_slice(&appended).unwrap();
    // Appended block is index 1 (block0 'a' survived at index 0).
    let bloom = mmap.try_bloom(1).unwrap();

    // The bug would have inserted ('X','Z') from the stale last_byte.
    assert!(
        !bloom.maybe_contains_exact(b'X', b'Z'),
        "stale boundary n-gram ('X','Z') must not be inserted after remove_blocks"
    );
    // Sanity: the block's own leading n-gram ('Z','c') is present, so we know
    // the block was actually indexed and the negative above is meaningful.
    assert!(
        bloom.maybe_contains_exact(b'Z', b'c'),
        "the appended block's own first n-gram ('Z','c') should be indexed"
    );
}
