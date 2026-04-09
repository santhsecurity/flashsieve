#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{
    BlockIndex, BlockIndexBuilder, ByteFilter, IncrementalBuilder, MmapBlockIndex, NgramFilter,
};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_end_to_end_workflow() {
    let mut file = NamedTempFile::new().unwrap();

    // 1. Create and write original index
    let data = vec![0xAB; 2048]; // 2 blocks of 1024
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&data)
        .unwrap();
    let serialized = index.to_bytes();
    file.write_all(&serialized).unwrap();

    // 2. Read back as MmapBlockIndex to query
    let mmap_idx = MmapBlockIndex::from_slice(&serialized).unwrap();
    assert_eq!(mmap_idx.block_count(), 2);

    let hist0 = mmap_idx.try_histogram(0).unwrap();
    assert_eq!(hist0.count(0xAB), 1024);

    // 3. Incrementally add a new block
    let new_data = vec![0xCD; 1024];
    let new_serialized =
        IncrementalBuilder::append_blocks_with_boundary(&serialized, Some(0xAB), &[&new_data])
            .unwrap();

    // 4. Overwrite file with new index
    let mut file2 = NamedTempFile::new().unwrap();
    file2.write_all(&new_serialized).unwrap();

    // 5. Query new index via standard BlockIndex
    let updated_index = BlockIndex::from_bytes_checked(&new_serialized).unwrap();
    assert_eq!(updated_index.block_count(), 3);

    let candidates = updated_index.candidate_blocks(
        &ByteFilter::from_patterns(&[b"\xCD"]),
        &NgramFilter::from_patterns(&[b"\xCD\xCD"]),
    );

    // The match MUST include the last block (block 2) — zero false negatives guarantee.
    // Bloom filters may also return false positives (other blocks), so we check >= 1.
    assert!(
        !candidates.is_empty(),
        "candidate_blocks must find the block containing the pattern"
    );
    assert!(
        candidates
            .iter()
            .any(|c| c.offset <= 2048 && c.offset + c.length > 2048),
        "block at offset 2048 must be covered by candidates. Got: {candidates:?}"
    );
}
