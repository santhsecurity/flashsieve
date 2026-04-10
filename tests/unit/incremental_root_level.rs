#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndex, BlockIndexBuilder, ByteFilter, NgramFilter};

const BLOCK_SIZE: usize = 256;
const BLOOM_BITS: usize = 1024;

fn patterned_block(fill: u8, marker: &[u8]) -> Vec<u8> {
    let mut block = vec![fill; BLOCK_SIZE];
    block[..marker.len()].copy_from_slice(marker);
    block
}

fn build_index(blocks: &[Vec<u8>]) -> flashsieve::Result<BlockIndex> {
    BlockIndexBuilder::new()
        .block_size(BLOCK_SIZE)
        .bloom_bits(BLOOM_BITS)
        .build_streaming(blocks.iter().cloned())
}

#[test]
fn append_block_matches_full_rebuild() {
    let blocks = vec![
        patterned_block(b'a', b"alpha"),
        patterned_block(b'b', b"bravo"),
    ];
    let extra_block = patterned_block(b'c', b"charlie");

    let mut incremental = build_index(&blocks).unwrap();
    incremental.append_block(&extra_block).unwrap();

    let mut expected_blocks = blocks;
    expected_blocks.push(extra_block);
    let rebuilt = build_index(&expected_blocks).unwrap();

    let byte_filter = ByteFilter::from_patterns(&[b"charlie".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"charlie".as_slice()]);
    assert_eq!(
        incremental.candidate_blocks(&byte_filter, &ngram_filter),
        rebuilt.candidate_blocks(&byte_filter, &ngram_filter)
    );
}

#[test]
fn merge_matches_full_rebuild() {
    let left_blocks = vec![
        patterned_block(b'l', b"left-0"),
        patterned_block(b'm', b"left-1"),
    ];
    let right_blocks = vec![
        patterned_block(b'r', b"right-0"),
        patterned_block(b's', b"right-1"),
    ];

    let mut merged = build_index(&left_blocks).unwrap();
    let right = build_index(&right_blocks).unwrap();
    merged.merge(&right).unwrap();

    let mut all_blocks = left_blocks;
    all_blocks.extend(right_blocks);
    let rebuilt = build_index(&all_blocks).unwrap();

    assert_eq!(merged.block_count(), rebuilt.block_count());

    let byte_filter = ByteFilter::from_patterns(&[b"right-1".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"right-1".as_slice()]);
    assert_eq!(
        merged.candidate_blocks(&byte_filter, &ngram_filter),
        rebuilt.candidate_blocks(&byte_filter, &ngram_filter)
    );
}

#[test]
fn remove_blocks_requeries_on_compacted_offsets() {
    let blocks = vec![
        patterned_block(b'a', b"keep-0"),
        patterned_block(b'b', b"keep-1"),
        patterned_block(b'c', b"drop-2"),
        patterned_block(b'd', b"drop-3"),
    ];

    let mut index = build_index(&blocks).unwrap();
    // remove_blocks only supports suffix removal (trailing blocks)
    index.remove_blocks(&[2, 3]).unwrap();

    assert_eq!(index.block_count(), 2);
    assert_eq!(index.total_data_length(), BLOCK_SIZE * 2);

    let keep_filter = ByteFilter::from_patterns(&[b"keep-1".as_slice()]);
    let keep_candidates = index.candidate_blocks_byte(&keep_filter);
    assert_eq!(keep_candidates.len(), 1);
    assert_eq!(keep_candidates[0].offset, BLOCK_SIZE);
    assert_eq!(keep_candidates[0].length, BLOCK_SIZE);

    let dropped_filter = ByteFilter::from_patterns(&[b"drop-2".as_slice()]);
    assert!(index.candidate_blocks_byte(&dropped_filter).is_empty());
}

#[test]
fn serialization_roundtrip_after_incremental_updates() {
    let base_blocks = vec![
        patterned_block(b'a', b"base-0"),
        patterned_block(b'b', b"base-1"),
    ];

    let mut appended = build_index(&base_blocks).unwrap();
    appended
        .append_block(&patterned_block(b'c', b"append"))
        .unwrap();

    let appended_roundtrip = BlockIndex::from_bytes_checked(&appended.to_bytes()).unwrap();
    assert_eq!(appended_roundtrip.to_bytes(), appended.to_bytes());

    let mut merged = build_index(&base_blocks).unwrap();
    let other = build_index(&[patterned_block(b'd', b"merge")]).unwrap();
    merged.merge(&other).unwrap();

    let merged_roundtrip = BlockIndex::from_bytes_checked(&merged.to_bytes()).unwrap();
    assert_eq!(merged_roundtrip.to_bytes(), merged.to_bytes());

    let mut removed = build_index(&[
        patterned_block(b'e', b"keep-0"),
        patterned_block(b'f', b"keep-1"),
        patterned_block(b'g', b"remove-2"),
    ])
    .unwrap();
    // remove_blocks only supports suffix removal (trailing blocks)
    removed.remove_blocks(&[2]).unwrap();

    let removed_roundtrip = BlockIndex::from_bytes_checked(&removed.to_bytes()).unwrap();
    assert_eq!(removed_roundtrip.to_bytes(), removed.to_bytes());
}
