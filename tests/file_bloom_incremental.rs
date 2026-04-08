#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! File-level bloom short-circuit and incremental serialized append.

use flashsieve::{
    BlockIndex, BlockIndexBuilder, ByteFilter, FileBloomIndex, IncrementalBuilder, NgramFilter,
};

const BLOCK_SIZE: usize = 256;
const BLOOM_BITS: usize = 1024;

fn patterned_block(fill: u8, marker: &[u8]) -> Vec<u8> {
    let mut block = vec![fill; BLOCK_SIZE];
    block[..marker.len()].copy_from_slice(marker);
    block
}

#[test]
fn file_bloom_ngram_matches_plain_index() {
    let data = vec![b'q'; BLOCK_SIZE * 3];
    let index = BlockIndexBuilder::new()
        .block_size(BLOCK_SIZE)
        .bloom_bits(BLOOM_BITS)
        .build(&data)
        .unwrap();
    let wrapped = FileBloomIndex::try_new(index.clone()).unwrap();

    for pattern in [b"qq".as_slice(), b"xyz".as_slice(), b"a".as_slice()] {
        let ngram = NgramFilter::from_patterns(&[pattern]);
        assert_eq!(
            wrapped.candidate_blocks_ngram(&ngram),
            index.candidate_blocks_ngram(&ngram),
            "pattern {pattern:?}"
        );
    }
}

#[test]
fn file_bloom_combined_matches_plain_index() {
    let mut data = vec![b'm'; BLOCK_SIZE * 2];
    data[BLOCK_SIZE + 10..BLOCK_SIZE + 16].copy_from_slice(b"needle");
    let index = BlockIndexBuilder::new()
        .block_size(BLOCK_SIZE)
        .bloom_bits(BLOOM_BITS)
        .build(&data)
        .unwrap();
    let wrapped = FileBloomIndex::try_new(index.clone()).unwrap();

    let byte = ByteFilter::from_patterns(&[b"needle".as_slice()]);
    let ngram = NgramFilter::from_patterns(&[b"needle".as_slice()]);
    assert_eq!(
        wrapped.candidate_blocks(&byte, &ngram),
        index.candidate_blocks(&byte, &ngram)
    );
}

#[test]
fn file_bloom_skips_all_blocks_when_union_has_no_ngrams() {
    // Only byte 'a' repeated — no "bc" bigram anywhere.
    let data = vec![b'a'; BLOCK_SIZE * 4];
    let index = BlockIndexBuilder::new()
        .block_size(BLOCK_SIZE)
        .bloom_bits(BLOOM_BITS)
        .build(&data)
        .unwrap();
    let wrapped = FileBloomIndex::try_new(index).unwrap();

    let ngram = NgramFilter::from_patterns(&[b"abc".as_slice()]);
    assert!(
        !ngram.matches_bloom(wrapped.file_bloom()),
        "file bloom should not contain absent bigrams"
    );
    assert!(
        wrapped.candidate_blocks_ngram(&ngram).is_empty(),
        "hierarchical bloom should return no n-gram candidates"
    );

    let byte = ByteFilter::from_patterns(&[b"abc".as_slice()]);
    assert!(
        wrapped.candidate_blocks(&byte, &ngram).is_empty(),
        "combined query should short-circuit on file bloom"
    );
}

#[test]
fn file_bloom_empty_index_errors() {
    let index = BlockIndex::new(BLOCK_SIZE, 0, Vec::new(), Vec::new());
    let err = FileBloomIndex::try_new(index).unwrap_err();
    assert!(matches!(err, flashsieve::Error::EmptyBlockIndex));
}

#[test]
fn incremental_append_matches_full_rebuild() {
    let blocks = vec![
        patterned_block(b'a', b"alpha"),
        patterned_block(b'b', b"bravo"),
    ];
    let extra = patterned_block(b'c', b"charlie");

    let base = BlockIndexBuilder::new()
        .block_size(BLOCK_SIZE)
        .bloom_bits(BLOOM_BITS)
        .build_streaming(blocks.iter().cloned())
        .unwrap();
    let serialized = base.to_bytes();

    let appended = IncrementalBuilder::append_blocks(&serialized, &[extra.as_slice()]).unwrap();

    let mut all = blocks;
    all.push(extra);
    let rebuilt = BlockIndexBuilder::new()
        .block_size(BLOCK_SIZE)
        .bloom_bits(BLOOM_BITS)
        .build_streaming(all.into_iter())
        .unwrap();

    assert_eq!(
        flashsieve::BlockIndex::from_bytes_checked(&appended)
            .unwrap()
            .block_count(),
        rebuilt.block_count()
    );

    let byte = ByteFilter::from_patterns(&[b"charlie".as_slice()]);
    let ngram = NgramFilter::from_patterns(&[b"charlie".as_slice()]);
    let left = BlockIndex::from_bytes_checked(&appended).unwrap();
    assert_eq!(
        left.candidate_blocks(&byte, &ngram),
        rebuilt.candidate_blocks(&byte, &ngram)
    );
}

#[test]
fn incremental_append_rejects_invalid_blob() {
    let err = IncrementalBuilder::append_blocks(b"FSBX", &[]).unwrap_err();
    assert!(matches!(err, flashsieve::Error::TruncatedHeader { .. }));
}
