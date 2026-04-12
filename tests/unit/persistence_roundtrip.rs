#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::explicit_iter_loop,
    clippy::uninlined_format_args,
    clippy::unreadable_literal
)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use flashsieve::{
    transport, BlockIndex, BlockIndexBuilder, ByteFilter, MmapBlockIndex, NgramFilter,
};

/// Standard serialization round-trip must preserve all query behaviour.
#[test]
fn block_index_round_trip_preserves_queries() {
    let block_size = 256;
    let mut data = vec![b'x'; block_size * 4];
    data[block_size..block_size + 6].copy_from_slice(b"secret");
    data[block_size * 3..block_size * 3 + 5].copy_from_slice(b"token");

    let original = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let bytes = original.to_bytes();
    let recovered = BlockIndex::from_bytes_checked(&bytes).unwrap();

    assert_eq!(original.block_size(), recovered.block_size());
    assert_eq!(original.block_count(), recovered.block_count());
    assert_eq!(original.total_data_length(), recovered.total_data_length());

    for pattern in [
        b"secret".as_slice(),
        b"token".as_slice(),
        b"missing".as_slice(),
    ] {
        let bf = ByteFilter::from_patterns(&[pattern]);
        let nf = NgramFilter::from_patterns(&[pattern]);
        assert_eq!(
            original.candidate_blocks(&bf, &nf),
            recovered.candidate_blocks(&bf, &nf),
            "query mismatch for pattern {pattern:?}"
        );
    }
}

/// Exact-pair tables must survive serialization and remain functional.
#[test]
fn exact_pair_table_survives_round_trip() {
    let original = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(4096) // triggers exact-pair allocation
        .build(b"hello world")
        .unwrap();

    let bytes = original.to_bytes();
    let recovered = BlockIndex::from_bytes_checked(&bytes).unwrap();

    let nf = NgramFilter::from_patterns(&[b"hello".as_slice()]);
    assert_eq!(
        original.candidate_blocks_ngram(&nf),
        recovered.candidate_blocks_ngram(&nf)
    );

    // With exact pairs, a non-existent n-gram should produce zero candidates
    let nf_miss = NgramFilter::from_patterns(&[b"xyz".as_slice()]);
    assert!(recovered.candidate_blocks_ngram(&nf_miss).is_empty());
}

/// MmapBlockIndex must agree with heap-deserialized BlockIndex after round-trip.
#[test]
fn mmap_index_matches_heap_after_round_trip() {
    let bytes = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"secret token zebra")
        .unwrap()
        .to_bytes();

    let heap = BlockIndex::from_bytes_checked(&bytes).unwrap();
    let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();

    let bf = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    let nf = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    assert_eq!(
        heap.candidate_blocks(&bf, &nf),
        mmap.candidate_blocks(&bf, &nf)
    );
}

/// Transport format round-trip with RLE compression.
#[test]
fn transport_round_trip_rle() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"compression test data")
        .unwrap();

    let transport = transport::to_transport_bytes(&index);
    let recovered = transport::from_transport_bytes(&transport).unwrap();
    assert_eq!(index.to_bytes(), recovered.to_bytes());
}

/// Transport format round-trip with no compression.
#[test]
fn transport_round_trip_none() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(512)
        .build(b"no compression")
        .unwrap();

    let transport = transport::to_transport_bytes_with(&index, transport::Compression::None);
    let recovered = transport::from_transport_bytes(&transport).unwrap();
    assert_eq!(index.to_bytes(), recovered.to_bytes());
}

/// Corrupted CRC should fail deserialization.
#[test]
fn corruption_detected_by_crc() {
    let mut bytes = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"data")
        .unwrap()
        .to_bytes();

    // Flip a bit in the middle of the payload
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;

    let result = BlockIndex::from_bytes_checked(&bytes);
    assert!(
        matches!(result, Err(flashsieve::Error::ChecksumMismatch { .. })),
        "expected CRC mismatch, got {:?}",
        result
    );
}

/// Truncated serialized data should fail gracefully.
#[test]
fn truncated_data_fails_gracefully() {
    let bytes = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"truncation test")
        .unwrap()
        .to_bytes();

    for cut in [1, 10, bytes.len() / 2, bytes.len() - 1] {
        let result = BlockIndex::from_bytes_checked(&bytes[..cut]);
        assert!(result.is_err(), "truncation at {} should fail", cut);
    }
}

/// from_bytes (Option API) must return None on bad magic without panicking.
#[test]
fn from_bytes_option_api_on_bad_input() {
    let bad = b"NOT_AN_INDEX".to_vec();
    assert!(BlockIndex::from_bytes(&bad).is_none());
}
