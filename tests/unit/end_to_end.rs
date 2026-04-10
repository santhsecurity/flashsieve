#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! End-to-end integration tests for `flashsieve`.

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[test]
fn end_to_end_filtering() {
    let block_size = 4096;
    let total_size = 1024 * 1024;
    let mut data = vec![0_u8; total_size];
    let mut rng = StdRng::seed_from_u64(0xF1A5_510E);
    rng.fill_bytes(&mut data);

    let patterns: [&[u8]; 3] = [b"alpha-secret", b"beta-token", b"gamma-key"];
    let offsets = [12_345_usize, 456_789, 900_000];
    for (pattern, offset) in patterns.iter().zip(offsets) {
        data[offset..offset + pattern.len()].copy_from_slice(pattern);
    }

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(4096)
        .build(&data)
        .unwrap_or_else(|error| panic!("{error}"));

    let byte_filter = ByteFilter::from_patterns(&patterns);
    let ngram_filter = NgramFilter::from_patterns(&patterns);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    for offset in offsets {
        assert!(
            candidates.iter().any(|range| range.offset <= offset && offset < range.offset + range.length),
            "pattern at offset {offset} not found in candidates {candidates:?}"
        );
    }

    assert!(index.selectivity(&candidates) < 0.5);
}
