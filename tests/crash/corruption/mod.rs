#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! crash/corruption tests for flashsieve.
//!
//! Tests for index file corruption during crashes or bit flips.

use flashsieve::{BlockIndex, BlockIndexBuilder, ByteFilter, NgramFilter};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

fn generate_base_index() -> Vec<u8> {
    let mut data = vec![0u8; 1024 * 1024]; // 1MB to have many blocks and a large index
    let mut rng = StdRng::seed_from_u64(0x1234_5678);
    rng.fill_bytes(&mut data);

    // insert a known pattern to verify correct results
    data[1024 * 512..1024 * 512 + 10].copy_from_slice(b"MAGIC_PATT");

    let index = BlockIndexBuilder::new()
        .block_size(4096)
        .bloom_bits(1024)
        .build(&data)
        .expect("build failed");

    index.to_bytes()
}

fn verify_results(index: &BlockIndex) {
    // If it loaded, it MUST still give correct candidates for the known pattern.
    let byte_filter = ByteFilter::from_patterns(&[b"MAGIC_PATT".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"MAGIC_PATT".as_slice()]);
    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    // We inserted MAGIC_PATT at 512KB offset.
    // The candidate must include the block covering 512KB.
    let expected_offset = 1024 * 512;
    let found = candidates
        .iter()
        .any(|c| expected_offset >= c.offset && expected_offset < c.offset + c.length);
    assert!(
        found,
        "Index silently returned wrong results after corruption!"
    );
}

#[test]
fn test_corruption_flip_random_bits() {
    let base = generate_base_index();
    let mut rng = StdRng::seed_from_u64(0xFEED_BEEF);

    let mut caught = 0;
    let mut passed = 0;

    for _ in 0..1000 {
        let mut corrupted = base.clone();

        let flip_idx = rng.gen_range(4..corrupted.len()); // skip magic
        let bit_idx = rng.gen_range(0..8);
        corrupted[flip_idx] ^= 1 << bit_idx;

        match BlockIndex::from_bytes_checked(&corrupted) {
            Ok(idx) => {
                passed += 1;
                // As per prompt: Verify it produces correct results if it loaded
                verify_results(&idx);
            }
            Err(_) => caught += 1,
        }
    }

    assert!(caught > 900, "Failed to catch corruption! passed: {passed}");
}

#[test]
fn test_corruption_zero_random_pages() {
    let base = generate_base_index();
    let mut rng = StdRng::seed_from_u64(0xBEEF_CAFE);
    let mut passed = 0;
    let mut caught = 0;

    for _ in 0..100 {
        let mut corrupted = base.clone();

        // Zero out a 4KB chunk
        let start_idx = rng.gen_range(4..corrupted.len());
        for i in start_idx..start_idx + 4096 {
            if i < corrupted.len() {
                corrupted[i] = 0;
            }
        }

        match BlockIndex::from_bytes_checked(&corrupted) {
            Ok(idx) => {
                passed += 1;
                verify_results(&idx);
            }
            Err(_) => caught += 1,
        }
    }

    assert!(caught > 0 || passed > 0);
}

#[test]
fn test_corruption_truncate_at_1kb_boundaries() {
    let base = generate_base_index();

    for length in (0..base.len()).step_by(1024) {
        if length == base.len() || length == 0 {
            continue;
        }

        let truncated = &base[..length];
        assert!(
            BlockIndex::from_bytes_checked(truncated).is_err(),
            "Silently accepted truncated index at length {length}!"
        );
    }
}
