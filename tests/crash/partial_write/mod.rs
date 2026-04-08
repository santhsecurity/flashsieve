#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! `crash/partial_write` tests for flashsieve.
//!
//! Tests for truncated writes during serialization.

use flashsieve::{BlockIndex, BlockIndexBuilder};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

fn generate_base_index() -> Vec<u8> {
    let mut data = vec![0u8; 1024 * 64];
    let mut rng = StdRng::seed_from_u64(0x1111_2222);
    rng.fill_bytes(&mut data);

    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .bloom_bits(2048)
        .build(&data)
        .expect("build failed");

    index.to_bytes()
}

#[test]
fn test_partial_write_random_truncation() {
    let base = generate_base_index();
    let mut rng = StdRng::seed_from_u64(0xAAAA_BBBB);

    // Simulate crashing and writing only a prefix of the file.
    for _ in 0..100 {
        let truncate_len = rng.gen_range(1..base.len());
        let truncated = &base[..truncate_len];

        let result = BlockIndex::from_bytes_checked(truncated);

        // Truncated writes should ALWAYS error. They must never yield a valid
        // BlockIndex (e.g. they should fail CRC or be missing blocks).
        assert!(
            result.is_err(),
            "Partial write of length {truncate_len} was silently accepted as valid!"
        );
    }
}
