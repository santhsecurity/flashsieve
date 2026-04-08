#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! `crash/power_failure` tests for flashsieve.
//!
//! Simulates power failure scenarios where OS buffers flush out of order or stop partway.

use flashsieve::{BlockIndex, BlockIndexBuilder};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

fn generate_data() -> Vec<u8> {
    let mut data = vec![0u8; 1024 * 128];
    let mut rng = StdRng::seed_from_u64(0x9043_F411);
    rng.fill_bytes(&mut data);
    data
}

#[test]
fn test_power_failure_during_flush() {
    let data = generate_data();
    let index = BlockIndexBuilder::new()
        .block_size(4096)
        .bloom_bits(2048)
        .build(&data)
        .expect("build failed");

    let base = index.to_bytes();

    // Simulate a power failure where only the first N bytes were flushed to stable storage,
    // and the rest are either missing or garbage.
    let mut rng = StdRng::seed_from_u64(0xC4A5_1234);

    for _ in 0..50 {
        let flush_len = rng.gen_range(1..base.len());
        let mut on_disk = base[..flush_len].to_vec();

        // Sometimes the OS leaves garbage after the flushed bytes if the file was extended
        // but blocks weren't written.
        if rng.gen_bool(0.5) {
            let garbage_len = rng.gen_range(1..4096);
            let mut garbage = vec![0u8; garbage_len];
            rng.fill_bytes(&mut garbage);
            on_disk.extend(garbage);
        }

        let result = BlockIndex::from_bytes_checked(&on_disk);

        assert!(
            result.is_err(),
            "Power failure artifact silently accepted as valid!"
        );
    }
}
