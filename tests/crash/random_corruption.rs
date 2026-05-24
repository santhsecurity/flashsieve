use flashsieve::{BlockIndex, BlockIndexBuilder};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[test]
fn test_random_corruption_recovery() {
    let block_size = 256;
    let bloom_bits = 512;
    let data = vec![b'x'; block_size * 10]; // 10 blocks

    let original = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(bloom_bits)
        .build(&data)
        .unwrap();

    let valid_bytes = original.to_bytes();

    // Test random single byte corruptions
    let mut rng = StdRng::seed_from_u64(0x1234567890ABCDEF);

    // We'll run a few hundred random corruptions
    for _ in 0..1000 {
        let mut corrupted = valid_bytes.clone();
        let idx = rng.gen_range(0..corrupted.len());
        corrupted[idx] = corrupted[idx].wrapping_add(rng.gen_range(1..255));

        // This must either return an error cleanly (e.g. CRC mismatch, invalid magic, etc.)
        // or return a valid BlockIndex if the corruption didn't affect anything structurally critical and somehow passed checks (unlikely with CRC).
        // The key is that IT MUST NOT PANIC.

        let result = std::panic::catch_unwind(|| BlockIndex::from_bytes_checked(&corrupted));

        assert!(
            result.is_ok(),
            "FINDING: BlockIndex::from_bytes_checked panicked on corrupted bytes at index {}",
            idx
        );
        let inner_result = result.unwrap();
        // The CRC must fail or it must fail parsing; if by a 1-in-4-billion chance the CRC matches, it could succeed, but it's extremely unlikely.
        assert!(inner_result.is_err(), "FINDING: Corruption was not detected! BlockIndex::from_bytes_checked returned Ok despite random corruption.");

        // Let's also check `from_bytes` (which skips CRC but might still fail structurally)
        let result_unchecked = std::panic::catch_unwind(|| BlockIndex::from_bytes(&corrupted));

        assert!(
            result_unchecked.is_ok(),
            "FINDING: BlockIndex::from_bytes panicked on corrupted bytes at index {}",
            idx
        );
        // We don't assert that unchecked fails because it might just silently accept the corrupt data without CRC.
    }
}
