//! Fuzz target: BlockIndexBuilder
//!
//! This fuzzer feeds arbitrary block data to `BlockIndexBuilder`
//! with randomized block size and bloom bits to ensure it never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use flashsieve::BlockIndexBuilder;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let block_size = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let bloom_bits = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
    let payload = &data[16..];

    let builder = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(bloom_bits);

    let _ = builder.build(payload);
    let _ = builder.build_streaming(payload.chunks(block_size.max(1)).map(<[u8]>::to_vec));
});
