//! Fuzz target: NgramBloom from raw parts
//!
//! This fuzzer feeds arbitrary bytes to `NgramBloom::from_raw_parts`
//! to ensure it never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use flashsieve::NgramBloom;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let num_bits = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let mut words = Vec::new();
    for chunk in data[8..].chunks_exact(8) {
        words.push(u64::from_le_bytes(chunk.try_into().unwrap()));
    }

    // According to the task, this must never panic.
    // We now return Result so it's robust.
    if let Ok(bloom) = NgramBloom::from_raw_parts(num_bits, words) {
        // Exercise the bloom filter
        let _ = bloom.maybe_contains(b'a', b'b');
        let _ = bloom.maybe_contains_pattern(b"pattern");
        let _ = bloom.estimated_false_positive_rate();
    }
});
