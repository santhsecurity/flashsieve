//! Fuzz target: deserialization
//!
//! This fuzzer feeds random bytes to `BlockIndex::from_bytes` and
//! `BlockIndex::from_bytes_checked` to ensure neither panics on
//! malformed input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic - the result itself doesn't matter
    let _ = flashsieve::BlockIndex::from_bytes(data);
    let _ = flashsieve::BlockIndex::from_bytes_checked(data);
});
