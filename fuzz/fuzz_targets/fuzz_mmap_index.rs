//! Fuzz target: MmapBlockIndex
//!
//! This fuzzer feeds arbitrary bytes to `MmapBlockIndex::from_slice`
//! to ensure it never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use flashsieve::{MmapBlockIndex, ByteFilter, NgramFilter};

fuzz_target!(|data: &[u8]| {
    if let Ok(mmap) = MmapBlockIndex::from_slice(data) {
        let count = mmap.block_count();
        if count > 0 {
            let id = 0;
            let histogram = mmap.histogram(id);
            let bloom = mmap.bloom(id);

            // Exercise queries
            let byte_filter = ByteFilter::from_patterns(&[b"a".as_slice()]);
            let ngram_filter = NgramFilter::from_patterns(&[b"a".as_slice()]);
            let _ = mmap.candidate_blocks(&byte_filter, &ngram_filter);

            let _ = histogram.count(b'a');
            let _ = bloom.maybe_contains_exact(b'a', b'b');
            let _ = bloom.maybe_contains_bloom(b'a', b'b');
        }
    }
});
