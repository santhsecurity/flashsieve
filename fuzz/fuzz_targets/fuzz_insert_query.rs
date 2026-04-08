//! Fuzz target: insert and query operations
//!
//! This fuzzer performs random sequences of insert and query operations
//! on bloom filters and verifies that:
//! 1. No panic occurs
//! 2. Inserted items are always found (no false negatives)

#![no_main]

use flashsieve::NgramBloom;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Clone, Copy)]
enum Operation {
    Insert(u8, u8),
    Query(u8, u8),
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Parse operations from fuzz input
    let bloom_size = 1024usize;
    let mut bloom = match NgramBloom::new(bloom_size) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Track inserted items to verify no false negatives
    let mut inserted = std::collections::HashSet::new();

    // Parse operations
    for chunk in data.chunks(3) {
        if chunk.len() < 3 {
            continue;
        }

        let op = chunk[0];
        let a = chunk[1];
        let b = chunk[2];

        match op % 2 {
            0 => {
                // Insert
                bloom.insert_ngram(a, b);
                inserted.insert((a, b));
            }
            1 => {
                // Query
                let result = bloom.maybe_contains(a, b);

                // Verify no false negatives for inserted items
                if inserted.contains(&(a, b)) {
                    assert!(
                        result,
                        "False negative for inserted n-gram ({}, {})",
                        a, b
                    );
                }
            }
            _ => unreachable!(),
        }
    }

    // Final verification: all inserted items must still be found
    for (a, b) in &inserted {
        assert!(
            bloom.maybe_contains(*a, *b),
            "False negative in final check for ({}, {})",
            a, b
        );
    }
});
