#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! Internet-scale stress tests for flashsieve bloom filters.

use flashsieve::NgramBloom;

#[test]
fn bloom_handles_all_possible_2byte_pairs() {
    // 256 × 256 = 65536 possible 2-byte n-grams
    let mut bloom = NgramBloom::new(1_048_576).unwrap(); // 1M bits
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            bloom.insert_ngram((a & 0xFF) as u8, (b & 0xFF) as u8);
        }
    }
    // Every pair should be present (zero false negatives)
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            assert!(
                bloom.maybe_contains((a & 0xFF) as u8, (b & 0xFF) as u8),
                "false negative for ({a}, {b})"
            );
        }
    }
}

#[test]
fn bloom_from_1mb_block() {
    // Simulate scanning a 1MB source file
    let data: Vec<u8> = (0u32..1_048_576)
        .map(|i| ((i.wrapping_mul(2_654_435_761)) >> 24) as u8)
        .collect();
    let bloom = NgramBloom::from_block(&data, 65536).unwrap();
    // First n-gram of the data should be present
    assert!(bloom.maybe_contains(data[0], data[1]));
}

#[test]
fn bloom_rejects_impossible_pair() {
    // Build bloom from ASCII-only data, check non-ASCII pair
    let data = b"hello world this is all ascii text for testing bloom rejection";
    let bloom = NgramBloom::from_block(data, 4096).unwrap();
    // High-byte pairs like (0xFF, 0xFE) should not appear in ASCII data
    // (may be a false positive, but with 4096 bits it's unlikely)
    // This is a probabilistic test — we check 10 rare pairs
    let mut rejections = 0;
    for a in 240u8..=255 {
        for b in 240u8..=255 {
            if !bloom.maybe_contains(a, b) {
                rejections += 1;
            }
        }
    }
    // At least some high-byte pairs should be rejected
    assert!(rejections > 0, "bloom should reject some non-ASCII pairs");
}
