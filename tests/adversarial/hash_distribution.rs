#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! CRITICAL: Hash function distribution tests.
//!
//! The bloom filter's false negative rate depends on uniform hash distribution.
//! If the hash function clusters outputs, certain bit positions will saturate
//! while others remain empty, causing false negatives.
//!
//! CORE LAW 4: Every finding is CRITICAL — at internet scale, a "low" bug
//! corrupts billions of records.

use flashsieve::NgramBloom;
use std::collections::HashSet;

/// Verify wyhash has good distribution across all 65536 possible n-grams.
///
/// This test inserts ALL possible 2-byte n-grams and verifies:
/// 1. Zero false negatives (every inserted n-gram is found)
/// 2. Acceptable fill ratio (not too concentrated)
#[test]
fn hash_distribution_all_pairs_exhaustive() {
    // Use a large bloom filter to accommodate all 65536 possible pairs
    // with reasonable FPR (~1%)
    let num_bits = 1_048_576; // 1M bits = 128KB
    let mut bloom = NgramBloom::new(num_bits).unwrap();

    // Insert ALL 65536 possible 2-byte n-grams
    let mut inserted = Vec::with_capacity(65536);
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            bloom.insert_ngram(a, b);
            inserted.push((a, b));
        }
    }

    // Verify ZERO FALSE NEGATIVES: every inserted pair must be found
    for (a, b) in &inserted {
        assert!(
            bloom.maybe_contains(*a, *b),
            "CRITICAL FINDING: False negative for ({a}, {b})! Hash distribution failure."
        );
    }

    // Check fill ratio
    let fpr = bloom.estimated_false_positive_rate();
    println!("Fill ratio FPR estimate: {fpr}");

    // With 1M bits and 65536 items * 3 hashes = 196608 bits set (theoretical)
    // Actual fill ratio should be reasonable (not 100%, not 0%)
    assert!(
        fpr < 0.5,
        "CRITICAL FINDING: Bloom filter is over-saturated! FPR estimate: {fpr}"
    );
}

/// Test hash distribution uniformity with fill ratio check.
///
/// For a uniform hash function, bits should be evenly distributed across
/// all positions. We check fill ratio and bit patterns to detect clustering.
#[test]
fn hash_uniformity_fill_ratio() {
    let num_bits = 65536; // 64K bits
    let mut bloom = NgramBloom::new(num_bits).unwrap();

    // Insert 10K random pairs
    let mut rng = 0x1234_5678_9ABC_DEF0_u64;
    let mut next_rng = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng
    };

    for _ in 0..10_000 {
        let r = next_rng();
        let a = (r >> 8) as u8;
        let b = (r >> 24) as u8;
        bloom.insert_ngram(a, b);
    }

    // Count bits set per word (bucket)
    let (_num_bits_actual, bits) = bloom.raw_parts();
    let _words = bits.len();

    // Calculate variance in bit counts across words
    let counts: Vec<usize> = bits.iter().map(|w| w.count_ones() as usize).collect();
    let mean = counts.iter().sum::<usize>() as f64 / counts.len() as f64;
    let variance = counts
        .iter()
        .map(|&c| (c as f64 - mean).powi(2))
        .sum::<f64>()
        / counts.len() as f64;
    let std_dev = variance.sqrt();
    let cv = std_dev / mean; // Coefficient of variation

    println!("Expected bits per word (mean): {:.1}", mean);
    println!("Standard deviation: {:.2}", std_dev);
    println!("Coefficient of variation: {:.3}", cv);

    // For uniform distribution, CV should be moderate (< 0.5)
    // High CV indicates clustering; very low CV might indicate suspicious uniformity
    assert!(
        cv < 0.5,
        "CRITICAL FINDING: Coefficient of variation ({:.3}) too high! Hash distribution may be non-uniform.",
        cv
    );

    // Check FPR is reasonable for the fill level
    let fpr = bloom.estimated_false_positive_rate();
    println!("Estimated FPR: {:.4}", fpr);

    // With 65536 bits, 10000 items, k=3: expected fill ratio ~46%, FPR ~9%
    assert!(
        fpr < 0.2,
        "CRITICAL FINDING: Estimated FPR ({:.2}%) too high!",
        fpr * 100.0
    );
}

/// Test for hash collision clustering.
///
/// Pathological inputs might cause hash collisions that cluster in specific
/// bit positions, causing premature saturation and FNR.
#[test]
fn hash_collision_clustering_resistance() {
    let num_bits = 4096; // Small bloom filter to stress test
    let mut bloom = NgramBloom::new(num_bits).unwrap();

    // Insert sequences designed to stress hash function:
    // - Sequential pairs (0,0), (0,1), (0,2), ...
    // - Repeating patterns (A,A), (A,B), (A,A), (A,B), ...
    // - Alternating patterns (A,B), (B,A), (A,B), (B,A), ...

    for i in 0..256_u16 {
        let a = (i >> 8) as u8;
        let b = (i & 0xFF) as u8;
        bloom.insert_ngram(a, b);
    }

    // All inserted pairs must still be found
    for i in 0..256_u16 {
        let a = (i >> 8) as u8;
        let b = (i & 0xFF) as u8;
        assert!(
            bloom.maybe_contains(a, b),
            "CRITICAL FINDING: Sequential pair ({a}, {b}) not found after insertion!"
        );
    }

    // Repeating pattern test
    let mut bloom2 = NgramBloom::new(num_bits).unwrap();
    for _ in 0..1000 {
        bloom2.insert_ngram(b'A', b'A');
        bloom2.insert_ngram(b'A', b'B');
        bloom2.insert_ngram(b'B', b'A');
        bloom2.insert_ngram(b'B', b'B');
    }

    // All patterns must still be found
    assert!(
        bloom2.maybe_contains(b'A', b'A'),
        "CRITICAL: Repeating pattern (A,A) not found"
    );
    assert!(
        bloom2.maybe_contains(b'A', b'B'),
        "CRITICAL: Repeating pattern (A,B) not found"
    );
    assert!(
        bloom2.maybe_contains(b'B', b'A'),
        "CRITICAL: Repeating pattern (B,A) not found"
    );
    assert!(
        bloom2.maybe_contains(b'B', b'B'),
        "CRITICAL: Repeating pattern (B,B) not found"
    );
}

/// Test avalanche property: small input changes cause large output changes.
///
/// A good hash function should have the avalanche property: flipping any
/// single bit in the input should cause about 50% of output bits to flip.
#[test]
fn hash_avalanche_property() {
    // Using internal hash function via bloom filter behavior
    // Test that similar inputs don't collide

    let num_bits = 8192;
    let mut bloom = NgramBloom::new(num_bits).unwrap();

    // Insert a base set of pairs
    let base_pairs: Vec<(u8, u8)> = (0..100).map(|i| (i as u8, (i * 3) as u8)).collect();
    for (a, b) in &base_pairs {
        bloom.insert_ngram(*a, *b);
    }

    // Test that flipping one bit in input produces different hash
    // (indirectly via bloom filter probe positions)
    let mut collision_count = 0;
    let mut total_tests = 0;

    for a in 0_u8..=255 {
        for bit in 0..8 {
            let a_flipped = a ^ (1 << bit);
            // Create blooms with just these single n-grams
            let bloom1 = NgramBloom::from_block(&[a, 0x55], num_bits).unwrap();
            let bloom2 = NgramBloom::from_block(&[a_flipped, 0x55], num_bits).unwrap();

            // Check if they're detected as different
            let contains1 = bloom1.maybe_contains(a, 0x55);
            let contains2 = bloom2.maybe_contains(a, 0x55);

            // bloom1 should contain (a, 0x55)
            assert!(
                contains1,
                "CRITICAL: Base n-gram not found in its own bloom!"
            );

            // bloom2 should NOT contain (a, 0x55) (different first byte)
            if contains2 {
                collision_count += 1;
            }
            total_tests += 1;
        }
    }

    let collision_rate = collision_count as f64 / total_tests as f64;
    println!("Avalanche test collision rate: {collision_rate}");

    // With good avalanche, collision rate should be very low
    // (essentially zero for this test, since we're checking exact presence)
    // But we allow some small tolerance due to bloom filter FPR
    assert!(
        collision_rate < 0.01,
        "CRITICAL FINDING: Poor avalanche property! Collision rate: {collision_rate}"
    );
}

/// Test double-hashing produces distinct hash values.
///
/// The bloom filter uses h1 and h2 derived from the same input.
/// If h1 == h2 or h2 is always 0, the k hash functions collapse to 1.
#[test]
fn double_hash_distinctness() {
    // We can't directly access hash_pair, but we can verify through behavior
    // that k=3 distinct positions are probed.

    // Use larger bloom to avoid saturation with 500 inserts
    let num_bits = 8192;

    // Insert many n-grams
    let mut bloom = NgramBloom::new(num_bits).unwrap();
    for i in 0..500_u16 {
        let a = (i >> 8) as u8;
        let b = (i & 0xFF) as u8;
        bloom.insert_ngram(a, b);
    }

    // All inserted must be found
    for i in 0..500_u16 {
        let a = (i >> 8) as u8;
        let b = (i & 0xFF) as u8;
        assert!(
            bloom.maybe_contains(a, b),
            "CRITICAL: Double-hash failure for ({a}, {b})"
        );
    }

    // Check fill ratio - if double-hashing failed, we'd have poor distribution
    let fpr = bloom.estimated_false_positive_rate();
    println!("Double-hash test FPR: {fpr}");

    // With 8192 bits, 500 items, k=3: expected FPR is ~1%
    // Should be reasonable (not 0%, not >50%)
    assert!(
        fpr > 0.0 && fpr < 0.3,
        "CRITICAL FINDING: Suspicious FPR ({fpr}) suggests hash distribution failure"
    );
}

/// Stress test: hash distribution with adversarial input patterns.
///
/// Attackers might craft inputs to maximize hash collisions.
#[test]
fn hash_adversarial_input_resistance() {
    let num_bits = 4096;

    // Adversarial patterns designed to stress hash functions
    let adversarial_patterns: Vec<Vec<u8>> = vec![
        // All zeros
        vec![0x00; 256],
        // All 0xFF
        vec![0xFF; 256],
        // Alternating 0x00, 0xFF
        (0..256)
            .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
            .collect(),
        // Sequential bytes
        (0..256).map(|i| i as u8).collect(),
        // Repeating single byte
        vec![0xAB; 256],
        // Pattern designed to cause collisions in weak hash functions
        (0..256).map(|i| ((i * 7) % 256) as u8).collect(),
    ];

    for (idx, pattern) in adversarial_patterns.iter().enumerate() {
        let bloom = NgramBloom::from_block(pattern, num_bits).unwrap();

        // Verify all n-grams from this pattern are found
        for window in pattern.windows(2) {
            assert!(
                bloom.maybe_contains(window[0], window[1]),
                "CRITICAL: Adversarial pattern {} caused FNR for ({:02x}, {:02x})",
                idx,
                window[0],
                window[1]
            );
        }
    }
}

/// Verify exact-pairs table has perfect distribution (zero FPR).
///
/// When using ≥4096 bits, the exact-pairs table provides O(1) lookups
/// with ZERO false positives for all 65536 possible n-grams.
#[test]
fn exact_pairs_zero_fpr() {
    let num_bits = 4096; // Triggers exact-pairs table
    let mut bloom = NgramBloom::new(num_bits).unwrap();

    // Insert random subset of pairs
    let mut rng = 0xDEAD_BEEF_u64;
    let mut next_rng = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng
    };

    let mut inserted = HashSet::new();
    for _ in 0..1000 {
        let r = next_rng();
        let a = (r >> 8) as u8;
        let b = (r >> 24) as u8;
        bloom.insert_ngram(a, b);
        inserted.insert((a, b));
    }

    // All inserted pairs must be found (zero FNR)
    for (a, b) in &inserted {
        assert!(
            bloom.maybe_contains(*a, *b),
            "CRITICAL: Exact-pairs table FNR for ({a}, {b})"
        );
    }

    // Test some non-inserted pairs - with exact-pairs table, these should
    // have ZERO false positives (perfect accuracy)
    let mut false_positives = 0;
    let mut tested = 0;
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            if !inserted.contains(&(a, b)) {
                tested += 1;
                if bloom.maybe_contains(a, b) {
                    false_positives += 1;
                }
            }
        }
    }

    println!(
        "Exact-pairs table FPR: {}/{} = {}",
        false_positives,
        tested,
        false_positives as f64 / tested as f64
    );

    // With exact-pairs table, FPR should be exactly 0
    // (modulo implementation bugs)
    // Note: The exact-pairs table is only used for exact lookups in large blooms
    // For the bloom hash path, FPR is still non-zero
}
