//! Adversarial tests for extreme FPR values — Jules missed these.
//!
//! These tests verify that NgramBloom::with_target_fpr handles extreme
//! false positive rate values without panicking or producing invalid results.

#![allow(
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::unwrap_used
)]

use flashsieve::NgramBloom;

/// Tests that extremely low FPR values are handled gracefully (clamped).
#[test]
fn fpr_extremely_low_value() {
    // FPR of 1e-100 is impossibly low — should clamp to minimum, not error
    let result = NgramBloom::with_target_fpr(1e-100, 1000);
    assert!(
        result.is_ok(),
        "Extremely low FPR (1e-100) should clamp gracefully, not error. Got: {:?}",
        result
    );

    let bloom = result.unwrap();
    let (num_bits, words) = bloom.raw_parts();

    // Should produce a valid bloom filter
    assert!(
        num_bits >= 64,
        "Extreme low FPR should still produce at least 64 bits, got {}",
        num_bits
    );
    assert!(
        !words.is_empty(),
        "Extreme low FPR should produce non-empty bit vector"
    );
}

/// Tests that extremely high FPR values are handled gracefully (clamped).
#[test]
fn fpr_extremely_high_value() {
    // FPR of 1.0 - 1e-15 is essentially 100% — should clamp to maximum
    let result = NgramBloom::with_target_fpr(1.0 - 1e-15, 1000);
    assert!(
        result.is_ok(),
        "Extremely high FPR (1.0 - 1e-15) should clamp gracefully, not error. Got: {:?}",
        result
    );

    let bloom = result.unwrap();
    let (num_bits, _) = bloom.raw_parts();

    // Should produce a valid (though minimal) bloom filter
    assert!(
        num_bits >= 64,
        "Extreme high FPR should still produce at least 64 bits, got {}",
        num_bits
    );
}

/// Tests FPR = 0.0 edge case.
#[test]
fn fpr_zero() {
    let result = NgramBloom::with_target_fpr(0.0, 1000);
    assert!(
        result.is_ok(),
        "FPR = 0.0 should be handled gracefully. Got: {:?}",
        result
    );

    // Zero FPR implies infinite bits needed — should clamp to reasonable max
    let bloom = result.unwrap();
    let (num_bits, _) = bloom.raw_parts();
    assert!(
        num_bits >= 64,
        "FPR=0 should produce at least 64 bits, got {}",
        num_bits
    );
}

/// Tests FPR = 1.0 edge case.
#[test]
fn fpr_one() {
    let result = NgramBloom::with_target_fpr(1.0, 1000);
    assert!(
        result.is_ok(),
        "FPR = 1.0 should be handled gracefully. Got: {:?}",
        result
    );

    // FPR = 1.0 implies zero bits needed — should produce minimum
    let bloom = result.unwrap();
    let (num_bits, _) = bloom.raw_parts();
    assert!(
        num_bits >= 64,
        "FPR=1.0 should produce at least minimum 64 bits, got {}",
        num_bits
    );
}

/// Tests FPR = 0.5 (50% false positive rate).
#[test]
fn fpr_fifty_percent() {
    let result = NgramBloom::with_target_fpr(0.5, 1000);
    assert!(result.is_ok(), "FPR = 0.5 should succeed");

    let bloom = result.unwrap();
    let (num_bits, _) = bloom.raw_parts();

    // 50% FPR should need fewer bits
    assert!(
        num_bits >= 64 && num_bits < 100_000,
        "FPR=0.5 should produce reasonable bit count, got {}",
        num_bits
    );
}

/// Tests negative FPR (should be handled gracefully).
#[test]
fn fpr_negative() {
    // Negative FPR is mathematically impossible — should clamp or error gracefully
    let result = NgramBloom::with_target_fpr(-0.01, 1000);
    // Could either succeed (clamped to 0) or error — both are acceptable
    // The important thing is it doesn't panic
    let _ = result;
}

/// Tests FPR > 1.0 (should be handled gracefully).
#[test]
fn fpr_greater_than_one() {
    // FPR > 1.0 is mathematically impossible — should clamp or error gracefully
    let result = NgramBloom::with_target_fpr(1.5, 1000);
    // Could either succeed (clamped to 1) or error — both are acceptable
    // The important thing is it doesn't panic
    let _ = result;
}

/// Tests that with_target_fpr produces consistent results across calls.
#[test]
fn fpr_consistency() {
    let fpr = 0.01;
    let expected_items = 1000;

    let bloom1 = NgramBloom::with_target_fpr(fpr, expected_items).unwrap();
    let bloom2 = NgramBloom::with_target_fpr(fpr, expected_items).unwrap();

    let (bits1, _) = bloom1.raw_parts();
    let (bits2, _) = bloom2.raw_parts();

    assert_eq!(
        bits1, bits2,
        "Same FPR and expected_items should produce same bit count"
    );
}

/// Tests with_target_fpr with various expected item counts.
#[test]
fn fpr_various_expected_items() {
    for &expected_items in &[1, 10, 100, 1000, 10000, 100000] {
        let result = NgramBloom::with_target_fpr(0.01, expected_items);
        assert!(
            result.is_ok(),
            "with_target_fpr(0.01, {}) should succeed",
            expected_items
        );

        let bloom = result.unwrap();
        let (num_bits, words) = bloom.raw_parts();

        // Verify bit count is reasonable
        assert!(
            num_bits >= 64,
            "Expected {} items should produce at least 64 bits",
            expected_items
        );

        // Verify words cover all bits
        let required_words = num_bits.div_ceil(64);
        assert!(
            words.len() >= required_words,
            "Expected {} items: {} bits requires {} words, got {}",
            expected_items,
            num_bits,
            required_words,
            words.len()
        );
    }
}

/// Tests that the produced bloom filter achieves the target FPR approximately.
#[test]
#[allow(clippy::cast_precision_loss)]
fn fpr_achieves_target() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::HashSet;

    let target_fpr = 0.05; // 5% target
    let expected_items = 500;
    let num_tests = 5000;

    let mut bloom = NgramBloom::with_target_fpr(target_fpr, expected_items).unwrap();
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    let mut inserted = HashSet::new();

    // Insert expected_items random n-grams
    for _ in 0..expected_items {
        let a = rng.gen();
        let b = rng.gen();
        bloom.insert_ngram(a, b);
        inserted.insert((a, b));
    }

    // Test num_tests random n-grams that were NOT inserted
    let mut false_positives = 0;
    let mut tested = 0;
    for _ in 0..num_tests {
        let a = rng.gen::<u8>();
        let b = rng.gen::<u8>();
        if !inserted.contains(&(a, b)) {
            tested += 1;
            if bloom.maybe_contains(a, b) {
                false_positives += 1;
            }
        }
    }

    let measured_fpr = false_positives as f64 / tested as f64;

    // Allow 2x margin above target (measuring with limited samples)
    assert!(
        measured_fpr < target_fpr * 2.0,
        "Measured FPR {} exceeds target {} with 2x margin (tested {} items)",
        measured_fpr,
        target_fpr,
        tested
    );
}

/// Tests FPR with extremely large expected item count.
#[test]
fn fpr_extremely_large_expected_items() {
    // 1 billion items — should not overflow
    let result = NgramBloom::with_target_fpr(0.01, 1_000_000_000);

    // This might succeed (with large allocation) or error gracefully
    // The important thing is it doesn't panic
    match result {
        Ok(bloom) => {
            let (num_bits, _) = bloom.raw_parts();
            assert!(
                num_bits >= 64,
                "Large item count should produce at least 64 bits"
            );
        }
        Err(_) => {
            // Error is acceptable for extremely large item counts
        }
    }
}

/// Tests FPR with zero expected items.
#[test]
fn fpr_zero_expected_items() {
    let result = NgramBloom::with_target_fpr(0.01, 0);
    assert!(
        result.is_ok(),
        "with_target_fpr with 0 expected items should succeed"
    );

    let bloom = result.unwrap();
    let (num_bits, _) = bloom.raw_parts();
    assert!(
        num_bits >= 64,
        "Zero expected items should still produce minimum bit count"
    );
}
