#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::unwrap_used
)]
//! Gap tests for flashsieve — empirical FPR measurement and invariant proofs.
//!
//! These tests measure the ACTUAL false positive rate of the bloom filter
//! under realistic conditions. If the FPR exceeds bounds, the bloom parameters
//! need tuning.

use flashsieve::{NgramBloom, NgramFilter};

/// Measure empirical FPR for a given data size and pattern count.
fn measure_fpr(data_size: usize, num_test_patterns: usize, seed: u64) -> f64 {
    // Generate deterministic "file content"
    let data: Vec<u8> = (0..data_size)
        .map(|i| ((i as u64).wrapping_mul(seed).wrapping_add(7)) as u8)
        .collect();

    let bloom = NgramBloom::from_block(&data, 65536).unwrap();

    // Collect actual n-grams in the data
    let mut actual_ngrams = std::collections::HashSet::new();
    for window in data.windows(2) {
        actual_ngrams.insert((window[0], window[1]));
    }

    // Test random n-grams NOT in the data
    let mut false_positives = 0u64;
    let mut trials = 0u64;

    for i in 0..num_test_patterns {
        let a = ((i as u64).wrapping_mul(0xDEAD).wrapping_add(seed)) as u8;
        let b = ((i as u64).wrapping_mul(0xBEEF).wrapping_add(seed)) as u8;
        if actual_ngrams.contains(&(a, b)) {
            continue; // skip — this is a true positive
        }
        trials += 1;
        if bloom.maybe_contains(a, b) {
            false_positives += 1;
        }
    }

    if trials == 0 {
        return 0.0;
    }
    false_positives as f64 / trials as f64
}

#[test]
fn fpr_below_5_percent_for_1kb_data() {
    let fpr = measure_fpr(1024, 10_000, 42);
    assert!(
        fpr < 0.05,
        "FINDING: FPR for 1KB data is {:.2}% (expected < 5%)",
        fpr * 100.0
    );
}

#[test]
fn fpr_below_5_percent_for_64kb_data() {
    let fpr = measure_fpr(65536, 10_000, 99);
    assert!(
        fpr < 0.05,
        "FINDING: FPR for 64KB data is {:.2}% (expected < 5%)",
        fpr * 100.0
    );
}

#[test]
fn fpr_below_10_percent_for_1mb_data() {
    let fpr = measure_fpr(1_000_000, 10_000, 7);
    assert!(
        fpr < 0.10,
        "FINDING: FPR for 1MB data is {:.2}% (expected < 10%)",
        fpr * 100.0
    );
}

/// The critical invariant: ZERO false negatives.
/// Every n-gram that exists in the data MUST be detected by the bloom.
#[test]
fn zero_false_negatives_exhaustive_1mb() {
    let data: Vec<u8> = (0..1_000_000u64)
        .map(|i| (i.wrapping_mul(31).wrapping_add(17)) as u8)
        .collect();

    let bloom = NgramBloom::from_block(&data, 65536).unwrap();

    let mut false_negatives = 0u64;
    for window in data.windows(2) {
        if !bloom.maybe_contains(window[0], window[1]) {
            false_negatives += 1;
        }
    }

    assert_eq!(
        false_negatives, 0,
        "CRITICAL FINDING: {false_negatives} false negatives in 1MB data. Bloom filter \
         invariant violated — patterns in data not detected."
    );
}

/// `NgramFilter`: verify that filter matches bloom for known-present patterns.
#[test]
fn ngram_filter_matches_known_present_patterns() {
    let patterns: &[&[u8]] = &[b"password", b"secret_key", b"api_token", b"credentials"];
    let filter = NgramFilter::from_patterns(patterns);

    for &pattern in patterns {
        let data = format!("prefix {} suffix", std::str::from_utf8(pattern).unwrap());
        let bloom = NgramBloom::from_block(data.as_bytes(), 4096).unwrap();

        assert!(
            filter.matches_bloom(&bloom),
            "FINDING: NgramFilter failed to match bloom for data containing pattern {:?}",
            std::str::from_utf8(pattern).unwrap()
        );
    }
}

/// `NgramFilter`: verify filter does NOT match when NO patterns are present.
/// (This tests the filter's ability to reject, bounded by FPR.)
#[test]
fn ngram_filter_rejects_unrelated_data() {
    let patterns: &[&[u8]] = &[b"XYZZY_MAGIC_1", b"PLUGH_MAGIC_2"];
    let filter = NgramFilter::from_patterns(patterns);

    let mut rejections = 0u64;
    let trials = 100u64;

    for i in 0..trials {
        let data = format!("completely unrelated content number {i} with random words");
        let bloom = NgramBloom::from_block(data.as_bytes(), 4096).unwrap();
        if !filter.matches_bloom(&bloom) {
            rejections += 1;
        }
    }

    // With good FPR, most unrelated data should be rejected
    assert!(
        rejections > 80,
        "FINDING: NgramFilter only rejected {rejections}/{trials} unrelated files. \
         Expected >80% rejection rate for non-matching data."
    );
}
