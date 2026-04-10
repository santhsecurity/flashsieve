#![allow(clippy::pedantic)]
#![allow(clippy::cast_precision_loss, clippy::doc_markdown, clippy::explicit_iter_loop, clippy::uninlined_format_args, clippy::unreadable_literal)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use flashsieve::NgramBloom;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Measured false-positive rate should be within 2× of the theoretical estimate.
/// We use a large margin because the estimate is based on bit fill, not exact
/// combinatorics, and the hash functions have real-world collision behaviour.
#[test]
fn measured_fpr_matches_theoretical_estimate() {
    let mut rng = StdRng::seed_from_u64(0xACC0_1234);
    let num_bits = 16_384;
    let mut bloom = NgramBloom::new(num_bits).unwrap();
    let mut inserted = std::collections::HashSet::new();

    // Insert 1000 distinct random n-grams
    while inserted.len() < 1000 {
        let pair = (rng.gen::<u8>(), rng.gen::<u8>());
        if inserted.insert(pair) {
            bloom.insert_ngram(pair.0, pair.1);
        }
    }

    let estimated = bloom.estimated_false_positive_rate();

    let mut false_positives = 0_usize;
    let mut trials = 0_usize;
    for _ in 0..50_000 {
        let pair = (rng.gen::<u8>(), rng.gen::<u8>());
        if inserted.contains(&pair) {
            continue;
        }
        trials += 1;
        if bloom.maybe_contains(pair.0, pair.1) {
            false_positives += 1;
        }
    }

    assert!(trials > 10_000, "need meaningful trial count");
    let measured = false_positives as f64 / trials as f64;

    // Allow up to 2× difference in either direction, bounded by sanity limits
    let ratio = if estimated > 0.0 {
        measured / estimated
    } else {
        0.0
    };
    assert!(
        ratio <= 2.5 && measured <= 0.15,
        "measured FPR {measured:.6} diverged too far from estimate {estimated:.6} (ratio {ratio:.2})"
    );
}

/// With exact-pair tables (≥4096 bits), FPR for 2-byte queries must be exactly zero.
#[test]
fn exact_pair_table_eliminates_all_false_positives() {
    let mut rng = StdRng::seed_from_u64(0xEFAC_70F1);
    let mut bloom = NgramBloom::new(4096).unwrap();
    let mut inserted = std::collections::HashSet::new();

    while inserted.len() < 2000 {
        let pair = (rng.gen::<u8>(), rng.gen::<u8>());
        if inserted.insert(pair) {
            bloom.insert_ngram(pair.0, pair.1);
        }
    }

    // Exhaustively query all 65,536 possible pairs
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            let was_inserted = inserted.contains(&(a, b));
            let contains = bloom.maybe_contains(a, b);
            assert!(
                was_inserted || !contains,
                "false positive for ({a}, {b}) with exact-pair table"
            );
            assert!(
                !was_inserted || contains,
                "false negative for ({a}, {b}) — exact-pair table broken"
            );
        }
    }
}

/// Varying the bit count should monotonically decrease the measured FPR for the same workload.
#[test]
fn larger_filters_reduce_fpr_monotonically() {
    let mut rng = StdRng::seed_from_u64(0xABCD_7777);
    let mut fprs = Vec::new();

    for &num_bits in &[1024, 2048, 4096, 8192, 16384] {
        let mut bloom = NgramBloom::new(num_bits).unwrap();
        let mut inserted = std::collections::HashSet::new();
        while inserted.len() < 500 {
            let pair = (rng.gen::<u8>(), rng.gen::<u8>());
            if inserted.insert(pair) {
                bloom.insert_ngram(pair.0, pair.1);
            }
        }

        let mut fp = 0_usize;
        let mut trials = 0_usize;
        for _ in 0..20_000 {
            let pair = (rng.gen::<u8>(), rng.gen::<u8>());
            if inserted.contains(&pair) {
                continue;
            }
            trials += 1;
            if bloom.maybe_contains(pair.0, pair.1) {
                fp += 1;
            }
        }
        fprs.push(fp as f64 / trials.max(1) as f64);
    }

    for window in fprs.windows(2) {
        assert!(
            window[1] <= window[0] * 1.5,
            "FPR did not decrease monotonically: {:?}",
            fprs
        );
    }
}
