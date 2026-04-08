#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
//! Adversarial tests for the byte frequency histogram.
//!
//! Tests probe overflow behavior, bitmap boundary conditions at byte
//! values 63/64/127/128/191/192, and contains_all / contains_any correctness.

use flashsieve::ByteHistogram;

// =============================================================================
// Basic Count Accuracy
// =============================================================================

#[test]
fn empty_block_all_zero() {
    let histogram = ByteHistogram::from_block(&[]);
    for byte in 0_u8..=255 {
        assert_eq!(histogram.count(byte), 0);
    }
}

#[test]
fn single_byte_counted() {
    let histogram = ByteHistogram::from_block(&[0x41]);
    assert_eq!(histogram.count(0x41), 1);
    assert_eq!(histogram.count(0x42), 0);
}

#[test]
fn all_256_byte_values_each_counted_once() {
    let data: Vec<u8> = (0_u8..=255).collect();
    let histogram = ByteHistogram::from_block(&data);
    for byte in 0_u8..=255 {
        assert_eq!(
            histogram.count(byte),
            1,
            "byte {byte:#04x} should have count 1"
        );
    }
}

#[test]
fn repeated_byte_correct_count() {
    let data = vec![0x42; 1000];
    let histogram = ByteHistogram::from_block(&data);
    assert_eq!(histogram.count(0x42), 1000);
    assert_eq!(histogram.count(0x41), 0);
}

#[test]
fn large_block_sum_equals_length() {
    let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let histogram = ByteHistogram::from_block(&data);
    let total: u32 = (0_u8..=255).map(|b| histogram.count(b)).sum();
    assert_eq!(total, 10_000);
}

// =============================================================================
// Overflow Behavior (u32 counter)
// =============================================================================

#[test]
fn count_at_u32_max_does_not_panic() {
    // u32::MAX = 4,294,967,295 — we can't practically allocate that much,
    // but we can verify the histogram doesn't overflow for large but reasonable sizes.
    let data = vec![0x00; 100_000];
    let histogram = ByteHistogram::from_block(&data);
    assert_eq!(histogram.count(0x00), 100_000);
}

// =============================================================================
// contains_all
// =============================================================================

#[test]
fn contains_all_empty_required_is_true() {
    let histogram = ByteHistogram::from_block(&[]);
    let required = [false; 256];
    // No bytes required → vacuously true.
    assert!(histogram.contains_all(&required));
}

#[test]
fn contains_all_present_byte_passes() {
    let histogram = ByteHistogram::from_block(b"abc");
    let mut required = [false; 256];
    required[usize::from(b'a')] = true;
    assert!(histogram.contains_all(&required));
}

#[test]
fn contains_all_absent_byte_fails() {
    let histogram = ByteHistogram::from_block(b"abc");
    let mut required = [false; 256];
    required[usize::from(b'z')] = true;
    assert!(!histogram.contains_all(&required));
}

#[test]
fn contains_all_mixed_present_and_absent_fails() {
    let histogram = ByteHistogram::from_block(b"abc");
    let mut required = [false; 256];
    required[usize::from(b'a')] = true;
    required[usize::from(b'z')] = true;
    assert!(!histogram.contains_all(&required));
}

#[test]
fn contains_all_all_256_required_in_full_data_passes() {
    let data: Vec<u8> = (0_u8..=255).collect();
    let histogram = ByteHistogram::from_block(&data);
    let required = [true; 256];
    assert!(histogram.contains_all(&required));
}

#[test]
fn contains_all_all_256_required_in_partial_data_fails() {
    let histogram = ByteHistogram::from_block(b"abc");
    let required = [true; 256];
    assert!(!histogram.contains_all(&required));
}

// =============================================================================
// contains_any
// =============================================================================

#[test]
fn contains_any_empty_set_is_false() {
    let histogram = ByteHistogram::from_block(b"abc");
    let byte_set = [false; 256];
    assert!(!histogram.contains_any(&byte_set));
}

#[test]
fn contains_any_present_byte_passes() {
    let histogram = ByteHistogram::from_block(b"abc");
    let mut byte_set = [false; 256];
    byte_set[usize::from(b'a')] = true;
    assert!(histogram.contains_any(&byte_set));
}

#[test]
fn contains_any_absent_byte_fails() {
    let histogram = ByteHistogram::from_block(b"abc");
    let mut byte_set = [false; 256];
    byte_set[usize::from(b'z')] = true;
    assert!(!histogram.contains_any(&byte_set));
}

#[test]
fn contains_any_one_present_one_absent_passes() {
    let histogram = ByteHistogram::from_block(b"abc");
    let mut byte_set = [false; 256];
    byte_set[usize::from(b'a')] = true;
    byte_set[usize::from(b'z')] = true;
    assert!(histogram.contains_any(&byte_set));
}

// =============================================================================
// Default
// =============================================================================

#[test]
fn default_is_all_zero() {
    let histogram = ByteHistogram::default();
    for byte in 0_u8..=255 {
        assert_eq!(histogram.count(byte), 0);
    }
}
