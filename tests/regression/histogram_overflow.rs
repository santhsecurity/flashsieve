#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! Regression tests for histogram overflow and correctness.

use flashsieve::histogram::ByteHistogram;

#[test]
fn histogram_counts_match_actual_frequencies() {
    let data = b"aaabbc";
    let hist = ByteHistogram::from_block(data);
    assert_eq!(hist.count(b'a'), 3);
    assert_eq!(hist.count(b'b'), 2);
    assert_eq!(hist.count(b'c'), 1);
    assert_eq!(hist.count(b'd'), 0);
}

#[test]
fn empty_block_produces_zero_histogram() {
    let hist = ByteHistogram::from_block(b"");
    for byte in 0..=u8::MAX {
        assert_eq!(
            hist.count(byte),
            0,
            "empty histogram must have zero count for byte {byte}"
        );
    }
}

#[test]
fn contains_all_works_correctly() {
    let hist = ByteHistogram::from_block(b"hello");
    let mut required = [false; 256];
    required[b'h' as usize] = true;
    required[b'e' as usize] = true;
    required[b'l' as usize] = true;
    required[b'o' as usize] = true;
    assert!(
        hist.contains_all(&required),
        "histogram must contain all bytes in 'hello'"
    );

    required[b'z' as usize] = true;
    assert!(!hist.contains_all(&required), "'z' is NOT in 'hello'");
}

#[test]
fn contains_any_detects_partial_presence() {
    let hist = ByteHistogram::from_block(b"abc");
    let mut byte_set = [false; 256];
    byte_set[b'z' as usize] = true;
    assert!(!hist.contains_any(&byte_set), "'z' is not in 'abc'");

    byte_set[b'a' as usize] = true;
    assert!(hist.contains_any(&byte_set), "'a' IS in 'abc'");
}

#[test]
fn all_256_bytes_counted() {
    let data: Vec<u8> = (0..=255).collect();
    let hist = ByteHistogram::from_block(&data);
    for byte in 0..=u8::MAX {
        assert_eq!(
            hist.count(byte),
            1,
            "byte {byte} should appear exactly once"
        );
    }
}
