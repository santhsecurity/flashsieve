#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::ByteHistogram;

fn make_mask(bytes: &[u8]) -> [bool; 256] {
    let mut mask = [false; 256];
    for &b in bytes {
        mask[b as usize] = true;
    }
    mask
}

#[test]
fn test_histogram_empty_block() {
    let hist = ByteHistogram::from_block(b"");
    for i in 0..=255 {
        assert_eq!(hist.count(i), 0);
    }
}

#[test]
fn test_histogram_all_same_byte() {
    let hist = ByteHistogram::from_block(&vec![0xAA; 1024]);
    assert_eq!(hist.count(0xAA), 1024);
    for i in 0..=255 {
        if i != 0xAA {
            assert_eq!(hist.count(i), 0);
        }
    }
}

#[test]
fn test_histogram_contains_all() {
    let hist = ByteHistogram::from_block(b"abc");
    assert!(hist.contains_all(&make_mask(b"ab")));
    assert!(hist.contains_all(&make_mask(b"abc")));
    assert!(!hist.contains_all(&make_mask(b"abd")));
    assert!(hist.contains_all(&make_mask(b""))); // empty required array always matched
}

#[test]
fn test_histogram_contains_any() {
    let hist = ByteHistogram::from_block(b"abc");
    assert!(hist.contains_any(&make_mask(b"ax")));
    assert!(hist.contains_any(&make_mask(b"yc")));
    assert!(!hist.contains_any(&make_mask(b"xyz")));
    assert!(!hist.contains_any(&make_mask(b""))); // empty array never matches
}
