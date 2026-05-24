#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::NgramBloom;

#[test]
fn test_bloom_empty() {
    let bloom = NgramBloom::new(1024).unwrap();
    assert!(bloom.estimated_false_positive_rate() < f64::EPSILON);
    assert!(!bloom.maybe_contains(0, 0));
}

#[test]
fn test_bloom_insert_and_query() {
    let mut bloom = NgramBloom::new(1024).unwrap();
    bloom.insert_ngram(b'a', b'b');
    assert!(bloom.maybe_contains(b'a', b'b'));
    // Depending on FPR, 'a', 'c' might match, but with 1 insert in 1024 bits, very unlikely.
    assert!(!bloom.maybe_contains(b'a', b'c'));
}

#[test]
fn test_bloom_from_block() {
    let bloom = NgramBloom::from_block(b"hello", 1024).unwrap();
    assert!(bloom.maybe_contains(b'h', b'e'));
    assert!(bloom.maybe_contains(b'e', b'l'));
    assert!(bloom.maybe_contains(b'l', b'l'));
    assert!(bloom.maybe_contains(b'l', b'o'));
    assert!(!bloom.maybe_contains(b'z', b'z'));
}

#[test]
fn test_bloom_union() {
    let mut b1 = NgramBloom::new(1024).unwrap();
    b1.insert_ngram(b'a', b'b');

    let mut b2 = NgramBloom::new(1024).unwrap();
    b2.insert_ngram(b'c', b'd');

    // We clone because union_of consumes
    let b3 = NgramBloom::union_of(&[b1.clone(), b2.clone()]).unwrap();
    assert!(b3.maybe_contains(b'a', b'b'));
    assert!(b3.maybe_contains(b'c', b'd'));
    assert!(!b3.maybe_contains(b'e', b'f'));
}

#[test]
fn test_bloom_union_different_sizes_fails() {
    let b1 = NgramBloom::new(1024).unwrap();
    let b2 = NgramBloom::new(2048).unwrap();
    assert!(NgramBloom::union_of(&[b1, b2]).is_err());
}
