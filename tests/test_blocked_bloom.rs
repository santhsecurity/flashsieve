#![allow(clippy::unwrap_used)]

use flashsieve::bloom::filter::BlockedNgramBloom;
#[test]
fn test_blocked() {
    let mut bloom = BlockedNgramBloom::new(1024).unwrap();
    bloom.insert(b'a', b'b');
    assert!(bloom.maybe_contains(b'a', b'b'));
}
