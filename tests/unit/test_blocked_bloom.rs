#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::explicit_iter_loop,
    clippy::uninlined_format_args,
    clippy::unreadable_literal
)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use flashsieve::bloom::filter::BlockedNgramBloom;
#[test]
fn test_blocked() {
    let mut bloom = BlockedNgramBloom::new(1024).unwrap();
    bloom.insert(b'a', b'b');
    assert!(bloom.maybe_contains(b'a', b'b'));
}
