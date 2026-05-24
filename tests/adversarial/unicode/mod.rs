#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::NgramBloom;

#[test]
fn test_unicode_rtl_override() {
    // Right-to-Left Override (U+202E) mixed with standard text.
    let data = b"admin\xE2\x80\xAEtxt.exe";
    let bloom = NgramBloom::from_block(data, 1024).unwrap();

    // Bloom should correctly ingest UTF-8 bytes regardless of semantics
    assert!(bloom.maybe_contains(b'a', b'd'));
    assert!(bloom.maybe_contains(0xE2, 0x80));
    assert!(bloom.maybe_contains(0x80, 0xAE));
    assert!(bloom.maybe_contains(0xAE, b't'));
}

#[test]
fn test_unicode_zero_width_joiner() {
    let data = "👨‍👩‍👧‍👦".as_bytes(); // family emoji using ZWJ (U+200D)
    let bloom = NgramBloom::from_block(data, 1024).unwrap();

    // ZWJ is E2 80 8D
    assert!(bloom.maybe_contains(0xE2, 0x80));
    assert!(bloom.maybe_contains(0x80, 0x8D));
}
