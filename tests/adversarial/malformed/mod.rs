#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::BlockIndex;

#[test]
fn test_malformed_index_truncated() {
    let data = vec![0xFF; 100];
    // BlockIndex requires specific headers, magic bytes, versions.
    // Ensure truncated input handles gracefully and doesn't panic.
    assert!(BlockIndex::from_bytes_checked(&data).is_err());

    // Test truncation of valid data
    let valid = flashsieve::BlockIndexBuilder::new()
        .block_size(1024)
        .build(&[0; 1024])
        .unwrap();
    let valid_bytes = valid.to_bytes();
    for i in 0..valid_bytes.len() {
        assert!(BlockIndex::from_bytes_checked(&valid_bytes[..i]).is_err());
    }
}
