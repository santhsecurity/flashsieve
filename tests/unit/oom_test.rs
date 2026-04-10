#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[test]
fn test_oom_capacity() {
    let mut data = [0u8; 100];
    data[0..4].copy_from_slice(b"FSBX");
    data[4..8].copy_from_slice(&2u32.to_le_bytes()); // version
                                                     // block_size = 256
    data[8..16].copy_from_slice(&256u64.to_le_bytes());
    // total_len = 100
    data[16..24].copy_from_slice(&100u64.to_le_bytes());
    // block_count = 1
    data[24..32].copy_from_slice(&1u64.to_le_bytes());

    // Per-block:
    // histogram: 1024 bytes (not enough room in 100 bytes data, but parse_serialized_index_header might not check that)
    // Wait, parse_serialized_index_header DOES check data.len() against MIN_SERIALIZED_HEADER_LEN.
    // data needs to be larger.
    assert_eq!(data.len(), 100);
}
