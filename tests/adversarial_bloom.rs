#![allow(
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::unwrap_used
)]
//! Adversarial tests for flashsieve - designed to BREAK the implementation.
//!
//! These tests verify that the crate handles malformed inputs, edge cases,
//! and resource exhaustion scenarios gracefully with proper error returns
//! instead of panics or undefined behavior.

use flashsieve::{BlockIndex, BlockIndexBuilder, Error, MmapBlockIndex, NgramBloom};

/// 1. NgramBloom::new(0) — zero bits bloom filter. Should error, not panic.
#[test]
fn bloom_new_zero_bits_errors() {
    let result = NgramBloom::new(0);
    assert!(
        matches!(result, Err(Error::ZeroBloomBits)),
        "NgramBloom::new(0) should return ZeroBloomBits error, got: {:?}",
        result
    );
}

/// 2. NgramBloom::new with non-power-of-two gets rounded up.
///
/// This test verifies that non-power-of-two values are handled correctly.
#[test]
fn bloom_new_non_power_of_two_rounded() {
    // Test that non-power-of-two values get rounded up to next power of two
    let result = NgramBloom::new(1000);
    assert!(
        result.is_ok(),
        "NgramBloom::new(1000) should succeed (rounded to 1024), got: {:?}",
        result
    );
    let bloom = result.unwrap();
    let (num_bits, _) = bloom.raw_parts();
    assert_eq!(
        num_bits, 1024,
        "1000 should be rounded up to next power of two (1024)"
    );
}

/// 3. from_raw_parts with bits.len() = 0 but num_bits = 1000 — should reject.
#[test]
fn bloom_from_raw_parts_empty_bits_rejected() {
    let bits: Vec<u64> = vec![];
    let result = NgramBloom::from_raw_parts(1000, bits);
    assert!(
        matches!(result, Err(Error::InvalidBlockSize { .. } | Error::TruncatedBlock { .. })),
        "from_raw_parts with empty bits and num_bits=1000 should return TruncatedBlock error, got: {:?}",
        result
    );
}

/// 4. from_raw_parts with num_bits > bits.len() * 64 — should reject.
#[test]
fn bloom_from_raw_parts_insufficient_bits_rejected() {
    // 2 u64 words = 128 bits, but we're claiming 1000 bits
    let bits: Vec<u64> = vec![0u64; 2];
    let result = NgramBloom::from_raw_parts(1000, bits);
    assert!(
        matches!(result, Err(Error::InvalidBlockSize { .. } | Error::TruncatedBlock { .. })),
        "from_raw_parts with 128 bits but claiming 1000 should return TruncatedBlock error, got: {:?}",
        result
    );
}

/// 5. BlockIndex::from_bytes with truncated header (< MIN_HEADER_LEN=29) — error not panic.
#[test]
fn block_index_truncated_header_errors() {
    // MIN_SERIALIZED_HEADER_LEN = 4 (magic) + 1 (version) + 8 (block_size) + 8 (total_len) + 8 (block_count) = 29
    let truncated = vec![0u8; 10]; // Way too short
    let result = BlockIndex::from_bytes_checked(&truncated);
    assert!(
        matches!(result, Err(Error::TruncatedHeader { .. })),
        "from_bytes with truncated header should return TruncatedHeader error, got: {:?}",
        result
    );
}

/// 6. BlockIndex::from_bytes with valid header but corrupt CRC — should reject.
#[test]
fn block_index_corrupt_crc_rejected() {
    // Build a valid index first
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test data for corruption")
        .expect("valid index should build");

    let mut bytes = index.to_bytes();

    // Corrupt a byte in the middle (before the CRC)
    let corrupt_pos = bytes.len() / 2;
    bytes[corrupt_pos] ^= 0xFF;

    let result = BlockIndex::from_bytes_checked(&bytes);
    assert!(
        matches!(result, Err(Error::ChecksumMismatch { .. })),
        "from_bytes with corrupt CRC should return ChecksumMismatch error, got: {:?}",
        result
    );
}

/// 7. BlockIndex::from_bytes with block_count = u64::MAX — OOM protection.
#[test]
fn block_index_max_block_count_rejected() {
    // Construct a valid header but with block_count = u64::MAX
    let mut malicious = Vec::new();

    // Magic: "FSIE"
    malicious.extend_from_slice(b"FSBX");

    // Version: 1 (no CRC to simplify)
    malicious.extend_from_slice(&1u32.to_le_bytes());

    // block_size: 256 (u64 LE)
    malicious.extend_from_slice(&(256u64).to_le_bytes());

    // total_len: 1024 (u64 LE)
    malicious.extend_from_slice(&(1024u64).to_le_bytes());

    // block_count: u64::MAX - this should be rejected due to overflow check
    malicious.extend_from_slice(&u64::MAX.to_le_bytes());

    let result = BlockIndex::from_bytes_checked(&malicious);
    // Should fail with BlockCountOverflow since u64::MAX blocks is impossible
    assert!(
        matches!(result, Err(Error::BlockCountOverflow { .. })),
        "from_bytes with block_count=u64::MAX should return BlockCountOverflow error, got: {:?}",
        result
    );
}

/// 8. BlockIndex::from_bytes with block_size = 0 — should error.
#[test]
fn block_index_zero_block_size_handled() {
    // Construct a header with block_size = 0
    let mut malicious = Vec::new();

    // Magic: "FSIE"
    malicious.extend_from_slice(b"FSBX");

    // Version: 1
    malicious.extend_from_slice(&1u32.to_le_bytes());

    // block_size: 0 (u64 LE)
    malicious.extend_from_slice(&0u64.to_le_bytes());

    // total_len: 0 (u64 LE)
    malicious.extend_from_slice(&0u64.to_le_bytes());

    // block_count: 0 (u64 LE)
    malicious.extend_from_slice(&0u64.to_le_bytes());

    // The result depends on implementation - it may succeed (empty index) or error
    // We just verify it doesn't panic
    let _result = BlockIndex::from_bytes_checked(&malicious);
}

/// 9. Incremental: append_block then remove_blocks with invalid block ID — should error.
#[test]
fn incremental_remove_invalid_block_id_errors() {
    // Build a valid index with 2 blocks
    let mut index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&[0u8; 512]) // 2 blocks of 256 bytes
        .expect("valid index should build");

    assert_eq!(index.block_count(), 2);

    // Try to remove block id 100 (which doesn't exist)
    let result = index.remove_blocks(&[100]);
    assert!(
        matches!(
            result,
            Err(Error::InvalidBlockId {
                block_id: 100,
                block_count: 2
            })
        ),
        "remove_blocks with invalid block_id should return InvalidBlockId error, got: {:?}",
        result
    );

    // Also test with a mix of valid and invalid IDs
    let result = index.remove_blocks(&[0, 5]); // 0 is valid, 5 is not
    assert!(
        matches!(
            result,
            Err(Error::InvalidBlockId {
                block_id: 5,
                block_count: 2
            })
        ),
        "remove_blocks with mix of valid and invalid should return InvalidBlockId for the invalid one, got: {:?}",
        result
    );
}

/// 10. MmapBlockIndex::from_slice with zero-length slice.
#[test]
fn mmap_from_empty_slice_errors() {
    let empty: &[u8] = b"";
    let result = MmapBlockIndex::from_slice(empty);
    assert!(
        matches!(result, Err(Error::TruncatedHeader { .. })),
        "from_slice with empty data should return TruncatedHeader error, got: {:?}",
        result
    );
}

/// Additional adversarial test: NgramBloom::from_raw_parts with exact boundary condition
#[test]
fn bloom_from_raw_parts_boundary_condition() {
    // Exactly 64 bits requires 1 word
    let bits: Vec<u64> = vec![0u64; 1];
    let result = NgramBloom::from_raw_parts(64, bits.clone());
    assert!(
        result.is_ok(),
        "from_raw_parts with exactly 64 bits and 1 word should succeed, got: {:?}",
        result
    );

    // 65 bits requires 2 words, but we only provide 1
    let result = NgramBloom::from_raw_parts(65, bits);
    assert!(
        matches!(
            result,
            Err(Error::InvalidBlockSize { .. } | Error::TruncatedBlock { .. })
        ),
        "from_raw_parts with 65 bits but only 1 word should fail, got: {:?}",
        result
    );
}

/// Additional adversarial test: BlockIndex::from_bytes with truncated block data
///
/// This test verifies that truncated block data is detected. The exact error
/// depends on where the truncation occurs - it could be ChecksumMismatch if
/// the CRC is cut off, or TruncatedBlock if block data is incomplete.
#[test]
fn block_index_truncated_block_data_errors() {
    // Build a valid index with version 2 format
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test data for truncation test")
        .expect("valid index should build");

    let bytes = index.to_bytes();

    // The header is 29 bytes. CRC is last 4 bytes.
    // Truncate to remove CRC entirely - should get checksum error
    let no_crc = &bytes[..bytes.len() - 4];
    let result = BlockIndex::from_bytes_checked(no_crc);
    assert!(
        matches!(
            result,
            Err(Error::ChecksumMismatch { .. } | Error::TruncatedHeader { .. })
        ),
        "from_bytes without CRC should return ChecksumMismatch or TruncatedHeader, got: {:?}",
        result
    );

    // Truncate somewhere in the middle of block data
    // Header (29) + some of first block histogram (1024 bytes) = 1053 bytes
    let mid_block = &bytes[..200];
    let result = BlockIndex::from_bytes_checked(mid_block);
    // This will either fail at CRC check or at block parsing
    assert!(
        result.is_err(),
        "from_bytes with truncated block data should error, got: {:?}",
        result
    );
}

/// Additional adversarial test: BlockIndex::merge with incompatible configurations
#[test]
fn merge_incompatible_block_sizes_errors() {
    let mut index1 = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&[0u8; 256])
        .expect("valid index should build");

    let index2 = BlockIndexBuilder::new()
        .block_size(512) // Different block size
        .bloom_bits(1024)
        .build(&[0u8; 512])
        .expect("valid index should build");

    let result = index1.merge(&index2);
    assert!(
        matches!(
            result,
            Err(Error::IncompatibleIndexConfiguration {
                reason: "block_size differs"
            })
        ),
        "merge with different block sizes should return IncompatibleIndexConfiguration, got: {:?}",
        result
    );
}

/// Additional adversarial test: BlockIndex::merge with incompatible bloom bits
#[test]
fn merge_incompatible_bloom_bits_errors() {
    let mut index1 = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&[0u8; 256])
        .expect("valid index should build");

    let index2 = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(2048) // Different bloom bits
        .build(&[0u8; 256])
        .expect("valid index should build");

    let result = index1.merge(&index2);
    assert!(
        matches!(
            result,
            Err(Error::IncompatibleIndexConfiguration {
                reason: "bloom_bits differs"
            })
        ),
        "merge with different bloom bits should return IncompatibleIndexConfiguration, got: {:?}",
        result
    );
}

/// MmapBlockIndex must reject num_bits = 0 to prevent panic on query.
#[test]
fn mmap_rejects_zero_num_bits() {
    use flashsieve::{BlockIndex, MmapBlockIndex};

    // Build a valid index
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test")
        .expect("valid index should build");

    let mut bytes = index.to_bytes();
    // Corrupt the first block's bloom num_bits to 0 (offset 29 = histogram end)
    let bloom_num_bits_offset = 29 + 1024;
    bytes[bloom_num_bits_offset..bloom_num_bits_offset + 8].copy_from_slice(&0u64.to_le_bytes());

    // BlockIndex::from_bytes_checked should reject it
    let result = BlockIndex::from_bytes_checked(&bytes);
    assert!(
        result.is_err(),
        "from_bytes_checked with num_bits=0 should error, got: {:?}",
        result
    );

    // MmapBlockIndex::from_slice should also reject it
    let result = MmapBlockIndex::from_slice(&bytes);
    assert!(
        result.is_err(),
        "MmapBlockIndex::from_slice with num_bits=0 should error, got: {:?}",
        result
    );
}

/// MmapBlockIndex must reject non-power-of-two num_bits.
#[test]
fn mmap_rejects_non_power_of_two_num_bits() {
    use flashsieve::{BlockIndex, MmapBlockIndex};

    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"test")
        .expect("valid index should build");

    let mut bytes = index.to_bytes();
    let bloom_num_bits_offset = 29 + 1024;
    bytes[bloom_num_bits_offset..bloom_num_bits_offset + 8].copy_from_slice(&1000u64.to_le_bytes());

    let result = BlockIndex::from_bytes_checked(&bytes);
    assert!(
        result.is_err(),
        "from_bytes_checked with non-power-of-two num_bits should error, got: {:?}",
        result
    );

    let result = MmapBlockIndex::from_slice(&bytes);
    assert!(
        result.is_err(),
        "MmapBlockIndex::from_slice with non-power-of-two num_bits should error, got: {:?}",
        result
    );
}
