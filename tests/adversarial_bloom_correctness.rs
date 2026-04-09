#![allow(clippy::unwrap_used)]

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};
use std::collections::HashSet;

fn assert_pattern_found(data: &[u8], pattern: &[u8], offset: usize, block_size: usize) {
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(data)
        .unwrap();

    let byte_filter = ByteFilter::from_patterns(&[pattern]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    let start_block = offset / block_size;
    let end_block = if pattern.is_empty() {
        start_block
    } else {
        (offset + pattern.len() - 1) / block_size
    };

    let mut expected_blocks = HashSet::new();
    for b in start_block..=end_block {
        expected_blocks.insert(b * block_size);
    }

    let mut found_blocks = HashSet::new();
    for cand in candidates {
        for b in (cand.offset..cand.offset + cand.length).step_by(block_size) {
            found_blocks.insert(b);
        }
    }

    for expected in expected_blocks {
        assert!(
            found_blocks.contains(&expected),
            "Pattern at offset {offset} not found in block {expected}. Found: {found_blocks:?}"
        );
    }
}

// 1-byte patterns
#[test]
fn test_1_byte_pattern_offset_0() {
    let mut d = vec![0; 512];
    d[0] = b'A';
    assert_pattern_found(&d, b"A", 0, 256);
}
#[test]
fn test_1_byte_pattern_offset_1() {
    let mut d = vec![0; 512];
    d[1] = b'B';
    assert_pattern_found(&d, b"B", 1, 256);
}
#[test]
fn test_1_byte_pattern_offset_255() {
    let mut d = vec![0; 512];
    d[255] = b'C';
    assert_pattern_found(&d, b"C", 255, 256);
}
#[test]
fn test_1_byte_pattern_offset_256() {
    let mut d = vec![0; 512];
    d[256] = b'D';
    assert_pattern_found(&d, b"D", 256, 256);
}
#[test]
fn test_1_byte_pattern_last_byte() {
    let mut d = vec![0; 512];
    d[511] = b'E';
    assert_pattern_found(&d, b"E", 511, 256);
}
#[test]
fn test_1_byte_pattern_single_block() {
    let mut d = vec![0; 256];
    d[100] = b'F';
    assert_pattern_found(&d, b"F", 100, 256);
}

// Patterns at offset 0
#[test]
fn test_offset_0_len_2() {
    let mut d = vec![0; 512];
    d[0..2].copy_from_slice(b"AB");
    assert_pattern_found(&d, b"AB", 0, 256);
}
#[test]
fn test_offset_0_len_3() {
    let mut d = vec![0; 512];
    d[0..3].copy_from_slice(b"ABC");
    assert_pattern_found(&d, b"ABC", 0, 256);
}
#[test]
fn test_offset_0_len_256() {
    let mut d = vec![0; 512];
    let p = vec![b'X'; 256];
    d[0..256].copy_from_slice(&p);
    assert_pattern_found(&d, &p, 0, 256);
}
#[test]
fn test_offset_0_len_512() {
    let mut d = vec![0; 512];
    let p = vec![b'Y'; 512];
    d[0..512].copy_from_slice(&p);
    assert_pattern_found(&d, &p, 0, 256);
}

// Patterns at last byte of last block
#[test]
fn test_last_byte_len_1() {
    let mut d = vec![0; 512];
    d[511] = b'Z';
    assert_pattern_found(&d, b"Z", 511, 256);
}
#[test]
fn test_last_byte_len_2_spanning() {
    let mut d = vec![0; 512];
    d[510..512].copy_from_slice(b"YZ");
    assert_pattern_found(&d, b"YZ", 510, 256);
}
#[test]
fn test_last_block_exact_fit() {
    let mut d = vec![0; 512];
    let p = vec![b'W'; 256];
    d[256..512].copy_from_slice(&p);
    assert_pattern_found(&d, &p, 256, 256);
}

// Patterns spanning block boundary
#[test]
fn test_span_boundary_2_bytes() {
    let mut d = vec![0; 512];
    d[255..257].copy_from_slice(b"AB");
    assert_pattern_found(&d, b"AB", 255, 256);
}
#[test]
fn test_span_boundary_3_bytes() {
    let mut d = vec![0; 512];
    d[254..257].copy_from_slice(b"ABC");
    assert_pattern_found(&d, b"ABC", 254, 256);
}
#[test]
fn test_span_boundary_4_bytes() {
    let mut d = vec![0; 512];
    d[254..258].copy_from_slice(b"ABCD");
    assert_pattern_found(&d, b"ABCD", 254, 256);
}
#[test]
fn test_span_boundary_10_bytes() {
    let mut d = vec![0; 512];
    d[250..260].copy_from_slice(b"0123456789");
    assert_pattern_found(&d, b"0123456789", 250, 256);
}
#[test]
fn test_span_multiple_boundaries() {
    let mut d = vec![0; 1024];
    let p = vec![b'X'; 600];
    d[200..800].copy_from_slice(&p);
    assert_pattern_found(&d, &p, 200, 256);
}

// All-zero blocks
#[test]
fn test_all_zero_block_len_1() {
    let d = vec![0; 512];
    assert_pattern_found(&d, &[0], 100, 256);
}
#[test]
fn test_all_zero_block_len_2() {
    let d = vec![0; 512];
    assert_pattern_found(&d, &[0, 0], 255, 256);
}

// All-zero blocks cont.
#[test]
fn test_all_zero_block_len_10() {
    let d = vec![0; 512];
    assert_pattern_found(&d, &[0; 10], 100, 256);
}

// All-0xFF blocks
#[test]
fn test_all_ff_block_len_1() {
    let d = vec![0xFF; 512];
    assert_pattern_found(&d, &[0xFF], 100, 256);
}
#[test]
fn test_all_ff_block_len_2() {
    let d = vec![0xFF; 512];
    assert_pattern_found(&d, &[0xFF, 0xFF], 255, 256);
}
#[test]
fn test_all_ff_block_len_10() {
    let d = vec![0xFF; 512];
    assert_pattern_found(&d, &[0xFF; 10], 100, 256);
}
#[test]
fn test_all_ff_boundary() {
    let d = vec![0xFF; 512];
    assert_pattern_found(&d, &[0xFF, 0xFF, 0xFF], 255, 256);
}

// Patterns that are substrings of each other
#[test]
fn test_substrings_1() {
    let mut d = vec![0; 512];
    d[100..105].copy_from_slice(b"HELLO");
    assert_pattern_found(&d, b"HELL", 100, 256);
    assert_pattern_found(&d, b"HELLO", 100, 256);
}
#[test]
fn test_substrings_2() {
    let mut d = vec![0; 512];
    d[254..259].copy_from_slice(b"WORLD");
    assert_pattern_found(&d, b"WOR", 254, 256);
    assert_pattern_found(&d, b"WORLD", 254, 256);
}

// 100 patterns in same block
#[test]
fn test_100_patterns_in_same_block() {
    let mut d = vec![0; 256];
    for i in 0..100 {
        d[i * 2..i * 2 + 2].copy_from_slice(&[i as u8, (i + 1) as u8]);
    }
    for i in 0..100 {
        assert_pattern_found(&d, &[i as u8, (i + 1) as u8], i * 2, 256);
    }
}

// Single-block index
#[test]
fn test_single_block_start() {
    let mut d = vec![0; 256];
    d[0..4].copy_from_slice(b"TEST");
    assert_pattern_found(&d, b"TEST", 0, 256);
}
#[test]
fn test_single_block_end() {
    let mut d = vec![0; 256];
    d[252..256].copy_from_slice(b"TEST");
    assert_pattern_found(&d, b"TEST", 252, 256);
}

// 1000-block index
#[test]
fn test_1000_block_first() {
    let mut d = vec![0; 256 * 1000];
    d[0..4].copy_from_slice(b"TEST");
    assert_pattern_found(&d, b"TEST", 0, 256);
}
#[test]
fn test_1000_block_middle() {
    let mut d = vec![0; 256 * 1000];
    let offset = 256 * 500 + 128;
    d[offset..offset + 4].copy_from_slice(b"TEST");
    assert_pattern_found(&d, b"TEST", offset, 256);
}
#[test]
fn test_1000_block_last() {
    let mut d = vec![0; 256 * 1000];
    let offset = 256 * 1000 - 4;
    d[offset..offset + 4].copy_from_slice(b"TEST");
    assert_pattern_found(&d, b"TEST", offset, 256);
}
#[test]
fn test_1000_block_boundary() {
    let mut d = vec![0; 256 * 1000];
    let offset = 256 * 500 - 2;
    d[offset..offset + 4].copy_from_slice(b"TEST");
    assert_pattern_found(&d, b"TEST", offset, 256);
}

// Additional specific edge cases
#[test]
fn test_1_byte_boundary_0() {
    let mut d = vec![0; 512];
    d[255] = b'X';
    assert_pattern_found(&d, b"X", 255, 256);
}
#[test]
fn test_1_byte_boundary_1() {
    let mut d = vec![0; 512];
    d[256] = b'X';
    assert_pattern_found(&d, b"X", 256, 256);
}
#[test]
fn test_2_byte_exactly_on_boundary() {
    let mut d = vec![0; 512];
    d[255..257].copy_from_slice(b"XY");
    assert_pattern_found(&d, b"XY", 255, 256);
}
#[test]
fn test_all_zeros_with_one_one() {
    let mut d = vec![0; 512];
    d[300] = 1;
    assert_pattern_found(&d, &[1], 300, 256);
}
#[test]
fn test_all_ones_with_one_zero() {
    let mut d = vec![0xFF; 512];
    d[300] = 0;
    assert_pattern_found(&d, &[0], 300, 256);
}
#[test]
fn test_1000_block_span_3_blocks() {
    let mut d = vec![0; 256 * 1000];
    let offset = 256 * 500 - 100;
    let p = vec![b'A'; 400];
    d[offset..offset + 400].copy_from_slice(&p);
    assert_pattern_found(&d, &p, offset, 256);
}
