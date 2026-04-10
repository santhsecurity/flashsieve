#![allow(clippy::pedantic)]
#![allow(clippy::cast_precision_loss, clippy::doc_markdown, clippy::explicit_iter_loop, clippy::uninlined_format_args, clippy::unreadable_literal)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};

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

    let mut expected_blocks = std::collections::HashSet::new();
    for b in start_block..=end_block {
        expected_blocks.insert(b * block_size);
    }

    let mut found_blocks = std::collections::HashSet::new();
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

// 1-10: Insert N patterns, verify EVERY pattern returns 'possibly present' (soundness)
fn assert_n_patterns_soundness(n: usize, seed: u8) {
    let block_size = 4096;
    let mut data = vec![0u8; block_size];
    
    // Fill block with N 2-byte patterns
    let mut offset = 0;
    for i in 0..n {
        if offset >= block_size - 1 {
            break;
        }
        data[offset] = seed.wrapping_add((i % 256) as u8);
        data[offset + 1] = seed.wrapping_add(((i / 256) % 256) as u8);
        offset += 2;
    }
    
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    for i in 0..n {
        let p0 = seed.wrapping_add((i % 256) as u8);
        let p1 = seed.wrapping_add(((i / 256) % 256) as u8);
        let pattern = [p0, p1];
        
        let byte_filter = ByteFilter::from_patterns(&[&pattern]);
        let ngram_filter = NgramFilter::from_patterns(&[&pattern]);

        let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
        assert!(!candidates.is_empty(), "Pattern {i} not found (soundness violation)");
    }
}

#[test]
fn test_soundness_insert_1() { assert_n_patterns_soundness(10, 1); }

#[test]
fn test_soundness_insert_2() { assert_n_patterns_soundness(50, 2); }

#[test]
fn test_soundness_insert_3() { assert_n_patterns_soundness(100, 3); }

#[test]
fn test_soundness_insert_4() { assert_n_patterns_soundness(200, 4); }

#[test]
fn test_soundness_insert_5() { assert_n_patterns_soundness(300, 5); }

#[test]
fn test_soundness_insert_6() { assert_n_patterns_soundness(400, 6); }

#[test]
fn test_soundness_insert_7() { assert_n_patterns_soundness(500, 7); }

#[test]
fn test_soundness_insert_8() { assert_n_patterns_soundness(600, 8); }

#[test]
fn test_soundness_insert_9() { assert_n_patterns_soundness(700, 9); }

#[test]
fn test_soundness_insert_10() { assert_n_patterns_soundness(800, 10); }

// 11-15: Patterns at exact block size boundaries (4096, 8192)
#[test]
fn test_boundary_11_span_4096() {
    let mut data = vec![0u8; 16384];
    data[4095..4097].copy_from_slice(b"AB"); // Spans 4096 boundary
    assert_pattern_found(&data, b"AB", 4095, 4096);
}

#[test]
fn test_boundary_12_exact_4096() {
    let mut data = vec![0u8; 16384];
    data[4096..4098].copy_from_slice(b"CD"); // Starts exactly at 4096 boundary
    assert_pattern_found(&data, b"CD", 4096, 4096);
}

#[test]
fn test_boundary_13_span_8192() {
    let mut data = vec![0u8; 16384];
    data[8191..8193].copy_from_slice(b"EF"); // Spans 8192 boundary
    assert_pattern_found(&data, b"EF", 8191, 4096);
}

#[test]
fn test_boundary_14_exact_8192() {
    let mut data = vec![0u8; 16384];
    data[8192..8194].copy_from_slice(b"GH"); // Starts exactly at 8192 boundary
    assert_pattern_found(&data, b"GH", 8192, 4096);
}

#[test]
fn test_boundary_15_span_12288() {
    let mut data = vec![0u8; 16384];
    data[12287..12289].copy_from_slice(b"IJ"); // Spans 12288 boundary
    assert_pattern_found(&data, b"IJ", 12287, 4096);
}

// 16-20: Single-byte patterns, two-byte patterns, maximum-length patterns
#[test]
fn test_length_16_single_byte() {
    let mut data = vec![0u8; 1024];
    data[500] = b'X';
    assert_pattern_found(&data, b"X", 500, 256);
}

#[test]
fn test_length_17_two_byte() {
    let mut data = vec![0u8; 1024];
    data[600..602].copy_from_slice(b"YZ");
    assert_pattern_found(&data, b"YZ", 600, 256);
}

#[test]
fn test_length_18_large_pattern() {
    let mut data = vec![0u8; 2048];
    let pattern = vec![b'A'; 1000];
    data[100..1100].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 100, 256);
}

#[test]
fn test_length_19_max_block_size_pattern() {
    let mut data = vec![0u8; 1024];
    let pattern = vec![b'B'; 256];
    data[0..256].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 0, 256);
}

#[test]
fn test_length_20_pattern_larger_than_block() {
    let mut data = vec![0u8; 2048];
    let pattern = vec![b'C'; 512];
    data[256..768].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 256, 256);
}

// 21-25: Patterns with all-zero bytes, all-0xFF bytes, alternating
#[test]
fn test_content_21_all_zeros() {
    let mut data = vec![1u8; 1024]; // Fill with 1s so 0s are unique
    let pattern = vec![0u8; 10];
    data[100..110].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 100, 256);
}

#[test]
fn test_content_22_all_ffs() {
    let mut data = vec![0u8; 1024];
    let pattern = vec![0xFFu8; 10];
    data[200..210].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 200, 256);
}

#[test]
fn test_content_23_alternating_00_ff() {
    let mut data = vec![1u8; 1024];
    let pattern = vec![0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF];
    data[300..306].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 300, 256);
}

#[test]
fn test_content_24_alternating_aa_55() {
    let mut data = vec![0u8; 1024];
    let pattern = vec![0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];
    data[400..406].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 400, 256);
}

#[test]
fn test_content_25_random_bytes() {
    let mut data = vec![0u8; 1024];
    let pattern = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    data[500..508].copy_from_slice(&pattern);
    assert_pattern_found(&data, &pattern, 500, 256);
}

// 26-30: High fill ratio (insert 10K patterns into small filter, verify all still queryable)
fn assert_high_fill_ratio(num_patterns: usize, start_id: usize) {
    let block_size = 65536; // large block to fit 10k 2-byte patterns
    let mut data = vec![0u8; block_size];
    
    // Fill a single block with many unique 2-byte patterns
    let mut offset = 0;
    let mut i = 0;
    while offset < block_size - 1 && i < num_patterns {
        let val = (start_id + i) as u16;
        data[offset] = (val & 0xFF) as u8;
        data[offset + 1] = ((val >> 8) & 0xFF) as u8;
        offset += 2;
        i += 1;
    }
    
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        // deliberately small filter for high fill (128 bits = 16 bytes, extremely small for 10k elements)
        .bloom_bits(128) 
        .build(&data)
        .unwrap();

    let mut i = 0;
    while i * 2 < block_size - 1 && i < num_patterns {
        let val = (start_id + i) as u16;
        let pattern = [(val & 0xFF) as u8, ((val >> 8) & 0xFF) as u8];
        
        let byte_filter = ByteFilter::from_patterns(&[&pattern]);
        let ngram_filter = NgramFilter::from_patterns(&[&pattern]);

        let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
        assert!(!candidates.is_empty(), "Pattern {i} not found in high fill block");
        i += 1;
    }
}

#[test]
fn test_high_fill_26() {
    assert_high_fill_ratio(10000, 0);
}

#[test]
fn test_high_fill_27() {
    assert_high_fill_ratio(10000, 10000);
}

#[test]
fn test_high_fill_28() {
    assert_high_fill_ratio(10000, 20000);
}

#[test]
fn test_high_fill_29() {
    assert_high_fill_ratio(10000, 30000);
}

#[test]
fn test_high_fill_30() {
    assert_high_fill_ratio(10000, 40000);
}

// 31-33: Empty filter queries (must return false, not panic)
#[test]
fn test_empty_query_31_empty_pattern() {
    let data = vec![0u8; 1024];
    
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let byte_filter = ByteFilter::from_patterns(&[b""]);
    let ngram_filter = NgramFilter::from_patterns(&[b""]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    // Since pattern is empty and data is all zeros, it shouldn't find anything actually. Wait, empty patterns trivially match everything in regex but we are a bloom filter.
    // The requirement says "must return false". So candidates must be empty.
    assert!(candidates.is_empty());
}

#[test]
fn test_empty_query_32_empty_data_nonempty_pattern() {
    let data = vec![0u8; 0];
    
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let byte_filter = ByteFilter::from_patterns(&[b"TEST"]);
    let ngram_filter = NgramFilter::from_patterns(&[b"TEST"]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(candidates.is_empty(), "Empty data should have no candidates");
}

#[test]
fn test_empty_query_33_empty_data_empty_pattern() {
    let data = vec![0u8; 0];
    
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let byte_filter = ByteFilter::from_patterns(&[b""]);
    let ngram_filter = NgramFilter::from_patterns(&[b""]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
    assert!(candidates.is_empty());
}



