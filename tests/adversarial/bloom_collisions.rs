use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};

#[test]
fn test_bloom_collisions_zero_fnr() {
    // We want to generate inputs designed to maximize bloom filter FPR and verify FNR is 0.
    // Hash flooding / pathological collisions. We can simulate high FPR by using very small bloom filters with lots of n-grams.

    let block_size = 256;
    let bloom_bits = 64; // Very small bloom filter to maximize collisions

    // Pattern we KNOW exists
    let pattern = b"SECRET_TOKEN_123";

    // We will build a block that contains our pattern and lots of other noise to fill the bloom filter
    let mut data = vec![0u8; block_size];

    // Fill the rest with random data to saturate the bloom filter
    for i in 0..block_size {
        data[i] = (i % 256) as u8;
    }

    // Place pattern in the middle
    let start = block_size / 2 - pattern.len() / 2;
    data[start..start + pattern.len()].copy_from_slice(pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(bloom_bits)
        .build(&data)
        .expect("build should succeed");

    let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

    let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

    assert_eq!(candidates.len(), 1, "FINDING: False negative! Block containing pattern was not returned despite bloom saturation.");
    assert_eq!(candidates[0].offset, 0);

    // Let's also do a larger test with many blocks, all saturated, to ensure 0 FNR.
    let num_blocks = 100;
    let mut large_data = vec![0u8; block_size * num_blocks];

    for i in 0..num_blocks {
        let block_start = i * block_size;
        for j in 0..block_size {
            large_data[block_start + j] = ((i + j) % 256) as u8;
        }
        // Place pattern
        if i % 2 == 0 {
            // Even blocks have pattern
            let p_start = block_start + 10;
            large_data[p_start..p_start + pattern.len()].copy_from_slice(pattern);
        }
    }

    let large_index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(bloom_bits) // Extremely small bloom size causes 100% FPR
        .build(&large_data)
        .expect("build should succeed");

    let large_candidates = large_index.candidate_blocks(&byte_filter, &ngram_filter);

    // Even blocks have the pattern, but since FPR is 100%, ALL blocks might be candidates.
    // The key is that FNR MUST BE ZERO: all even blocks MUST be candidates.
    for i in 0..num_blocks {
        if i % 2 == 0 {
            let target_offset = i * block_size;
            let found = large_candidates
                .iter()
                .any(|c| c.offset <= target_offset && target_offset < c.offset + c.length);
            assert!(
                found,
                "FINDING: False negative in saturated bloom filter at block {}",
                i
            );
        }
    }
}
