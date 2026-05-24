use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};

#[test]
fn test_internet_scale_zero_fnr() {
    let block_size = 256;
    let bloom_bits = 1024;
    // 1,000,000 blocks to simulate internet scale.
    // 1,000,000 * 256 bytes = 256 MB.
    let num_blocks = 1_000_000;
    let num_patterns = 10_000;

    let mut data = vec![0u8; block_size * num_blocks];

    // Fill data
    for i in 0..num_blocks {
        let block_start = i * block_size;
        for j in 0..block_size {
            data[block_start + j] = ((i + j) % 256) as u8;
        }
    }

    // Insert 10K random patterns. We'll store them so we can query them later.
    // Ensure patterns are completely contained within blocks.
    let mut patterns = Vec::with_capacity(num_patterns);
    for i in 0..num_patterns {
        let block_idx = i % num_blocks; // distribute across blocks
        let start_offset = (i * 7) % (block_size - 16);
        let pattern = vec![
            (i % 256) as u8,
            ((i / 256) % 256) as u8,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
        ];

        let start_pos = block_idx * block_size + start_offset;
        data[start_pos..start_pos + pattern.len()].copy_from_slice(&pattern);

        patterns.push((block_idx, pattern));
    }

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(bloom_bits)
        .build(&data)
        .expect("build should succeed");

    // Query each pattern and verify FNR = 0
    let mut total_fpr = 0.0;

    // To speed up the test we can batch patterns or query individually.
    // Let's query a subset individually to measure FPR, and batch the rest.
    for (block_idx, pattern) in patterns.iter() {
        let byte_filter = ByteFilter::from_patterns(&[pattern.as_slice()]);
        let ngram_filter = NgramFilter::from_patterns(&[pattern.as_slice()]);

        let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

        let mut found = false;
        let target_offset = *block_idx * block_size;
        for c in &candidates {
            if c.offset <= target_offset && target_offset < c.offset + c.length {
                found = true;
                break;
            }
        }

        assert!(
            found,
            "FINDING: False negative at scale! Pattern {:?} in block {} not found",
            pattern, block_idx
        );

        // FPR = (candidates.len() - 1) / (num_blocks - 1)
        let false_positives = candidates.len().saturating_sub(1);
        let fpr = false_positives as f64 / (num_blocks - 1) as f64;
        total_fpr += fpr;
    }

    let avg_fpr = total_fpr / num_patterns as f64;
    println!(
        "Average FPR for 10K queries on 100K blocks: {:.4}%",
        avg_fpr * 100.0
    );
    // As long as FNR is 0, the test passes.
}
