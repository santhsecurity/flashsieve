#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, NgramFilter};

#[test]
fn test_resource_exhaustion_massive_filter() {
    // Generate 100,000 patterns to test filter creation time/memory.
    let mut patterns = Vec::new();
    let mut arena = Vec::new();
    for i in 0..100_000 {
        arena.push(format!("pattern_{i}").into_bytes());
    }
    for p in &arena {
        patterns.push(p.as_slice());
    }

    // This shouldn't panic or OOM if bounded properly.
    let filter = NgramFilter::from_patterns(&patterns);
    let bloom = flashsieve::NgramBloom::from_block(b"pattern_500", 1024).unwrap();
    assert!(filter.matches_bloom(&bloom));
}

#[test]
fn test_builder_massive_block_size() {
    // 2 GB block size
    let builder = BlockIndexBuilder::new().block_size(2 * 1024 * 1024 * 1024);
    // Build empty data with it
    let index = builder.build(&[]).unwrap();
    assert_eq!(index.block_size(), 2 * 1024 * 1024 * 1024);
}
