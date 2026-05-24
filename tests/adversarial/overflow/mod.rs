#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::BlockIndexBuilder;

#[test]
fn test_overflow_block_size() {
    // Extremely large block sizes shouldn't overflow calculations inside builder
    let max_pow2 = 1usize << (usize::BITS - 1);

    // We expect this to fail gracefully or not panic if the data is small
    // Actually, block size is required to be power of two.
    let builder = BlockIndexBuilder::new().block_size(max_pow2);
    let index = builder.build(&[]).unwrap();
    assert_eq!(index.block_size(), max_pow2);
}
