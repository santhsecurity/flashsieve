//! S-proptest-03 - flashsieve mass proptest (p11-p34).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use flashsieve::{
    BlockIndexBuilder, BlockedNgramBloom, ByteFilter, ByteHistogram, NgramBloom, NgramFilter,
};
use proptest::prelude::*;

fn bloom_size() -> impl Strategy<Value = usize> {
    prop_oneof![Just(64usize), 128usize..=1024, 1024usize..=4096]
}

fn ngram_strategy() -> impl Strategy<Value = (u8, u8)> {
    any::<(u8, u8)>()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn p11_ngram_strategy_insert(
        grams in prop::collection::vec(any::<(u8, u8)>(), 0..64),
        size in bloom_size(),
    ) {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            for (a, b) in &grams {
                bloom.insert_ngram(*a, *b);
            }
            for (a, b) in &grams {
                prop_assert!(bloom.maybe_contains(*a, *b));
            }
        }
    }

    #[test]
    fn p12_blocked_ngram_strategy_insert(
        grams in prop::collection::vec(any::<(u8, u8)>(), 1..64),
        size in bloom_size(),
    ) {
        if let Ok(mut bloom) = BlockedNgramBloom::new(size) {
            for (a, b) in &grams {
                bloom.insert(*a, *b);
            }
            for (a, b) in &grams {
                prop_assert!(bloom.maybe_contains(*a, *b));
            }
        }
    }

    #[test]
    fn p13_multi_pattern_byte_filter(
        patterns in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..8), 1..4),
        block in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let refs: Vec<&[u8]> = patterns.iter().map(Vec::as_slice).collect();
        let filter = ByteFilter::from_patterns(&refs);
        let hist = ByteHistogram::from_block(&block);
        let _ = filter.matches_histogram(&hist);
    }

    #[test]
    fn p14_multi_pattern_ngram_filter(
        patterns in prop::collection::vec(prop::collection::vec(any::<u8>(), 2..8), 1..4),
    ) {
        let refs: Vec<&[u8]> = patterns.iter().map(Vec::as_slice).collect();
        let _ = NgramFilter::from_patterns(&refs);
    }

    #[test]
    fn p15_builder_two_blocks(
        a in prop::collection::vec(any::<u8>(), 1..128),
        b in prop::collection::vec(any::<u8>(), 1..128),
        size in bloom_size(),
    ) {
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let _ = builder.build_streaming(vec![a, b].into_iter());
    }

    #[test]
    fn p16_builder_large_block_size(
        block in prop::collection::vec(any::<u8>(), 0..256),
        size in bloom_size(),
    ) {
        let builder = BlockIndexBuilder::new().block_size(256).bloom_bits(size.max(64));
        let data = if block.len() < 256 {
            let mut padded = block;
            padded.resize(256, 0);
            padded
        } else {
            block
        };
        let _ = builder.build(&data);
    }

    #[test]
    fn p17_ngram_bloom_after_clear_pattern(
        block in prop::collection::vec(any::<u8>(), 2..64),
        size in bloom_size(),
    ) {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            let (a, b) = (block[0], block[1]);
            bloom.insert_ngram(a, b);
            prop_assert!(bloom.maybe_contains(a, b));
            prop_assert!(!bloom.maybe_contains(a, b ^ 0xFF) || (a, b ^ 0xFF) == (a, b));
        }
    }

    #[test]
    fn p18_index_candidate_blocks_smoke(
        block in prop::collection::vec(any::<u8>(), 64..128),
        size in bloom_size(),
    ) {
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        if let Ok(index) = builder.build(&block) {
            let pat = if block.len() >= 2 { &block[..2] } else { b"ab" };
            let byte_f = ByteFilter::from_patterns(&[pat]);
            let ngram_f = NgramFilter::from_patterns(&[pat]);
            let _ = index.candidate_blocks(&byte_f, &ngram_f);
        }
    }

    #[test]
    fn p19_blocked_bloom_double_insert(
        a in any::<u8>(),
        b in any::<u8>(),
        size in bloom_size(),
    ) {
        if let Ok(mut bloom) = BlockedNgramBloom::new(size) {
            bloom.insert(a, b);
            bloom.insert(a, b);
            prop_assert!(bloom.maybe_contains(a, b));
        }
    }

    #[test]
    fn p20_ngram_bloom_all_ff_pairs(size in bloom_size()) {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            bloom.insert_ngram(0xFF, 0xFF);
            prop_assert!(bloom.maybe_contains(0xFF, 0xFF));
        }
    }

    #[test]
    fn p21_ngram_bloom_all_zero_pairs(size in bloom_size()) {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            bloom.insert_ngram(0, 0);
            prop_assert!(bloom.maybe_contains(0, 0));
        }
    }

    #[test]
    fn p22_byte_filter_empty_patterns_ok(_unused in 0..1i32) {
        let empty: &[&[u8]] = &[];
        let _ = ByteFilter::from_patterns(empty);
    }

    #[test]
    fn p23_streaming_empty_iterator(size in bloom_size()) {
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let blocks: Vec<Vec<u8>> = vec![];
        let _ = builder.build_streaming(blocks.into_iter());
    }

    #[test]
    fn p24_high_entropy_block(
        block in prop::collection::vec(any::<u8>(), 64..128),
        size in bloom_size(),
    ) {
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let _ = builder.build(&block);
    }

    #[test]
    fn p25_repeated_byte_block(byte in any::<u8>(), size in bloom_size()) {
        let block = vec![byte; 128];
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let _ = builder.build(&block);
    }

    #[test]
    fn p26_alternating_block(size in bloom_size()) {
        let block: Vec<u8> = (0..128u8).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let _ = builder.build(&block);
    }

    #[test]
    fn p27_many_small_patterns(block in prop::collection::vec(any::<u8>(), 8..64)) {
        let patterns: Vec<&[u8]> = block.windows(2).map(|w| &w[..]).collect();
        if !patterns.is_empty() {
            let _ = NgramFilter::from_patterns(&patterns);
        }
    }

    #[test]
    fn p28_builder_default_config(block in prop::collection::vec(any::<u8>(), 1..256)) {
        let builder = BlockIndexBuilder::new();
        let padded = if block.len() < 64 {
            let mut p = block;
            p.resize(64, 0);
            p
        } else {
            block
        };
        let _ = builder.build(&padded);
    }

    #[test]
    fn p29_ngram_filter_single_byte_pattern_skipped(
        block in prop::collection::vec(any::<u8>(), 1..4),
    ) {
        let _ = NgramFilter::from_patterns(&[&block]);
    }

    #[test]
    fn p30_blocked_bloom_many_pairs(
        grams in prop::collection::vec(any::<(u8, u8)>(), 1..128),
        size in bloom_size(),
    ) {
        if let Ok(mut bloom) = BlockedNgramBloom::new(size) {
            for (a, b) in grams {
                bloom.insert(a, b);
            }
        }
    }

    #[test]
    fn p31_ngram_bloom_many_pairs(
        grams in prop::collection::vec(any::<(u8, u8)>(), 1..128),
        size in bloom_size(),
    ) {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            for (a, b) in grams {
                bloom.insert_ngram(a, b);
            }
        }
    }

    #[test]
    fn p32_three_block_stream(
        a in prop::collection::vec(any::<u8>(), 64..96),
        b in prop::collection::vec(any::<u8>(), 64..96),
        c in prop::collection::vec(any::<u8>(), 64..96),
        size in bloom_size(),
    ) {
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let _ = builder.build_streaming(vec![a, b, c].into_iter());
    }

    #[test]
    fn p33_byte_filter_matches_histogram(block in prop::collection::vec(any::<u8>(), 1..32)) {
        let filter = ByteFilter::from_patterns(&[&block]);
        let hist = ByteHistogram::from_block(&block);
        let _ = filter.matches_histogram(&hist);
    }

    #[test]
    fn p34_ngram_bloom_size_pow2(block in prop::collection::vec(any::<u8>(), 0..64)) {
        for bits in [64usize, 128, 256, 512] {
            if let Ok(mut bloom) = NgramBloom::new(bits) {
                for w in block.windows(2) {
                    bloom.insert_ngram(w[0], w[1]);
                }
            }
        }
    }
}
