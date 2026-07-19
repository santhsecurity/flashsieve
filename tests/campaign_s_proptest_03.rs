//! S-proptest-03 (flashsieve mass proptest: bloom/index invariants, no panic on arbitrary bytes).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use flashsieve::{
    BlockIndexBuilder, BlockedNgramBloom, ByteFilter, ByteHistogram, NgramBloom, NgramFilter,
};
use proptest::prelude::*;

fn bloom_size() -> impl Strategy<Value = usize> {
    prop_oneof![Just(64usize), 128usize..=1024, 1024usize..=4096]
}

fn ngram() -> impl Strategy<Value = (u8, u8)> {
    any::<(u8, u8)>()
}

macro_rules! flash_cases {
    ($($name:ident => |$block:ident, $size:ident| $body:block),+ $(,)?) => {
        $(
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(64))]
                #[test]
                // Some property cases exercise only `block` and legitimately
                // ignore the generated `size` input; allow that without forcing
                // an underscore that would break the cases which DO use `size`.
                #[allow(unused_variables)]
                fn $name(
                    $block in prop::collection::vec(any::<u8>(), 0..512),
                    $size in bloom_size(),
                ) {
                    $body
                }
            }
        )+
    };
}

flash_cases! {
    p00_ngram_bloom_no_false_negative_inserted => |block, size| {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            for w in block.windows(2) {
                bloom.insert_ngram(w[0], w[1]);
            }
            for w in block.windows(2) {
                prop_assert!(bloom.maybe_contains(w[0], w[1]));
            }
        }
    },
    p01_blocked_bloom_no_false_negative => |block, size| {
        if block.len() >= 2 {
            if let Ok(mut bloom) = BlockedNgramBloom::new(size) {
                for w in block.windows(2) {
                    bloom.insert(w[0], w[1]);
                }
                for w in block.windows(2) {
                    prop_assert!(bloom.maybe_contains(w[0], w[1]));
                }
            }
        }
    },
    p02_ngram_insert_idempotent => |block, size| {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            if block.len() >= 2 {
                let (a, b) = (block[0], block[1]);
                bloom.insert_ngram(a, b);
                bloom.insert_ngram(a, b);
                prop_assert!(bloom.maybe_contains(a, b));
            }
        }
    },
    p03_byte_filter_from_patterns => |block, size| {
        if !block.is_empty() {
            let patterns: Vec<&[u8]> = vec![&block[..block.len().min(8)]];
            let _ = ByteFilter::from_patterns(&patterns);
        }
    },
    p04_ngram_filter_from_patterns => |block, size| {
        if block.len() >= 2 {
            let pat = &block[..block.len().min(16)];
            let _ = NgramFilter::from_patterns(&[pat]);
        }
    },
    p05_block_index_build_streaming => |block, size| {
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let blocks = if block.is_empty() {
            vec![vec![0u8; 64]]
        } else {
            vec![block.clone()]
        };
        let _ = builder.build_streaming(blocks.into_iter());
    },
    p06_block_index_build_flat => |block, size| {
        let builder = BlockIndexBuilder::new().block_size(64).bloom_bits(size.max(64));
        let data = if block.is_empty() { vec![0u8; 64] } else { block.clone() };
        let _ = builder.build(&data);
    },
    p07_ngram_bloom_maybe_contains_never_panics => |block, size| {
        if let Ok(bloom) = NgramBloom::new(size) {
            for w in block.windows(2) {
                let _ = bloom.maybe_contains(w[0], w[1]);
            }
        }
    },
    p08_blocked_bloom_maybe_contains_never_panics => |block, size| {
        if let Ok(bloom) = BlockedNgramBloom::new(size) {
            for w in block.windows(2) {
                let _ = bloom.maybe_contains(w[0], w[1]);
            }
        }
    },
    p09_random_pair_insert_lookup => |block, size| {
        if let Ok(mut bloom) = NgramBloom::new(size) {
            for i in 0..block.len().saturating_sub(1) {
                bloom.insert_ngram(block[i], block[i + 1]);
            }
            for i in 0..block.len().saturating_sub(1) {
                prop_assert!(bloom.maybe_contains(block[i], block[i + 1]));
            }
        }
    },
    p10_empty_block_bloom_ok => |_block, size| {
        let _ = NgramBloom::new(size);
    },
}

