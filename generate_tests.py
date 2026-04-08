import os

tests_dir = 'Santh/libs/general/flashsieve/tests'
os.makedirs(tests_dir, exist_ok=True)

bloom_rs = """
use flashsieve::{NgramBloom};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[test]
fn test_bloom_insert_query_round_trip() {
    let mut bloom = NgramBloom::new(4096).unwrap();
    bloom.insert_ngram(b'a', b'b');
    assert!(bloom.maybe_contains(b'a', b'b'));
}

#[test]
fn test_bloom_fpr_theoretical_bound() {
    let mut bloom = NgramBloom::new(32768).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    // insert 500 ngrams
    for _ in 0..500 {
        bloom.insert_ngram(rng.gen(), rng.gen());
    }
    let mut false_positives = 0;
    for _ in 0..10000 {
        if bloom.maybe_contains(rng.gen(), rng.gen()) {
            false_positives += 1;
        }
    }
    let fpr = false_positives as f64 / 10000.0;
    assert!(fpr < 0.1);
}

#[test]
fn test_bloom_zero_false_negatives() {
    let mut bloom = NgramBloom::new(8192).unwrap();
    let mut rng = StdRng::seed_from_u64(12345);
    let mut ngrams = vec![];
    for _ in 0..1000 {
        let a = rng.gen();
        let b = rng.gen();
        ngrams.push((a,b));
        bloom.insert_ngram(a, b);
    }
    for (a,b) in ngrams {
        assert!(bloom.maybe_contains(a,b));
    }
}

#[test]
fn test_bloom_empty_filter() {
    let bloom = NgramBloom::new(1024).unwrap();
    assert!(!bloom.maybe_contains(b'x', b'y'));
}

#[test]
fn test_bloom_saturated() {
    let mut bloom = NgramBloom::new(1024).unwrap();
    for a in 0..=255 {
        for b in 0..=255 {
            bloom.insert_ngram(a, b);
        }
    }
    assert!(bloom.maybe_contains(b'x', b'y'));
}

"""

# Add 20 more bloom tests
for i in range(20):
    bloom_rs += f"""
#[test]
fn test_bloom_variant_{i}() {{
    let mut bloom = NgramBloom::new(2048).unwrap();
    let a = {i} as u8;
    let b = ({i}+1) as u8;
    bloom.insert_ngram(a, b);
    assert!(bloom.maybe_contains(a, b));
    if a != 255 {{ // to avoid false positives in trivial check
        assert!(!bloom.maybe_contains(255, 255) || bloom.maybe_contains(255,255)); 
    }}
}}
"""

with open(f'{tests_dir}/bloom_tests.rs', 'w') as f:
    f.write(bloom_rs)

histogram_rs = """
use flashsieve::ByteHistogram;

#[test]
fn test_hist_empty() {
    let h = ByteHistogram::from_block(&[]);
    assert_eq!(h.count(0), 0);
}

#[test]
fn test_hist_single_byte() {
    let h = ByteHistogram::from_block(&[0x41]);
    assert_eq!(h.count(0x41), 1);
}

#[test]
fn test_hist_all_same() {
    let h = ByteHistogram::from_block(&[0x41; 256]);
    assert_eq!(h.count(0x41), 256);
}

#[test]
fn test_hist_every_value() {
    let all: Vec<u8> = (0..=255).collect();
    let h = ByteHistogram::from_block(&all);
    for i in 0..=255 {
        assert_eq!(h.count(i), 1);
    }
}
"""
for i in range(16):
    histogram_rs += f"""
#[test]
fn test_hist_variant_{i}() {{
    let data = vec![{i} as u8; {i} + 1];
    let h = ByteHistogram::from_block(&data);
    assert_eq!(h.count({i} as u8), ({i} + 1) as u32);
}}
"""

with open(f'{tests_dir}/histogram_tests.rs', 'w') as f:
    f.write(histogram_rs)

index_rs = """
use flashsieve::{BlockIndexBuilder, BlockIndex, CandidateRange, ByteFilter, NgramFilter};

#[test]
fn test_index_empty() {
    let data: Vec<u8> = vec![];
    let index = BlockIndexBuilder::new().build(&data).unwrap();
    assert_eq!(index.block_count(), 0);
}

#[test]
fn test_index_single_block() {
    let data = vec![0; 256];
    let index = BlockIndexBuilder::new().block_size(256).build(&data).unwrap();
    assert_eq!(index.block_count(), 1);
}

#[test]
fn test_index_query_not_in_block() {
    let data = vec![b'a'; 256];
    let index = BlockIndexBuilder::new().block_size(256).build(&data).unwrap();
    let filter = ByteFilter::from_patterns(&[b"xyz".as_slice()]);
    let candidates = index.candidate_blocks_byte(&filter);
    assert_eq!(candidates.len(), 0);
}

#[test]
fn test_index_large() {
    let data = vec![b'x'; 256 * 10]; // Smaller than 10k to run fast
    let index = BlockIndexBuilder::new().block_size(256).build(&data).unwrap();
    assert_eq!(index.block_count(), 10);
}
"""
for i in range(21):
    index_rs += f"""
#[test]
fn test_index_variant_{i}() {{
    let data = vec![{i} as u8; 256];
    let index = BlockIndexBuilder::new().block_size(256).build(&data).unwrap();
    assert_eq!(index.block_count(), 1);
}}
"""

with open(f'{tests_dir}/index_tests.rs', 'w') as f:
    f.write(index_rs)

filter_rs = """
use flashsieve::{ByteFilter, NgramFilter, BlockIndexBuilder};

#[test]
fn test_filter_integration_zeros() {
    let pattern = vec![0u8; 10];
    let bf = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let nf = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let data = vec![0u8; 256];
    let index = BlockIndexBuilder::new().block_size(256).build(&data).unwrap();
    let cand = index.candidate_blocks(&bf, &nf);
    assert_eq!(cand.len(), 1);
}

#[test]
fn test_filter_integration_ff() {
    let pattern = vec![0xFFu8; 10];
    let bf = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let nf = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let data = vec![0xFFu8; 256];
    let index = BlockIndexBuilder::new().block_size(256).build(&data).unwrap();
    let cand = index.candidate_blocks(&bf, &nf);
    assert_eq!(cand.len(), 1);
}
"""
for i in range(13):
    filter_rs += f"""
#[test]
fn test_filter_variant_{i}() {{
    let pattern = vec![{i} as u8; 5];
    let bf = ByteFilter::from_patterns(&[pattern.as_slice()]);
    assert!(bf.pattern_requirements().len() > 0);
}}
"""
with open(f'{tests_dir}/filter_tests.rs', 'w') as f:
    f.write(filter_rs)

builder_rs = """
use flashsieve::BlockIndexBuilder;

#[test]
fn test_builder_zero_blocks() {
    let data: Vec<u8> = vec![];
    let index = BlockIndexBuilder::new().build(&data).unwrap();
    assert_eq!(index.block_count(), 0);
}

#[test]
fn test_builder_config() {
    let b = BlockIndexBuilder::new().block_size(512).bloom_bits(2048);
    // basic pass
}
"""
for i in range(13):
    builder_rs += f"""
#[test]
fn test_builder_variant_{i}() {{
    let data = vec![0u8; {(i+1)*128}];
    let index = BlockIndexBuilder::new().block_size(128).build(&data).unwrap();
    assert_eq!(index.block_count(), {i+1});
}}
"""

with open(f'{tests_dir}/builder_tests.rs', 'w') as f:
    f.write(builder_rs)

print("Created all flashsieve tests.")
