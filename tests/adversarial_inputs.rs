use flashsieve::{BlockIndexBuilder, ByteFilter, NgramBloom, NgramFilter};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Insert every possible 2-byte n-gram into a bloom filter and verify
/// zero false negatives under exhaustive query.
#[test]
fn exhaustive_all_65536_ngrams_zero_false_negatives() {
    let mut bloom = NgramBloom::new(65_536).unwrap();
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            bloom.insert_ngram(a, b);
        }
    }

    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            assert!(
                bloom.maybe_contains(a, b),
                "false negative for ({a}, {b}) after exhaustive insert"
            );
        }
    }
}

/// Patterns placed at exact block boundaries must not produce false negatives.
#[test]
fn patterns_at_exact_block_boundaries() {
    let block_size = 256;
    let pattern = b"boundary";
    let mut data = vec![b'x'; block_size * 3];

    // Place pattern so it straddles block 0/1 and block 1/2
    let offset1 = block_size - 2;
    let offset2 = block_size * 2 - 3;
    data[offset1..offset1 + pattern.len()].copy_from_slice(pattern);
    data[offset2..offset2 + pattern.len()].copy_from_slice(pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let bf = ByteFilter::from_patterns(&[pattern.as_slice()]);
    let nf = NgramFilter::from_patterns(&[pattern.as_slice()]);
    let candidates = index.candidate_blocks(&bf, &nf);

    for &offset in &[offset1, offset2] {
        let expected_start = (offset / block_size) * block_size;
        let found = candidates.iter().any(|r| {
            expected_start >= r.offset && expected_start < r.offset + r.length
        });
        eprintln!("offset={} expected_start={} candidates={:?} found={}", offset, expected_start, candidates, found);
        assert!(
            found,
            "pattern at offset {offset} not found in candidates {candidates:?}"
        );
    }
}

/// Highly repetitive data (worst-case for histogram aliasing) must be correct.
#[test]
fn worst_case_repetitive_data() {
    let data = vec![0x41; 10_000];
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let bf = ByteFilter::from_patterns(&[b"AAAA".as_slice()]);
    let nf = NgramFilter::from_patterns(&[b"AAAA".as_slice()]);
    let candidates = index.candidate_blocks(&bf, &nf);

    // Every block contains only 'A', so every block should match
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].length, index.total_data_length());
}

/// Random garbage data should never cause a panic during indexing or querying.
#[test]
fn random_garbage_never_panics() {
    let mut rng = StdRng::seed_from_u64(0x6A6B_6167);
    for _ in 0..1000 {
        let len = rng.gen_range(0..4096);
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        let _ = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(&data);
    }
}

/// Random garbage serialized indexes should never panic during deserialization.
#[test]
fn random_serialized_garbage_never_panics() {
    let mut rng = StdRng::seed_from_u64(0x6A6B_616A);
    for _ in 0..1000 {
        let len = rng.gen_range(0..2000);
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        let _ = flashsieve::BlockIndex::from_bytes(&data);
        let _ = flashsieve::BlockIndex::from_bytes_checked(&data);
        let _ = flashsieve::MmapBlockIndex::from_slice(&data);
    }
}

/// Collision resistance: many distinct patterns sharing the same byte set
/// should still produce correct candidates.
#[test]
fn collision_resistance_shared_byte_set() {
    let data = b"abcdefghijklmnopqrstuvwxyz";
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(data)
        .unwrap();

    // All patterns use the exact same bytes, but only one is present
    let patterns: Vec<&[u8]> = vec![
        b"abcde",
        b"edcba",
        b"aebcd",
        b"badce",
    ];

    let bf = ByteFilter::from_patterns(&patterns);
    let nf = NgramFilter::from_patterns(&patterns);
    let candidates = index.candidate_blocks(&bf, &nf);

    // Because of cross-pattern false positives from shared bytes/n-grams,
    // candidates might still include the block, but it must NOT be empty
    // for the patterns that actually match.
    assert!(!candidates.is_empty());
}

/// Maximum block size (power of two) should still work end-to-end.
#[test]
fn large_block_size_end_to_end() {
    let block_size = 65536;
    let mut data = vec![b'x'; block_size * 2];
    data[1000..1006].copy_from_slice(b"secret");

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192)
        .build(&data)
        .unwrap();

    let bf = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    let nf = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    let candidates = index.candidate_blocks(&bf, &nf);
    assert!(!candidates.is_empty());
}
