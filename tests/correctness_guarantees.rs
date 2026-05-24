//! Correctness audit invariants for flashsieve bloom filters.
//! A failure here is a security-critical finding: false negatives cause warpscan
//! to skip files that contain malware.

use flashsieve::{BlockedNgramBloom, NgramBloom};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

fn insert_pattern_ngram(bloom: &mut NgramBloom, pattern: &[u8]) {
    for w in pattern.windows(2) { bloom.insert_ngram(w[0], w[1]); }
}
fn insert_pattern_blocked(bloom: &mut BlockedNgramBloom, pattern: &[u8]) {
    for w in pattern.windows(2) { bloom.insert(w[0], w[1]); }
}
fn blocked_maybe_contains_pattern(bloom: &BlockedNgramBloom, pattern: &[u8]) -> bool {
    pattern.windows(2).all(|w| bloom.maybe_contains(w[0], w[1]))
}
fn random_patterns(rng: &mut StdRng, n: usize, len: usize) -> Vec<Vec<u8>> {
    (0..n).map(|_| (0..len).map(|_| rng.gen::<u8>()).collect()).collect()
}
fn random_distinct_ngrams(rng: &mut StdRng, n: usize) -> Vec<(u8, u8)> {
    let mut set = HashSet::new();
    while set.len() < n { set.insert((rng.gen(), rng.gen())); }
    set.into_iter().collect()
}

// 1. ZERO FALSE NEGATIVES
#[test]
fn zero_false_negatives_across_scales() {
    let mut rng = StdRng::seed_from_u64(0xC0FF_EE00);
    const PATTERN_LEN: usize = 8;
    for &n in &[1usize, 10, 100, 1000, 10000, 100000] {
        let patterns = random_patterns(&mut rng, n, PATTERN_LEN);
        let expected_ngrams = n * (PATTERN_LEN - 1);
        let mut bloom = NgramBloom::with_target_fpr(0.01, expected_ngrams)
            .unwrap_or_else(|e| panic!("failed to create bloom for N={n}: {e}"));
        for p in &patterns { insert_pattern_ngram(&mut bloom, p); }
        for p in &patterns {
            assert!(bloom.maybe_contains_pattern(p), "FALSE NEGATIVE at scale N={n} for pattern {p:?}");
        }
    }
    for &n in &[100usize, 1000, 10000] {
        let patterns = random_patterns(&mut rng, n, PATTERN_LEN);
        let mut bloom = BlockedNgramBloom::new(65_536)
            .unwrap_or_else(|e| panic!("failed to create blocked bloom for N={n}: {e}"));
        for p in &patterns { insert_pattern_blocked(&mut bloom, p); }
        for p in &patterns {
            assert!(blocked_maybe_contains_pattern(&bloom, p), "FALSE NEGATIVE in BlockedNgramBloom at scale N={n} for pattern {p:?}");
        }
    }
}

// 2. FALSE POSITIVE RATE
#[test]
fn false_positive_rate_matches_theory() {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    const M: usize = 2048;
    const N: usize = 500;
    const K: u32 = 3;
    const TRIALS: usize = 20_000;
    let mut bloom = NgramBloom::new(M).unwrap();
    let inserted: HashSet<(u8, u8)> = random_distinct_ngrams(&mut rng, N).into_iter().collect();
    for &(a, b) in &inserted { bloom.insert_ngram(a, b); }
    let mut false_positives = 0usize;
    for _ in 0..TRIALS {
        let (a, b) = loop {
            let p = (rng.gen::<u8>(), rng.gen::<u8>());
            if !inserted.contains(&p) { break p; }
        };
        if bloom.maybe_contains_bloom(a, b) { false_positives += 1; }
    }
    let measured = false_positives as f64 / TRIALS as f64;
    let theoretical = (1.0f64 - (-(K as f64) * N as f64 / M as f64).exp()).powi(K as i32);
    let diff = (measured - theoretical).abs();
    assert!(diff < 0.02, "FP rate mismatch: measured={measured:.4}, theoretical={theoretical:.4}, diff={diff:.4}");
}

// 3. HASH INDEPENDENCE
#[test]
fn hash_independence_verified() {
    #[inline(always)] fn wyhash_pair(a: u8, b: u8) -> u64 {
        let x = (u64::from(a) << 8) | u64::from(b);
        let x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x ^ (x >> 32)
    }
    #[inline(always)] fn derive_second_hash(h1: u64) -> u64 {
        let h2 = h1 ^ (h1 >> 32); h2.max(1)
    }
    let mut rng = StdRng::seed_from_u64(0x1111_2222_3333_4444);
    const M: usize = 1 << 20;
    const SAMPLES: usize = 100_000;
    const BUCKETS: usize = 1024;
    let mask = (M as u64).wrapping_sub(1);
    let (mut idx0, mut idx1, mut idx2) = (vec![0usize; SAMPLES], vec![0usize; SAMPLES], vec![0usize; SAMPLES]);
    for i in 0..SAMPLES {
        let (a, b) = (rng.gen::<u8>(), rng.gen::<u8>());
        let h1 = wyhash_pair(a, b);
        let h2 = derive_second_hash(h1);
        idx0[i] = (h1 & mask) as usize;
        idx1[i] = (h1.wrapping_add(h2) & mask) as usize;
        idx2[i] = (h1.wrapping_add(h2.wrapping_mul(2)) & mask) as usize;
    }
    let expected = SAMPLES as f64 / BUCKETS as f64;
    for probe in [&idx0, &idx1, &idx2] {
        let mut counts = vec![0usize; BUCKETS];
        for &v in probe.iter() { counts[v % BUCKETS] += 1; }
        assert!(counts.iter().copied().min().unwrap() > 0, "uniformity failure: empty bucket");
        assert!(counts.iter().copied().max().unwrap() < (expected * 3.0) as usize,
            "uniformity failure: max bucket count far exceeds expected {expected}");
    }
    let (mut c01, mut c02, mut c12) = (0usize, 0usize, 0usize);
    for i in 0..SAMPLES {
        if idx0[i] == idx1[i] { c01 += 1; }
        if idx0[i] == idx2[i] { c02 += 1; }
        if idx1[i] == idx2[i] { c12 += 1; }
    }
    assert!(c01 <= 5, "too many idx0==idx1 collisions: {c01}");
    assert!(c02 <= 5, "too many idx0==idx2 collisions: {c02}");
    assert!(c12 <= 5, "too many idx1==idx2 collisions: {c12}");
    fn pearson(x: &[usize], y: &[usize]) -> f64 {
        let n = x.len() as f64;
        let (mx, my) = (x.iter().sum::<usize>() as f64 / n, y.iter().sum::<usize>() as f64 / n);
        let num: f64 = x.iter().zip(y).map(|(&xi, &yi)| {
            let (dx, dy) = (xi as f64 - mx, yi as f64 - my); dx * dy
        }).sum();
        let denx: f64 = x.iter().map(|&xi| { let dx = xi as f64 - mx; dx * dx }).sum();
        let deny: f64 = y.iter().map(|&yi| { let dy = yi as f64 - my; dy * dy }).sum();
        num / (denx.sqrt() * deny.sqrt())
    }
    assert!(pearson(&idx0, &idx1).abs() < 0.01, "correlation idx0-idx1 too high");
    assert!(pearson(&idx0, &idx2).abs() < 0.01, "correlation idx0-idx2 too high");
    assert!(pearson(&idx1, &idx2).abs() < 0.01, "correlation idx1-idx2 too high");
}

// 4. CAPACITY OVERFLOW
#[test]
fn capacity_overflow_never_creates_false_negatives() {
    let mut rng = StdRng::seed_from_u64(0x0BAD_C0DE);
    let mut bloom = NgramBloom::with_target_fpr(0.01, 100).unwrap();
    let inserted = random_distinct_ngrams(&mut rng, 10_000);
    for &(a, b) in &inserted { bloom.insert_ngram(a, b); }
    for &(a, b) in &inserted { assert!(bloom.maybe_contains(a, b), "false negative after overflow"); }
    const TRIALS: usize = 1_000;
    let mut fp = 0usize;
    for _ in 0..TRIALS {
        let (a, b) = loop {
            let p = (rng.gen::<u8>(), rng.gen::<u8>());
            if !inserted.contains(&p) { break p; }
        };
        if bloom.maybe_contains(a, b) { fp += 1; }
    }
    let rate = fp as f64 / TRIALS as f64;
    assert!(rate > 0.5, "expected severe FP degradation after overflow, got {rate}");
}

// 5. SERIALIZATION ROUNDTRIP
#[test]
fn serialization_roundtrip_zero_false_negatives() {
    let mut rng = StdRng::seed_from_u64(0x5EED_5EED);
    let patterns = random_patterns(&mut rng, 1_000, 8);
    let mut bloom = NgramBloom::new(8192).unwrap();
    for p in &patterns { insert_pattern_ngram(&mut bloom, p); }
    let (num_bits, bits, exact_pairs) = bloom.serialize_with_exact_pairs();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&(num_bits as u64).to_le_bytes()).unwrap();
    file.write_all(&(bits.len() as u64).to_le_bytes()).unwrap();
    for &w in bits { file.write_all(&w.to_le_bytes()).unwrap(); }
    file.write_all(&[if exact_pairs.is_some() { 1u8 } else { 0u8 }]).unwrap();
    if let Some(ep) = exact_pairs {
        for &w in ep.as_ref() { file.write_all(&w.to_le_bytes()).unwrap(); }
    }
    file.flush().unwrap();
    let mut buf = Vec::new();
    File::open(file.path()).unwrap().read_to_end(&mut buf).unwrap();
    let mut rest = &buf[..];
    let read_u64 = |slice: &mut &[u8]| -> u64 {
        let (bytes, tail) = slice.split_at(8); *slice = tail;
        u64::from_le_bytes(bytes.try_into().unwrap())
    };
    let read_num_bits = read_u64(&mut rest) as usize;
    let read_bits_len = read_u64(&mut rest) as usize;
    let mut read_bits = Vec::with_capacity(read_bits_len);
    for _ in 0..read_bits_len { read_bits.push(read_u64(&mut rest)); }
    let has_exact = rest[0] == 1; rest = &rest[1..];
    let read_exact_pairs = if has_exact {
        let mut ep = Box::new([0u64; 1024]);
        for i in 0..1024 { ep[i] = read_u64(&mut rest); }
        Some(ep)
    } else { None };
    let reconstructed = NgramBloom::from_serialized_parts(read_num_bits, read_bits, read_exact_pairs).unwrap();
    // Verify exact-pairs were restored by checking a known-absent n-gram returns false.
    let inserted_ngrams: HashSet<(u8, u8)> = patterns.iter()
        .flat_map(|p| p.windows(2).map(|w| (w[0], w[1]))).collect();
    let absent = (0u8..=255).flat_map(|a| (0u8..=255).map(move |b| (a, b)))
        .find(|p| !inserted_ngrams.contains(p));
    if let Some((a, b)) = absent {
        assert!(!reconstructed.maybe_contains(a, b), "exact-pairs likely missing: true for uninserted ({a}, {b})");
    }
    for p in &patterns {
        assert!(reconstructed.maybe_contains_pattern(p), "false negative after roundtrip for pattern {p:?}");
    }
    // raw-parts roundtrip (no exact pairs)
    let mut small = NgramBloom::new(1024).unwrap();
    let small_patterns = random_patterns(&mut rng, 100, 4);
    for p in &small_patterns { insert_pattern_ngram(&mut small, p); }
    let (nb, sbits) = small.raw_parts();
    let raw_reconstructed = NgramBloom::from_raw_parts(nb, sbits.to_vec()).unwrap();
    for p in &small_patterns {
        assert!(raw_reconstructed.maybe_contains_pattern(p), "false negative after raw roundtrip for pattern {p:?}");
    }
}

// 6. CONCURRENT ACCESS
#[test]
fn concurrent_queries_match_single_threaded() {
    let mut rng = StdRng::seed_from_u64(0xC0FF_EE01);
    let mut bloom = NgramBloom::new(1 << 16).unwrap();
    let inserted = random_distinct_ngrams(&mut rng, 5_000);
    for &(a, b) in &inserted { bloom.insert_ngram(a, b); }
    let bloom = Arc::new(bloom);
    let mut queries: Vec<(u8, u8)> = inserted.clone();
    queries.extend((0..5_000).map(|_| (rng.gen::<u8>(), rng.gen::<u8>())));
    let expected: Vec<bool> = queries.iter().map(|&(a, b)| bloom.maybe_contains(a, b)).collect();
    let mut handles = Vec::new();
    for _ in 0..16 {
        let b = Arc::clone(&bloom);
        let (q, e) = (queries.clone(), expected.clone());
        handles.push(thread::spawn(move || {
            let actual: Vec<bool> = q.iter().map(|&(x, y)| b.maybe_contains(x, y)).collect();
            assert_eq!(actual, e, "concurrent query results diverged from single-threaded");
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// 7. EMPTY BLOOM
#[test]
fn empty_bloom_rejects_everything() {
    let bloom = NgramBloom::new(1024).unwrap();
    for a in 0u8..=255 { for b in 0u8..=255 {
        assert!(!bloom.maybe_contains(a, b), "empty NgramBloom returned true for ({a}, {b})");
    }}
    let blocked = BlockedNgramBloom::new(4096).unwrap();
    for a in 0u8..=255 { for b in 0u8..=255 {
        assert!(!blocked.maybe_contains(a, b), "empty BlockedNgramBloom returned true for ({a}, {b})");
    }}
    let mut rng = StdRng::seed_from_u64(0xE77E_E77E);
    for _ in 0..100 {
        let pattern: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        assert!(!bloom.maybe_contains_pattern(&pattern), "empty bloom matched pattern");
    }
    assert!(bloom.maybe_contains_all(&[]), "empty maybe_contains_all should be vacuously true");
    assert!(!bloom.maybe_contains_any(&[]), "empty maybe_contains_any should be false");
}

// 8. ADVERSARIAL INPUTS
#[test]
fn adversarial_collisions_no_false_negatives() {
    #[inline(always)] fn wyhash_pair(a: u8, b: u8) -> u64 {
        let x = (u64::from(a) << 8) | u64::from(b);
        let x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x ^ (x >> 32)
    }
    #[inline(always)] fn derive_second_hash(h1: u64) -> u64 {
        let h2 = h1 ^ (h1 >> 32); h2.max(1)
    }
    const M: usize = 64;
    let mask = (M as u64).wrapping_sub(1);
    let mut groups: std::collections::HashMap<(usize, usize, usize), Vec<(u8, u8)>> =
        std::collections::HashMap::new();
    for a in 0u8..=255 { for b in 0u8..=255 {
        let h1 = wyhash_pair(a, b);
        let h2 = derive_second_hash(h1);
        let i0 = (h1 & mask) as usize;
        let i1 = (h1.wrapping_add(h2) & mask) as usize;
        let i2 = (h1.wrapping_add(h2.wrapping_mul(2)) & mask) as usize;
        groups.entry((i0, i1, i2)).or_default().push((a, b));
    }}
    let mut max_group = Vec::new();
    for g in groups.values() { if g.len() > max_group.len() { max_group.clone_from(g); } }
    assert!(!max_group.is_empty(), "collision search failed");
    let mut bloom = NgramBloom::new(M).unwrap();
    for &(a, b) in &max_group { bloom.insert_ngram(a, b); }
    for &(a, b) in &max_group {
        assert!(bloom.maybe_contains(a, b), "false negative for adversarial collision pair ({a}, {b})");
    }
    // Ultimate adversarial load: every possible 2-byte n-gram into a 64-bit filter.
    let mut exhaustive = NgramBloom::new(M).unwrap();
    for a in 0u8..=255 { for b in 0u8..=255 { exhaustive.insert_ngram(a, b); } }
    for a in 0u8..=255 { for b in 0u8..=255 {
        assert!(exhaustive.maybe_contains(a, b), "false negative in exhaustive adversarial load for ({a}, {b})");
    }}
}
