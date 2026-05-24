#![allow(
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::unreadable_literal,
    clippy::unwrap_used
)]
//! Legendary benchmarks for flashsieve using Criterion.
//!
//! These benchmarks measure:
//! - Insert throughput
//! - Query hit/miss throughput
//! - Serialization/deserialization speed
//! - FPR vs load factor

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use flashsieve::{
    BlockIndex, BlockIndexBuilder, BlockedNgramBloom, ByteFilter, ByteHistogram, NgramBloom,
    NgramFilter,
};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

/// Generate deterministic random data
fn random_data(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; len];
    rng.fill_bytes(&mut data);
    data
}

/// Generate random n-grams
fn random_ngrams(count: usize, seed: u64) -> Vec<(u8, u8)> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..count).map(|_| (rng.gen(), rng.gen())).collect()
}

// ============================================================================
// Bloom Filter Benchmarks
// ============================================================================

fn bench_bloom_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_insert");

    for size in [1024, 4096, 16384, 65536] {
        group.throughput(Throughput::Elements(1000));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let ngrams = random_ngrams(1000, 0x1234_5678);
            b.iter(|| {
                let mut bloom = NgramBloom::new(size).unwrap();
                for (a, b_) in &ngrams {
                    bloom.insert_ngram(*a, *b_);
                }
                black_box(bloom);
            });
        });
    }

    group.finish();
}

fn bench_bloom_query_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_query_hit");

    for size in [1024, 4096, 16384, 65536] {
        let ngrams = random_ngrams(1000, 0x1234_5678);
        let mut bloom = NgramBloom::new(size).unwrap();
        for (a, b_) in &ngrams {
            bloom.insert_ngram(*a, *b_);
        }

        group.throughput(Throughput::Elements(ngrams.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ngrams, |b, ngrams| {
            b.iter(|| {
                for (a, b_) in ngrams {
                    black_box(bloom.maybe_contains(*a, *b_));
                }
            });
        });
    }

    group.finish();
}

fn bench_bloom_query_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_query_miss");

    for size in [1024, 4096, 16384, 65536] {
        let inserted = random_ngrams(1000, 0x1234_5678);
        let queries = random_ngrams(1000, 0x8765_4321);

        let mut bloom = NgramBloom::new(size).unwrap();
        for (a, b_) in &inserted {
            bloom.insert_ngram(*a, *b_);
        }

        group.throughput(Throughput::Elements(queries.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &queries, |b, queries| {
            b.iter(|| {
                for (a, b_) in queries {
                    black_box(bloom.maybe_contains(*a, *b_));
                }
            });
        });
    }

    group.finish();
}

fn bench_bloom_hot_path_10m(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_hot_path_10m");
    let query_count = 10_000_000usize;

    for size in [1024, 65536] {
        let mut bloom = NgramBloom::new(size).unwrap();
        let inserted = random_ngrams(4096, 0xA1B2_C3D4);
        for (a, b_) in &inserted {
            bloom.insert_ngram(*a, *b_);
        }

        let queries = random_ngrams(query_count, 0xD4C3_B2A1);
        group.throughput(Throughput::Elements(query_count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &queries, |b, queries| {
            b.iter(|| {
                for (a, b_) in queries {
                    black_box(bloom.maybe_contains(*a, *b_));
                }
            });
        });
    }

    group.finish();
}

fn bench_blocked_vs_standard_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("blocked_vs_standard_queries");
    let inserted = random_ngrams(10_000, 0xA11C_E001);
    let queries = random_ngrams(100_000, 0xB10C_0BAD);

    let Ok(mut standard) = NgramBloom::new(2048) else {
        return;
    };
    let Ok(mut blocked) = BlockedNgramBloom::new(2048) else {
        return;
    };

    for (a, b) in &inserted {
        standard.insert_ngram(*a, *b);
        blocked.insert(*a, *b);
    }

    group.throughput(Throughput::Elements(queries.len() as u64));
    group.bench_function("standard_100k", |b| {
        b.iter(|| {
            for (a, b_) in &queries {
                black_box(standard.maybe_contains(*a, *b_));
            }
        });
    });
    group.bench_function("blocked_100k", |b| {
        b.iter(|| {
            for (a, b_) in &queries {
                black_box(blocked.maybe_contains(*a, *b_));
            }
        });
    });
    group.finish();
}

fn bench_bloom_from_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_from_block");

    for block_size in [256, 1024, 4096, 16384, 65536, 262144] {
        let data = random_data(block_size, 0xDEAD_BEEF);

        group.throughput(Throughput::Bytes(block_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(block_size), &data, |b, data| {
            b.iter(|| {
                let bloom = NgramBloom::from_block(data, 8192).unwrap();
                black_box(bloom);
            });
        });
    }

    group.finish();
}

// ============================================================================
// Histogram Benchmarks
// ============================================================================

fn bench_histogram_from_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("histogram_from_block");

    for block_size in [256, 1024, 4096, 16384, 65536, 262144] {
        let data = random_data(block_size, 0xCAFE_BABE);

        group.throughput(Throughput::Bytes(block_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(block_size), &data, |b, data| {
            b.iter(|| {
                let hist = ByteHistogram::from_block(data);
                black_box(hist);
            });
        });
    }

    group.finish();
}

fn bench_histogram_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("histogram_query");

    let data = random_data(4096, 0xBEEF_CAFE);
    let hist = ByteHistogram::from_block(&data);

    group.throughput(Throughput::Elements(256));
    group.bench_function("all_bytes", |b| {
        b.iter(|| {
            for byte in 0u8..=255 {
                black_box(hist.count(byte));
            }
        });
    });

    group.finish();
}

// ============================================================================
// Index Construction Benchmarks
// ============================================================================

fn bench_index_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("index_build");

    for total_size in [1, 10, 100] {
        let size_mb = total_size * 1024 * 1024;
        let data = random_data(size_mb, 0xB10C_1D3A);

        group.throughput(Throughput::Bytes(size_mb as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MiB", total_size)),
            &data,
            |b, data| {
                b.iter(|| {
                    let index = BlockIndexBuilder::new()
                        .block_size(256 * 1024)
                        .bloom_bits(65536)
                        .build(data)
                        .unwrap();
                    black_box(index);
                });
            },
        );
    }

    group.finish();
}

fn bench_index_streaming_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("index_streaming_build");

    for num_blocks in [10, 100, 1000] {
        let blocks: Vec<Vec<u8>> = (0..num_blocks)
            .map(|i| random_data(256 * 1024, i as u64))
            .collect();

        group.throughput(Throughput::Bytes((num_blocks * 256 * 1024) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &blocks,
            |b, blocks| {
                let blocks_clone: Vec<Vec<u8>> = blocks.clone();
                b.iter(|| {
                    let index = BlockIndexBuilder::new()
                        .block_size(256 * 1024)
                        .bloom_bits(65536)
                        .build_streaming(blocks_clone.clone().into_iter())
                        .unwrap();
                    black_box(index);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Query Benchmarks
// ============================================================================

fn bench_candidate_blocks_byte(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_blocks_byte");

    for num_blocks in [10, 100, 1000] {
        let data = random_data(num_blocks * 256, 0xABCD_EF01);
        let index = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();

        // Filter that matches nothing (worst case - scans all)
        let filter = ByteFilter::from_patterns(&[b"ZZZZZZ".as_slice()]);

        group.throughput(Throughput::Elements(num_blocks as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &(&index, filter),
            |b, (index, filter)| {
                b.iter(|| {
                    let candidates = index.candidate_blocks_byte(filter);
                    black_box(candidates);
                });
            },
        );
    }

    group.finish();
}

fn bench_candidate_blocks_ngram(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_blocks_ngram");

    for num_blocks in [10, 100, 1000] {
        let data = random_data(num_blocks * 256, 0xFEDC_BA09);
        let index = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();

        let filter = NgramFilter::from_patterns(&[b"ZZZZZZ".as_slice()]);

        group.throughput(Throughput::Elements(num_blocks as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &(&index, filter),
            |b, (index, filter)| {
                b.iter(|| {
                    let candidates = index.candidate_blocks_ngram(filter);
                    black_box(candidates);
                });
            },
        );
    }

    group.finish();
}

fn bench_candidate_blocks_combined(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_blocks_combined");

    for num_blocks in [10, 100, 1000] {
        let data = random_data(num_blocks * 256, 0x1357_9BDF);
        let index = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();

        let patterns = [b"secret".as_slice(), b"token".as_slice()];
        let byte_filter = ByteFilter::from_patterns(&patterns);
        let ngram_filter = NgramFilter::from_patterns(&patterns);

        group.throughput(Throughput::Elements(num_blocks as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &(&index, &byte_filter, &ngram_filter),
            |b, (index, bf, nf)| {
                b.iter(|| {
                    let candidates = index.candidate_blocks(bf, nf);
                    black_box(candidates);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Serialization Benchmarks
// ============================================================================

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    for num_blocks in [10, 100, 1000] {
        let data = random_data(num_blocks * 256, 0xAABB_CCDD);
        let index = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &index,
            |b, index| {
                b.iter(|| {
                    let bytes = index.to_bytes();
                    black_box(bytes);
                });
            },
        );
    }

    group.finish();
}

fn bench_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialize");

    for num_blocks in [10, 100, 1000] {
        let data = random_data(num_blocks * 256, 0xAABB_CCDD);
        let index = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();
        let bytes = index.to_bytes();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &bytes,
            |b, bytes| {
                b.iter(|| {
                    let index = BlockIndex::from_bytes(bytes).unwrap();
                    black_box(index);
                });
            },
        );
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for num_blocks in [10, 100] {
        let data = random_data(num_blocks * 256, 0x1122_3344);
        let index = BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(1024)
            .build(&data)
            .unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_blocks),
            &index,
            |b, index| {
                b.iter(|| {
                    let bytes = index.to_bytes();
                    let recovered = BlockIndex::from_bytes(&bytes).unwrap();
                    black_box(recovered);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// FPR vs Load Factor Benchmark
// ============================================================================

fn bench_fpr_vs_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("fpr_vs_load");

    // Fixed 64k-bit filter, varying number of inserts
    let size = 65536;

    for num_inserts in [100, 500, 1000, 5000, 10000, 20000] {
        // Create fresh bloom filter
        let mut bloom = NgramBloom::new(size).unwrap();
        let ngrams = random_ngrams(num_inserts, 0x9999_8888);

        for (a, b_) in &ngrams {
            bloom.insert_ngram(*a, *b_);
        }

        let fpr_estimate = bloom.estimated_false_positive_rate();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_inserts_fpr_{:.4}", num_inserts, fpr_estimate)),
            &(&bloom, &ngrams),
            |b, (bloom, inserted)| {
                let queries = random_ngrams(10000, 0x7777_6666);
                b.iter(|| {
                    let mut false_positives = 0u64;
                    let mut trials = 0u64;
                    for (a, b_) in &queries {
                        // Skip if it was actually inserted
                        if !inserted.contains(&(*a, *b_)) {
                            trials += 1;
                            if bloom.maybe_contains(*a, *b_) {
                                false_positives += 1;
                            }
                        }
                    }
                    black_box((false_positives, trials));
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Composite Filter Benchmarks
// ============================================================================

fn bench_composite_filter(c: &mut Criterion) {
    use flashsieve::filter::{CompositeFilter, FilterOp};

    let mut group = c.benchmark_group("composite_filter");

    let data = random_data(256 * 100, 0x5555_6666);
    let _index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let hist = ByteHistogram::from_block(&data[..256]);
    let bloom = NgramBloom::from_block(&data[..256], 1024).unwrap();

    let a = ByteFilter::from_patterns(&[b"abc".as_slice()]);
    let b = ByteFilter::from_patterns(&[b"def".as_slice()]);

    let combined_and = CompositeFilter::combine_byte(a.clone(), b.clone(), FilterOp::And);
    let combined_or = CompositeFilter::combine_byte(a, b, FilterOp::Or);

    group.bench_function("and", |b_| {
        b_.iter(|| {
            black_box(combined_and.matches(&hist, &bloom));
        });
    });

    group.bench_function("or", |b_| {
        b_.iter(|| {
            black_box(combined_or.matches(&hist, &bloom));
        });
    });

    group.finish();
}

// ============================================================================
// Merge Adjacent Benchmarks
// ============================================================================

fn bench_merge_adjacent(c: &mut Criterion) {
    use flashsieve::index::CandidateRange;

    let mut group = c.benchmark_group("merge_adjacent");

    for num_ranges in [10, 100, 1000, 10000] {
        // Create alternating ranges (no merges possible)
        let ranges: Vec<CandidateRange> = (0..num_ranges)
            .map(|i| CandidateRange {
                offset: i * 512,
                length: 256,
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_no_merge", num_ranges)),
            &ranges,
            |b, ranges| {
                b.iter(|| {
                    let merged = BlockIndex::merge_adjacent(ranges);
                    black_box(merged);
                });
            },
        );

        // Create contiguous ranges (all merge into one)
        let ranges: Vec<CandidateRange> = (0..num_ranges)
            .map(|i| CandidateRange {
                offset: i * 256,
                length: 256,
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_all_merge", num_ranges)),
            &ranges,
            |b, ranges| {
                b.iter(|| {
                    let merged = BlockIndex::merge_adjacent(ranges);
                    black_box(merged);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    benches,
    bench_bloom_insert,
    bench_bloom_query_hit,
    bench_bloom_query_miss,
    bench_blocked_vs_standard_queries,
    bench_bloom_hot_path_10m,
    bench_bloom_from_block,
    bench_histogram_from_block,
    bench_histogram_query,
    bench_index_build,
    bench_index_streaming_build,
    bench_candidate_blocks_byte,
    bench_candidate_blocks_ngram,
    bench_candidate_blocks_combined,
    bench_serialize,
    bench_deserialize,
    bench_roundtrip,
    bench_fpr_vs_load,
    bench_composite_filter,
    bench_merge_adjacent,
);

criterion_main!(benches);
