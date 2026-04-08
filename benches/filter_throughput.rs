#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use flashsieve::{BlockIndexBuilder, ByteFilter, ByteHistogram, NgramBloom, NgramFilter};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

const BLOCK_SIZE: usize = 256 * 1024;
const BLOOM_BITS: usize = 4_096;
const DATASET_BYTES: usize = 100 * 1024 * 1024;

fn synthetic_block() -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(0xB100_0001);
    let mut block = vec![0_u8; BLOCK_SIZE];
    rng.fill_bytes(&mut block);
    block
}

fn synthetic_dataset() -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(0xB100_0002);
    let mut data = vec![0_u8; DATASET_BYTES];
    rng.fill_bytes(&mut data);

    for offset in (0..DATASET_BYTES).step_by(BLOCK_SIZE * 7) {
        let end = offset + b"needle".len();
        if end <= data.len() {
            data[offset..end].copy_from_slice(b"needle");
        }
    }

    data
}

fn bench_bloom_insert_query(criterion: &mut Criterion) {
    let block = synthetic_block();
    let mut group = criterion.benchmark_group("bloom");
    group.throughput(Throughput::Bytes(block.len() as u64));

    group.bench_function("insert_from_block", |bencher| {
        bencher.iter(|| {
            let mut bloom = NgramBloom::new(BLOOM_BITS).unwrap_or_else(|error| panic!("{error}"));
            for window in black_box(block.as_slice()).windows(2) {
                bloom.insert_ngram(window[0], window[1]);
            }
            black_box(bloom);
        });
    });

    let bloom =
        NgramBloom::from_block(&block, BLOOM_BITS).unwrap_or_else(|error| panic!("{error}"));
    group.bench_function("query_pattern", |bencher| {
        bencher.iter(|| black_box(bloom.maybe_contains_pattern(black_box(b"needle"))));
    });

    group.finish();
}

fn bench_histogram_build(criterion: &mut Criterion) {
    let block = synthetic_block();
    let mut group = criterion.benchmark_group("histogram");
    group.throughput(Throughput::Bytes(block.len() as u64));
    group.bench_function("build", |bencher| {
        bencher.iter(|| black_box(ByteHistogram::from_block(black_box(block.as_slice()))));
    });
    group.finish();
}

fn bench_skip_decision(criterion: &mut Criterion) {
    let data = synthetic_dataset();
    let index = BlockIndexBuilder::new()
        .block_size(BLOCK_SIZE)
        .bloom_bits(BLOOM_BITS)
        .build(&data)
        .unwrap_or_else(|error| panic!("{error}"));
    let byte_filter = ByteFilter::from_patterns(&[b"needle".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"needle".as_slice()]);

    let mut group = criterion.benchmark_group("skip_decision");
    group.throughput(Throughput::Elements(index.block_count() as u64));
    group.bench_function("candidate_blocks", |bencher| {
        bencher.iter(|| {
            black_box(index.candidate_blocks(black_box(&byte_filter), black_box(&ngram_filter)));
        });
    });
    group.finish();
}

fn bench_full_pipeline(criterion: &mut Criterion) {
    let data = synthetic_dataset();
    let byte_filter = ByteFilter::from_patterns(&[b"needle".as_slice()]);
    let ngram_filter = NgramFilter::from_patterns(&[b"needle".as_slice()]);
    let mut group = criterion.benchmark_group("pipeline");
    group.throughput(Throughput::Bytes(DATASET_BYTES as u64));
    group.bench_with_input(
        BenchmarkId::new("build_and_query", "100_mib"),
        &data,
        |bencher, data| {
            bencher.iter(|| {
                let index = BlockIndexBuilder::new()
                    .block_size(BLOCK_SIZE)
                    .bloom_bits(BLOOM_BITS)
                    .build(black_box(data))
                    .unwrap_or_else(|error| panic!("{error}"));
                black_box(
                    index.candidate_blocks(black_box(&byte_filter), black_box(&ngram_filter)),
                );
            });
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_bloom_insert_query,
    bench_histogram_build,
    bench_skip_decision,
    bench_full_pipeline
);
criterion_main!(benches);
