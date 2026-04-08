use super::MmapBlockIndex;
use crate::{BlockIndex, BlockIndexBuilder, ByteFilter, NgramFilter};

#[test]
fn mmap_candidate_blocks_match_heap_index() {
    let block_size = 256;
    let mut block_a = vec![b'x'; block_size];
    let mut block_b = vec![b'y'; block_size];
    let mut block_c = vec![b'z'; block_size];
    block_a[..6].copy_from_slice(b"secret");
    block_b[..5].copy_from_slice(b"token");
    block_c[..6].copy_from_slice(b"secret");

    let bytes = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(2048)
        .build_streaming([block_a, block_b, block_c].into_iter())
        .unwrap_or_else(|error| panic!("{error}"))
        .to_bytes();
    let heap_index =
        BlockIndex::from_bytes_checked(&bytes).unwrap_or_else(|error| panic!("{error}"));
    let mmap_index =
        MmapBlockIndex::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));

    for pattern in [
        b"secret".as_slice(),
        b"token".as_slice(),
        b"miss".as_slice(),
    ] {
        let byte_filter = ByteFilter::from_patterns(&[pattern]);
        let ngram_filter = NgramFilter::from_patterns(&[pattern]);
        assert_eq!(
            mmap_index.candidate_blocks(&byte_filter, &ngram_filter),
            heap_index.candidate_blocks(&byte_filter, &ngram_filter)
        );
    }
}

#[test]
fn mmap_accessors_match_heap_index_contents() {
    let bytes = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"abacus secret token zebra")
        .unwrap_or_else(|error| panic!("{error}"))
        .to_bytes();
    let heap_index =
        BlockIndex::from_bytes_checked(&bytes).unwrap_or_else(|error| panic!("{error}"));
    let mmap_index =
        MmapBlockIndex::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));

    #[allow(clippy::unwrap_used)]
    let histogram = mmap_index.try_histogram(0).unwrap();
    for byte in [b'a', b's', b't', b'z', b'!'] {
        assert_eq!(
            histogram.count(byte),
            heap_index.histograms[0].count(byte),
            "byte {byte}"
        );
    }

    #[allow(clippy::unwrap_used)]
    let mmap_bloom = mmap_index.try_bloom(0).unwrap();
    let heap_bloom = &heap_index.blooms[0];
    for (first, second) in [(b'a', b'b'), (b's', b'e'), (b't', b'o'), (b'!', b'!')] {
        assert_eq!(
            mmap_bloom.maybe_contains_bloom(first, second),
            heap_bloom.maybe_contains_bloom(first, second)
        );
    }

    assert_eq!(
        histogram.to_owned().raw_counts(),
        heap_index.histograms[0].raw_counts()
    );
    assert_eq!(mmap_bloom.num_bits(), heap_bloom.raw_parts().0);
}

#[test]
fn mmap_rejects_truncated_block_payload() {
    let mut bytes = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"secret token")
        .unwrap_or_else(|error| panic!("{error}"))
        .to_bytes();
    bytes.pop();

    assert!(MmapBlockIndex::from_slice(&bytes).is_err());
}
