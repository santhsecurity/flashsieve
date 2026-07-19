#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::{BlockIndexBuilder, MmapBlockIndex};

#[test]
fn test_mmap_index_from_slice_basic() {
    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&vec![0xAA; 1024])
        .unwrap();
    let serialized = index.to_bytes();

    let mmap_idx = MmapBlockIndex::from_slice(&serialized).unwrap();
    assert_eq!(mmap_idx.block_count(), 1);
    assert_eq!(mmap_idx.block_size(), 1024);
    assert_eq!(mmap_idx.total_data_length(), 1024);
}

#[test]
fn test_mmap_index_from_slice_invalid_file() {
    let bad_data = b"not an index";
    assert!(MmapBlockIndex::from_slice(bad_data).is_err());
}

fn ab_index() -> MmapBlockIndex<'static> {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(1024)
        .build(b"ab")
        .unwrap();
    // Leak the serialized bytes so the returned index can borrow them for 'static
    // in these small tests (the process exits right after).
    let serialized: &'static [u8] = Box::leak(index.to_bytes().into_boxed_slice());
    MmapBlockIndex::from_slice(serialized).unwrap()
}

#[test]
#[allow(deprecated)]
#[should_panic(expected = "MmapBlockIndex::bloom(9999)")]
fn deprecated_bloom_out_of_range_fails_closed() {
    // Law 10: the deprecated `bloom()` must NOT return a dummy empty bloom for an
    // out-of-range block id (an empty bloom answers "contains nothing" to every
    // query, silently dropping recall). It fails closed with a panic; the
    // deprecation note advertises this and points at the fallible `try_bloom`.
    let mmap = ab_index();
    let _ = mmap.bloom(9999);
}

#[test]
#[allow(deprecated)]
#[should_panic(expected = "MmapBlockIndex::histogram(9999)")]
fn deprecated_histogram_out_of_range_fails_closed() {
    // Law 10: `histogram()` must not return a dummy all-zero histogram (which
    // reads as "block has no bytes") for an out-of-range block id.
    let mmap = ab_index();
    let _ = mmap.histogram(9999);
}

#[test]
fn try_bloom_and_try_histogram_return_err_out_of_range_and_ok_in_range() {
    let mmap = ab_index();
    // In range: succeeds.
    assert!(mmap.try_bloom(0).is_ok());
    assert!(mmap.try_histogram(0).is_ok());
    // Out of range: explicit Err, not a dummy value.
    assert!(mmap.try_bloom(9999).is_err());
    assert!(mmap.try_histogram(9999).is_err());
}

#[test]
#[allow(deprecated)]
fn deprecated_accessors_return_real_data_for_a_valid_block() {
    // The happy path still works: a valid block yields the real histogram/bloom.
    let mmap = ab_index();
    let hist = mmap.histogram(0);
    assert_eq!(hist.count(b'a'), 1);
    assert_eq!(hist.count(b'b'), 1);
    let bloom = mmap.bloom(0);
    assert!(bloom.maybe_contains_bloom(b'a', b'b'));
}
