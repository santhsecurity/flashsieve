#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::BlockedNgramBloom;

fn pair_for_index(index: u16) -> (u8, u8) {
    let bytes = index.to_be_bytes();
    (bytes[0], bytes[1])
}

#[test]
fn blocked_bloom_rejects_zero_bits() {
    assert!(BlockedNgramBloom::new(0).is_err());
}

#[test]
fn blocked_bloom_empty_block_has_no_pairs() -> flashsieve::Result<()> {
    let bloom = BlockedNgramBloom::from_block(b"", 4096)?;
    assert!(!bloom.maybe_contains(b'a', b'b'));
    Ok(())
}

#[test]
fn blocked_bloom_single_byte_block_has_no_pairs() -> flashsieve::Result<()> {
    let bloom = BlockedNgramBloom::from_block(b"x", 4096)?;
    assert!(!bloom.maybe_contains(b'x', b'x'));
    Ok(())
}

#[test]
fn blocked_bloom_from_block_tracks_adjacent_pairs() -> flashsieve::Result<()> {
    let bloom = BlockedNgramBloom::from_block(b"abracadabra", 4096)?;
    assert!(bloom.maybe_contains(b'a', b'b'));
    assert!(bloom.maybe_contains(b'b', b'r'));
    assert!(bloom.maybe_contains(b'r', b'a'));
    Ok(())
}

#[test]
fn blocked_bloom_duplicate_inserts_are_stable() -> flashsieve::Result<()> {
    let mut bloom = BlockedNgramBloom::new(4096)?;
    for _ in 0..32 {
        bloom.insert(b'q', b'r');
    }
    assert!(bloom.maybe_contains(b'q', b'r'));
    assert!(!bloom.maybe_contains(b'r', b'q'));
    Ok(())
}

#[test]
fn blocked_bloom_has_no_false_negatives_for_ten_thousand_insertions() -> flashsieve::Result<()> {
    let mut bloom = BlockedNgramBloom::new(4096)?;
    let mut inserted = vec![false; 65_536];

    for raw in 0u16..10_000u16 {
        let value = raw.wrapping_mul(40_503).wrapping_add(17);
        let (first, second) = pair_for_index(value);
        bloom.insert(first, second);
        inserted[usize::from(value)] = true;
    }

    for (pair, present) in inserted.iter().enumerate() {
        if *present {
            let (first, second) = pair_for_index(u16::try_from(pair).unwrap_or(0));
            assert!(bloom.maybe_contains(first, second));
        }
    }
    Ok(())
}

#[test]
fn blocked_bloom_false_positive_rate_stays_below_five_percent() -> flashsieve::Result<()> {
    let mut bloom = BlockedNgramBloom::new(4096)?;
    let mut inserted = vec![false; 65_536];

    for raw in 0u16..10_000u16 {
        let value = raw.wrapping_mul(40_503).wrapping_add(17);
        let (first, second) = pair_for_index(value);
        bloom.insert(first, second);
        inserted[usize::from(value)] = true;
    }

    let mut false_positives = 0usize;
    let mut trials = 0usize;
    for raw in 10_000u16..20_000u16 {
        let value = raw.wrapping_mul(40_503).wrapping_add(17);
        if inserted[usize::from(value)] {
            continue;
        }

        let (first, second) = pair_for_index(value);
        trials += 1;
        if bloom.maybe_contains(first, second) {
            false_positives += 1;
        }
    }

    let rate = f64::from(u32::try_from(false_positives).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(trials).unwrap_or(1));
    assert!(rate < 0.05, "false positive rate was {rate}");
    Ok(())
}

#[test]
fn blocked_bloom_exact_mode_rejects_absent_pairs() -> flashsieve::Result<()> {
    let bloom = BlockedNgramBloom::from_block(b"abcdefghij", 4096)?;
    assert!(!bloom.maybe_contains(b'z', b'z'));
    Ok(())
}

#[test]
fn blocked_bloom_small_filter_still_preserves_inserted_pairs() -> flashsieve::Result<()> {
    let mut bloom = BlockedNgramBloom::new(512)?;
    bloom.insert(b'a', b'a');
    bloom.insert(b'b', b'c');
    bloom.insert(b'c', b'd');

    assert!(bloom.maybe_contains(b'a', b'a'));
    assert!(bloom.maybe_contains(b'b', b'c'));
    assert!(bloom.maybe_contains(b'c', b'd'));
    Ok(())
}

#[test]
fn blocked_bloom_rebuilds_deterministically_from_same_block() -> flashsieve::Result<()> {
    let left = BlockedNgramBloom::from_block(b"mississippi", 4096)?;
    let right = BlockedNgramBloom::from_block(b"mississippi", 4096)?;

    for &(first, second) in &[
        (b'm', b'i'),
        (b'i', b's'),
        (b's', b's'),
        (b's', b'i'),
        (b'p', b'p'),
        (b'z', b'z'),
    ] {
        assert_eq!(
            left.maybe_contains(first, second),
            right.maybe_contains(first, second)
        );
    }
    Ok(())
}
