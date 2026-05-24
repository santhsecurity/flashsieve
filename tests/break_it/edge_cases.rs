use flashsieve::NgramBloom;

#[test]
fn empty_input_rejects_real_patterns_but_accepts_degenerate_ones() -> flashsieve::Result<()> {
    let bloom = NgramBloom::from_block(b"", 512)?;
    assert!(bloom.maybe_contains_pattern(b""));
    assert!(bloom.maybe_contains_pattern(b"a"));
    assert!(
        !bloom.maybe_contains_pattern(b"ab"),
        "FINDING: empty input claimed to maybe contain a 2-byte pattern"
    );
    Ok(())
}

#[test]
fn single_byte_patterns_never_false_reject() -> flashsieve::Result<()> {
    let bloom = NgramBloom::from_block(b"abc", 512)?;
    for pattern in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
        assert!(
            bloom.maybe_contains_pattern(pattern),
            "FINDING: single-byte pattern {:?} was rejected",
            pattern
        );
    }
    Ok(())
}

#[test]
fn pattern_longer_than_input_is_rejected_when_input_cannot_contain_it() -> flashsieve::Result<()> {
    let bloom = NgramBloom::from_block(b"ab", 512)?;
    assert!(
        !bloom.maybe_contains_pattern(b"abc"),
        "FINDING: pattern longer than input produced a false positive"
    );
    Ok(())
}
