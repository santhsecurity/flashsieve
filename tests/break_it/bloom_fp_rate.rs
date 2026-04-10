use flashsieve::NgramBloom;

fn million_insert_stream() -> Vec<u8> {
    let mut state = 0xC0FF_EE12_u32;
    let mut data = Vec::with_capacity(1_000_001);
    for _ in 0..1_000_001 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state as u8) & 0x0F);
    }
    data
}

#[test]
fn bloom_with_one_million_insertions_keeps_false_positive_rate_bounded() -> flashsieve::Result<()> {
    let data = million_insert_stream();
    let bloom = NgramBloom::from_block(&data, 2_048)?;

    let mut inserted = vec![false; 65_536];
    for window in data.windows(2) {
        let idx = ((usize::from(window[0])) << 8) | usize::from(window[1]);
        inserted[idx] = true;
    }

    for (idx, present) in inserted.iter().enumerate() {
        if *present {
            let a = (idx >> 8) as u8;
            let b = (idx & 0xFF) as u8;
            assert!(
                bloom.maybe_contains(a, b),
                "FINDING: false negative after 1M insertions for pair ({a:#04x}, {b:#04x})"
            );
        }
    }

    let mut false_positives = 0usize;
    let mut trials = 0usize;
    for a in 16u8..=255 {
        for b in 16u8..=255 {
            let idx = ((usize::from(a)) << 8) | usize::from(b);
            if inserted[idx] {
                continue;
            }
            trials += 1;
            if bloom.maybe_contains(a, b) {
                false_positives += 1;
            }
        }
    }

    let rate = false_positives as f64 / trials as f64;
    assert!(
        rate <= 0.10,
        "FINDING: false positive rate {rate:.4} exceeded 10% after 1M insertions"
    );
    Ok(())
}
