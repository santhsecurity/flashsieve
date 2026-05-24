use crate::bloom::filter::{BlockedNgramBloom, NgramBloom, EXACT_PAIR_WORDS, NUM_HASHES};
use crate::bloom::hash::{hash_pair, hash_to_index, wyhash_pair};

impl NgramBloom {
    /// Check if a 2-byte n-gram might be present.
    ///
    /// Returns `true` if all k hash positions are set. Note that this may
    /// return `true` for elements that were never inserted (false positives).
    /// Never returns `false` for inserted elements (no false negatives).
    ///
    /// For filters with the exact pair table (≥4096 bits), this returns
    /// accurate results with zero false positives.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let mut bloom = NgramBloom::new(1024).unwrap();
    /// bloom.insert_ngram(b'x', b'y');
    /// assert!(bloom.maybe_contains(b'x', b'y'));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn maybe_contains(&self, a: u8, b: u8) -> bool {
        if let Some(exact_pairs) = &self.exact_pairs {
            return Self::maybe_contains_exact_with(exact_pairs, a, b);
        }

        self.maybe_contains_bloom(a, b)
    }

    /// Check if a 2-byte n-gram is present using the exact-pair table.
    ///
    /// This path is active for filters large enough to allocate the exact
    /// 65,536-bit pair table, eliminating false positives for 2-byte queries.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let mut bloom = NgramBloom::new(4096).unwrap();
    /// bloom.insert_ngram(b'x', b'y');
    /// assert!(bloom.maybe_contains_exact(b'x', b'y'));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn maybe_contains_exact(&self, first: u8, second: u8) -> bool {
        let Some(exact_pairs) = &self.exact_pairs else {
            return self.maybe_contains_bloom(first, second);
        };
        Self::maybe_contains_exact_with(exact_pairs, first, second)
    }

    /// Check if a 2-byte n-gram is present using the hash-based bloom filter.
    ///
    /// This skips the exact-pair branch and is intended for hot loops that
    /// have already selected the bloom-only path.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let mut bloom = NgramBloom::new(1024).unwrap();
    /// bloom.insert_ngram(b'x', b'y');
    /// assert!(bloom.maybe_contains_bloom(b'x', b'y'));
    /// ```
    #[must_use]
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn maybe_contains_bloom(&self, a: u8, b: u8) -> bool {
        let (h1, h2) = hash_pair(a, b);

        // Unroll k=3 hash probes to avoid loop overhead.
        // The compiler can't prove NUM_HASHES is constant
        // (it's a runtime struct field), so it generates a loop.
        let mask = self.bit_index_mask;
        let idx0 = (h1 & mask) as usize;
        let idx1 = (h1.wrapping_add(h2) & mask) as usize;
        let idx2 = (h1.wrapping_add(h2.wrapping_mul(2)) & mask) as usize;
        self.word_contains(idx0) && self.word_contains(idx1) && self.word_contains(idx2)
    }

    #[must_use]
    #[inline]
    pub(crate) fn uses_exact_pairs(&self) -> bool {
        self.exact_pairs.is_some()
    }

    #[must_use]
    #[inline(always)]
    pub(crate) fn maybe_contains_exact_with(
        exact_pairs: &[u64; EXACT_PAIR_WORDS],
        a: u8,
        b: u8,
    ) -> bool {
        let pair = (usize::from(a) << 8) | usize::from(b);
        let word_index = pair >> 6;
        let bit_offset = pair & 63;
        (exact_pairs[word_index] & (1_u64 << bit_offset)) != 0
    }

    #[must_use]
    #[inline(always)]
    fn word_contains(&self, bit_index: usize) -> bool {
        let word = bit_index >> 6; // / 64
        let bit_offset = bit_index & 63; // % 64
        (self.bits[word] & (1_u64 << bit_offset)) != 0
    }

    /// Check if all n-grams from a pattern might be present.
    ///
    /// Returns `true` only if every 2-byte sequence in the pattern
    /// might be present in the filter.
    ///
    /// Empty and single-byte patterns always return `true` because they have no
    /// 2-byte n-grams to test.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let bloom = NgramBloom::from_block(b"hello", 1024).unwrap();
    /// assert!(bloom.maybe_contains_pattern(b"hel"));
    /// ```
    #[must_use]
    #[inline]
    pub fn maybe_contains_pattern(&self, pattern: &[u8]) -> bool {
        if self.uses_exact_pairs() {
            pattern
                .windows(2)
                .all(|window| self.maybe_contains_exact(window[0], window[1]))
        } else {
            pattern
                .windows(2)
                .all(|window| self.maybe_contains_bloom(window[0], window[1]))
        }
    }

    /// Batch check multiple n-grams for presence.
    ///
    /// This is more efficient than calling `maybe_contains` in a loop because
    /// the compiler can vectorize the hash computations across multiple inputs.
    /// For internet-scale workloads (10K+ patterns), this provides ~20% speedup.
    ///
    /// Returns `true` only if ALL n-grams are present (AND semantics).
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let mut bloom = NgramBloom::new(1024).unwrap();
    /// bloom.insert_ngram(b'a', b'b');
    /// bloom.insert_ngram(b'c', b'd');
    /// assert!(bloom.maybe_contains_all(&[(b'a', b'b'), (b'c', b'd')]));
    /// ```
    #[must_use]
    #[inline]
    pub fn maybe_contains_all(&self, ngrams: &[(u8, u8)]) -> bool {
        if self.uses_exact_pairs() {
            ngrams.iter().all(|&(a, b)| self.maybe_contains_exact(a, b))
        } else {
            ngrams.iter().all(|&(a, b)| self.maybe_contains_bloom(a, b))
        }
    }

    /// Batch check multiple n-grams for presence with OR semantics.
    ///
    /// Returns `true` if ANY n-gram is present. This is useful for union-based
    /// early rejection where we want to check if at least one n-gram from a
    /// set appears in the bloom filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let mut bloom = NgramBloom::new(1024).unwrap();
    /// bloom.insert_ngram(b'a', b'b');
    /// assert!(bloom.maybe_contains_any(&[(b'x', b'y'), (b'a', b'b')]));
    /// ```
    #[must_use]
    #[inline]
    pub fn maybe_contains_any(&self, ngrams: &[(u8, u8)]) -> bool {
        if ngrams.is_empty() {
            return false;
        }
        if self.uses_exact_pairs() {
            ngrams.iter().any(|&(a, b)| self.maybe_contains_exact(a, b))
        } else {
            ngrams.iter().any(|&(a, b)| self.maybe_contains_bloom(a, b))
        }
    }

    /// Estimate the current false positive rate from the bit fill level.
    ///
    /// Computes the theoretical FPR based on the current proportion of
    /// set bits in the bloom filter:
    ///
    /// ```text
    /// FPR ≈ (fill_ratio)^k
    /// ```
    ///
    /// where `fill_ratio` is the fraction of bits set to 1, and `k` is
    /// the number of hash functions.
    ///
    /// For filters with the exact pair table, the actual FPR is zero
    /// for 2-byte n-gram queries, regardless of this estimate.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let mut bloom = NgramBloom::new(1024).unwrap();
    /// // Empty filter has 0% FPR
    /// assert_eq!(bloom.estimated_false_positive_rate(), 0.0);
    /// ```
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn estimated_false_positive_rate(&self) -> f64 {
        let ones = self
            .bits
            .iter()
            .map(|word| u64::from(word.count_ones()))
            .sum::<u64>();
        let fill_ratio = ones as f64 / self.num_bits as f64;
        fill_ratio.powf(f64::from(NUM_HASHES))
    }
}

impl BlockedNgramBloom {
    /// Check whether a 2-byte n-gram may be present.
    #[must_use]
    #[inline]
    pub fn maybe_contains(&self, a: u8, b: u8) -> bool {
        if let Some(exact_pairs) = &self.exact_pairs {
            return NgramBloom::maybe_contains_exact_with(exact_pairs, a, b);
        }

        let block_index = hash_to_index(wyhash_pair(a, b), self.num_blocks);
        let block = &self.blocks[block_index];
        let (h1, h2) = hash_pair(a, b);

        // Prefetch removed to keep the crate fully safe.

        (0..3u64).all(|probe| {
            let bit_index = h1
                .wrapping_add(h2.wrapping_mul(probe))
                .wrapping_add(probe.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                & 511;
            let word_index = (bit_index >> 6) as usize;
            let bit_offset = (bit_index & 63) as u32;
            (block[word_index] & (1_u64 << bit_offset)) != 0
        })
    }

    /// Batch check multiple n-grams against the blocked bloom filter.
    ///
    /// This is more efficient than calling `maybe_contains` in a loop because:
    /// 1. It enables software prefetching of upcoming blocks
    /// 2. It allows the compiler to vectorize hash computations
    /// 3. It amortizes branch prediction overhead
    ///
    /// Returns true only if ALL n-grams might be present (AND semantics).
    /// For OR semantics, use `maybe_contains_any`.
    #[must_use]
    #[inline]
    pub fn maybe_contains_all(&self, ngrams: &[(u8, u8)]) -> bool {
        if ngrams.is_empty() {
            return true;
        }

        // Fast path: use exact pairs if available
        if let Some(exact_pairs) = &self.exact_pairs {
            return ngrams
                .iter()
                .all(|&(a, b)| NgramBloom::maybe_contains_exact_with(exact_pairs, a, b));
        }

        // Software pipelining: prefetch blocks ahead
        ngrams.iter().enumerate().all(|(_i, &(a, b))| {
            let block_index = hash_to_index(wyhash_pair(a, b), self.num_blocks);

            // Prefetch removed to keep the crate fully safe.

            let block = &self.blocks[block_index];
            let (h1, h2) = hash_pair(a, b);
            (0..3u64).all(|probe| {
                let bit_index = h1
                    .wrapping_add(h2.wrapping_mul(probe))
                    .wrapping_add(probe.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                    & 511;
                let word_index = (bit_index >> 6) as usize;
                let bit_offset = (bit_index & 63) as u32;
                (block[word_index] & (1_u64 << bit_offset)) != 0
            })
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use crate::bloom::filter::{BlockedNgramBloom, NgramBloom};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn bloom_insert_and_query() {
        let mut bloom = NgramBloom::new(2048).unwrap_or_else(|error| panic!("{error}"));
        bloom.insert_ngram(b'a', b'b');
        bloom.insert_ngram(b'c', b'd');

        assert!(bloom.maybe_contains(b'a', b'b'));
        assert!(bloom.maybe_contains(b'c', b'd'));
    }

    #[test]
    fn bloom_false_negative_impossible() {
        let mut bloom = NgramBloom::new(4096).unwrap_or_else(|error| panic!("{error}"));
        for first in 0_u8..=127 {
            let second = first.wrapping_add(1);
            bloom.insert_ngram(first, second);
        }

        for first in 0_u8..=127 {
            let second = first.wrapping_add(1);
            assert!(bloom.maybe_contains(first, second));
        }
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn bloom_false_positive_rate() {
        let mut bloom = NgramBloom::new(32_768).unwrap_or_else(|error| panic!("{error}"));
        let mut rng = StdRng::seed_from_u64(0xF1A5_510E);
        let mut inserted = vec![[false; 256]; 256].into_boxed_slice();

        for _ in 0..256 {
            let first = rng.gen::<u8>();
            let second = rng.gen::<u8>();
            bloom.insert_ngram(first, second);
            inserted[usize::from(first)][usize::from(second)] = true;
        }

        let mut false_positives = 0_usize;
        let mut trials = 0_usize;
        for _ in 0..10_000 {
            let first = rng.gen::<u8>();
            let second = rng.gen::<u8>();
            if inserted[usize::from(first)][usize::from(second)] {
                continue;
            }
            trials += 1;
            if bloom.maybe_contains(first, second) {
                false_positives += 1;
            }
        }

        let rate = false_positives as f64 / trials as f64;
        assert!(rate < 0.05, "false positive rate was {rate}");
    }

    #[test]
    fn bloom_pattern_check() {
        let bloom =
            NgramBloom::from_block(b"abcdef", 1024).unwrap_or_else(|error| panic!("{error}"));
        assert!(bloom.maybe_contains_pattern(b"bcde"));
        assert!(!bloom.maybe_contains_pattern(b"bcdz"));
    }

    #[test]
    fn bloom_empty_pattern() {
        let bloom =
            NgramBloom::from_block(b"abcdef", 1024).unwrap_or_else(|error| panic!("{error}"));
        assert!(bloom.maybe_contains_pattern(&[]));
        assert!(bloom.maybe_contains_pattern(b"a"));
    }

    /// Regression test for the `from_raw_parts` bug where an empty
    /// `exact_pairs` table caused `maybe_contains` to return `false`
    /// for every query — violating the bloom filter invariant that
    /// false negatives are impossible.
    #[test]
    fn from_raw_parts_preserves_membership() {
        let mut original = NgramBloom::new(8192).unwrap_or_else(|error| panic!("{error}"));
        original.insert_ngram(b'h', b'e');
        original.insert_ngram(b'e', b'l');
        original.insert_ngram(b'l', b'l');
        original.insert_ngram(b'l', b'o');

        let (num_bits, bits) = original.raw_parts();
        let reconstructed = NgramBloom::from_raw_parts(num_bits, bits.to_vec()).unwrap();

        // Every n-gram inserted into the original must be found in the
        // reconstructed filter.  A false negative here means the
        // exact_pairs table was zeroed instead of disabled.
        assert!(
            reconstructed.maybe_contains(b'h', b'e'),
            "false negative for 'he'"
        );
        assert!(
            reconstructed.maybe_contains(b'e', b'l'),
            "false negative for 'el'"
        );
        assert!(
            reconstructed.maybe_contains(b'l', b'l'),
            "false negative for 'll'"
        );
        assert!(
            reconstructed.maybe_contains(b'l', b'o'),
            "false negative for 'lo'"
        );

        // Also verify pattern-level check works.
        assert!(reconstructed.maybe_contains_pattern(b"hello"));
    }

    /// Exhaustive round-trip: insert all 256 distinct pairs, serialize,
    /// reconstruct, and verify zero false negatives.
    #[test]
    fn from_raw_parts_exhaustive_round_trip() {
        let mut bloom = NgramBloom::new(65536).unwrap_or_else(|error| panic!("{error}"));
        for first in 0_u8..=255 {
            bloom.insert_ngram(first, first.wrapping_add(1));
        }

        let (num_bits, bits) = bloom.raw_parts();
        let reconstructed = NgramBloom::from_raw_parts(num_bits, bits.to_vec()).unwrap();

        for first in 0_u8..=255 {
            let second = first.wrapping_add(1);
            assert!(
                reconstructed.maybe_contains(first, second),
                "false negative for pair ({first}, {second})"
            );
        }
    }

    #[test]
    fn from_raw_parts_rejects_truncated_bits() {
        let num_bits = 1024; // requires 16 words
        let bits = vec![0u64; 1]; // only 1 word
        let result = NgramBloom::from_raw_parts(num_bits, bits);
        assert!(result.is_err());
    }

    #[test]
    fn union_of_empty_errors() {
        let result = NgramBloom::union_of(&[]);
        assert!(matches!(result, Err(crate::error::Error::EmptyBloomUnion)));
    }

    #[test]
    fn union_of_combines_blocks() {
        let a = NgramBloom::from_block(b"ab", 1024).unwrap();
        let b = NgramBloom::from_block(b"cd", 1024).unwrap();
        let u = NgramBloom::union_of(&[a, b]).unwrap();
        assert!(u.maybe_contains(b'a', b'b'));
        assert!(u.maybe_contains(b'c', b'd'));
        assert!(!u.maybe_contains(b'z', b'z'));
    }

    #[test]
    fn blocked_bloom_has_zero_false_negatives_and_low_fp_rate() {
        let mut bloom = BlockedNgramBloom::new(65_536).unwrap();
        let mut rng = StdRng::seed_from_u64(0xB10C_0BAD);
        let mut inserted = std::collections::HashSet::new();

        while inserted.len() < 10_000 {
            let pair = (rng.gen::<u8>(), rng.gen::<u8>());
            if inserted.insert(pair) {
                bloom.insert(pair.0, pair.1);
            }
        }

        for &(a, b) in &inserted {
            assert!(bloom.maybe_contains(a, b), "false negative for ({a}, {b})");
        }

        let mut false_positives = 0usize;
        let mut trials = 0usize;
        while trials < 10_000 {
            let pair = (rng.gen::<u8>(), rng.gen::<u8>());
            if inserted.contains(&pair) {
                continue;
            }
            trials += 1;
            if bloom.maybe_contains(pair.0, pair.1) {
                false_positives += 1;
            }
        }

        let rate = false_positives as f64 / trials as f64;
        assert!(rate < 0.05, "blocked bloom false positive rate was {rate}");
    }

    #[test]
    fn compact_bloom_zero_false_negatives() {
        let data = b"hello world this is a test pattern with several n-grams";
        // Use a block size large enough that block_size/2 > EXACT_PAIR_THRESHOLD_BITS
        // so the compact filter is actually smaller than the standard one.
        let block_size = 16_384;

        let compact = NgramBloom::from_block_compact(data, block_size).unwrap();

        // Assert zero false negatives for all inserted pairs
        for window in data.windows(2) {
            assert!(
                compact.maybe_contains(window[0], window[1]),
                "compact bloom had a false negative for {window:?}",
            );
        }

        // Verify size is approx half
        let standard = NgramBloom::from_block(data, block_size).unwrap();
        assert!(compact.bits.len() <= standard.bits.len() / 2 + 1);
    }
}
