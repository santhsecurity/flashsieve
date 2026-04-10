use crate::bloom::filter::{
    BlockedNgramBloom, NgramBloom, EXACT_PAIR_THRESHOLD_BITS, EXACT_PAIR_WORDS,
};
use crate::bloom::hash::{hash_pair, hash_to_index, wyhash_pair};
use crate::error::{Error, Result};

/// Maximum bloom filter bit count to prevent unbounded allocations (128 Mbits = 16 MiB).
const MAX_BLOOM_BITS: usize = 1 << 30;

impl NgramBloom {
    /// Create a new bloom filter with the specified number of bits.
    ///
    /// The actual bit count is rounded up to the next power of two and
    /// clamped to at least 64 bits for efficient indexing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroBloomBits`] if
    /// `num_bits` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let bloom = NgramBloom::new(1024).unwrap();
    /// ```
    pub fn new(num_bits: usize) -> Result<Self> {
        if num_bits == 0 {
            return Err(Error::ZeroBloomBits);
        }
        if num_bits > MAX_BLOOM_BITS {
            return Err(Error::BloomBitsTooLarge {
                bits: num_bits,
                max: MAX_BLOOM_BITS,
            });
        }

        // PERF: Enforce power of two allocation to replace hot-path `%` with `&`
        let num_bits = num_bits
            .checked_next_power_of_two()
            .unwrap_or(1_usize << (usize::BITS - 1))
            .max(64);

        let words = num_bits.div_ceil(64);
        Ok(Self {
            bits: vec![0; words],
            exact_pairs: (num_bits >= EXACT_PAIR_THRESHOLD_BITS)
                .then(|| Box::new([0; EXACT_PAIR_WORDS])),
            num_bits,
            bit_index_mask: (num_bits as u64).wrapping_sub(1),
        })
    }

    /// Build from a data block, inserting all 2-byte n-grams.
    ///
    /// **Boundary note:** This only indexes n-grams that lie entirely within
    /// `data`. If `data` is one block of a larger stream, the caller must
    /// manually insert the cross-boundary n-gram (last byte of the previous
    /// block + first byte of this block) to avoid false negatives for patterns
    /// that span the boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroBloomBits`] if
    /// `num_bits` is zero. Blocks shorter than two bytes produce an empty
    /// filter.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let bloom = NgramBloom::from_block(b"hello world", 1024).unwrap();
    /// assert!(bloom.maybe_contains(b'e', b'l'));
    /// ```
    pub fn from_block(data: &[u8], num_bits: usize) -> Result<Self> {
        let mut bloom = Self::new(num_bits)?;
        for window in data.windows(2) {
            bloom.insert_ngram(window[0], window[1]);
        }
        Ok(bloom)
    }

    /// Build a compact bloom filter using half the standard bits to fit in L1 cache.
    ///
    /// Trades slightly higher FPR for a 2x smaller memory footprint.
    ///
    /// # Errors
    /// Returns [`Error::ZeroBloomBits`] if the computed bit count is zero.
    pub fn from_block_compact(data: &[u8], block_size: usize) -> Result<Self> {
        // For small block sizes, block_size/2 produces a bloom filter so tiny that
        // the false-positive rate approaches 100 %. Force at least the exact-pair
        // threshold so the filter remains useful.
        let compact_bits = (block_size / 2).max(64).max(EXACT_PAIR_THRESHOLD_BITS);
        Self::from_block(data, compact_bits)
    }

    /// Auto-size a bloom filter for a target false positive rate.
    ///
    /// Uses the optimal bloom filter formula: `m = -n × ln(p) / (ln 2)²`.
    ///
    /// # Arguments
    ///
    /// * `target_fpr` — desired false positive rate (e.g. 0.01 for 1%)
    /// * `expected_items` — anticipated number of distinct n-grams to insert
    ///
    /// # Errors
    ///
    /// Returns an error when the computed bit count is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// // Target 1% FPR with ~1000 expected items
    /// let bloom = NgramBloom::with_target_fpr(0.01, 1000).unwrap();
    /// ```
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn with_target_fpr(target_fpr: f64, expected_items: usize) -> Result<Self> {
        if !target_fpr.is_finite() || target_fpr <= 0.0 || target_fpr >= 1.0 {
            return Err(Error::InvalidFpr { fpr: target_fpr });
        }
        let n = (expected_items.max(1)) as f64;
        // This bloom filter uses a fixed k = 3 hash functions.  The optimal
        // m formula for k = 3 is:
        //   m = -3n / ln(1 - p^(1/3))
        // where p is the target false-positive rate.
        let p = target_fpr;
        let root = p.powf(1.0 / 3.0);
        let denom = (1.0 - root).ln();
        let raw_bits = if denom == 0.0 {
            MAX_BLOOM_BITS as f64
        } else {
            -(3.0 * n) / denom
        };
        if raw_bits > MAX_BLOOM_BITS as f64 {
            return Err(Error::BloomBitsTooLarge {
                bits: raw_bits as usize,
                max: MAX_BLOOM_BITS,
            });
        }
        let num_bits = ((raw_bits.ceil() as u64).try_into().unwrap_or(usize::MAX)).max(64);
        Self::new(num_bits)
    }

    /// Insert a 2-byte n-gram.
    ///
    /// Marks all k hash positions in the bit vector. For large filters,
    /// also records the n-gram in the exact pair table.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let mut bloom = NgramBloom::new(1024).unwrap();
    /// bloom.insert_ngram(b'a', b'b');
    /// assert!(bloom.maybe_contains(b'a', b'b'));
    /// ```
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn insert_ngram(&mut self, a: u8, b: u8) {
        if let Some(exact_pairs) = &mut self.exact_pairs {
            let pair = (usize::from(a) << 8) | usize::from(b);
            let word_index = pair >> 6;
            let bit_offset = pair & 63;
            exact_pairs[word_index] |= 1_u64 << bit_offset;
        }

        let (h1, h2) = hash_pair(a, b);
        let mask = self.bit_index_mask;

        // Unrolled k=3 insertions (matches maybe_contains unroll).
        let idx0 = (h1 & mask) as usize;
        let idx1 = (h1.wrapping_add(h2) & mask) as usize;
        let idx2 = (h1.wrapping_add(h2.wrapping_mul(2)) & mask) as usize;
        self.bits[idx0 >> 6] |= 1_u64 << (idx0 & 63);
        self.bits[idx1 >> 6] |= 1_u64 << (idx1 & 63);
        self.bits[idx2 >> 6] |= 1_u64 << (idx2 & 63);
    }

    /// Bitwise OR of all bloom word vectors — the set union of n-grams across blocks.
    ///
    /// All inputs must share the same `num_bits` and word length (same as a single
    /// [`BlockIndex`](crate::BlockIndex) with uniform `bloom_bits`). The result uses only
    /// the hash-based representation (no exact-pair table), which is sufficient for
    /// membership queries on the merged bit vector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyBloomUnion`] when `blooms` is empty, or
    /// [`Error::IncompatibleIndexConfiguration`] when bit widths or word lengths differ.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::NgramBloom;
    ///
    /// let a = NgramBloom::from_block(b"ab", 1024).unwrap();
    /// let b = NgramBloom::from_block(b"cd", 1024).unwrap();
    /// let u = NgramBloom::union_of(&[a, b]).unwrap();
    /// assert!(u.maybe_contains(b'a', b'b'));
    /// assert!(u.maybe_contains(b'c', b'd'));
    /// ```
    pub fn union_of(blooms: &[Self]) -> Result<Self> {
        if blooms.is_empty() {
            return Err(Error::EmptyBloomUnion);
        }

        let (num_bits, first_words) = blooms[0].raw_parts();
        let word_len = first_words.len();

        for bloom in blooms.iter().skip(1) {
            let (nb, words) = bloom.raw_parts();
            if nb != num_bits {
                return Err(Error::IncompatibleIndexConfiguration {
                    reason: "bloom num_bits differs across blocks",
                });
            }
            if words.len() != word_len {
                return Err(Error::IncompatibleIndexConfiguration {
                    reason: "bloom word length differs across blocks",
                });
            }
        }

        let mut merged = vec![0_u64; word_len];
        for bloom in blooms {
            for (dst, &w) in merged.iter_mut().zip(bloom.raw_parts().1.iter()) {
                *dst |= w;
            }
        }

        Self::from_raw_parts(num_bits, merged)
    }
}

impl BlockedNgramBloom {
    /// Create a blocked bloom filter with at least `num_bits` bits.
    ///
    /// The block count is rounded up to the next power of two. Each block
    /// contains 512 bits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroBloomBits`] when `num_bits` is zero.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::BlockedNgramBloom;
    ///
    /// let bloom = BlockedNgramBloom::new(4096).unwrap();
    /// ```
    pub fn new(num_bits: usize) -> Result<Self> {
        if num_bits == 0 {
            return Err(Error::ZeroBloomBits);
        }
        if num_bits > MAX_BLOOM_BITS {
            return Err(Error::BloomBitsTooLarge {
                bits: num_bits,
                max: MAX_BLOOM_BITS,
            });
        }

        let block_count = num_bits
            .div_ceil(512)
            .max(1)
            .checked_next_power_of_two()
            .unwrap_or(1usize << (usize::BITS - 1));

        Ok(Self {
            blocks: vec![[0; 8]; block_count],
            exact_pairs: (num_bits >= EXACT_PAIR_THRESHOLD_BITS)
                .then(|| Box::new([0; EXACT_PAIR_WORDS])),
            num_blocks: block_count,
            block_mask: block_count - 1,
        })
    }

    /// Insert a 2-byte n-gram.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::BlockedNgramBloom;
    ///
    /// let mut bloom = BlockedNgramBloom::new(4096).unwrap();
    /// bloom.insert(b'a', b'b');
    /// assert!(bloom.maybe_contains(b'a', b'b'));
    /// ```
    pub fn insert(&mut self, a: u8, b: u8) {
        if let Some(exact_pairs) = &mut self.exact_pairs {
            let pair = (usize::from(a) << 8) | usize::from(b);
            let word_index = pair >> 6;
            let bit_offset = pair & 63;
            exact_pairs[word_index] |= 1_u64 << bit_offset;
        }

        let block_index = hash_to_index(wyhash_pair(a, b), self.num_blocks);
        let block = &mut self.blocks[block_index];
        let (h1, h2) = hash_pair(a, b);
        for probe in 0..3u64 {
            let bit_index = h1
                .wrapping_add(h2.wrapping_mul(probe))
                .wrapping_add(probe.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                & 511;
            let word_index = (bit_index >> 6) as usize;
            let bit_offset = (bit_index & 63) as u32;
            block[word_index] |= 1_u64 << bit_offset;
        }
    }

    /// Build a blocked bloom filter from an input block.
    ///
    /// **Boundary note:** Like [`NgramBloom::from_block`], this only indexes
    /// n-grams inside `data`. Cross-boundary n-grams must be inserted manually
    /// when the data is part of a larger stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroBloomBits`] when `num_bits` is zero.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::BlockedNgramBloom;
    ///
    /// let bloom = BlockedNgramBloom::from_block(b"hello", 4096).unwrap();
    /// assert!(bloom.maybe_contains(b'h', b'e'));
    /// ```
    pub fn from_block(data: &[u8], num_bits: usize) -> Result<Self> {
        let mut bloom = Self::new(num_bits)?;
        for window in data.windows(2) {
            bloom.insert(window[0], window[1]);
        }
        Ok(bloom)
    }
}
