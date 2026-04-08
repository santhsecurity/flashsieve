/// A zero-parse histogram view into serialized block-index bytes.
///
/// The serialized format stores histogram counts as 256 little-endian `u32`
/// values. This reference reads those counts in-place on demand.
#[derive(Clone, Copy, Debug)]
pub struct ByteHistogramRef<'a> {
    pub(super) data: &'a [u8],
}

impl ByteHistogramRef<'_> {
    /// Return the occurrence count for one byte value.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).build(b"hello").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let hist = mmap.try_histogram(0).unwrap();
    /// assert_eq!(hist.count(b'l'), 2);
    /// ```
    #[must_use]
    pub fn count(&self, byte: u8) -> u32 {
        let offset = usize::from(byte) * std::mem::size_of::<u32>();
        u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    #[cfg(test)]
    pub(super) fn to_owned(self) -> crate::histogram::ByteHistogram {
        let mut counts = [0_u32; 256];
        for byte in u8::MIN..=u8::MAX {
            counts[usize::from(byte)] = self.count(byte);
        }
        crate::histogram::ByteHistogram::from_raw_counts(counts)
    }
}

/// A zero-parse bloom-filter view into serialized block-index bytes.
///
/// The serialized format stores bloom words as little-endian `u64` values.
/// When exact-pair tables are present in the serialized data, they are
/// used for exact 2-byte n-gram queries.
#[derive(Clone, Copy, Debug)]
pub struct NgramBloomRef<'a> {
    pub(super) bloom_data: &'a [u8],
    pub(super) exact_pairs_data: Option<&'a [u8]>,
    pub(super) num_bits: usize,
}

impl NgramBloomRef<'_> {
    /// Return the serialized bloom bit count.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"x").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert_eq!(bloom.num_bits(), 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Test a 2-byte n-gram against the exact-pair path when available.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(4096).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_exact(b'a', b'b'));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn maybe_contains_exact(&self, first: u8, second: u8) -> bool {
        if let Some(exact_pairs) = self.exact_pairs_data {
            let pair = (usize::from(first) << 8) | usize::from(second);
            let word_index = pair >> 6;
            let bit_offset = pair & 63;
            let offset = word_index * std::mem::size_of::<u64>();
            let word = u64::from_le_bytes([
                exact_pairs[offset],
                exact_pairs[offset + 1],
                exact_pairs[offset + 2],
                exact_pairs[offset + 3],
                exact_pairs[offset + 4],
                exact_pairs[offset + 5],
                exact_pairs[offset + 6],
                exact_pairs[offset + 7],
            ]);
            return (word & (1_u64 << bit_offset)) != 0;
        }

        // Fall back to bloom filter if no exact-pair table
        self.maybe_contains_bloom(first, second)
    }

    /// Test a 2-byte n-gram against the serialized bloom filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_bloom(b'a', b'b'));
    /// ```
    #[must_use]
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn maybe_contains_bloom(&self, first: u8, second: u8) -> bool {
        let (h1, h2) = crate::bloom::hash::hash_pair(first, second);
        let mask = (self.num_bits as u64).wrapping_sub(1);
        let idx0 = (h1 & mask) as usize;
        let idx1 = (h1.wrapping_add(h2) & mask) as usize;
        let idx2 = (h1.wrapping_add(h2.wrapping_mul(2)) & mask) as usize;
        self.bit_is_set(idx0) && self.bit_is_set(idx1) && self.bit_is_set(idx2)
    }

    /// Batch check multiple n-grams with OR semantics.
    ///
    /// Returns `true` if ANY n-gram is present. Optimized for internet-scale
    /// workloads where early rejection based on union n-grams is critical.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
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

    /// Batch check multiple n-grams with AND semantics.
    ///
    /// Returns `true` only if ALL n-grams are present.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, MmapBlockIndex};
    ///
    /// let bytes = BlockIndexBuilder::new().block_size(256).bloom_bits(1024).build(b"ab").unwrap().to_bytes();
    /// let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    /// let bloom = mmap.try_bloom(0).unwrap();
    /// assert!(bloom.maybe_contains_all(&[(b'a', b'b')]));
    /// ```
    #[must_use]
    #[inline]
    pub fn maybe_contains_all(&self, ngrams: &[(u8, u8)]) -> bool {
        if ngrams.is_empty() {
            return true;
        }
        if self.uses_exact_pairs() {
            ngrams.iter().all(|&(a, b)| self.maybe_contains_exact(a, b))
        } else {
            ngrams.iter().all(|&(a, b)| self.maybe_contains_bloom(a, b))
        }
    }

    /// Returns true if this bloom filter has an exact-pair table.
    #[must_use]
    #[inline]
    pub(super) fn uses_exact_pairs(&self) -> bool {
        self.exact_pairs_data.is_some()
    }

    fn bit_is_set(&self, bit_index: usize) -> bool {
        let word_index = bit_index / 64;
        let bit_offset = bit_index % 64;
        (self.bloom_word(word_index) & (1_u64 << bit_offset)) != 0
    }

    fn bloom_word(&self, word_index: usize) -> u64 {
        let offset = word_index * std::mem::size_of::<u64>();
        u64::from_le_bytes([
            self.bloom_data[offset],
            self.bloom_data[offset + 1],
            self.bloom_data[offset + 2],
            self.bloom_data[offset + 3],
            self.bloom_data[offset + 4],
            self.bloom_data[offset + 5],
            self.bloom_data[offset + 6],
            self.bloom_data[offset + 7],
        ])
    }
}
