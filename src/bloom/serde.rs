//! Serialization for n-gram bloom filters.

use crate::bloom::filter::{NgramBloom, EXACT_PAIR_WORDS};
use crate::error::{Error, Result};

/// Magic marker indicating the serialized bloom filter includes the exact-pair table.
const EXACT_PAIR_MAGIC: u64 = 0x4558_5041_4952_535f; // "EXPAIRS_"

impl NgramBloom {
    /// Returns the internal representation for serialization.
    ///
    /// The returned tuple is `(num_bits, &[u64])` where the slice contains the
    /// raw bit vector words. Use [`from_raw_parts`](Self::from_raw_parts) to
    /// reconstruct.
    ///
    /// Note: This does not include the exact-pair table. Use
    /// [`serialize_with_exact_pairs`](Self::serialize_with_exact_pairs) to
    /// get the full serialized representation including exact pairs.
    #[must_use]
    pub fn raw_parts(&self) -> (usize, &[u64]) {
        (self.num_bits, &self.bits)
    }

    /// Serialize the bloom filter including the exact-pair table if present.
    ///
    /// Returns `(num_bits, bloom_bits, exact_pairs)` where:
    /// - `num_bits`: number of bloom bits
    /// - `bloom_bits`: slice of bloom bit vector words
    /// - `exact_pairs`: optional exact-pair table (65,536 bits = 1024 u64s)
    ///
    /// The exact-pair table is only included if the bloom filter was built
    /// with at least 4096 bits (the threshold for exact-pair allocation).
    #[must_use]
    pub fn serialize_with_exact_pairs(&self) -> (usize, &[u64], Option<&[u64; EXACT_PAIR_WORDS]>) {
        (self.num_bits, &self.bits, self.exact_pairs.as_deref())
    }

    /// Reconstruct a bloom filter from its serialized raw parts.
    ///
    /// The exact-pair acceleration table is **not** reconstructed because
    /// [`raw_parts`](Self::raw_parts) does not serialize it.  Queries on
    /// the returned filter fall through to the slower hash-based path,
    /// which is still correct (no false negatives are possible).
    ///
    /// To get the full acceleration, build a fresh bloom via
    /// [`from_block`](Self::from_block) instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedBlock`] if the provided `bits` vector is
    /// smaller than required for `num_bits`, or if `num_bits` is zero.
    pub fn from_raw_parts(num_bits: usize, bits: Vec<u64>) -> Result<Self> {
        if num_bits == 0 {
            return Err(Error::ZeroBloomBits);
        }
        if !num_bits.is_power_of_two() {
            return Err(Error::InvalidBlockSize { size: num_bits });
        }

        let required_words = num_bits.div_ceil(64);
        if bits.len() < required_words {
            return Err(Error::TruncatedBlock { block_index: 0 });
        }
        // Drop any surplus words: bit_index_mask only ever addresses the first
        // `num_bits` bits, so extra trailing words are unreachable dead weight
        // that would also break round-trip identity (serialize emits exactly
        // required_words). Keep the stored buffer exactly sized.
        let mut bits = bits;
        bits.truncate(required_words);
        Ok(Self {
            // The exact-pair table is a runtime-only acceleration
            // structure populated by insert_ngram().  It is not
            // serialized, so we must not create an empty one here, an
            // all-zero table would cause maybe_contains() to return
            // false for every query (false negatives).
            exact_pairs: None,
            bits,
            num_bits,
            bit_index_mask: (num_bits as u64).wrapping_sub(1),
        })
    }

    /// Reconstruct a bloom filter from serialized parts including exact-pair table.
    ///
    /// This restores the full acceleration capability including the exact-pair
    /// table for filters large enough to use it (≥4096 bits).
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedBlock`] if the provided data is insufficient,
    /// or [`Error::ZeroBloomBits`] if `num_bits` is zero.
    pub fn from_serialized_parts(
        num_bits: usize,
        bits: Vec<u64>,
        exact_pairs: Option<Box<[u64; EXACT_PAIR_WORDS]>>,
    ) -> Result<Self> {
        if num_bits == 0 {
            return Err(Error::ZeroBloomBits);
        }
        if !num_bits.is_power_of_two() {
            return Err(Error::InvalidBlockSize { size: num_bits });
        }

        let required_words = num_bits.div_ceil(64);
        if bits.len() < required_words {
            return Err(Error::TruncatedBlock { block_index: 0 });
        }
        // Same surplus-word truncation as from_raw_parts (ONE behavior for both
        // reconstruction entry points): keep the buffer exactly num_bits wide.
        let mut bits = bits;
        bits.truncate(required_words);

        Ok(Self {
            exact_pairs,
            bits,
            num_bits,
            bit_index_mask: (num_bits as u64).wrapping_sub(1),
        })
    }

    /// Returns the magic marker used to identify exact-pair table presence in serialized format.
    #[must_use]
    pub(crate) const fn exact_pair_magic() -> u64 {
        EXACT_PAIR_MAGIC
    }
}

#[cfg(test)]
mod truncation_tests {
    use super::*;

    #[test]
    fn from_raw_parts_truncates_surplus_words() {
        // num_bits = 64 needs exactly 1 word; pass 5. The stored buffer must be
        // trimmed to 1 (surplus words are unaddressable and break round-trip).
        let bloom = NgramBloom::from_raw_parts(64, vec![0xDEAD_BEEF; 5]).expect("valid parts");
        assert_eq!(bloom.bits.len(), 1, "surplus words must be truncated");
    }

    #[test]
    fn from_serialized_parts_truncates_surplus_words() {
        let bloom =
            NgramBloom::from_serialized_parts(128, vec![0u64; 9], None).expect("valid parts");
        // 128 bits -> 2 words required; the 9-word input must be trimmed to 2.
        assert_eq!(bloom.bits.len(), 2, "surplus words must be truncated");
    }

    #[test]
    fn from_raw_parts_still_rejects_too_few_words() {
        // 128 bits needs 2 words; 1 is too few and must still error.
        assert!(NgramBloom::from_raw_parts(128, vec![0u64; 1]).is_err());
    }
}
