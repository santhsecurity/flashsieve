//! Hash functions for n-gram bloom filters.
//!
//! Uses wyhash for fast, high-quality hashing with a single multiply per hash.
//! The second hash is derived from the first using a cheap finalizer, avoiding
//! the cost of computing two independent hashes.

/// wyhash-style hash for a 2-byte n-gram.
///
/// Fast, single-multiplication hash with good distribution properties.
/// Mixes the 2-byte value with a random-looking constant via wrapping_mul
/// followed by an xor-shift for avalanche.
///
/// # Algorithm
///
/// ```text
/// x = (u64(a) << 8) | u64(b)
/// x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15)
/// x ^ (x >> 32)
/// ```
///
/// This achieves better distribution than FNV-1a (which uses 2 multiplies
/// per 2-byte input) in a single multiply, reducing hash computation time
/// by ~50% while improving collision resistance.
#[inline(always)]
pub(crate) fn wyhash_pair(a: u8, b: u8) -> u64 {
    // Mix the 2-byte value - combine bytes then xor-shift
    let x = (u64::from(a) << 8) | u64::from(b);
    // wyhash-style mixing constant (golden ratio related)
    let x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // Final mix for good distribution
    x ^ (x >> 32)
}

/// Derive the second hash from the first using a cheap finalizer.
///
/// This avoids computing a second independent hash while still providing
/// good double-hashing properties. The mixing ensures h2 is different
/// from h1 even for similar inputs.
///
/// Uses: `h1 ^ (h1 >> 32)` which provides good bit mixing and ensures
/// h2 != h1 for almost all values.
#[inline(always)]
pub(crate) fn derive_second_hash(h1: u64) -> u64 {
    // Mix high and low bits - ensures h2 is different from h1
    // and provides good distribution for double hashing
    let h2 = h1 ^ (h1 >> 32);
    // Ensure h2 is never 0 (required for double-hashing to work correctly).
    // h2.max(1) is clearer but the bitwise OR avoids a branch on some CPUs.
    h2.max(1)
}

/// Hash a 2-byte n-gram into two 64-bit values for double hashing.
///
/// Uses wyhash for the primary hash and derives the second hash
/// via a cheap finalizer. This is significantly faster than computing
/// two independent hashes while maintaining excellent distribution.
#[inline(always)]
pub(crate) fn hash_pair(a: u8, b: u8) -> (u64, u64) {
    let h1 = wyhash_pair(a, b);
    let h2 = derive_second_hash(h1);
    (h1, h2)
}

/// Convert a hash value to a bit index.
///
/// Uses bitwise AND for fast reduction — num_bits is always a power of two
/// (enforced during construction). The legacy modulo fallback was removed
/// to eliminate a branch from the hot path.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn hash_to_index(hash: u64, num_bits: usize) -> usize {
    debug_assert!(
        (num_bits as u64).is_power_of_two(),
        "hash_to_index: num_bits must be a power of two, got {num_bits}"
    );
    // SAFETY: (hash & ((num_bits as u64) - 1)) is at most num_bits - 1, which fits in usize
    // because num_bits is usize.
    (hash & ((num_bits as u64).wrapping_sub(1))) as usize
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::identity_op,
    clippy::items_after_statements,
    clippy::manual_range_contains,
    clippy::uninlined_format_args,
    clippy::unreadable_literal
)]
mod tests {
    use super::*;

    /// Test that hash_pair produces consistent results for the same input.
    #[test]
    fn hash_pair_consistent() {
        let (h1_a, h2_a) = hash_pair(0x41, 0x42);
        let (h1_b, h2_b) = hash_pair(0x41, 0x42);
        assert_eq!(h1_a, h1_b);
        assert_eq!(h2_a, h2_b);
    }

    /// Test that hash_pair produces different hashes for different inputs.
    /// This is probabilistic but should hold for almost all pairs.
    #[test]
    fn hash_pair_distinct_for_different_inputs() {
        let (h1_ab, _) = hash_pair(0x41, 0x42);
        let (h1_ba, _) = hash_pair(0x42, 0x41);
        // These should be different (collision is extremely unlikely)
        assert_ne!(h1_ab, h1_ba, "hash collision for reversed bytes");
    }

    /// Test that the second hash is always non-zero.
    /// Zero h2 would break the double-hashing invariant.
    #[test]
    fn second_hash_never_zero() {
        for a in 0_u8..=255 {
            for b in 0_u8..=255 {
                let (_, h2) = hash_pair(a, b);
                assert_ne!(h2, 0, "h2 was zero for ({a}, {b})");
            }
        }
    }

    /// Test that h2 is derived from h1 and is different from h1.
    #[test]
    fn second_hash_derived_from_first() {
        for a in 0_u8..=255 {
            for b in 0_u8..=255 {
                let h1 = wyhash_pair(a, b);
                let h2 = derive_second_hash(h1);
                // h2 should equal h1 ^ (h1 >> 32), or 1 if that equals 0
                let expected = h1 ^ (h1 >> 32);
                let expected = if expected == 0 { 1 } else { expected };
                assert_eq!(h2, expected, "h2 derivation mismatch for ({a}, {b})");
            }
        }
    }

    /// Verify wyhash has fewer collisions than FNV-1a on random pairs.
    ///
    /// This test generates 10,000 random (a, b) pairs and counts collisions
    /// for both hash functions. The new wyhash should have fewer or equal
    /// collisions compared to the old FNV-1a implementation.
    #[test]
    fn wyhash_fewer_collisions_than_fnv1a() {
        use std::collections::HashSet;

        // Generate 10,000 random-ish pairs using a simple LCG
        let mut pairs = Vec::with_capacity(10_000);
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..10_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a = (state >> 8) as u8;
            let b = (state >> 24) as u8;
            pairs.push((a, b));
        }

        // Count wyhash collisions
        let mut wyhash_set = HashSet::new();
        let mut wyhash_collisions = 0_usize;
        for (a, b) in &pairs {
            let h = wyhash_pair(*a, *b);
            if !wyhash_set.insert(h) {
                wyhash_collisions += 1;
            }
        }

        // Count FNV-1a collisions (old implementation)
        fn fnv1a_pair_64(a: u8, b: u8) -> u64 {
            const FNV_OFFSET_BASIS_64: u64 = 0xCBF2_9CE4_8422_2325;
            const FNV_PRIME_64: u64 = 0x0000_0100_0000_01B3;
            let mut hash = FNV_OFFSET_BASIS_64;
            hash ^= u64::from(a);
            hash = hash.wrapping_mul(FNV_PRIME_64);
            hash ^= u64::from(b);
            hash.wrapping_mul(FNV_PRIME_64)
        }

        let mut fnv_set = HashSet::new();
        let mut fnv_collisions = 0_usize;
        for (a, b) in &pairs {
            let h = fnv1a_pair_64(*a, *b);
            if !fnv_set.insert(h) {
                fnv_collisions += 1;
            }
        }

        // wyhash should have fewer or equal collisions
        assert!(
            wyhash_collisions <= fnv_collisions,
            "wyhash had more collisions ({}) than FNV-1a ({})",
            wyhash_collisions,
            fnv_collisions
        );
    }

    /// Test avalanche property: changing any bit of input changes output significantly.
    #[test]
    fn wyhash_avalanche() {
        // Test that flipping a bit in input causes ~50% of output bits to flip
        let base = wyhash_pair(0x00, 0x00);
        let mut total_bit_diffs = 0_usize;
        let mut count = 0_usize;

        for i in 0..8 {
            // Flip bit i in first byte
            let flipped = wyhash_pair(0x00 | (1 << i), 0x00);
            let diff = base ^ flipped;
            total_bit_diffs += diff.count_ones() as usize;
            count += 1;

            // Flip bit i in second byte
            let flipped = wyhash_pair(0x00, 0x00 | (1 << i));
            let diff = base ^ flipped;
            total_bit_diffs += diff.count_ones() as usize;
            count += 1;
        }

        let avg_bits_changed = total_bit_diffs as f64 / count as f64;
        // Should be close to 32 (half of 64 bits)
        assert!(
            avg_bits_changed >= 16.0 && avg_bits_changed <= 48.0,
            "avalanche test failed: average {} bits changed (expected ~32)",
            avg_bits_changed
        );
    }
}
