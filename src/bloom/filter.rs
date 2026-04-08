pub(crate) const NUM_HASHES: u32 = 3;

/// Threshold for allocating the exact-pairs table (64KB).
///
/// The exact-pairs table provides O(1) zero-FPR lookups for all 65,536 possible
/// 2-byte n-grams. It's allocated when the bloom filter has ≥4096 bits because:
///
/// 1. At 4096 bits, the bloom uses 512 bytes; adding 64KB is a 128x increase
/// 2. The table eliminates ALL false positives for 2-byte queries
/// 3. Lookup is a single array index vs 3 hash probes
///
/// For internet-scale workloads (10K+ patterns × 1M+ files), this 64KB
/// investment pays off in reduced FPR and faster rejection of non-matching files.
///
/// NOTE: When using `NgramBloom::from_block` with exactly 4096 bits, the exact
/// pairs table IS allocated and used. However, after serialization via `raw_parts`
/// and deserialization via `from_raw_parts`, the exact-pairs table is NOT
/// reconstructed (it falls back to hash-based lookups). For full performance
/// with exact pairs, rebuild the bloom from raw data instead of deserializing.
pub(crate) const EXACT_PAIR_THRESHOLD_BITS: usize = 4096;

/// Number of u64 words in the exact-pairs table (65,536 bits = 8KB).
pub(crate) const EXACT_PAIR_WORDS: usize = 65_536 / 64;

/// A bloom filter tracking which n-grams (2-byte sequences) appear in a block.
///
/// Uses double hashing with k=3 for efficient membership testing.
/// For large filters (≥4096 bits), an exact 16-bit pair table provides
/// zero false positives for the 65,536 possible 2-byte sequences.
#[derive(Clone, Debug)]
pub struct NgramBloom {
    pub(crate) bits: Vec<u64>,
    pub(crate) exact_pairs: Option<Box<[u64; EXACT_PAIR_WORDS]>>,
    pub(crate) num_bits: usize,
    pub(crate) bit_index_mask: u64,
}

/// Cache-line-local blocked bloom filter for 2-byte n-grams.
///
/// Each n-gram maps to a single 512-bit block so all probes stay inside one
/// 64-byte cache line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedNgramBloom {
    pub(crate) blocks: Vec<[u64; 8]>,
    pub(crate) exact_pairs: Option<Box<[u64; EXACT_PAIR_WORDS]>>,
    pub(crate) num_blocks: usize,
    pub(crate) block_mask: usize,
}

impl PartialEq for NgramBloom {
    fn eq(&self, other: &Self) -> bool {
        // exact_pairs is a runtime-only acceleration structure not stored
        // on disk. We ignore it for equality so round-tripped indexes
        // compare equal to their originals.
        self.bits == other.bits
            && self.num_bits == other.num_bits
            && self.bit_index_mask == other.bit_index_mask
    }
}

impl Eq for NgramBloom {}
