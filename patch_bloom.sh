sed -i '/pub fn from_block(/i \
    /// Build a compact bloom filter using half the standard bits to fit in L1 cache.\n\
    ///\n\
    /// Trades slightly higher FPR for a 2x smaller memory footprint.\n\
    ///\n\
    /// # Errors\n\
    /// Returns [`Error::ZeroBloomBits`] if the computed bit count is zero.\n\
    pub fn from_block_compact(data: &[u8], block_size: usize) -> Result<Self> {\n\
        let compact_bits = (block_size / 2).max(64);\n\
        Self::from_block(data, compact_bits)\n\
    }\n' src/bloom/mod.rs
