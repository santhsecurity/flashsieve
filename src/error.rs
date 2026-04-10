//! Error types for `flashsieve`.
//!
//! This module defines the [`Error`] enum, which represents all error
//! conditions that can occur when building indexes, serializing data,
//! or performing queries.

/// Errors returned by `flashsieve` operations.
///
/// All variants include actionable context to help diagnose issues.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Block size was not a power of two or was smaller than the minimum.
    ///
    /// Block sizes must be powers of two and at least 256 bytes.
    #[error("block size must be a power of two and at least 256 bytes; got {size}. Fix: use 256, 512, 1024, 4096, or 65536.")]
    InvalidBlockSize {
        /// The invalid block size requested by the caller.
        size: usize,
    },
    /// Input length was not aligned to the configured block size.
    ///
    /// Use [`BlockIndexBuilder::build_streaming`](crate::BlockIndexBuilder::build_streaming)
    /// for unaligned data, or pad the input to a multiple of the block size.
    #[error("data length {data_len} is not aligned to block size {block_size}. Fix: pad the input or use build_streaming.")]
    UnalignedData {
        /// The provided input length in bytes.
        data_len: usize,
        /// The configured block size in bytes.
        block_size: usize,
    },
    /// Filters require at least one pattern.
    ///
    /// Provide at least one non-empty pattern when building filters.
    #[error("pattern set is empty. Fix: provide at least one non-empty pattern.")]
    EmptyPatterns,
    /// Bloom filters require at least one bit.
    ///
    /// The bloom bit count must be greater than zero.
    #[error(
        "bloom filter bit count must be greater than zero. Fix: set bloom_bits to at least 64."
    )]
    ZeroBloomBits,
    /// The serialized header is too short to contain the required fields.
    ///
    /// The minimum header size is 29 bytes (magic + version + 3 × u64).
    #[error("truncated header: expected at least {expected} bytes, got {got}. Fix: verify the serialized index file is complete.")]
    TruncatedHeader {
        /// Minimum required header size.
        expected: usize,
        /// Actual data length.
        got: usize,
    },
    /// The serialized magic number does not match `FSIE`.
    ///
    /// The data may be corrupted or in an unsupported format.
    #[error("invalid magic: expected FSBX, got {got:?}. Fix: ensure the file is a flashsieve index, not raw data.")]
    InvalidMagic {
        /// The four bytes found at the start of the data.
        got: [u8; 4],
    },
    /// The serialized format version is not supported.
    ///
    /// This crate supports version {max_supported}.
    #[error("unsupported format version: got {got}, supported: {max_supported}. Fix: rebuild the index with the current flashsieve version.")]
    UnsupportedVersion {
        /// The version byte in the data.
        got: u32,
        /// The highest version this build can read.
        max_supported: u32,
    },
    /// The block count in the header exceeds what the data could possibly hold.
    ///
    /// This usually indicates corrupted or truncated serialized data.
    #[error("block count overflow: header claims {claimed} blocks, max plausible {max_plausible}. Fix: the index file is likely corrupted — rebuild it.")]
    BlockCountOverflow {
        /// The block count from the header.
        claimed: u64,
        /// Maximum plausible blocks given the data size.
        max_plausible: usize,
    },
    /// A per-block section is truncated.
    ///
    /// The data ended unexpectedly while reading histogram or bloom data
    /// for the specified block.
    #[error("truncated block data at block index {block_index}. Fix: the index file is incomplete — rebuild it.")]
    TruncatedBlock {
        /// The zero-based block index that was being parsed.
        block_index: usize,
    },
    /// CRC checksum mismatch (version >= 2 only).
    ///
    /// The data may be corrupted. Verify the integrity of the serialized data.
    #[error("checksum mismatch: stored 0x{expected:08X}, computed 0x{computed:08X}. Fix: the index is corrupted — rebuild it from source data.")]
    ChecksumMismatch {
        /// The CRC stored in the data.
        expected: u32,
        /// The CRC computed over the data.
        computed: u32,
    },
    /// Two indexes could not be merged because their configurations differ.
    ///
    /// Merge only indexes built with the same block size and bloom filter size.
    #[error("incompatible index configuration: {reason}. Fix: merge only indexes with matching block_size and bloom_bits")]
    IncompatibleIndexConfiguration {
        /// Human-readable explanation of the mismatch.
        reason: &'static str,
    },
    /// A requested block ID does not exist in the index.
    ///
    /// Validate the provided IDs against `BlockIndex::block_count()`.
    #[error("block id {block_id} is out of range for {block_count} blocks. Fix: provide only ids in 0..{block_count}")]
    InvalidBlockId {
        /// The invalid zero-based block ID.
        block_id: usize,
        /// The current block count.
        block_count: usize,
    },
    /// A [`FileBloomIndex`](crate::FileBloomIndex) cannot be built from an empty index.
    ///
    /// The file-level bloom is a union of per-block blooms; with zero blocks there is nothing to merge.
    #[error("file-level bloom requires at least one indexed block; Fix: build an index with one or more blocks")]
    EmptyBlockIndex,
    /// [`NgramBloom::union_of`](crate::NgramBloom::union_of) was called with an empty slice.
    #[error("bloom union requires at least one filter; Fix: pass a non-empty slice of NgramBloom values")]
    EmptyBloomUnion,
    /// The compressed transport data is invalid or corrupted.
    #[error("transport format error: {reason}. Fix: verify the transport data was not truncated or corrupted in transit.")]
    Transport {
        /// Human-readable explanation of the transport failure.
        reason: String,
    },
    /// Removing non-trailing blocks would corrupt offset mapping.
    ///
    /// The index assumes uniform `index * block_size` offsets. Removing a block
    /// from the middle breaks this invariant for all subsequent blocks.
    #[error("remove_blocks only supports suffix removal (trailing blocks). Fix: pass only the last N block IDs, or rebuild the index from source data.")]
    NonSuffixBlockRemoval,
    /// Input data exceeds the maximum length representable by the platform.
    #[error("input data length exceeds platform limits. Fix: process data in smaller chunks.")]
    DataTooLarge,
    /// Target false-positive rate is not a valid finite number in (0, 1).
    #[error("target FPR must be a finite number in (0, 1); got {fpr}. Fix: use 0.01, 0.001, etc.")]
    InvalidFpr {
        /// The invalid FPR value provided by the caller.
        fpr: f64,
    },
    /// The index ends with a partial block and cannot be appended to or merged.
    #[error("index ends with a partial block ({total_len} bytes, block size {block_size}). Fix: rebuild from aligned source data or remove the trailing partial block.")]
    TrailingPartialBlock {
        /// Total length of the indexed data in bytes.
        total_len: usize,
        /// Block size in bytes.
        block_size: usize,
    },
}

/// Convenience result type for `flashsieve`.
pub type Result<T> = std::result::Result<T, Error>;
