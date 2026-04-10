#![allow(clippy::cast_possible_truncation)]
//! Storage-level pre-filtering for pattern matching.
//!
//! `flashsieve` builds per-block byte histograms and 2-byte n-gram bloom
//! filters, then uses them to answer which blocks might contain matches.
//!
//! # Overview
//!
//! This crate provides:
//!
//! - [`BlockIndexBuilder`] — construct indexes
//! - [`BlockIndex`] — query and serialize indexes
//! - [`FileBloomIndex`] — file-level bloom union for fast n-gram rejection before per-block scans
//! - [`IncrementalBuilder`] — append new blocks to serialized indexes without re-indexing prior data
//! - [`MmapBlockIndex`] — query serialized indexes in place
//! - [`ByteFilter`] — byte-level pre-filtering
//! - [`NgramFilter`] — n-gram bloom pre-filtering
//! - [`NgramBloom`] and [`BlockedNgramBloom`] — standalone bloom filters
//!
//! # Quick Start
//!
//! ```
//! use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};
//!
//! let mut block_a = vec![b'x'; 256];
//! let mut block_b = vec![b'y'; 256];
//! block_a[..6].copy_from_slice(b"secret");
//! block_b[..5].copy_from_slice(b"token");
//! let patterns: [&[u8]; 2] = [b"secret", b"token"];
//!
//! let index = BlockIndexBuilder::new()
//!     .block_size(256)
//!     .bloom_bits(512)
//!     .build_streaming([block_a, block_b].into_iter())?;
//!
//! let byte_filter = ByteFilter::from_patterns(&patterns);
//! let ngram_filter = NgramFilter::from_patterns(&patterns);
//!
//! let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
//! assert_eq!(candidates.len(), 1);
//! assert_eq!(candidates[0].length, 512);
//! # Ok::<(), flashsieve::Error>(())
//! ```
//!
//! # False Positive Rate
//!
//! The bloom filter's false positive rate depends on:
//! - `m` = number of bits
//! - `n` = number of distinct n-grams inserted
//! - `k` = number of hash functions (`k=3` in this crate)
//!
//! The theoretical FPR is:
//!
//! ```text
//! FPR ≈ (1 - e^(-kn/m))^k
//! ```
//!
//! For optimal `k = (m/n) × ln(2)`:
//!
//! ```text
//! FPR ≈ 0.6185^(m/n)
//! ```
//!
//! # Serialization Format
//!
//! Indexes can be serialized to a portable binary format (version 2):
//!
//! ```text
//! [magic: 4 bytes = "FSBX"]
//! [version: u32 LE = 2]
//! [block_size: u64 LE]
//! [total_len: u64 LE]
//! [block_count: u64 LE]
//! for each block:
//!   [histogram: 256 × u32 LE = 1024 bytes]
//!   [bloom_num_bits: u64 LE]
//!   [bloom_words: u64 LE]
//!   [bloom_data: bloom_words × u64 LE]
//! [crc32: u32 LE]
//! ```
//!
//! See the [`index`] module for detailed specification.
//!
//! # Hash Functions
//!
//! The bloom filter uses a primary 64-bit mix for each 2-byte n-gram and a
//! derived second hash for double hashing (`k = 3` probes):
//!
//! 1. **wyhash-style mix**: `x = (u64(a) << 8) | u64(b)`, then
//!    `x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15)`, then `x ^ (x >> 32)`.
//!
//! 2. **Second hash**: `h2 = (h1 ^ (h1 >> 32)).max(1)` so double hashing never
//!    uses a zero increment.
//!
//! # Safety
//!
//! This crate keeps `unsafe` usage narrowly scoped to hot-path bloom-filter
//! word loads where index validity is proven by construction.

#![warn(missing_docs, clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::inline_always,
    clippy::large_enum_variant,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
#![cfg_attr(
    test,
    allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]
#![deny(unsafe_code)]

/// Bloom filter primitives for block-level 2-byte n-gram summaries.
///
/// Provides [`NgramBloom`](crate::bloom::NgramBloom), a space-efficient
/// probabilistic data structure for testing membership of 2-byte sequences.
pub mod bloom;
/// Builders for constructing [`BlockIndex`](crate::BlockIndex) values from raw block data.
pub mod builder;
/// Error types returned by crate operations.
pub mod error;
/// File-level bloom wrapper over a [`BlockIndex`](crate::BlockIndex).
mod file_bloom_index;
/// Query filters used to pre-filter candidate blocks.
pub mod filter;
/// Byte histogram summaries stored for each indexed block.
pub mod histogram;
/// Incremental update operations for existing block indexes.
pub mod incremental;
/// Incremental index updates via filesystem notifications.
pub mod incremental_watch;
/// Indexed block metadata and candidate range queries.
pub mod index;
/// Zero-parse views over serialized block-index data.
pub mod mmap_index;
/// Compressed transport format for peer-to-peer bloom index sharing.
pub mod transport;

/// Per-block bloom filters for 2-byte n-gram membership checks.
pub use bloom::{BlockedNgramBloom, NgramBloom};
/// Configurable builder for constructing [`BlockIndex`] instances.
pub use builder::BlockIndexBuilder;
/// Crate error and result types.
pub use error::{Error, Result};
/// Hierarchical bloom wrapper: file-level union bloom for fast n-gram rejection.
pub use file_bloom_index::FileBloomIndex;
/// Byte-level and n-gram-level query filters.
pub use filter::{ByteFilter, NgramFilter};
/// Composite filters and logical operators for multi-pattern composition.
pub use filter::{CompositeFilter, FilterOp};
/// Per-block byte-frequency histogram.
pub use histogram::ByteHistogram;
/// Append blocks to serialized indexes without rebuilding from raw file data.
pub use incremental::IncrementalBuilder;
/// Indexed block summary and byte-range query results.
pub use index::{BlockIndex, CandidateRange};
/// Zero-parse block-index view and per-block serialized summary references.
pub use mmap_index::{ByteHistogramRef, MmapBlockIndex, NgramBloomRef};
