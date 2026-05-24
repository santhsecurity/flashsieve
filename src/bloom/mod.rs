//! Bloom filters for 2-byte n-grams.
//!
//! # Architecture Note: Cross-Crate Coherence
//!
//! This implementation (`NgramBloom`) is intentionally separate from the general
//! purpose `BloomFilter` in `ziftsieve`.
//!
//! While both are Bloom filters using fast non-cryptographic hashing, they serve
//! different purposes and have divergent performance requirements. `flashsieve::NgramBloom`
//! is heavily specialized for exactly 2-byte n-grams.
//!
//! # False Positive Rate
//!
//! The theoretical false positive rate (FPR) for a Bloom filter with:
//! - `m` = number of bits
//! - `n` = number of inserted elements
//! - `k` = number of hash functions
//!
//! ```text
//! FPR ≈ (1 - e^(-kn/m))^k
//! ```
//!
//! For optimal `k = (m/n) × ln(2)`, this simplifies to `FPR ≈ 0.6185^(m/n)`.
//! This crate uses `k = 3` hash functions by default.
//!
//! # Hash Functions
//!
//! Uses wyhash for fast, high-quality hashing. The second hash is derived from the first
//! using `h1 ^ (h1 >> 32)`, avoiding the cost of computing a second independent hash while
//! maintaining good double-hashing properties.

/// Bloom filter construction and modification.
pub mod builder;
/// Data structures for n-gram bloom filters.
pub mod filter;
/// Query operations for n-gram bloom filters.
pub mod query;

pub(crate) mod hash;
pub(crate) mod serde;

pub use filter::{BlockedNgramBloom, NgramBloom};
