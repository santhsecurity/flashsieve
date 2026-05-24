# flashsieve

[![crates.io](https://img.shields.io/crates/v/flashsieve.svg)](https://crates.io/crates/flashsieve)
[![docs.rs](https://docs.rs/flashsieve/badge.svg)](https://docs.rs/flashsieve)
[![license](https://img.shields.io/crates/l/flashsieve.svg)](LICENSE)

**Storage-level pre-filtering for pattern matching.**

`flashsieve` builds per-block byte histograms and 2-byte n-gram bloom filters,
then uses them to answer which blocks *might* contain matches. If a block cannot
contain a pattern, it is skipped entirely—saving CPU, I/O, and memory at scale.

---

## Installation

```toml
[dependencies]
flashsieve = "0.1"
```

Minimum supported Rust version: **1.85**.

---

## Quick Start

```rust
use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};

let mut block_a = vec![b'x'; 256];
let mut block_b = vec![b'y'; 256];
block_a[..6].copy_from_slice(b"secret");
block_b[..5].copy_from_slice(b"token");
let patterns: [&[u8]; 2] = [b"secret", b"token"];

let index = BlockIndexBuilder::new()
    .block_size(256)
    .bloom_bits(512)
    .build_streaming([block_a, block_b].into_iter())?;

let byte_filter = ByteFilter::from_patterns(&patterns);
let ngram_filter = NgramFilter::from_patterns(&patterns);

let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
assert_eq!(candidates.len(), 1);
assert_eq!(candidates[0].length, 512);
# Ok::<(), flashsieve::Error>(())
```

---

## What It Does

| Component | Purpose |
|-----------|---------|
| `BlockIndexBuilder` | Constructs indexes from raw bytes or streaming blocks |
| `BlockIndex` | In-memory index with per-block histograms & bloom filters |
| `FileBloomIndex` | File-level bloom union for fast n-gram rejection before per-block scans |
| `MmapBlockIndex` | Zero-parse, zero-copy queries over serialized indexes |
| `IncrementalBuilder` | Append new blocks to existing indexes without rebuilding |
| `ByteFilter` | Reject blocks that don't contain all required bytes |
| `NgramFilter` | Reject blocks that don't contain all required 2-byte n-grams |

---

## Bloom Filter Math

The theoretical false-positive rate for a Bloom filter with:

- `m` = number of bits  
- `n` = number of distinct n-grams inserted  
- `k` = number of hash functions (`k = 3` in this crate)

is approximately:

```text
FPR ≈ (1 - e^(-kn/m))^k
```

For the optimal number of hash functions `k = (m/n) × ln(2)`:

```text
FPR ≈ 0.6185^(m/n)
```

For filters with **≥4096 bits**, `flashsieve` allocates an exact 65,536-bit pair
table, giving **zero false positives** for all possible 2-byte n-gram queries.

---

## Safety

This crate keeps `unsafe` usage narrowly scoped to hot-path bloom-filter word
loads where index validity is proven by construction. All serialized input is
validated (magic, version, checksum, bounds) before use—corrupt files return
typed errors rather than panicking.

---

## License

Licensed under the MIT license ([LICENSE](LICENSE) or https://opensource.org/licenses/MIT).
