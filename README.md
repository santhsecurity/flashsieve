# flashsieve

`flashsieve` is a high-performance, zero-unsafe storage-level pre-filter for pattern matching. It builds a block index over raw bytes and answers a narrower question than a full matcher:

> Which blocks might contain a match?

It does this with two cheap summaries per block:

- A 256-entry byte-frequency histogram (1024 bytes)
- A 2-byte n-gram Bloom filter (configurable bit width)

This lets downstream matchers skip blocks that **cannot possibly match** while preserving **zero false negatives** for matches fully contained inside a block.

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

// Adjacent candidate ranges are merged automatically
let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);
assert_eq!(candidates.len(), 1);
assert_eq!(candidates[0].length, 512);
# Ok::<(), flashsieve::Error>(())
```

## Bloom Filter Theory

A Bloom filter is a space-efficient probabilistic data structure that answers set-membership queries. It can produce **false positives** but never **false negatives**.

For a standard Bloom filter with:
- `m` = number of bits
- `n` = number of distinct elements inserted
- `k` = number of independent hash functions

the theoretical false-positive rate is:

```
FPR ≈ (1 - e^(-kn/m))^k
```

For the optimal number of hash functions `k = (m/n) × ln(2)`, this simplifies to:

```
FPR ≈ 0.6185^(m/n)
```

`flashsieve` uses **k = 3** hash functions by default and rounds `m` up to the next power of two for fast bitwise indexing.

### Exact-Pair Acceleration

For filters with **≥4096 bits**, `flashsieve` allocates an exact 65,536-bit pair table (one bit per possible 2-byte n-gram). This provides **zero false positives** for 2-byte queries at the cost of an extra 8KB per block.

### Sizing a Filter

```rust
use flashsieve::NgramBloom;

// Target 1% FPR with ~1000 expected n-grams
let bloom = NgramBloom::with_target_fpr(0.01, 1000).unwrap();
println!("Allocated bits: {}", bloom.raw_parts().0);
```

### Reference Table (k = 3)

| Bits per element (m/n) | Expected FPR |
|------------------------|--------------|
| 4                      | ~2.6%        |
| 8                      | ~0.21%       |
| 16                     | ~0.0015%     |
| 32                     | ~2.6 × 10⁻⁸  |

## How It Works

`flashsieve` is **not** a matcher. It only rules blocks out quickly:

1. **Byte histograms** reject blocks missing required individual bytes.
2. **2-byte Bloom filters** reject blocks missing required adjacent byte pairs.
3. **Paired queries** keep per-pattern byte and n-gram requirements together, reducing cross-pattern false positives.
4. **File-level bloom union** (`FileBloomIndex`) adds a hierarchical short-circuit: if an n-gram is absent from the file-level union, no per-block scan is needed.

The result is a compact candidate set handed off to an expensive downstream matcher.

## Index Construction

- `BlockIndexBuilder::build` accepts any byte slice. A partial final block is indexed as-is.
- `BlockIndexBuilder::build_streaming` accepts an iterator of already-sized blocks and is ideal when chunking is managed externally.
- Block sizes must be powers of two and at least **256 bytes**.
- Bloom filter bit counts must be greater than zero.

## Serialization Format

Indexes serialize to a portable binary format (version 2) with CRC-32 integrity checking.

### Header

```text
Offset  Size  Field                    Description
─────────────────────────────────────────────────────────────
0       4     magic                    "FSBX" (0x46 0x53 0x42 0x58)
4       4     version                  Format version (u32 LE = 2)
8       8     block_size               Block size in bytes (u64 LE)
16      8     total_len                Total data length in bytes (u64 LE)
24      8     block_count              Number of blocks (u64 LE)
32      N     blocks[]                 Per-block data
N+32    4     crc32                    CRC-32 checksum (u32 LE)
```

### Per-Block Layout

```text
Offset  Size  Field
─────────────────────────────────────────────────────────────
0       1024  histogram                256 × u32 LE counts
1024    8     bloom_num_bits           Number of bloom bits (u64 LE)
1032    8     bloom_word_count         Number of u64 words (u64 LE)
1040    M     bloom_data               bloom_word_count × u64 LE
1040+M  8     exact_pair_marker        Optional: EXACT_PAIR magic
1048+M  8192  exact_pairs              Optional: 1024 × u64 LE
```

### CRC-32

Uses the standard ISO 3309 / ITU-T V.42 polynomial:
- Polynomial: `0xEDB8_8320` (reversed)
- Initial value: `0xFFFF_FFFF`
- Final XOR: `0xFFFF_FFFF`

### Example

```rust
use flashsieve::{BlockIndexBuilder, BlockIndex};

let index = BlockIndexBuilder::new()
    .block_size(256)
    .build(&[0u8; 512])
    .unwrap();

// Serialize
let bytes = index.to_bytes();

// Deserialize with full error reporting
let recovered = BlockIndex::from_bytes_checked(&bytes).unwrap();
```

## Advanced: Incremental Updates

Append new blocks to an existing serialized index without rebuilding from scratch:

```rust
use flashsieve::{BlockIndexBuilder, IncrementalBuilder};

let base = BlockIndexBuilder::new()
    .block_size(256)
    .bloom_bits(1024)
    .build_streaming([vec![b'a'; 256]].into_iter())
    .unwrap();

let serialized = base.to_bytes();
let extra = vec![b'b'; 256];

// Pass the last byte of the original data for correct boundary n-grams
let appended = IncrementalBuilder::append_blocks_with_boundary(
    &serialized, Some(b'a'), &[extra.as_slice()]
).unwrap();

let recovered = flashsieve::BlockIndex::from_bytes_checked(&appended).unwrap();
assert_eq!(recovered.block_count(), 2);
```

## Guarantees and Limits

- **No false negatives** for patterns that fit entirely inside one indexed block.
- **False positives** are possible by design from Bloom filtering (except when exact-pair tables are active).
- Patterns spanning two neighboring blocks are handled automatically via pair-wise union checks.
- Patterns spanning three or more blocks are handled by a sliding-window fallback sized from the longest pattern length.

## Hash Functions

The Bloom filter uses a **wyhash**-style primary hash and derives the second hash via a cheap finalizer:

```text
h1 = wyhash_pair(a, b)
h2 = derive_second_hash(h1) = (h1 ^ (h1 >> 32)).max(1)
```

All bit-index reductions use a power-of-two bitmask for constant-time lookup.

## Performance

- **Index build:** `O(n)` over the input bytes
- **Query:** `O(blocks)` for the block index
- **Memory:** one 256-entry histogram + one bloom filter per block

This trades a modest index size for a large reduction in bytes handed to the expensive matcher.

Criterion benchmarks live in `benches/` and cover bloom insert/query, histogram construction, skip decisions, and full indexing pipelines.

## Safety

This crate is `#![forbid(unsafe_code)]` at the top level. A small number of hot-path functions use narrowly scoped `unsafe` blocks for unchecked array accesses where index validity is proven by construction.

## License

MIT License — see [LICENSE](LICENSE) for details.
