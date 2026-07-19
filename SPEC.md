# flashsieve: Specification

## Overview

`flashsieve` is a storage-level pre-filtering library for pattern matching over byte streams. It partitions data into fixed-size blocks and builds two compact per-block summaries: a 256-entry byte frequency histogram and a 2-byte n-gram Bloom filter. At query time, patterns are translated into required bytes and n-grams; any block that cannot contain all required elements is skipped, yielding candidate byte ranges for a downstream matcher to scan.

## Architecture

The crate is organized around indexing, filtering, and querying:

- **`builder`**: `BlockIndexBuilder` constructs a `BlockIndex` from a contiguous slice or a streaming iterator of blocks. Validates that `block_size` is a power of two and ≥256, and that `bloom_bits` > 0.
- **`index`**: `BlockIndex` holds per-block `ByteHistogram` and `NgramBloom` values. Provides query methods, serialization, merge/append/remove operations, and statistics.
- **`histogram`**: `ByteHistogram` is a 256 × `u32` frequency table (1024 bytes serialized). Built with 4-way split accumulation to avoid store-forwarding stalls.
- **`bloom`**: `NgramBloom` is a bit-vector Bloom filter for 2-byte n-grams using `k = 3` hash probes (wyhash-style 64-bit mix plus double hashing). For `bloom_bits ≥ 4096`, an exact 65,536-bit pair table (8 KB) is allocated, giving zero false positives for any 2-byte query. `BlockedNgramBloom` is a cache-line-local variant (512-bit blocks).
- **`filter`**: `ByteFilter` tests histograms for required bytes; `NgramFilter` tests blooms for required 2-byte n-grams. `CompositeFilter` combines them recursively with `And` / `Or`.
- **`mmap_index`**: `MmapBlockIndex` is a zero-parse, zero-copy view over serialized bytes. Validates the header and block layout once, then queries directly by offset.
- **`file_bloom_index`**: `FileBloomIndex` wraps a `BlockIndex` with a file-level union Bloom filter (bitwise OR of all per-block blooms) to short-circuit n-gram queries before per-block scans.
- **`incremental`**: `IncrementalBuilder` appends new blocks to an existing serialized index without rebuilding. Handles cross-boundary n-grams via an explicit boundary byte parameter.
- **`transport`**: Compressed wire format (`FSTR`) with optional run-length encoding for peer-to-peer index sharing.

**Data flow:** raw bytes → `BlockIndexBuilder` → per-block histograms + blooms → `BlockIndex` → query with `ByteFilter` / `NgramFilter` → merged `CandidateRange`s.

## Guarantees

- **Zero false negatives for indexed data**, if a pattern appears in the stream, the covering block(s) are always included in the candidate set. Cross-boundary patterns are handled by pair and multi-block sliding-window checks.
- **Zero Bloom false negatives** (any 2-byte n-gram inserted into an `NgramBloom` will always test positive).
- **Zero FPR for exact-pair filters** (when `bloom_bits ≥ 4096`, the exact-pair table eliminates all false positives for 2-byte n-gram queries).
- **Fail-safe deserialization**, all serialized input is validated (magic, version, checksum, bounds) before use. Corrupt or truncated data returns typed errors; `from_bytes` never panics on arbitrary input.
- **Offset invariant**, block sizes are enforced to be powers of two. Block offsets are computed as `index × block_size`, so non-trailing block removal is rejected.

## Public API

**Builders**
- `BlockIndexBuilder::new()` → `block_size(usize)` → `bloom_bits(usize)` → `build(&[u8])` / `build_streaming(iter)`.
- `IncrementalBuilder::append_blocks(serialized, blocks)` and `append_blocks_with_boundary`.

**Index types**
- `BlockIndex`: primary in-memory index.
  - Accessors: `block_size()`, `block_count()`, `total_data_length()`, `stats()`.
  - Queries: `candidate_blocks(&ByteFilter, &NgramFilter)`, `candidate_blocks_byte(&ByteFilter)`, `candidate_blocks_ngram(&NgramFilter)`.
  - Mutation: `append_block(data)`, `merge(other)`, `remove_blocks(ids)`.
  - Serialization: `to_bytes()`, `from_bytes(data) -> Option<Self>`, `from_bytes_checked(data) -> Result<Self>`.
  - Utilities: `merge_adjacent(ranges)`, `selectivity(ranges)`.
- `FileBloomIndex::try_new(index)`: hierarchical wrapper with union-bloom short-circuit.
- `MmapBlockIndex::from_slice(data)`: zero-copy view with the same query interface.

**Filters**
- `ByteFilter::from_patterns(patterns)`: byte-level rejection.
- `NgramFilter::from_patterns(patterns)`: n-gram-level rejection; includes `quick_reject(data)` heuristic over the first 4 KB.
- `CompositeFilter`: recursive `Byte` / `Ngram` / `Combine(left, right, op)` tree with `FilterOp::And` / `FilterOp::Or`.

**Bloom primitives**
- `NgramBloom::new(bits)`, `from_block(data, bits)`, `with_target_fpr(fpr, expected_items)`.
- Queries: `maybe_contains(a, b)`, `maybe_contains_exact(a, b)`, `maybe_contains_pattern(p)`, `maybe_contains_all(ngrams)`, `maybe_contains_any(ngrams)`.
- `BlockedNgramBloom::new(bits)`, `from_block(data, bits)`: cache-local variant.

**Transport**
- `transport::to_transport_bytes(index)`: RLE-compressed serialization.
- `transport::from_transport_bytes(data)`: decompression and validation.

## Error handling

All fallible operations return `flashsieve::Result<T>`. `Error` is a `#[non_exhaustive]` `thiserror` enum:

- `InvalidBlockSize { size }`: block size not a power of two or < 256.
- `UnalignedData { data_len, block_size }`: streaming chunk size mismatch.
- `ZeroBloomBits`: bloom filter configured with zero bits.
- `TruncatedHeader { expected, got }` / `TruncatedBlock { block_index }`: incomplete serialized data.
- `InvalidMagic { got }`: magic does not match `"FSBX"`.
- `UnsupportedVersion { got, max_supported }`: unknown format version.
- `ChecksumMismatch { expected, computed }`: CRC-32 mismatch.
- `IncompatibleIndexConfiguration { reason }`: merging indexes with mismatched parameters.
- `InvalidBlockId { block_id, block_count }`: out-of-range block ID.
- `EmptyBlockIndex` / `EmptyBloomUnion`: empty input to union or hierarchical operations.
- `Transport { reason }`: invalid compressed transport data.
- `NonSuffixBlockRemoval`: `remove_blocks` attempted on a non-trailing block.
- `BloomBitsTooLarge { bits, max }`: requested bloom bits exceed the maximum (128 Mbits).
- `InvalidFpr { fpr }`: target FPR not in `(0, 1)`.
- `TrailingPartialBlock { total_len, block_size }`: append/merge on an index ending with a partial block.

## Performance characteristics

- **Index build:** O(N) where N = total bytes. Histograms use 4-way split accumulation. Bloom insertion is O(1) per n-gram.
- **Query:** O(B × P) where B = number of blocks and P = average pattern length (in unique bytes/n-grams). `ByteFilter` checks are O(k) per pattern where k = unique required bytes. `NgramFilter` uses union early-rejection and LCP deduplication.
- **Memory per block:** 1024 bytes (histogram) + `bloom_bits / 8` bytes (bloom). With `bloom_bits ≥ 4096`, an additional 8192 bytes for the exact-pair table.
- **Mmap query:** zero heap allocation per block; histograms and blooms are read directly from the backing slice.
- **FileBloomIndex short-circuit:** avoids per-block scans entirely when the file-level union bloom rejects a query.

## Limitations

- **2-byte n-grams only** (patterns with no repeating adjacent bytes and very short patterns (0–1 bytes) provide little filtering value).
- **Bloom false positives** (for `bloom_bits < 4096`, n-gram queries can produce false positives. The FPR depends on bit count and fill level).
- **Block size trade-off** (smaller blocks increase index size; larger blocks reduce selectivity).
- **No content-addressed deduplication** (identical blocks are indexed independently).
- **Removal restricted to trailing blocks** (removing internal blocks would break the `index × block_size` offset invariant).
- **Exact-pair table not reconstructed from `raw_parts`**, deserialization via `raw_parts` falls back to hash-based lookups. Use `from_serialized_parts` or rebuild from raw data to retain zero FPR.
- **No SIMD** (histogram and bloom operations are scalar; the crate is fully safe Rust (`#![forbid(unsafe_code)]`)).
