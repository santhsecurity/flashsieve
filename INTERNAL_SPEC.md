# flashsieve: Internal Spec

> This file is gitignored. It exists for agents and internal development. Never committed to public repos.

## Identity
Storage-level pre-filtering for pattern matching (skip blocks that can't contain matches).

## Purpose
Builds per-block byte histograms and 2-byte n-gram Bloom filters to eliminate disk reads for blocks guaranteed not to match patterns.

## North Star
The Bloom filter implementation that security vendors benchmark against (mathematically sound FPR bounds, mmap-backed persistence, and zero false negatives).

## Role in Ecosystem
- **Depends on:** (none internal)
- **Depended on by:** warpscan, warpgrep, ziftsieve, scanpipe, fusedpipe
- **Relationship to warpscan:** Flashsieve pre-filters file blocks before warpscan's regex/GPU engines see them, slashing I/O and CPU waste.
- **Standalone value:** YES (any scanner or database needing block-level pre-filtering can use it independently).

## Invariants
- Bloom filter never produces false negatives for indexed n-grams.
- Serialized indexes include a CRC32 footer.
- Mmap queries never allocate; they are zero-parse views over disk.
- Zero bits in a Bloom filter always mean "definitely not present."
- `hashkit`-compatible bloom hash pair (`FNV-1a` + `SplitMix`) is used for double hashing.

## Boundaries
- Does not parse full file formats (it works on opaque blocks).
- Does not replace a full text index (use trigramkit for document-level rejection).
- Does not perform regex or semantic matching.

## Quality State
- Tests: ~35+ declared test targets including adversarial bloom correctness, FPR extreme, hash distribution, memory sizing, concurrent 100 threads, property zero-FNR
- Lint preamble: yes
- #![forbid(unsafe_code)]: yes
- Doc coverage: ~90%
- Known issues: Lib.rs comments mention unsafe in bloom word loads, but crate-level attributes `#![forbid(unsafe_code)]` and `#![deny(unsafe_code)]` are both present (documentation should be reconciled).
