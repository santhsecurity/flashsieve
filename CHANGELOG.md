# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive documentation for all public items with examples
- Module-level documentation for every source file
- FPR formula documentation: `FPR ≈ (1 - e^(-kn/m))^k`
- FNV-1a 64-bit constants documentation with FNV spec reference
- SplitMix64 finalizer documentation with paper reference
- CRC-32 lookup table documentation with polynomial details
- Serialization wire format documentation with byte layout
- Adversarial test suite with 25+ tests (`tests/legendary.rs`)
- Property-based tests using proptest (`tests/legendary_proptest.rs`)
- Comprehensive benchmarks using Criterion (`benches/legendary_bench.rs`)
- CI workflow with test, clippy, fmt, doc, and MSRV checks
- Fuzz targets for deserialization and insert/query operations

### Changed

- Enhanced error messages with actionable guidance
- README.md with FPR calculator example and serialization format

## [0.1.0] - 2026-03-29

### Added

- Initial release of `flashsieve`
- `BlockIndexBuilder` for constructing block indexes
- `BlockIndex` with serialization (version 1 and 2) and candidate queries
- `ByteHistogram` for per-block byte frequency counting
- `NgramBloom` for 2-byte n-gram membership testing
- `ByteFilter` and `NgramFilter` for pattern-based filtering
- `CompositeFilter` with `FilterOp` for logical filter composition
- CRC-32 checksums for version 2 serialization format
- Comprehensive error types with `thiserror`
- Basic unit tests for all modules
- Criterion benchmarks for core operations

[Unreleased]: https://github.com/santhsecurity/flashsieve/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/santhsecurity/flashsieve/releases/tag/v0.1.0
