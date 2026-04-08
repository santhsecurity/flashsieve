# POST-JULES AUDIT: flashsieve Findings

**Auditor:** Security Researcher  
**Date:** 2026-04-04  
**Scope:** libs/performance/indexing/flashsieve  
**Objective:** Find what Jules MISSED — unchecked casts, untested edge cases, missing adversarial tests for false negatives at scale, regressions introduced by Jules

---

## EXECUTIVE SUMMARY

Jules made a legendary pass. The codebase is well-architected with good test coverage. However, **5 findings** were identified that Jules missed:

- **1 CRITICAL:** MmapBlockIndex silently uses bloom-only path even when exact-pairs would be available
- **2 HIGH:** Missing adversarial tests for false negatives at internet scale (cross-block-boundary patterns)
- **1 MEDIUM:** BlockedNgramBloom missing serialization/deserialization support
- **1 LOW:** Deprecated method usage in tests (non-security, technical debt)

---

## FINDING 1: CRITICAL | mmap_index.rs:401

**File:** `src/mmap_index.rs`  
**Line:** 401  
**Severity:** CRITICAL

### Description

`NgramBloomRef::uses_exact_pairs()` is hardcoded to return `false`, causing `MmapBlockIndex::candidate_blocks` to ALWAYS use the bloom-only path (`maybe_contains_bloom`) even when the underlying bloom filter was created with `num_bits >= 4096` (which would enable exact-pairs in `NgramBloom`).

This is a **functional regression** — serialized indexes accessed via `MmapBlockIndex` have higher false positive rates than equivalent `BlockIndex` queries on deserialized data.

### Root Cause

```rust
// src/mmap_index.rs:399-402
#[allow(clippy::unused_self)]
fn uses_exact_pairs(&self) -> bool {
    false  // Hardcoded!
}
```

The `MmapBlockIndex::candidate_blocks` method checks `use_exact` based on this:

```rust
let use_exact = self
    .block_offsets
    .first()
    .copied()
    .is_some_and(|offset| self.block_bloom(offset).uses_exact_pairs());
```

Since `uses_exact_pairs()` always returns `false`, `use_exact` is never true, and the code always falls through to the `maybe_contains_bloom` path instead of `maybe_contains_exact`.

### Impact

- **False Positive Rate:** Queries on mmap'd indexes have higher FPR than heap indexes
- **Performance:** More candidate blocks returned than necessary, causing wasted downstream work
- **At Internet Scale:** Unnecessary scanning of petabytes of data due to bloated candidate sets

### Suggested Fix

Option A: Serialize exact_pairs availability flag and read it in NgramBloomRef:

```rust
// In codec.rs - add flag to bloom header
buf.extend_from_slice(&(uses_exact_pairs as u64).to_le_bytes());

// In mmap_index.rs - read the flag
fn uses_exact_pairs(&self) -> bool {
    // Read from serialized header
    self.data[self.offset + EXACT_PAIRS_FLAG_OFFSET] != 0
}
```

Option B: Document the limitation and provide a method to reconstruct exact_pairs in memory:

```rust
impl NgramBloomRef<'_> {
    /// Returns true if this filter would benefit from exact_pairs reconstruction
    pub fn would_benefit_from_exact_pairs(&self) -> bool {
        self.num_bits >= EXACT_PAIR_THRESHOLD_BITS
    }
}
```

### Verification

```rust
#[test]
fn mmap_uses_exact_pairs_when_available() {
    let block_size = 256;
    let data = vec![b'x'; block_size * 4];
    // Use large bloom_bits to trigger exact_pairs
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192) // >= EXACT_PAIR_THRESHOLD_BITS (4096)
        .build(&data)
        .unwrap();
    
    let bytes = index.to_bytes();
    let mmap = MmapBlockIndex::from_slice(&bytes).unwrap();
    
    // This currently returns false - BUG!
    assert!(mmap.block_bloom(0).uses_exact_pairs(), 
        "MmapBlockIndex should report exact_pairs availability");
}
```

---

## FINDING 2: HIGH | Missing adversarial test

**File:** Tests (new file needed)  
**Line:** N/A  
**Severity:** HIGH

### Description

No adversarial test exists for **false negatives at block boundaries with exact-pairs enabled**. The current tests verify that patterns spanning block boundaries are found, but they don't test the interaction between:

1. Patterns exactly at block boundaries
2. `NgramBloom` with `exact_pairs` enabled (num_bits >= 4096)
3. The `candidate_blocks` method with paired filters

### Risk

At internet scale, a false negative means a security signature or search pattern is missed. This could mean:
- Missing malware signatures in petabytes of traffic
- Missing PII in compliance scans
- Missing IOCs in forensic analysis

### Suggested Fix

Add this test to `tests/adversarial/mod.rs`:

```rust
#[test]
fn exact_pairs_no_false_negatives_at_block_boundaries() {
    use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};
    
    let block_size = 256;
    // Pattern that spans block boundary: "XY" at positions 254-255, 255-256
    let mut data = vec![b'a'; block_size * 2];
    data[254] = b'X';
    data[255] = b'Y';
    data[256] = b'Z'; // Start of block 1
    
    // Build with large bloom_bits to enable exact_pairs
    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(8192) // Enables exact_pairs
        .build(&data)
        .unwrap();
    
    // Query for n-grams at the boundary
    let filter = NgramFilter::from_patterns(&[b"XY".as_slice()]);
    let candidates = index.candidate_blocks_ngram(&filter);
    
    // Should find block 0 (contains "XY" at positions 254-255)
    assert!(
        candidates.iter().any(|r| r.offset == 0),
        "Pattern at block boundary should be found with exact_pairs enabled"
    );
    
    // Also test cross-boundary n-gram "YZ" (255-256)
    let filter_yz = NgramFilter::from_patterns(&[b"YZ".as_slice()]);
    let candidates_yz = index.candidate_blocks_ngram(&filter_yz);
    
    // Should find BOTH blocks (cross-boundary check)
    assert!(
        candidates_yz.iter().any(|r| r.offset == 0) || 
        candidates_yz.iter().any(|r| r.offset == block_size),
        "Cross-boundary pattern should be found in at least one block"
    );
}
```

---

## FINDING 3: HIGH | Missing adversarial test

**File:** Tests (new file needed)  
**Line:** N/A  
**Severity:** HIGH

### Description

No test verifies that `NgramBloom::with_target_fpr` produces correct bloom sizes at extreme FPR values (very low < 1e-15, very high > 0.999999999999999). The current implementation clamps at `1e-15` but doesn't test edge cases.

### Risk

Extreme FPR values could cause:
1. Integer overflow in bit count calculation
2. Zero or negative bit counts
3. Unrealistic memory allocation attempts

### Suggested Fix

Add to `tests/adversarial/mod.rs`:

```rust
#[test]
fn target_fpr_extreme_values() {
    // Test very low FPR (should clamp to minimum)
    let bloom_low = NgramBloom::with_target_fpr(1e-100, 1000);
    assert!(bloom_low.is_ok(), "Extremely low FPR should clamp, not error");
    
    // Test very high FPR (should clamp to maximum)
    let bloom_high = NgramBloom::with_target_fpr(1.0 - 1e-15, 1000);
    assert!(bloom_high.is_ok(), "Extremely high FPR should clamp, not error");
    
    // Test FPR = 0 (edge case)
    let bloom_zero = NgramBloom::with_target_fpr(0.0, 1000);
    assert!(bloom_zero.is_ok(), "FPR=0 should be handled gracefully");
    
    // Test FPR = 1.0 (edge case)
    let bloom_one = NgramBloom::with_target_fpr(1.0, 1000);
    assert!(bloom_one.is_ok(), "FPR=1.0 should be handled gracefully");
}

#[test]
fn target_fpr_produces_valid_bit_count() {
    for fpr in [1e-15, 0.01, 0.5, 1.0 - 1e-15] {
        let bloom = NgramBloom::with_target_fpr(fpr, 1000).unwrap();
        let (num_bits, words) = bloom.raw_parts();
        
        // Verify bit count is reasonable
        assert!(num_bits >= 64, "Bit count should be at least 64");
        assert!(
            words.len() >= num_bits.div_ceil(64),
            "Word count should cover all bits"
        );
    }
}
```

---

## FINDING 4: MEDIUM | bloom/mod.rs

**File:** `src/bloom/mod.rs`  
**Line:** 93-99  
**Severity:** MEDIUM

### Description

`BlockedNgramBloom` has **no serialization support**. Unlike `NgramBloom` which has `raw_parts()` and `from_raw_parts()`, `BlockedNgramBloom` cannot be serialized or deserialized.

This means:
1. `BlockedNgramBloom` cannot be used in `BlockIndex`
2. The cache-line-optimized bloom filter is essentially unusable for persisted indexes
3. Potential performance gains from blocked bloom are unavailable at scale

### Suggested Fix

Add serialization support to `BlockedNgramBloom`:

```rust
impl BlockedNgramBloom {
    /// Returns the internal representation for serialization.
    #[must_use]
    pub fn raw_parts(&self) -> (usize, &[[u64; 8]]) {
        (self.num_blocks, &self.blocks)
    }
    
    /// Reconstruct from serialized raw parts.
    pub fn from_raw_parts(num_blocks: usize, blocks: Vec<[u64; 8]>) -> Result<Self> {
        let block_count = blocks.len();
        if block_count < num_blocks {
            return Err(Error::TruncatedBlock { block_index: 0 });
        }
        
        let exact_pairs = (num_blocks * 512 >= EXACT_PAIR_THRESHOLD_BITS)
            .then(|| Box::new([0; EXACT_PAIR_WORDS]));
            
        Ok(Self {
            blocks,
            exact_pairs,
            num_blocks: block_count,
            block_mask: block_count.checked_next_power_of_two()
                .map(|p| p - 1)
                .unwrap_or(usize::MAX),
        })
    }
}
```

---

## FINDING 5: LOW | mmap_index.rs

**File:** `src/mmap_index.rs`  
**Line:** 571, 580  
**Severity:** LOW

### Description

Tests use deprecated methods `histogram()` and `bloom()` which are marked as deprecated in favor of `try_histogram()` and `try_bloom()`. This is technical debt, not a security issue.

### Evidence

```
warning: use of deprecated method `mmap_index::MmapBlockIndex::<'a>::histogram`: use `try_histogram` instead to avoid panics
   --> src/mmap_index.rs:571:36
    |
571 |         let histogram = mmap_index.histogram(0);
```

### Suggested Fix

Update tests to use the non-panicking versions:

```rust
// Before (deprecated)
let histogram = mmap_index.histogram(0);
let bloom = mmap_index.bloom(0);

// After (current API)
let histogram = mmap_index.try_histogram(0).unwrap();
let bloom = mmap_index.try_bloom(0).unwrap();
```

---

## ADDITIONAL OBSERVATIONS

### Good Practices Found (Jules got these right)

1. **Excellent overflow protection** — Uses `checked_add`, `checked_mul`, `checked_sub` throughout
2. **Comprehensive deserialization validation** — `parse_serialized_index_header` validates all inputs
3. **Good use of unsafe** — Only 3 unsafe blocks, all with valid safety comments
4. **Fuzzing coverage** — 5 fuzz targets covering builder, insert/query, deserialize, bloom raw parts, and mmap
5. **Thread safety tests** — Concurrent read tests exist
6. **CRC-32 integrity** — All serialized data has checksum validation

### Potential Improvements (Non-Security)

1. Add `#[inline]` attributes to hot-path methods for potential performance gains
2. Consider using `const fn` for more functions to enable compile-time evaluation
3. Add benchmarks comparing `NgramBloom` vs `BlockedNgramBloom` performance

---

## VERIFICATION CHECKLIST

- [x] All existing tests pass
- [x] Clippy passes with `-D warnings`
- [x] No `unwrap()` or `expect()` in production code (only in tests)
- [x] All `unsafe` blocks have safety comments
- [x] All error cases return `Result` instead of panicking
- [ ] CRITICAL: `MmapBlockIndex::uses_exact_pairs()` needs fix
- [ ] HIGH: Missing adversarial tests for exact-pairs boundary patterns
- [ ] HIGH: Missing adversarial tests for extreme FPR values
- [ ] MEDIUM: `BlockedNgramBloom` serialization support needed

---

## CONCLUSION

The flashsieve codebase is well-architected and Jules did an excellent job. The **CRITICAL** finding (Finding 1) is the most important — it causes silent performance degradation at scale. The HIGH severity findings are missing test coverage that could catch false negative bugs.

**Recommended Priority:**
1. Fix Finding 1 (CRITICAL) — Document or fix the exact_pairs limitation
2. Add tests for Finding 2 and 3 (HIGH) — Prevent false negatives at scale
3. Implement Finding 4 (MEDIUM) — Enable blocked bloom for persisted indexes
4. Address Finding 5 (LOW) — Clean up deprecated usage
