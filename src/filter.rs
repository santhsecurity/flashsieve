//! Query filter types for block pre-filtering.
//!
//! This module provides filters that determine whether a block might contain
//! matches for given patterns:
//!
//! - [`ByteFilter`] — checks if all required bytes are present
//! - [`NgramFilter`] — checks if all required 2-byte n-grams might be present
//! - [`CompositeFilter`] — combines filters with logical operators

use crate::bloom::NgramBloom;
use crate::histogram::ByteHistogram;
use crate::mmap_write::ByteHistogramRef;

pub(crate) trait HistogramView {
    fn count(&self, byte: u8) -> u32;
}

impl HistogramView for &ByteHistogram {
    fn count(&self, byte: u8) -> u32 {
        ByteHistogram::count(self, byte)
    }
}

impl HistogramView for ByteHistogramRef<'_> {
    fn count(&self, byte: u8) -> u32 {
        ByteHistogramRef::count(self, byte)
    }
}

/// A filter based on required individual bytes.
///
/// A block passes if it contains all bytes required by at least one pattern.
///
/// # Example
///
/// ```
/// use flashsieve::ByteFilter;
///
/// let filter = ByteFilter::from_patterns(&[b"abc".as_slice()]);
/// // Blocks containing 'a', 'b', AND 'c' will match
/// ```
#[derive(Clone, Debug)]
pub struct ByteFilter {
    required: [bool; 256],
    required_count: usize,
    /// Compact lists of required byte values per pattern.
    /// Each inner Vec contains only the byte values that must be present,
    /// avoiding the 256-entry linear scan in the hot path.
    compact_requirements: Vec<Box<[u8]>>,
}

impl ByteFilter {
    /// Create an empty filter.
    ///
    /// Empty filters never match any block.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::ByteFilter;
    ///
    /// let filter = ByteFilter::new();
    /// assert_eq!(filter.required_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            required: [false; 256],
            required_count: 0,
            compact_requirements: Vec::new(),
        }
    }

    /// Build from a set of literal patterns.
    ///
    /// A block passes if it contains all bytes from at least one pattern.
    ///
    /// Empty pattern lists produce a filter that never matches.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::{ByteFilter, ByteHistogram};
    ///
    /// let filter = ByteFilter::from_patterns(&[b"abc".as_slice()]);
    /// let hist = ByteHistogram::from_block(b"abc");
    /// assert!(filter.matches_histogram(&hist));
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_patterns(patterns: &[&[u8]]) -> Self {
        let mut filter = Self::new();

        for &pattern in patterns {
            if pattern.is_empty() {
                continue;
            }
            let single = Self::from_single_pattern(pattern);
            for (index, required) in single.required.iter().enumerate() {
                if *required && !filter.required[index] {
                    filter.required[index] = true;
                    filter.required_count += 1;
                }
            }
            // Build compact list for O(k) histogram checks.
            let compact: Box<[u8]> = single
                .required
                .iter()
                .enumerate()
                .filter(|(_, &r)| r)
                .map(|(i, _)| i as u8)
                .collect::<Vec<_>>()
                .into_boxed_slice();
            filter.compact_requirements.push(compact);
        }

        filter
    }

    /// Build from a single pattern's byte set.
    ///
    /// Repeated bytes in the pattern only count once toward the requirement.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::ByteFilter;
    ///
    /// let filter = ByteFilter::from_single_pattern(b"hello");
    /// assert_eq!(filter.required_count(), 4);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_single_pattern(pattern: &[u8]) -> Self {
        let mut required = [false; 256];
        let mut required_count = 0_usize;

        for &byte in pattern {
            let slot = &mut required[usize::from(byte)];
            if !*slot {
                *slot = true;
                required_count += 1;
            }
        }

        let compact: Box<[u8]> = required
            .iter()
            .enumerate()
            .filter(|(_, &r)| r)
            .map(|(i, _)| i as u8)
            .collect();

        Self {
            required,
            required_count,
            compact_requirements: vec![compact],
        }
    }

    /// Check if a histogram passes this filter.
    ///
    /// Returns `true` when the histogram contains every required byte from at
    /// least one source pattern.
    #[must_use]
    pub fn matches_histogram(&self, histogram: &ByteHistogram) -> bool {
        if self.compact_requirements.is_empty() {
            return false;
        }

        // O(k) per pattern where k = number of unique required bytes (typically 3-10).
        // Previous version iterated all 256 entries per pattern.
        self.compact_requirements
            .iter()
            .any(|required_bytes| required_bytes.iter().all(|&b| histogram.count(b) > 0))
    }

    /// Return the total number of unique required bytes across all patterns.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::ByteFilter;
    ///
    /// let filter = ByteFilter::from_patterns(&[b"abc".as_slice()]);
    /// assert_eq!(filter.required_count(), 3);
    /// ```
    #[must_use]
    pub fn required_count(&self) -> usize {
        self.required_count
    }

    /// Check if the union of two histograms passes this filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{ByteFilter, ByteHistogram};
    ///
    /// let filter = ByteFilter::from_patterns(&[b"ab".as_slice()]);
    /// let h1 = ByteHistogram::from_block(b"a");
    /// let h2 = ByteHistogram::from_block(b"b");
    /// assert!(filter.matches_histogram_pair(&h1, &h2));
    /// ```
    #[must_use]
    pub fn matches_histogram_pair(&self, h1: &ByteHistogram, h2: &ByteHistogram) -> bool {
        if self.compact_requirements.is_empty() {
            return false;
        }

        self.compact_requirements.iter().any(|required_bytes| {
            required_bytes
                .iter()
                .all(|&b| h1.count(b) > 0 || h2.count(b) > 0)
        })
    }

    /// Check if the union of multiple histograms passes this filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{ByteFilter, ByteHistogram};
    ///
    /// let filter = ByteFilter::from_patterns(&[b"abc".as_slice()]);
    /// let h1 = ByteHistogram::from_block(b"a");
    /// let h2 = ByteHistogram::from_block(b"b");
    /// let h3 = ByteHistogram::from_block(b"c");
    /// assert!(filter.matches_histogram_multi(&[h1, h2, h3]));
    /// ```
    #[must_use]
    pub fn matches_histogram_multi(&self, histograms: &[ByteHistogram]) -> bool {
        if self.compact_requirements.is_empty() {
            return false;
        }

        self.compact_requirements.iter().any(|required_bytes| {
            required_bytes
                .iter()
                .all(|&b| histograms.iter().any(|h| h.count(b) > 0))
        })
    }

    pub(crate) fn compact_requirements(&self) -> &[Box<[u8]>] {
        &self.compact_requirements
    }

    /// Return true if any required byte from any pattern appears in the histogram.
    pub(crate) fn has_any_required_byte(&self, histogram: impl HistogramView) -> bool {
        self.compact_requirements
            .iter()
            .any(|required_bytes| required_bytes.iter().any(|&b| histogram.count(b) > 0))
    }
}

impl Default for ByteFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// A filter based on required n-grams (2-byte subsequences).
///
/// A block passes if all n-grams from at least one pattern might be present.
///
/// # Example
///
/// ```
/// use flashsieve::NgramFilter;
///
/// let filter = NgramFilter::from_patterns(&[b"abc".as_slice()]);
/// // Blocks that might contain "ab" AND "bc" will match
/// ```
#[derive(Clone, Debug)]
pub struct NgramFilter {
    pattern_ngrams: Vec<Vec<(u8, u8)>>,
    /// Union of all pattern n-grams for O(1) early rejection.
    /// If the file bloom doesn't contain ANY of the union n-grams,
    /// no pattern can possibly match → reject without per-pattern checks.
    union_ngrams: Vec<(u8, u8)>,
    /// Maximum original pattern length in bytes.
    /// Used to determine how many consecutive blocks must be checked
    /// to prevent false negatives for patterns spanning block boundaries.
    max_pattern_bytes: usize,
}

impl NgramFilter {
    /// Build a filter from a set of patterns.
    ///
    /// Patterns shorter than two bytes contribute zero n-grams and therefore
    /// match any bloom filter.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::{NgramFilter, NgramBloom};
    ///
    /// let filter = NgramFilter::from_patterns(&[b"hello".as_slice()]);
    /// let bloom = NgramBloom::from_block(b"hello world", 1024).unwrap();
    /// assert!(filter.matches_bloom(&bloom));
    /// ```
    #[must_use]
    pub fn from_patterns(patterns: &[&[u8]]) -> Self {
        let mut pattern_ngrams = Vec::with_capacity(patterns.len());
        let mut prev_pattern: &[u8] = b"";
        let mut prev_raw_ngrams: Vec<(u8, u8)> = Vec::new();

        for &pattern in patterns {
            if pattern.is_empty() {
                continue;
            }
            let lcp = pattern
                .iter()
                .zip(prev_pattern.iter())
                .take_while(|(a, b)| a == b)
                .count();

            let mut raw_ngrams = if lcp >= 2 {
                prev_raw_ngrams[..lcp - 1].to_vec()
            } else {
                Vec::new()
            };

            if pattern.len() >= 2 {
                let start_idx = if lcp >= 2 { lcp - 1 } else { 0 };
                for window in pattern[start_idx..].windows(2) {
                    raw_ngrams.push((window[0], window[1]));
                }
            }

            prev_pattern = pattern;
            prev_raw_ngrams.clone_from(&raw_ngrams);

            let mut ngrams = raw_ngrams;
            ngrams.sort_unstable();
            ngrams.dedup();
            pattern_ngrams.push(ngrams);
        }

        // Build union of all unique n-grams for fast early rejection.
        let mut union_ngrams: Vec<(u8, u8)> = pattern_ngrams.iter().flatten().copied().collect();
        union_ngrams.sort_unstable();
        union_ngrams.dedup();

        let max_pattern_bytes = patterns.iter().map(|p| p.len()).max().unwrap_or(0);

        Self {
            pattern_ngrams,
            union_ngrams,
            max_pattern_bytes,
        }
    }

    /// Check if a bloom filter passes this filter.
    ///
    /// Returns `true` when all 2-byte n-grams from at least one source pattern
    /// might be present in the bloom filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{NgramFilter, NgramBloom};
    ///
    /// let filter = NgramFilter::from_patterns(&[b"hello".as_slice()]);
    /// let bloom = NgramBloom::from_block(b"hello world", 1024).unwrap();
    /// assert!(filter.matches_bloom(&bloom));
    /// ```
    #[inline]
    #[must_use]
    pub fn matches_bloom(&self, bloom: &NgramBloom) -> bool {
        if self.pattern_ngrams.is_empty() {
            return false;
        }

        // Fast early rejection: if the bloom doesn't contain ANY of the
        // union n-grams, no pattern that *requires* a 2-byte n-gram can match.
        // This is O(union_size) instead of O(patterns × ngrams_per_pattern).
        //
        // CORRECTNESS: The union is the set of all 2-byte n-grams from patterns
        // of length ≥ 2. If some pattern has no 2-byte n-grams (length 0–1), it
        // matches any bloom (`all` over an empty n-gram list is true). In that
        // case we must NOT reject here, or we get a false negative when a long
        // pattern's n-grams are absent but a short pattern still applies.
        let any_pattern_has_no_ngrams = self.pattern_ngrams.iter().any(Vec::is_empty);
        if !any_pattern_has_no_ngrams
            && !self.union_ngrams.is_empty()
            && !bloom.maybe_contains_any(&self.union_ngrams)
        {
            return false;
        }

        if bloom.uses_exact_pairs() {
            self.pattern_ngrams.iter().any(|ngrams| {
                ngrams
                    .iter()
                    .all(|&(first, second)| bloom.maybe_contains_exact(first, second))
            })
        } else {
            self.pattern_ngrams.iter().any(|ngrams| {
                ngrams
                    .iter()
                    .all(|&(first, second)| bloom.maybe_contains_bloom(first, second))
            })
        }
    }

    /// Fast-path heuristic that checks only the first 4KB of data.
    ///
    /// This avoids building a full bloom filter for large files when checking
    /// a few n-grams.
    ///
    /// This is a heuristic with possible false positives, but never false
    /// negatives for patterns that appear entirely within the first 4KB.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::NgramFilter;
    ///
    /// let filter = NgramFilter::from_patterns(&[b"hello".as_slice()]);
    /// let data = b"hello world";
    /// assert!(filter.quick_reject(data));
    /// ```
    #[must_use]
    pub fn quick_reject(&self, data: &[u8]) -> bool {
        if self.pattern_ngrams.is_empty() {
            return false;
        }

        let prefix_len = data.len().min(4096);
        let prefix = &data[..prefix_len];

        // Build a minimal bloom filter over just the first 4KB
        // Using 4096 bits (512 bytes) is fast to allocate and zero.
        if let Ok(bloom) = crate::bloom::NgramBloom::from_block(prefix, 4096) {
            self.matches_bloom(&bloom)
        } else {
            // If we somehow fail to build the bloom, conservatively return true
            // to avoid false negatives.
            true
        }
    }

    /// Check if the union of two bloom filters passes this filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{NgramFilter, NgramBloom};
    ///
    /// let filter = NgramFilter::from_patterns(&[b"ab".as_slice()]);
    /// let b1 = NgramBloom::from_block(b"ab", 1024).unwrap();
    /// let b2 = NgramBloom::from_block(b"xy", 1024).unwrap();
    /// assert!(filter.matches_bloom_pair(&b1, &b2));
    /// ```
    #[inline]
    #[must_use]
    pub fn matches_bloom_pair(&self, b1: &NgramBloom, b2: &NgramBloom) -> bool {
        if self.pattern_ngrams.is_empty() {
            return false;
        }

        if b1.uses_exact_pairs() && b2.uses_exact_pairs() {
            self.pattern_ngrams.iter().any(|ngrams| {
                ngrams.iter().all(|&(first, second)| {
                    b1.maybe_contains_exact(first, second) || b2.maybe_contains_exact(first, second)
                })
            })
        } else {
            self.pattern_ngrams.iter().any(|ngrams| {
                ngrams.iter().all(|&(first, second)| {
                    b1.maybe_contains_bloom(first, second) || b2.maybe_contains_bloom(first, second)
                })
            })
        }
    }

    /// Check if the union of multiple consecutive bloom filters passes this filter.
    ///
    /// Returns `true` when all 2-byte n-grams from at least one source pattern
    /// might be present in the union of the provided blooms.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{NgramFilter, NgramBloom};
    ///
    /// let filter = NgramFilter::from_patterns(&[b"ab".as_slice()]);
    /// let b1 = NgramBloom::from_block(b"ab", 1024).unwrap();
    /// let b2 = NgramBloom::from_block(b"cd", 1024).unwrap();
    /// let b3 = NgramBloom::from_block(b"ef", 1024).unwrap();
    /// assert!(filter.matches_bloom_multi(&[b1, b2, b3]));
    /// ```
    #[inline]
    #[must_use]
    pub fn matches_bloom_multi(&self, blooms: &[NgramBloom]) -> bool {
        if self.pattern_ngrams.is_empty() || blooms.is_empty() {
            return false;
        }

        let use_exact = blooms.first().is_some_and(NgramBloom::uses_exact_pairs);
        if use_exact {
            self.pattern_ngrams.iter().any(|ngrams| {
                ngrams.iter().all(|&(first, second)| {
                    blooms
                        .iter()
                        .any(|bloom| bloom.maybe_contains_exact(first, second))
                })
            })
        } else {
            self.pattern_ngrams.iter().any(|ngrams| {
                ngrams.iter().all(|&(first, second)| {
                    blooms
                        .iter()
                        .any(|bloom| bloom.maybe_contains_bloom(first, second))
                })
            })
        }
    }

    pub(crate) fn pattern_ngrams(&self) -> &[Vec<(u8, u8)>] {
        &self.pattern_ngrams
    }

    pub(crate) fn union_ngrams(&self) -> &[(u8, u8)] {
        &self.union_ngrams
    }

    pub(crate) fn max_pattern_bytes(&self) -> usize {
        self.max_pattern_bytes
    }
}

/// Logical operator for composing filters.
///
/// # Example
///
/// ```
/// use flashsieve::filter::FilterOp;
///
/// let op = FilterOp::And;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterOp {
    /// Both sub-filters must match.
    And,
    /// At least one sub-filter must match.
    Or,
}

/// A composite filter that combines byte and n-gram filters with logical
/// operators.
///
/// # Example
///
/// ```
/// use flashsieve::{ByteFilter, NgramFilter};
/// use flashsieve::filter::{CompositeFilter, FilterOp};
///
/// let a = ByteFilter::from_patterns(&[b"secret".as_slice()]);
/// let b = ByteFilter::from_patterns(&[b"token".as_slice()]);
/// let combined = CompositeFilter::combine_byte(a, b, FilterOp::Or);
/// ```
#[derive(Clone, Debug)]
pub enum CompositeFilter {
    /// A leaf byte filter.
    Byte(ByteFilter),
    /// A leaf n-gram filter.
    Ngram(NgramFilter),
    /// Logical combination of two composite filters.
    Combine {
        /// Left operand.
        left: Box<CompositeFilter>,
        /// Right operand.
        right: Box<CompositeFilter>,
        /// The logical operator.
        op: FilterOp,
    },
}

impl CompositeFilter {
    /// Combine two byte filters under a logical operator.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{ByteFilter, filter::{CompositeFilter, FilterOp}};
    ///
    /// let a = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    /// let b = ByteFilter::from_patterns(&[b"token".as_slice()]);
    /// let combined = CompositeFilter::combine_byte(a, b, FilterOp::Or);
    /// ```
    #[must_use]
    pub fn combine_byte(a: ByteFilter, b: ByteFilter, op: FilterOp) -> Self {
        Self::Combine {
            left: Box::new(Self::Byte(a)),
            right: Box::new(Self::Byte(b)),
            op,
        }
    }

    /// Combine two ngram filters under a logical operator.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{NgramFilter, filter::{CompositeFilter, FilterOp}};
    ///
    /// let a = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    /// let b = NgramFilter::from_patterns(&[b"token".as_slice()]);
    /// let combined = CompositeFilter::combine_ngram(a, b, FilterOp::Or);
    /// ```
    #[must_use]
    pub fn combine_ngram(a: NgramFilter, b: NgramFilter, op: FilterOp) -> Self {
        Self::Combine {
            left: Box::new(Self::Ngram(a)),
            right: Box::new(Self::Ngram(b)),
            op,
        }
    }

    /// Combine two composite filters under an arbitrary logical operator.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{ByteFilter, filter::{CompositeFilter, FilterOp}};
    ///
    /// let left = CompositeFilter::Byte(ByteFilter::from_patterns(&[b"a".as_slice()]));
    /// let right = CompositeFilter::Byte(ByteFilter::from_patterns(&[b"b".as_slice()]));
    /// let combined = CompositeFilter::combine(left, right, FilterOp::And);
    /// ```
    #[must_use]
    pub fn combine(a: Self, b: Self, op: FilterOp) -> Self {
        Self::Combine {
            left: Box::new(a),
            right: Box::new(b),
            op,
        }
    }

    /// Evaluate against a histogram and bloom pair.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{ByteFilter, NgramBloom, filter::{CompositeFilter, FilterOp}};
    ///
    /// let filter = CompositeFilter::Byte(ByteFilter::from_patterns(&[b"ab".as_slice()]));
    /// let hist = flashsieve::ByteHistogram::from_block(b"ab");
    /// let bloom = NgramBloom::from_block(b"ab", 1024).unwrap();
    /// assert!(filter.matches(&hist, &bloom));
    /// ```
    #[must_use]
    pub fn matches(&self, histogram: &ByteHistogram, bloom: &NgramBloom) -> bool {
        match self {
            Self::Byte(filter) => filter.matches_histogram(histogram),
            Self::Ngram(filter) => filter.matches_bloom(bloom),
            Self::Combine { left, right, op } => {
                let l = left.matches(histogram, bloom);
                match op {
                    FilterOp::And => l && right.matches(histogram, bloom),
                    FilterOp::Or => l || right.matches(histogram, bloom),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ngram_filter_union_short_circuit_skips_when_any_pattern_has_no_bigrams() {
        // Regression: union early-rejection must not fire when one pattern has
        // zero 2-byte n-grams (length 0–1), which vacuously matches any bloom.
        let filter = NgramFilter::from_patterns(&[b"x".as_slice(), b"hello".as_slice()]);
        let bloom = NgramBloom::from_block(b"x", 1024).unwrap();
        assert!(
            filter.matches_bloom(&bloom),
            "short pattern should match; long pattern's union must not force rejection"
        );
    }

    #[test]
    fn ngram_filter_from_patterns_with_lcp_optimization() {
        let pattern1 = b"test_pattern_a".as_slice();
        let pattern2 = b"test_pattern_b".as_slice();

        let filter = NgramFilter::from_patterns(&[pattern1, pattern2]);

        let mut expected_ngrams1: Vec<_> = pattern1.windows(2).map(|w| (w[0], w[1])).collect();
        expected_ngrams1.sort_unstable();
        expected_ngrams1.dedup();

        let mut expected_ngrams2: Vec<_> = pattern2.windows(2).map(|w| (w[0], w[1])).collect();
        expected_ngrams2.sort_unstable();
        expected_ngrams2.dedup();

        assert_eq!(filter.pattern_ngrams().len(), 2);
        assert_eq!(filter.pattern_ngrams()[0], expected_ngrams1);
        assert_eq!(filter.pattern_ngrams()[1], expected_ngrams2);
    }
}
