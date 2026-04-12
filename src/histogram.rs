//! Per-block byte frequency histograms.
//!
//! This module provides [`ByteHistogram`], a 256-entry frequency table
//! for counting byte occurrences within a data block.

/// A 256-entry byte frequency histogram for one block.
///
/// `histogram[b] = number of times byte value b appears in the block.`
///
/// # Example
///
/// ```
/// use flashsieve::ByteHistogram;
///
/// let hist = ByteHistogram::from_block(b"hello");
/// assert_eq!(hist.count(b'l'), 2);
/// assert_eq!(hist.count(b'x'), 0);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteHistogram {
    counts: [u32; 256],
}

impl ByteHistogram {
    /// Create an empty histogram with all counts set to zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::ByteHistogram;
    ///
    /// let hist = ByteHistogram::new();
    /// assert_eq!(hist.count(b'a'), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { counts: [0; 256] }
    }

    /// Build a histogram from a block of bytes.
    ///
    /// Counts the occurrence of each byte value (0-255) in the input.
    ///
    /// Uses **4-way histogram splitting** to eliminate store-forwarding stalls:
    /// when two adjacent bytes have the same value, a single histogram creates
    /// a read-modify-write hazard (the CPU must wait for the previous increment
    /// to retire before the next one can read the old value). By splitting into
    /// 4 independent histograms and processing 4 bytes at a time, adjacent
    /// bytes ALWAYS target different histogram arrays.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::ByteHistogram;
    ///
    /// let hist = ByteHistogram::from_block(b"abcabc");
    /// assert_eq!(hist.count(b'a'), 2);
    /// assert_eq!(hist.count(b'b'), 2);
    /// assert_eq!(hist.count(b'c'), 2);
    /// ```
    #[must_use]
    pub fn from_block(data: &[u8]) -> Self {
        // 4-way split: each sub-histogram handles every 4th byte.
        // This ensures adjacent bytes never collide in the same array,
        // eliminating store-forwarding stalls on OoO CPUs.
        let mut h0 = [0u32; 256];
        let mut h1 = [0u32; 256];
        let mut h2 = [0u32; 256];
        let mut h3 = [0u32; 256];

        // Process 4 bytes at a time.
        let chunks = data.chunks_exact(4);
        let remainder = chunks.remainder();
        for chunk in chunks {
            h0[usize::from(chunk[0])] = h0[usize::from(chunk[0])].saturating_add(1);
            h1[usize::from(chunk[1])] = h1[usize::from(chunk[1])].saturating_add(1);
            h2[usize::from(chunk[2])] = h2[usize::from(chunk[2])].saturating_add(1);
            h3[usize::from(chunk[3])] = h3[usize::from(chunk[3])].saturating_add(1);
        }

        // Handle tail bytes (0-3 remaining).
        for (i, &byte) in remainder.iter().enumerate() {
            match i {
                0 => {
                    let idx = usize::from(byte);
                    h0[idx] = h0[idx].saturating_add(1);
                }
                1 => {
                    let idx = usize::from(byte);
                    h1[idx] = h1[idx].saturating_add(1);
                }
                2 => {
                    let idx = usize::from(byte);
                    h2[idx] = h2[idx].saturating_add(1);
                }
                _ => {
                    let idx = usize::from(byte);
                    h3[idx] = h3[idx].saturating_add(1);
                }
            }
        }

        // Merge the 4 sub-histograms into one.
        let mut counts = [0u32; 256];
        for i in 0..256 {
            counts[i] = h0[i]
                .saturating_add(h1[i])
                .saturating_add(h2[i])
                .saturating_add(h3[i]);
        }

        Self { counts }
    }

    /// Reconstruct a histogram from a pre-computed count array.
    ///
    /// Used for deserialization; the caller is responsible for providing a
    /// valid 256-entry count array.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::ByteHistogram;
    ///
    /// let counts = [1u32; 256];
    /// let hist = ByteHistogram::from_raw_counts(counts);
    /// assert_eq!(hist.count(b'x'), 1);
    /// ```
    #[must_use]
    pub fn from_raw_counts(counts: [u32; 256]) -> Self {
        Self { counts }
    }

    /// Return the count for a single byte value.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::ByteHistogram;
    ///
    /// let hist = ByteHistogram::from_block(b"hello");
    /// assert_eq!(hist.count(b'h'), 1);
    /// assert_eq!(hist.count(b'l'), 2);
    /// ```
    #[must_use]
    #[inline]
    pub fn count(&self, byte: u8) -> u32 {
        self.counts[usize::from(byte)]
    }

    /// Raw access to the 256-entry count array for bulk serialization.
    ///
    /// Avoids 256 individual `count()` calls during index persistence —
    /// the caller can write the entire array with a single `copy_from_slice`.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::ByteHistogram;
    ///
    /// let hist = ByteHistogram::from_block(b"hello");
    /// let counts = hist.raw_counts();
    /// assert_eq!(counts[usize::from(b'h')], 1);
    /// ```
    #[must_use]
    #[inline]
    pub fn raw_counts(&self) -> &[u32; 256] {
        &self.counts
    }

    /// Return `true` if all required bytes appear at least once.
    ///
    /// The `required_bytes` array is a boolean mask where `true` indicates
    /// that the corresponding byte value must be present.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::ByteHistogram;
    ///
    /// let hist = ByteHistogram::from_block(b"hello");
    /// let mut required = [false; 256];
    /// required[usize::from(b'h')] = true;
    /// required[usize::from(b'e')] = true;
    /// assert!(hist.contains_all(&required));
    /// ```
    #[must_use]
    pub fn contains_all(&self, required_bytes: &[bool; 256]) -> bool {
        required_bytes
            .iter()
            .enumerate()
            .all(|(byte, required)| !required || self.counts[byte] > 0)
    }

    /// Return `true` if any byte in the set appears at least once.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::ByteHistogram;
    ///
    /// let hist = ByteHistogram::from_block(b"hello");
    /// let mut set = [false; 256];
    /// set[usize::from(b'x')] = true;
    /// set[usize::from(b'y')] = true;
    /// assert!(!hist.contains_any(&set));
    ///
    /// set[usize::from(b'h')] = true;
    /// assert!(hist.contains_any(&set));
    /// ```
    #[must_use]
    pub fn contains_any(&self, byte_set: &[bool; 256]) -> bool {
        byte_set
            .iter()
            .enumerate()
            .any(|(byte, required)| *required && self.counts[byte] > 0)
    }
}

impl Default for ByteHistogram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ByteHistogram;

    #[test]
    fn histogram_empty_block() {
        let histogram = ByteHistogram::from_block(&[]);
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(histogram.count(byte), 0);
        }
    }

    #[test]
    fn histogram_single_byte_repeated() {
        let histogram = ByteHistogram::from_block(&[0x41; 64]);
        assert_eq!(histogram.count(0x41), 64);
        assert_eq!(histogram.count(0x42), 0);
    }

    #[test]
    fn histogram_all_256_values() {
        let all_bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
        let histogram = ByteHistogram::from_block(&all_bytes);
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(histogram.count(byte), 1);
        }
    }

    #[test]
    fn histogram_contains_all_true() {
        let histogram = ByteHistogram::from_block(b"abcdef");
        let mut required = [false; 256];
        required[usize::from(b'a')] = true;
        required[usize::from(b'c')] = true;
        required[usize::from(b'f')] = true;
        assert!(histogram.contains_all(&required));
    }

    #[test]
    fn histogram_contains_all_false() {
        let histogram = ByteHistogram::from_block(b"abcdef");
        let mut required = [false; 256];
        required[usize::from(b'a')] = true;
        required[usize::from(b'z')] = true;
        assert!(!histogram.contains_all(&required));
    }
}
