//! Construction of block indexes from raw data.
//!
//! This module provides [`BlockIndexBuilder`], a configurable builder
//! for constructing [`BlockIndex`](crate::BlockIndex) instances from
//! contiguous data or streaming block iterators.

use crate::bloom::NgramBloom;
use crate::error::{Error, Result};
use crate::histogram::ByteHistogram;
use crate::index::BlockIndex;

const DEFAULT_BLOCK_SIZE: usize = 256 * 1024;
const DEFAULT_BLOOM_BITS: usize = 65_536;

/// Builder for constructing a [`BlockIndex`] from raw data.
///
/// # Example
///
/// ```
/// use flashsieve::BlockIndexBuilder;
///
/// let index = BlockIndexBuilder::new()
///     .block_size(512)
///     .bloom_bits(2048)
///     .build(&[0u8; 1024])
///     .unwrap();
///
/// assert_eq!(index.block_count(), 2);
/// ```
#[derive(Clone, Debug)]
pub struct BlockIndexBuilder {
    block_size: usize,
    bloom_bits: usize,
}

impl BlockIndexBuilder {
    /// Create a new builder with sensible defaults.
    ///
    /// The default block size is 256 KiB and the default bloom filter size is
    /// 65,536 bits per block (1 bit per possible 2-byte n-gram).
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            bloom_bits: DEFAULT_BLOOM_BITS,
        }
    }

    /// Set the block size to use when indexing.
    ///
    /// The size must be a power of two and at least 256 bytes. Validation is
    /// performed when [`build`](Self::build) or
    /// [`build_streaming`](Self::build_streaming) runs.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let builder = BlockIndexBuilder::new()
    ///     .block_size(4096);
    /// ```
    #[must_use]
    pub fn block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    /// Set the bloom filter bit count for each block.
    ///
    /// The bit count must be greater than zero. Validation is performed when
    /// the index is built.
    ///
    /// Larger bloom filters reduce false positive rate at the cost of
    /// increased memory and serialization size.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let builder = BlockIndexBuilder::new()
    ///     .bloom_bits(8192);
    /// ```
    #[must_use]
    pub fn bloom_bits(mut self, bits: usize) -> Self {
        self.bloom_bits = bits;
        self
    }

    /// Build an index from a contiguous data slice.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The configured block size is not a power of two or is less than 256
    /// - The bloom filter size is zero
    ///
    /// The input length does not need to be aligned to the block size; a
    /// partial final block is indexed as-is.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let data = vec![0u8; 1024];
    /// let index = BlockIndexBuilder::new()
    ///     .block_size(256)
    ///     .build(&data)
    ///     .unwrap();
    ///
    /// assert_eq!(index.block_count(), 4);
    /// ```
    pub fn build(&self, data: &[u8]) -> Result<BlockIndex> {
        validate_block_size(self.block_size)?;
        if self.bloom_bits == 0 {
            return Err(Error::ZeroBloomBits);
        }

        // Allow unaligned data — the last block can be smaller than block_size.
        // Real files are almost never exact multiples of the block size.
        // A partial final block still gets a valid histogram and bloom filter.
        let mut histograms = Vec::new();
        let mut blooms = Vec::new();

        let mut prev_byte = None;
        for block in data.chunks(self.block_size) {
            histograms.push(ByteHistogram::from_block(block));
            let mut bloom = NgramBloom::from_block(block, self.bloom_bits)?;
            if let Some(b) = prev_byte {
                if let Some(&first) = block.first() {
                    bloom.insert_ngram(b, first);
                }
            }
            prev_byte = block.last().copied();
            blooms.push(bloom);
        }

        let last_byte = data.last().copied();
        Ok(BlockIndex::new_with_last_byte(
            self.block_size,
            data.len(),
            histograms,
            blooms,
            last_byte,
        ))
    }

    /// Build an index from an iterator of blocks.
    ///
    /// This method is useful when data arrives in chunks or when the final
    /// chunk size is managed externally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The configured block size is not a power of two or is less than 256
    /// - The bloom filter size is zero
    /// - Any yielded block length differs from the configured block size
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::BlockIndexBuilder;
    ///
    /// let blocks = vec![vec![0u8; 256], vec![0u8; 256]];
    /// let index = BlockIndexBuilder::new()
    ///     .block_size(256)
    ///     .build_streaming(blocks.into_iter())
    ///     .unwrap();
    ///
    /// assert_eq!(index.block_count(), 2);
    /// ```
    pub fn build_streaming<I: Iterator<Item = Vec<u8>>>(&self, blocks: I) -> Result<BlockIndex> {
        validate_block_size(self.block_size)?;
        if self.bloom_bits == 0 {
            return Err(Error::ZeroBloomBits);
        }

        let mut histograms = Vec::new();
        let mut blooms = Vec::new();
        let mut total_len = 0_usize;

        let mut prev_byte = None;
        for block in blocks {
            if block.len() != self.block_size {
                return Err(Error::UnalignedData {
                    data_len: block.len(),
                    block_size: self.block_size,
                });
            }
            total_len = total_len
                .checked_add(block.len())
                .ok_or(Error::DataTooLarge)?;
            histograms.push(ByteHistogram::from_block(&block));
            let mut bloom = NgramBloom::from_block(&block, self.bloom_bits)?;
            if let Some(b) = prev_byte {
                if let Some(&first) = block.first() {
                    bloom.insert_ngram(b, first);
                }
            }
            prev_byte = block.last().copied();
            blooms.push(bloom);
        }

        let last_byte = prev_byte;
        Ok(BlockIndex::new_with_last_byte(
            self.block_size,
            total_len,
            histograms,
            blooms,
            last_byte,
        ))
    }
}

impl Default for BlockIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_block_size(size: usize) -> Result<()> {
    if size < 256 || !size.is_power_of_two() {
        return Err(Error::InvalidBlockSize { size });
    }
    Ok(())
}
