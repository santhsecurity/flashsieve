//! Incremental update operations for [`BlockIndex`](crate::BlockIndex).

use crate::bloom::NgramBloom;
use crate::error::{Error, Result};
use crate::histogram::ByteHistogram;
use crate::BlockIndex;

/// Append blocks to an existing serialized index without re-indexing from scratch.
///
/// Deserializes the blob, appends new blocks using the same rules as
/// [`BlockIndex::append_block`], and re-serializes. Existing per-block histograms and
/// blooms are preserved exactly; only the new blocks are hashed from the provided slices.
///
/// # Errors
///
/// Returns the same errors as [`BlockIndex::from_bytes_checked`] and
/// [`BlockIndex::append_block`].
///
/// # Examples
///
/// ```
/// use flashsieve::{BlockIndexBuilder, IncrementalBuilder};
///
/// let base = BlockIndexBuilder::new()
///     .block_size(256)
///     .bloom_bits(1024)
///     .build_streaming([vec![b'a'; 256]].into_iter())
///     .unwrap();
/// let serialized = base.to_bytes();
/// let extra = vec![b'b'; 256];
/// let appended = IncrementalBuilder::append_blocks(&serialized, &[extra.as_slice()]).unwrap();
/// let recovered = flashsieve::BlockIndex::from_bytes_checked(&appended).unwrap();
/// assert_eq!(recovered.block_count(), 2);
/// ```
pub struct IncrementalBuilder;

impl IncrementalBuilder {
    /// Append one or more blocks to a validated serialized index.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`BlockIndex::from_bytes_checked`] or
    /// [`BlockIndex::append_block`] while rebuilding the extended index.
    ///
    /// # Boundary Handling
    ///
    /// To properly index n-grams crossing the boundary between the existing
    /// index and the first new block, provide `prev_last_byte` as the last
    /// byte of the original data that was indexed. Without this, patterns
    /// spanning the boundary may produce false negatives.
    ///
    /// # Examples
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, IncrementalBuilder};
    ///
    /// let base = BlockIndexBuilder::new()
    ///     .block_size(256)
    ///     .bloom_bits(1024)
    ///     .build_streaming([vec![b'a'; 256]].into_iter())
    ///     .unwrap();
    /// let serialized = base.to_bytes();
    /// let extra = vec![b'b'; 256];
    /// // Pass Some(b'a') as the last byte of original data for correct boundary handling
    /// let appended = IncrementalBuilder::append_blocks_with_boundary(&serialized, Some(b'a'), &[extra.as_slice()]).unwrap();
    /// let recovered = flashsieve::BlockIndex::from_bytes_checked(&appended).unwrap();
    /// assert_eq!(recovered.block_count(), 2);
    /// ```
    pub fn append_blocks(serialized: &[u8], blocks: &[&[u8]]) -> Result<Vec<u8>> {
        Self::append_blocks_with_boundary(serialized, None, blocks)
    }

    /// Append one or more blocks with explicit boundary byte handling.
    ///
    /// `prev_last_byte` should be the last byte of the data that was originally
    /// indexed. When provided, n-grams crossing the old/new boundary are properly
    /// indexed in the first new block's bloom filter.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`BlockIndex::from_bytes_checked`] or
    /// [`BlockIndex::append_block`] while rebuilding the extended index.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, IncrementalBuilder};
    ///
    /// let base = BlockIndexBuilder::new()
    ///     .block_size(256)
    ///     .bloom_bits(1024)
    ///     .build_streaming([vec![b'a'; 256]].into_iter())
    ///     .unwrap();
    /// let serialized = base.to_bytes();
    /// let extra = vec![b'b'; 256];
    /// let appended = IncrementalBuilder::append_blocks_with_boundary(
    ///     &serialized, Some(b'a'), &[extra.as_slice()]
    /// ).unwrap();
    /// let recovered = flashsieve::BlockIndex::from_bytes_checked(&appended).unwrap();
    /// assert_eq!(recovered.block_count(), 2);
    /// ```
    pub fn append_blocks_with_boundary(
        serialized: &[u8],
        prev_last_byte: Option<u8>,
        blocks: &[&[u8]],
    ) -> Result<Vec<u8>> {
        let mut index = BlockIndex::from_bytes_checked(serialized)?;
        let mut prev_last_byte = prev_last_byte;
        for &block in blocks {
            index.append_block_with_boundary(block, prev_last_byte)?;
            prev_last_byte = block.last().copied();
        }
        Ok(index.to_bytes())
    }
}

impl BlockIndex {
    /// Append one full block to an existing index.
    ///
    /// The input must be exactly `self.block_size()` bytes long.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnalignedData`] when the
    /// provided block length differs from the configured block size, or
    /// [`Error::ZeroBloomBits`] if the index was
    /// constructed with an invalid zero-bit bloom configuration.
    pub fn append_block(&mut self, block_data: &[u8]) -> Result<()> {
        self.append_block_with_boundary(block_data, None)
    }

    /// Append one full block, inserting the cross-boundary n-gram if `prev_last_byte` is provided.
    ///
    /// Without the boundary byte, patterns spanning block boundaries may be missed (false negatives).
    ///
    /// # Errors
    ///
    /// Same as [`append_block`](Self::append_block).
    pub fn append_block_with_boundary(
        &mut self,
        block_data: &[u8],
        prev_last_byte: Option<u8>,
    ) -> Result<()> {
        if block_data.is_empty() || block_data.len() > self.block_size {
            return Err(Error::UnalignedData {
                data_len: block_data.len(),
                block_size: self.block_size,
            });
        }

        if self.total_len % self.block_size != 0 {
            return Err(Error::UnalignedData {
                data_len: self.total_len,
                block_size: self.block_size,
            });
        }

        let bloom_bits = self.bloom_bits()?;
        self.histograms.push(ByteHistogram::from_block(block_data));
        let mut bloom = NgramBloom::from_block(block_data, bloom_bits)?;
        if let Some(prev_byte) = prev_last_byte {
            if let Some(&first) = block_data.first() {
                bloom.insert_ngram(prev_byte, first);
            }
        }
        self.blooms.push(bloom);
        self.total_len =
            self.total_len
                .checked_add(block_data.len())
                .ok_or(Error::UnalignedData {
                    data_len: self.total_len,
                    block_size: self.block_size,
                })?;
        Ok(())
    }

    /// Merge `other` into `self`, appending `other`'s blocks after `self`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncompatibleIndexConfiguration`]
    /// when the indexes use different block sizes or bloom filter sizes.
    pub fn merge(&mut self, other: &BlockIndex) -> Result<()> {
        if self.block_size != other.block_size {
            return Err(Error::IncompatibleIndexConfiguration {
                reason: "block_size differs",
            });
        }

        let self_bloom_bits = self.bloom_bits()?;
        let other_bloom_bits = other.bloom_bits()?;
        if self_bloom_bits != other_bloom_bits {
            return Err(Error::IncompatibleIndexConfiguration {
                reason: "bloom_bits differs",
            });
        }

        self.total_len = self.total_len.checked_add(other.total_len).ok_or(
            Error::IncompatibleIndexConfiguration {
                reason: "total length overflow",
            },
        )?;
        self.histograms.extend(other.histograms.iter().cloned());
        self.blooms.extend(other.blooms.iter().cloned());
        self.bloom_bits = self_bloom_bits;
        Ok(())
    }

    /// Remove blocks by block ID and compact the index in-place.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBlockId`] if any
    /// requested block ID is out of range.
    pub fn remove_blocks(&mut self, block_ids: &[usize]) -> Result<()> {
        if block_ids.is_empty() {
            return Ok(());
        }

        let block_count = self.block_count();
        let mut remove = vec![false; block_count];
        for &block_id in block_ids {
            if block_id >= block_count {
                return Err(Error::InvalidBlockId {
                    block_id,
                    block_count,
                });
            }
            remove[block_id] = true;
        }

        // Removing non-trailing blocks would break the index * block_size offset invariant.
        let mut found_removed = false;
        for &should_remove in &remove {
            if should_remove {
                found_removed = true;
            } else if found_removed {
                return Err(Error::NonSuffixBlockRemoval);
            }
        }

        let mut removed_len = 0;
        for (i, &should_remove) in remove.iter().enumerate() {
            if should_remove {
                let is_last = i == block_count - 1;
                let partial = self.total_len % self.block_size;
                let block_len = if is_last && partial != 0 {
                    partial
                } else {
                    self.block_size
                };
                removed_len += block_len;
            }
        }

        let removed_blocks = remove.iter().filter(|&&flag| flag).count();
        if removed_blocks == 0 {
            return Ok(());
        }

        let mut next_histograms = Vec::with_capacity(block_count - removed_blocks);
        let mut next_blooms = Vec::with_capacity(block_count - removed_blocks);

        for ((histogram, bloom), should_remove) in self
            .histograms
            .drain(..)
            .zip(self.blooms.drain(..))
            .zip(remove)
        {
            if !should_remove {
                next_histograms.push(histogram);
                next_blooms.push(bloom);
            }
        }

        self.histograms = next_histograms;
        self.blooms = next_blooms;
        self.total_len = self
            .total_len
            .checked_sub(removed_len)
            .ok_or(Error::InvalidBlockId {
                block_id: block_count,
                block_count,
            })?;
        Ok(())
    }

    fn bloom_bits(&self) -> Result<usize> {
        if self.bloom_bits == 0 {
            match self.blooms.first() {
                Some(bloom) => Ok(bloom.raw_parts().0),
                None => Err(Error::ZeroBloomBits),
            }
        } else {
            Ok(self.bloom_bits)
        }
    }
}
