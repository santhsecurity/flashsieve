//! Hierarchical bloom: a file-level bloom filter over an entire [`BlockIndex`](crate::BlockIndex).

use crate::bloom::NgramBloom;
use crate::error::{Error, Result};
use crate::filter::{ByteFilter, NgramFilter};
use crate::index::{BlockIndex, CandidateRange};

/// Wraps a [`BlockIndex`] with a file-level n-gram bloom filter.
///
/// The file bloom is the bitwise OR (set union) of every per-block bloom. If a
/// query's n-gram filter does not match this union, no per-block bloom can match
/// either, so n-gram and combined queries return no candidates without scanning blocks.
///
/// Byte-only queries are unchanged: there is no hierarchical shortcut for histograms.
///
/// # Examples
///
/// ```
/// use flashsieve::{BlockIndexBuilder, ByteFilter, FileBloomIndex, NgramFilter};
///
/// let index = BlockIndexBuilder::new()
///     .block_size(256)
///     .bloom_bits(1024)
///     .build(b"aaaa")
///     .unwrap();
/// let wrapped = FileBloomIndex::try_new(index).unwrap();
/// let ngram = NgramFilter::from_patterns(&[b"bc".as_slice()]);
/// assert!(wrapped.candidate_blocks_ngram(&ngram).is_empty());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileBloomIndex {
    inner: BlockIndex,
    file_bloom: NgramBloom,
}

impl FileBloomIndex {
    /// Build a file-level bloom summary over `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyBlockIndex`] when `inner` has zero blocks.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"x").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// assert_eq!(wrapped.block_count(), 1);
    /// ```
    pub fn try_new(inner: BlockIndex) -> Result<Self> {
        if inner.block_count() == 0 {
            return Err(Error::EmptyBlockIndex);
        }
        let file_bloom = NgramBloom::union_of(&inner.blooms)?;
        Ok(Self { inner, file_bloom })
    }

    /// Borrow the wrapped index.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"x").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// assert_eq!(wrapped.inner().block_count(), 1);
    /// ```
    #[must_use]
    pub fn inner(&self) -> &BlockIndex {
        &self.inner
    }

    /// The union bloom used for the hierarchical n-gram pre-filter.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"ab").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// assert!(wrapped.file_bloom().maybe_contains(b'a', b'b'));
    /// ```
    #[must_use]
    pub fn file_bloom(&self) -> &NgramBloom {
        &self.file_bloom
    }

    /// Recover the inner index (file bloom is discarded).
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"x").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// let inner = wrapped.into_inner();
    /// assert_eq!(inner.block_count(), 1);
    /// ```
    #[must_use]
    pub fn into_inner(self) -> BlockIndex {
        self.inner
    }

    /// [`BlockIndex::block_size`].
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(512).build(b"x").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// assert_eq!(wrapped.block_size(), 512);
    /// ```
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// [`BlockIndex::block_count`].
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(&[0u8; 512]).unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// assert_eq!(wrapped.block_count(), 2);
    /// ```
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.inner.block_count()
    }

    /// [`BlockIndex::total_data_length`].
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"hello").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// assert_eq!(wrapped.total_data_length(), 5);
    /// ```
    #[must_use]
    pub fn total_data_length(&self) -> usize {
        self.inner.total_data_length()
    }

    /// [`BlockIndex::candidate_blocks_byte`].
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, ByteFilter, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"secret").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// let filter = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    /// let candidates = wrapped.candidate_blocks_byte(&filter);
    /// assert!(!candidates.is_empty());
    /// ```
    #[must_use]
    pub fn candidate_blocks_byte(&self, filter: &ByteFilter) -> Vec<CandidateRange> {
        self.inner.candidate_blocks_byte(filter)
    }

    /// N-gram candidate query with a file-level bloom short-circuit.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex, NgramFilter};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"secret").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// let filter = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    /// let candidates = wrapped.candidate_blocks_ngram(&filter);
    /// assert!(!candidates.is_empty());
    /// ```
    #[must_use]
    pub fn candidate_blocks_ngram(&self, filter: &NgramFilter) -> Vec<CandidateRange> {
        if !filter.matches_bloom(&self.file_bloom) {
            return Vec::new();
        }
        self.inner.candidate_blocks_ngram(filter)
    }

    /// Combined query with a file-level n-gram short-circuit.
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, ByteFilter, FileBloomIndex, NgramFilter};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"secret").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// let bf = ByteFilter::from_patterns(&[b"secret".as_slice()]);
    /// let nf = NgramFilter::from_patterns(&[b"secret".as_slice()]);
    /// let candidates = wrapped.candidate_blocks(&bf, &nf);
    /// assert!(!candidates.is_empty());
    /// ```
    #[must_use]
    pub fn candidate_blocks(
        &self,
        byte_filter: &ByteFilter,
        ngram_filter: &NgramFilter,
    ) -> Vec<CandidateRange> {
        if !ngram_filter.matches_bloom(&self.file_bloom) {
            return Vec::new();
        }
        self.inner.candidate_blocks(byte_filter, ngram_filter)
    }

    /// [`BlockIndex::selectivity`].
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, ByteFilter, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(&[0u8; 512]).unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// let filter = ByteFilter::from_patterns(&[b"x".as_slice()]);
    /// let candidates = wrapped.candidate_blocks_byte(&filter);
    /// let sel = wrapped.selectivity(&candidates);
    /// assert!(sel >= 0.0 && sel <= 1.0);
    /// ```
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn selectivity(&self, ranges: &[CandidateRange]) -> f64 {
        self.inner.selectivity(ranges)
    }

    /// Serialize the inner index ([`BlockIndex::to_bytes`]).
    ///
    /// # Example
    ///
    /// ```
    /// use flashsieve::{BlockIndexBuilder, FileBloomIndex};
    ///
    /// let index = BlockIndexBuilder::new().block_size(256).build(b"x").unwrap();
    /// let wrapped = FileBloomIndex::try_new(index).unwrap();
    /// let bytes = wrapped.to_bytes();
    /// assert!(!bytes.is_empty());
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}
