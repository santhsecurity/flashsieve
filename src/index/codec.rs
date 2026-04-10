use super::BlockIndex;
use crate::bloom::filter::{NgramBloom, EXACT_PAIR_WORDS};
use crate::error::Error;
use crate::histogram::ByteHistogram;

pub(crate) const SERIALIZED_MAGIC: &[u8; 4] = b"FSBX";
pub(crate) const MAX_SUPPORTED_SERIALIZATION_VERSION: u32 = 2;
pub(crate) const MIN_SERIALIZED_HEADER_LEN: usize = 4 + 4 + 8 + 8 + 8;
pub(crate) const SERIALIZED_HISTOGRAM_LEN: usize = 256 * std::mem::size_of::<u32>();
pub(crate) const SERIALIZED_BLOOM_HEADER_LEN: usize = 8 + 8;
pub(crate) const MIN_SERIALIZED_BLOCK_LEN: usize =
    SERIALIZED_HISTOGRAM_LEN + SERIALIZED_BLOOM_HEADER_LEN;
pub(crate) const SERIALIZED_CRC_LEN: usize = 4;

/// Size of the exact-pair table in bytes (65,536 bits = 1024 u64s).
pub(crate) const EXACT_PAIR_TABLE_SIZE: usize = EXACT_PAIR_WORDS * 8;

/// Magic marker indicating presence of exact-pair table in bloom filter data.
const EXACT_PAIR_MARKER_PRESENT: u64 = NgramBloom::exact_pair_magic();

#[derive(Clone, Copy, Debug)]
pub(crate) struct ParsedIndexHeader {
    pub(crate) block_size: usize,
    pub(crate) total_len: usize,
    pub(crate) block_count: usize,
    pub(crate) payload_end: usize,
}

impl BlockIndex {
    /// Serialize the index to a portable binary format (version 2).
    ///
    /// Version 2 appends a CRC-32 checksum after all block data.
    ///
    /// When bloom filters have exact-pair tables (≥4096 bits), they are
    /// serialized after the bloom bit vector for faster mmap queries.
    ///
    /// # Wire Format
    ///
    /// See the [module-level documentation](crate::index) for the complete
    /// wire format specification.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-calculate exact size to avoid reallocations.
        let block_overhead: usize = self
            .blooms
            .iter()
            .map(|b| {
                let (_num_bits, words, exact_pairs) = b.serialize_with_exact_pairs();
                let exact_pair_size = if exact_pairs.is_some() {
                    8 + EXACT_PAIR_TABLE_SIZE // marker + table
                } else {
                    0
                };
                SERIALIZED_HISTOGRAM_LEN
                    + SERIALIZED_BLOOM_HEADER_LEN
                    + words.len() * 8
                    + exact_pair_size
            })
            .sum();
        let total_size = 32 + block_overhead + 4; // +4 for CRC
        let mut buf = Vec::with_capacity(total_size);
        buf.extend_from_slice(b"FSBX");
        buf.extend_from_slice(&2u32.to_le_bytes());

        buf.extend_from_slice(&(self.block_size as u64).to_le_bytes());
        buf.extend_from_slice(&(self.total_len as u64).to_le_bytes());
        buf.extend_from_slice(&(self.histograms.len() as u64).to_le_bytes());

        for (histogram, bloom) in self.histograms.iter().zip(&self.blooms) {
            // Bulk-write all 256 counts — avoids 256 individual to_le_bytes calls.
            for &count in histogram.raw_counts() {
                buf.extend_from_slice(&count.to_le_bytes());
            }
            let (num_bits, words, exact_pairs) = bloom.serialize_with_exact_pairs();

            // Write bloom header with exact-pair marker in num_bits high bit
            let num_bits_with_marker = if exact_pairs.is_some() {
                num_bits as u64 | 0x8000_0000_0000_0000
            } else {
                num_bits as u64
            };
            buf.extend_from_slice(&num_bits_with_marker.to_le_bytes());
            buf.extend_from_slice(&word_count_to_le_bytes(words));
            for &word in words {
                buf.extend_from_slice(&word.to_le_bytes());
            }

            // Write exact-pair table if present
            if let Some(pairs) = exact_pairs {
                buf.extend_from_slice(&EXACT_PAIR_MARKER_PRESENT.to_le_bytes());
                for &word in pairs {
                    buf.extend_from_slice(&word.to_le_bytes());
                }
            }
        }

        let crc = crc32_simple(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Deserialize a `BlockIndex` from bytes, returning typed errors.
    ///
    /// Reads both version 1 (no CRC) and version 2 (CRC-checked) formats.
    /// Also reads exact-pair tables when present (bit 63 set in num_bits field).
    ///
    /// # Errors
    ///
    /// Returns a variant of [`Error`] describing the exact
    /// failure mode — truncated header, invalid magic, unsupported version,
    /// block count overflow, truncated block data, or CRC mismatch.
    pub fn from_bytes_checked(data: &[u8]) -> crate::error::Result<Self> {
        let header = parse_serialized_index_header(data)?;
        let mut offset = 8 + (3 * std::mem::size_of::<u64>());

        let mut histograms = Vec::with_capacity(header.block_count);
        let mut blooms = Vec::with_capacity(header.block_count);

        for block_index in 0..header.block_count {
            let mut counts = [0_u32; 256];
            for count in &mut counts {
                if offset + 4 > header.payload_end {
                    return Err(Error::TruncatedBlock { block_index });
                }
                *count = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
            }
            histograms.push(ByteHistogram::from_raw_counts(counts));

            let num_bits_raw = read_u64_le_checked(data, &mut offset)
                .map_err(|_| Error::TruncatedBlock { block_index })?;
            // Check for exact-pair table marker in high bit
            let has_exact_pairs = (num_bits_raw & 0x8000_0000_0000_0000) != 0;
            let num_bits =
                usize::try_from(num_bits_raw & !0x8000_0000_0000_0000).unwrap_or(usize::MAX);

            let word_count = usize::try_from(
                read_u64_le_checked(data, &mut offset)
                    .map_err(|_| Error::TruncatedBlock { block_index })?,
            )
            .unwrap_or(usize::MAX);

            let required_bytes = word_count
                .checked_mul(8)
                .ok_or(Error::TruncatedBlock { block_index })?;
            let end_offset = offset
                .checked_add(required_bytes)
                .ok_or(Error::TruncatedBlock { block_index })?;
            if end_offset > header.payload_end || end_offset > data.len() {
                return Err(Error::TruncatedBlock { block_index });
            }
            if word_count < num_bits.div_ceil(64) {
                return Err(Error::TruncatedBlock { block_index });
            }
            let mut words = Vec::with_capacity(word_count);
            for _ in 0..word_count {
                words.push(u64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]));
                offset += 8;
            }

            // Read exact-pair table if present
            let exact_pairs: Option<Box<[u64; EXACT_PAIR_WORDS]>> = if has_exact_pairs {
                // Verify marker
                if offset + 8 > header.payload_end {
                    return Err(Error::TruncatedBlock { block_index });
                }
                let marker = u64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                offset += 8;
                if marker != EXACT_PAIR_MARKER_PRESENT {
                    // Marker mismatch - exact pair table corrupted or missing
                    return Err(Error::TruncatedBlock { block_index });
                }

                // Read exact-pair table (1024 u64s)
                if offset + EXACT_PAIR_TABLE_SIZE > header.payload_end {
                    return Err(Error::TruncatedBlock { block_index });
                }
                let mut pairs = Box::new([0u64; EXACT_PAIR_WORDS]);
                for i in 0..EXACT_PAIR_WORDS {
                    pairs[i] = u64::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    offset += 8;
                }
                Some(pairs)
            } else {
                None
            };

            blooms.push(
                NgramBloom::from_serialized_parts(num_bits, words, exact_pairs)
                    .map_err(|_| Error::TruncatedBlock { block_index })?,
            );
        }

        Ok(Self {
            block_size: header.block_size,
            bloom_bits: blooms.first().map_or(0, |bloom| bloom.raw_parts().0),
            total_len: header.total_len,
            histograms,
            blooms,
        })
    }

    /// Deserialize a `BlockIndex` from bytes.
    ///
    /// This is the backwards-compatible entry point that returns `Option`.
    /// Prefer [`from_bytes_checked`](Self::from_bytes_checked) for
    /// actionable error diagnostics.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        Self::from_bytes_checked(data).ok()
    }
}

fn word_count_to_le_bytes(words: &[u64]) -> [u8; 8] {
    (words.len() as u64).to_le_bytes()
}

/// CRC-32 (ISO 3309 / ITU-T V.42) over a byte slice.
///
/// Uses a 256-entry lookup table for O(n) performance instead of the
/// bit-serial O(n*8) approach.
///
/// # Polynomial
///
/// Uses the standard CRC-32 polynomial (reversed representation):
///
/// ```text
/// 0xEDB8_8320
/// ```
///
/// This corresponds to the polynomial:
/// `x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1`
///
/// # Algorithm
///
/// The lookup table is pre-computed at compile time using the standard
/// bit-serial CRC algorithm:
///
/// ```text
/// for i in 0..256:
///     crc = i
///     for _ in 0..8:
///         if crc & 1:
///             crc = (crc >> 1) ^ 0xEDB8_8320
///         else:
///             crc >>= 1
///     table[i] = crc
/// ```
fn crc32_simple(data: &[u8]) -> u32 {
    static TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            #[allow(clippy::cast_possible_truncation)]
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ TABLE[index];
    }
    !crc
}

pub(crate) fn parse_serialized_index_header(
    data: &[u8],
) -> crate::error::Result<ParsedIndexHeader> {
    use crate::error::Error;

    if data.len() < MIN_SERIALIZED_HEADER_LEN {
        return Err(Error::TruncatedHeader {
            expected: MIN_SERIALIZED_HEADER_LEN,
            got: data.len(),
        });
    }

    if &data[0..4] != SERIALIZED_MAGIC {
        let mut got = [0u8; 4];
        got.copy_from_slice(&data[0..4]);
        return Err(Error::InvalidMagic { got });
    }

    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&data[4..8]);
    let version = u32::from_le_bytes(version_bytes);
    if version == 0 || version > MAX_SUPPORTED_SERIALIZATION_VERSION {
        return Err(Error::UnsupportedVersion {
            got: version,
            max_supported: MAX_SUPPORTED_SERIALIZATION_VERSION,
        });
    }

    let payload_end = if version == MAX_SUPPORTED_SERIALIZATION_VERSION {
        if data.len() < MIN_SERIALIZED_HEADER_LEN + SERIALIZED_CRC_LEN {
            return Err(Error::TruncatedHeader {
                expected: MIN_SERIALIZED_HEADER_LEN + SERIALIZED_CRC_LEN,
                got: data.len(),
            });
        }
        let payload_end = data.len() - SERIALIZED_CRC_LEN;
        let stored_crc = u32::from_le_bytes([
            data[payload_end],
            data[payload_end + 1],
            data[payload_end + 2],
            data[payload_end + 3],
        ]);
        let computed_crc = crc32_simple(&data[..payload_end]);
        if stored_crc != computed_crc {
            return Err(Error::ChecksumMismatch {
                expected: stored_crc,
                computed: computed_crc,
            });
        }
        payload_end
    } else {
        data.len()
    };

    let mut offset = 8;
    let block_size = usize::try_from(read_u64_le_checked(data, &mut offset)?).unwrap_or(usize::MAX);
    if block_size == 0 || !block_size.is_power_of_two() || block_size < 256 {
        return Err(Error::InvalidBlockSize { size: block_size });
    }
    let total_len = usize::try_from(read_u64_le_checked(data, &mut offset)?).unwrap_or(usize::MAX);
    let block_count_raw = read_u64_le_checked(data, &mut offset)?;
    let block_count = usize::try_from(block_count_raw).unwrap_or(usize::MAX);

    let max_plausible =
        payload_end.saturating_sub(MIN_SERIALIZED_HEADER_LEN) / MIN_SERIALIZED_BLOCK_LEN;
    if block_count > max_plausible {
        return Err(Error::BlockCountOverflow {
            claimed: block_count_raw,
            max_plausible,
        });
    }

    Ok(ParsedIndexHeader {
        block_size,
        total_len,
        block_count,
        payload_end,
    })
}

pub(crate) fn read_u64_le_checked(data: &[u8], offset: &mut usize) -> crate::error::Result<u64> {
    if *offset + 8 > data.len() {
        return Err(crate::error::Error::TruncatedHeader {
            expected: *offset + 8,
            got: data.len(),
        });
    }
    let value = u64::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;
    Ok(value)
}
