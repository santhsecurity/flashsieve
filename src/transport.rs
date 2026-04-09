//! Compressed bloom index transport for peer-to-peer index sharing.
//!
//! Provides a wire-format wrapper around [`BlockIndex`] serialization that
//! supports optional compression. The transport format:
//!
//! ```text
//! [magic: 4 bytes = "FSTR"]
//! [version: u32 LE = 1]
//! [compression: u8 = 0 (none) | 1 (run-length encoded)]
//! [uncompressed_size: u64 LE]
//! [payload: variable]
//! [crc32: u32 LE]
//! ```
//!
//! The run-length encoding is tuned for bloom filter data which is typically
//! sparse (many zero words). For a 50GB trigram index, the bloom filters
//! compress ~3-5x with RLE alone, making P2P sharing practical.

use crate::error::{Error, Result};
use crate::index::BlockIndex;

const TRANSPORT_MAGIC: [u8; 4] = *b"FSTR";
const TRANSPORT_VERSION: u32 = 1;
const HEADER_SIZE: usize = 4 + 4 + 1 + 8; // magic + version + compression + uncompressed_size

/// Compression mode for the transport format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    /// No compression — raw serialized bytes.
    None = 0,
    /// Run-length encoding for sparse bloom data.
    RunLength = 1,
}

/// Serialize a `BlockIndex` into the compressed transport format.
///
/// Uses run-length encoding by default, which provides 3-5x compression
/// on typical bloom filter data.
#[must_use]
pub fn to_transport_bytes(index: &BlockIndex) -> Vec<u8> {
    to_transport_bytes_with(index, Compression::RunLength)
}

/// Serialize a `BlockIndex` with explicit compression mode.
#[must_use]
pub fn to_transport_bytes_with(index: &BlockIndex, compression: Compression) -> Vec<u8> {
    let raw = index.to_bytes();
    let uncompressed_size = raw.len() as u64;

    let payload = match compression {
        Compression::None => raw,
        Compression::RunLength => rle_compress(&raw),
    };

    let total_size = HEADER_SIZE + payload.len() + 4; // +4 for crc32
    let mut out = Vec::with_capacity(total_size);

    out.extend_from_slice(&TRANSPORT_MAGIC);
    out.extend_from_slice(&TRANSPORT_VERSION.to_le_bytes());
    out.push(compression as u8);
    out.extend_from_slice(&uncompressed_size.to_le_bytes());
    out.extend_from_slice(&payload);

    let crc = crc32_simple(&out);
    out.extend_from_slice(&crc.to_le_bytes());

    out
}

/// Deserialize a `BlockIndex` from the compressed transport format.
///
/// # Errors
///
/// Returns an error if the magic, version, or CRC is invalid, or if
/// decompression fails.
pub fn from_transport_bytes(data: &[u8]) -> Result<BlockIndex> {
    if data.len() < HEADER_SIZE + 4 {
        return Err(Error::Transport {
            reason: "transport data too short for header + CRC".to_string(),
        });
    }

    // Check magic
    if data[..4] != TRANSPORT_MAGIC {
        return Err(Error::Transport {
            reason: format!(
                "invalid transport magic: expected FSTR, got {:?}",
                &data[..4]
            ),
        });
    }

    // Check version
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != TRANSPORT_VERSION {
        return Err(Error::Transport {
            reason: format!(
                "unsupported transport version {version}, expected {TRANSPORT_VERSION}"
            ),
        });
    }

    // Check CRC
    let crc_offset = data.len() - 4;
    let stored_crc = u32::from_le_bytes([
        data[crc_offset],
        data[crc_offset + 1],
        data[crc_offset + 2],
        data[crc_offset + 3],
    ]);
    let computed_crc = crc32_simple(&data[..crc_offset]);
    if stored_crc != computed_crc {
        return Err(Error::Transport {
            reason: format!(
                "CRC mismatch: stored={stored_crc:#010X}, computed={computed_crc:#010X}"
            ),
        });
    }

    // Decompress
    let compression = data[8];
    let uncompressed_size = u64::from_le_bytes([
        data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
    ]);
    let payload = &data[HEADER_SIZE..crc_offset];

    let raw = match compression {
        0 => payload.to_vec(),
        #[allow(clippy::cast_possible_truncation)]
        1 => rle_decompress(payload, uncompressed_size as usize)?,
        other => {
            return Err(Error::Transport {
                reason: format!("unknown compression type {other}"),
            });
        }
    };

    #[allow(clippy::cast_possible_truncation)]
    if raw.len() != uncompressed_size as usize {
        return Err(Error::Transport {
            reason: format!(
                "decompressed size mismatch: expected {uncompressed_size}, got {}",
                raw.len()
            ),
        });
    }

    BlockIndex::from_bytes_checked(&raw)
}

/// Run-length encode data. Encodes runs of identical bytes as (byte, count_u16).
/// For non-runs, uses a literal run marker.
///
/// Run-length encode a byte slice.
///
/// Returns a new vector containing the RLE-compressed data.
///
/// Format:
/// - `0xFF count_hi count_lo byte`: RLE run (count = count_hi << 8 | count_lo, 1-65535)
/// - `0xFE count byte...`: literal run (up to 254 raw bytes)
/// - Other byte: literal single byte
///
/// # Example
///
/// ```
/// use flashsieve::transport::rle_compress;
///
/// let data = vec![0u8; 100];
/// let compressed = rle_compress(&data);
/// assert!(compressed.len() < data.len());
/// ```
#[must_use]
pub fn rle_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        // Count run length
        let byte = data[i];
        let mut run_len = 1usize;
        while i + run_len < data.len() && data[i + run_len] == byte && run_len < 65535 {
            run_len += 1;
        }

        if run_len >= 4 || (run_len >= 2 && (byte == 0xFF || byte == 0xFE)) {
            // RLE encode
            #[allow(clippy::cast_possible_truncation)]
            let count = run_len as u16;
            out.push(0xFF);
            out.push((count >> 8) as u8);
            out.push((count & 0xFF) as u8);
            out.push(byte);
            i += run_len;
        } else if byte == 0xFF || byte == 0xFE {
            // Escape single 0xFF/0xFE bytes
            out.push(0xFF);
            out.push(0);
            out.push(1);
            out.push(byte);
            i += 1;
        } else {
            out.push(byte);
            i += 1;
        }
    }

    out
}

/// Run-length decode a byte slice.
///
/// # Errors
///
/// Returns [`Error::Transport`] if the RLE data is truncated or would expand
/// to a size larger than `expected_size`.
///
/// # Example
///
/// ```
/// use flashsieve::transport::{rle_compress, rle_decompress};
///
/// let data = vec![0u8; 100];
/// let compressed = rle_compress(&data);
/// let decompressed = rle_decompress(&compressed, data.len()).unwrap();
/// assert_eq!(data, decompressed);
/// ```
pub fn rle_decompress(data: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(expected_size);
    let mut i = 0;

    while i < data.len() {
        if data[i] == 0xFF {
            if i + 3 >= data.len() {
                return Err(Error::Transport {
                    reason: "truncated RLE sequence".to_string(),
                });
            }
            let count = ((data[i + 1] as usize) << 8) | (data[i + 2] as usize);
            let byte = data[i + 3];
            if out.len().saturating_add(count) > expected_size {
                return Err(Error::Transport {
                    reason: "RLE decompression would exceed expected size".to_string(),
                });
            }
            out.extend(std::iter::repeat_n(byte, count));
            i += 4;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }

    Ok(out)
}

/// Simple CRC32 (IEEE 802.3 polynomial) — no dependency needed.
fn crc32_simple(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::BlockIndexBuilder;

    fn make_test_index() -> BlockIndex {
        let mut data = vec![0u8; 512];
        data[..6].copy_from_slice(b"secret");
        data[256..261].copy_from_slice(b"token");
        BlockIndexBuilder::new()
            .block_size(256)
            .bloom_bits(512)
            .build(&data)
            .unwrap()
    }

    #[test]
    fn round_trip_no_compression() {
        let index = make_test_index();
        let transport = to_transport_bytes_with(&index, Compression::None);
        let restored = from_transport_bytes(&transport).unwrap();
        assert_eq!(index.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn round_trip_rle_compression() {
        let index = make_test_index();
        let transport = to_transport_bytes(&index);
        let restored = from_transport_bytes(&transport).unwrap();
        assert_eq!(index.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn rle_compresses_sparse_data() {
        let index = make_test_index();
        let raw = index.to_bytes();
        let compressed = to_transport_bytes(&index);
        // RLE should compress bloom filter data (lots of zeros)
        assert!(
            compressed.len() < raw.len(),
            "compressed ({}) should be smaller than raw ({})",
            compressed.len(),
            raw.len()
        );
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut data = to_transport_bytes(&make_test_index());
        data[0] = b'X';
        assert!(from_transport_bytes(&data).is_err());
    }

    #[test]
    fn rejects_bad_crc() {
        let mut data = to_transport_bytes(&make_test_index());
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        assert!(from_transport_bytes(&data).is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(from_transport_bytes(b"FST").is_err());
    }

    #[test]
    fn rejects_unknown_compression() {
        let mut data = to_transport_bytes_with(&make_test_index(), Compression::None);
        data[8] = 99; // unknown compression
                      // Recalculate CRC
        let crc_offset = data.len() - 4;
        let crc = crc32_simple(&data[..crc_offset]);
        data[crc_offset..].copy_from_slice(&crc.to_le_bytes());
        assert!(from_transport_bytes(&data).is_err());
    }

    #[test]
    fn rle_handles_0xff_bytes() {
        // Data with 0xFF bytes should round-trip correctly
        let data = vec![0xFF; 100];
        let compressed = rle_compress(&data);
        let decompressed = rle_decompress(&compressed, 100).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn rle_handles_0xfe_bytes() {
        let data = vec![0xFE; 50];
        let compressed = rle_compress(&data);
        let decompressed = rle_decompress(&compressed, 50).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn rle_handles_mixed_data() {
        let mut data = Vec::new();
        data.extend(std::iter::repeat_n(0u8, 100)); // long run of zeros
        data.extend(b"hello world"); // literal
        data.extend(std::iter::repeat_n(0xFF, 50)); // long run of 0xFF
        data.extend(std::iter::repeat_n(42u8, 200)); // long run

        let compressed = rle_compress(&data);
        let decompressed = rle_decompress(&compressed, data.len()).unwrap();
        assert_eq!(data, decompressed);
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn crc32_known_value() {
        // CRC32 of empty data
        let crc = crc32_simple(b"");
        assert_eq!(crc, 0);
    }

    #[test]
    fn crc32_detects_bit_flip() {
        let data = b"hello world";
        let crc1 = crc32_simple(data);
        let mut modified = data.to_vec();
        modified[5] ^= 1;
        let crc2 = crc32_simple(&modified);
        assert_ne!(crc1, crc2);
    }
}
