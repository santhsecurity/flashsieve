#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::explicit_iter_loop,
    clippy::uninlined_format_args,
    clippy::unreadable_literal
)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Adversarial tests for transport serialization and incremental watching.
//!
//! These tests are designed to break the implementation: pathological inputs,
//! exhaustive truncation, concurrent races, and CRC collision resistance.

use flashsieve::incremental_watch::{IncrementalWatch, WatchConfig};
use flashsieve::transport::{
    from_transport_bytes, rle_compress, rle_decompress, to_transport_bytes,
};
use flashsieve::{BlockIndex, BlockIndexBuilder, ByteHistogram, NgramBloom};
use std::sync::{Arc, Mutex};
use std::thread;

/// (1) Transport round-trip with a maximum-size index of 1M blocks.
///
/// Constructs the largest practical index and verifies that the transport
/// layer can serialize, compress, and deserialize it without corruption.
/// The index is intentionally sparse (all-zero histograms and blooms) so
/// RLE compression keeps the wire format small, but the deserialized
/// index still contains 1M fully materialized blocks.
#[test]
fn transport_round_trip_maximum_size_index() {
    const BLOCK_COUNT: usize = 1_000_000;
    const BLOCK_SIZE: usize = 256;

    let histograms = vec![ByteHistogram::new(); BLOCK_COUNT];
    let bloom = NgramBloom::new(64).unwrap();
    let blooms = vec![bloom; BLOCK_COUNT];
    let index = BlockIndex::new(BLOCK_SIZE, BLOCK_SIZE * BLOCK_COUNT, histograms, blooms);

    assert_eq!(index.block_count(), BLOCK_COUNT);

    let transport = to_transport_bytes(&index);
    let restored = from_transport_bytes(&transport).unwrap();

    assert_eq!(restored.block_count(), BLOCK_COUNT);
    assert_eq!(restored.block_size(), BLOCK_SIZE);
    assert_eq!(restored.total_data_length(), BLOCK_SIZE * BLOCK_COUNT);
    assert_eq!(index.to_bytes(), restored.to_bytes());
}

/// (2) RLE compression with pathological input (alternating 0xFF/0x00).
///
/// The transport RLE scheme must escape every 0xFF byte. Alternating
/// 0xFF/0x00 is the worst possible pattern: no runs compress and every
/// 0xFF expands from 1 byte to 4 bytes. We assert both correct round-trip
/// and that the compressed payload is at least 1.5x the raw data.
#[test]
fn rle_pathological_alternating_ff_00() {
    let data: Vec<u8> = (0..10_000)
        .map(|i| if i % 2 == 0 { 0xFF } else { 0x00 })
        .collect();

    let compressed = rle_compress(&data);
    let decompressed = rle_decompress(&compressed, data.len()).unwrap();

    // Exact round-trip is mandatory
    assert_eq!(
        data, decompressed,
        "RLE round-trip corrupted pathological data"
    );

    // Pathological input must expand: each 0xFF turns into a 4-byte escape
    // and each 0x00 is a 1-byte literal. Expected expansion factor is ~2.5x.
    assert!(
        compressed.len() >= data.len() + (data.len() / 2) * 3,
        "pathological RLE did not expand as expected: compressed={} raw={}",
        compressed.len(),
        data.len()
    );
}

/// (3) Truncated transport data at every possible offset.
///
/// For a valid transport packet, removing even a single byte must be
/// rejected. We truncate at every offset from 0 to len-1 and assert
/// that deserialization returns an error every time.
#[test]
fn truncated_transport_data_at_every_offset() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(512)
        .build(&[0xabu8; 512])
        .unwrap();
    let transport = to_transport_bytes(&index);

    for len in 0..transport.len() {
        let result = from_transport_bytes(&transport[..len]);
        assert!(
            result.is_err(),
            "truncation at offset {} (of {}) must fail",
            len,
            transport.len()
        );
    }
}

/// (4) Concurrent `IncrementalWatch` polls don't race.
///
/// Spawns multiple threads that hammer `poll()` on the same watcher
/// (protected by a Mutex) while another thread mutates the watched
/// directory. After all threads finish we assert that the watcher is
/// not corrupted and that a final stable poll returns an empty change set.
#[test]
fn concurrent_incremental_watch_polls_do_not_race() {
    let dir = tempfile::tempdir().unwrap();
    let config = WatchConfig {
        block_size: 256,
        bloom_bits: 512,
        poll_interval: std::time::Duration::from_millis(1),
        max_file_size: 1024 * 1024,
    };

    // Seed the directory
    for i in 0..50 {
        std::fs::write(dir.path().join(format!("file{i}.txt")), b"seed").unwrap();
    }

    let watcher = Arc::new(Mutex::new(IncrementalWatch::new(dir.path(), config)));

    // Establish baseline
    {
        let mut w = watcher.lock().unwrap();
        let _ = w.poll();
    }

    let mut handles = vec![];

    // Pollers
    for _ in 0..8 {
        let w = watcher.clone();
        handles.push(thread::spawn(move || {
            let mut changes_seen = 0usize;
            for _ in 0..100 {
                let mut guard = w.lock().unwrap();
                let changes = guard.poll();
                changes_seen += changes.len();
            }
            changes_seen
        }));
    }

    // Concurrent mutator
    let dir_path = dir.path().to_path_buf();
    let mutator = thread::spawn(move || {
        for i in 0..30 {
            std::fs::write(dir_path.join(format!("new{i}.txt")), b"new").unwrap();
            let _ = std::fs::remove_file(dir_path.join(format!("file{}.txt", i % 50)));
        }
    });

    let total_changes: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    mutator.join().unwrap();

    // Final poll to converge
    let converged = {
        let mut w = watcher.lock().unwrap();
        w.poll()
    };

    // One more poll must be empty — stable state
    let stable = {
        let mut w = watcher.lock().unwrap();
        w.poll()
    };
    assert!(
        stable.is_empty(),
        "watcher should be stable after convergence, got {} changes",
        stable.len()
    );

    // Watcher metadata must remain intact
    assert_eq!(watcher.lock().unwrap().root(), dir.path());

    // We don't assert an exact change count because races with the mutator
    // are nondeterministic, but we do assert that the watcher stayed consistent.
    let _ = total_changes;
    let _ = converged;
}

/// (5) CRC32 collision resistance — flip every bit position.
///
/// CRC32 is expected to detect all single-bit errors. For every byte in
/// the transport packet and every bit in that byte, we flip the bit and
/// assert that `from_transport_bytes` returns an error. Any `Ok` result
/// is a CRC collision and a critical bug at scale.
#[test]
fn crc32_collision_resistance_flip_every_bit() {
    let index = BlockIndexBuilder::new()
        .block_size(256)
        .bloom_bits(512)
        .build(&[0xcdu8; 512])
        .unwrap();
    let transport = to_transport_bytes(&index);

    for byte_idx in 0..transport.len() {
        for bit in 0..8 {
            let mut corrupted = transport.clone();
            corrupted[byte_idx] ^= 1 << bit;
            let result = from_transport_bytes(&corrupted);
            assert!(
                result.is_err(),
                "CRC32 missed collision: byte {} bit {} produced Ok",
                byte_idx,
                bit
            );
        }
    }
}
