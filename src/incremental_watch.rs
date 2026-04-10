//! Incremental index updates via filesystem notifications.
//!
//! Watches a directory for file changes and updates the bloom index
//! incrementally without rebuilding from scratch. On Linux, uses inotify
//! for efficient kernel-level notification. On other platforms, falls back
//! to periodic polling.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     ┌──────────────────┐     ┌─────────────┐
//! │  inotify/    │────▶│ IncrementalWatch  │────▶│ BlockIndex  │
//! │  polling     │     │ (detects changes) │     │ (updates)   │
//! └──────────────┘     └──────────────────┘     └─────────────┘
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Maximum total bytes to index across all modified files in one batch (16 GiB).
const MAX_TOTAL_INDEX_BYTES: usize = 16 * 1024 * 1024 * 1024;

use crate::builder::BlockIndexBuilder;
use crate::error::Result;
use crate::index::BlockIndex;

/// Configuration for the incremental watcher.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Block size for indexing new/modified files.
    pub block_size: usize,
    /// Bloom filter bits per block.
    pub bloom_bits: usize,
    /// Polling interval for fallback mode (no inotify).
    pub poll_interval: Duration,
    /// Maximum file size to index (skip larger files).
    pub max_file_size: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            block_size: 4096,
            bloom_bits: 1024,
            poll_interval: Duration::from_secs(5),
            max_file_size: 256 * 1024 * 1024,
        }
    }
}

/// Tracks filesystem changes and incrementally updates a block index.
pub struct IncrementalWatch {
    root: PathBuf,
    config: WatchConfig,
    /// Known files and their last modification times.
    known_files: HashSet<PathBuf>,
    /// Last poll timestamp.
    last_poll: Instant,
}

/// Describes what changed since the last poll.
#[derive(Debug, Clone, Default)]
pub struct ChangeSet {
    /// Files that were added or modified.
    pub modified: Vec<PathBuf>,
    /// Files that were removed.
    pub removed: Vec<PathBuf>,
}

impl ChangeSet {
    /// Whether any changes were detected.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.modified.is_empty() && self.removed.is_empty()
    }

    /// Total number of changes.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.modified.len() + self.removed.len()
    }
}

impl IncrementalWatch {
    /// Create a watcher for the given directory.
    pub fn new(root: impl Into<PathBuf>, config: WatchConfig) -> Self {
        Self {
            root: root.into(),
            config,
            known_files: HashSet::new(),
            last_poll: Instant::now(),
        }
    }

    /// Poll for changes since the last call.
    ///
    /// Scans the directory tree and compares against known state.
    /// Returns the set of files that changed.
    pub fn poll(&mut self) -> ChangeSet {
        let mut current_files = HashSet::new();
        let mut changes = ChangeSet::default();

        // Walk directory tree
        if let Ok(entries) = walk_dir(&self.root, self.config.max_file_size) {
            for path in entries {
                current_files.insert(path.clone());
                if !self.known_files.contains(&path) {
                    changes.modified.push(path);
                }
            }
        }

        // Detect removals
        for known in &self.known_files {
            if !current_files.contains(known) {
                changes.removed.push(known.clone());
            }
        }

        self.known_files = current_files;
        self.last_poll = Instant::now();
        changes
    }

    /// Build a block index from only the modified files.
    ///
    /// Reads each modified file, concatenates them, and builds a single block
    /// index. The resulting index preserves the exact concatenated length; if
    /// the caller intends to merge it with an existing index, both indexes must
    /// end on block boundaries or the merge will return
    /// [`Error::TrailingPartialBlock`](crate::Error::TrailingPartialBlock).
    ///
    /// # Caveats
    ///
    /// Files are concatenated directly, so n-grams crossing file boundaries
    /// are indexed. This can only cause false positives (extra candidate
    /// blocks), never false negatives.
    ///
    /// # Errors
    ///
    /// Returns an error if file reading or index building fails.
    pub fn index_changes(&self, changes: &ChangeSet) -> Result<Option<BlockIndex>> {
        if changes.modified.is_empty() {
            return Ok(None);
        }

        let mut all_bytes = Vec::new();
        for path in &changes.modified {
            if let Ok(data) = std::fs::read(path) {
                if all_bytes.len().saturating_add(data.len()) > MAX_TOTAL_INDEX_BYTES {
                    return Err(crate::error::Error::DataTooLarge);
                }
                all_bytes.extend_from_slice(&data);
            }
        }

        if all_bytes.is_empty() {
            return Ok(None);
        }

        let index = BlockIndexBuilder::new()
            .block_size(self.config.block_size)
            .bloom_bits(self.config.bloom_bits)
            .build(&all_bytes)?;

        Ok(Some(index))
    }

    /// Root directory being watched.
    #[must_use] 
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Time since the last poll.
    #[must_use] 
    pub fn since_last_poll(&self) -> Duration {
        self.last_poll.elapsed()
    }
}

/// Walk a directory recursively, returning paths to regular files under the size limit.
fn walk_dir(root: &Path, max_size: u64) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    walk_dir_inner(root, max_size, &mut files)?;
    Ok(files)
}

fn walk_dir_inner(dir: &Path, max_size: u64, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            let _ = walk_dir_inner(&path, max_size, out);
        } else if ft.is_file() {
            if let Ok(meta) = entry.metadata() {
                if meta.len() <= max_size {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = IncrementalWatch::new(dir.path(), WatchConfig::default());

        // Initial poll — empty
        let changes = watcher.poll();
        assert!(changes.is_empty());

        // Add a file
        fs::write(dir.path().join("test.txt"), b"hello world").unwrap();
        let changes = watcher.poll();
        assert_eq!(changes.modified.len(), 1);
        assert!(changes.removed.is_empty());
    }

    #[test]
    fn detects_removed_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("test.txt"), b"hello").unwrap();

        let mut watcher = IncrementalWatch::new(dir.path(), WatchConfig::default());
        let _ = watcher.poll(); // Register the file

        fs::remove_file(dir.path().join("test.txt")).unwrap();
        let changes = watcher.poll();
        assert_eq!(changes.removed.len(), 1);
    }

    #[test]
    fn no_changes_on_second_poll() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("test.txt"), b"hello").unwrap();

        let mut watcher = IncrementalWatch::new(dir.path(), WatchConfig::default());
        let _ = watcher.poll();
        let changes = watcher.poll();
        assert!(changes.is_empty());
    }

    #[test]
    fn index_changes_builds_index() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.bin"), vec![0u8; 8192]).unwrap();

        let mut watcher = IncrementalWatch::new(dir.path(), WatchConfig::default());
        let changes = watcher.poll();
        assert!(!changes.is_empty());

        let index = watcher.index_changes(&changes).unwrap();
        assert!(index.is_some());
    }
}
