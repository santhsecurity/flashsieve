#![allow(clippy::unwrap_used)]

use flashsieve::{BlockIndexBuilder, ByteFilter, NgramFilter};
use proptest::prelude::*;

proptest! {
    #[test]
    fn legendary_property_zero_false_negatives(
        data in prop::collection::vec(any::<u8>(), 256..2048),
        start_idx in 0usize..2048,
        len in 2usize..100
    ) {
        let actual_start = start_idx.min(data.len().saturating_sub(len));
        let actual_len = len.min(data.len() - actual_start);

        prop_assume!(actual_len >= 2);

        let pattern = &data[actual_start..actual_start + actual_len];

        let index = BlockIndexBuilder::new().block_size(256).build(&data).unwrap();

        let byte_filter = ByteFilter::from_patterns(&[pattern]);
        let ngram_filter = NgramFilter::from_patterns(&[pattern]);

        let candidates = index.candidate_blocks(&byte_filter, &ngram_filter);

        // The pattern must be found in at least one candidate block range
        // Note: patterns spanning blocks will still trigger match in both if checked loosely,
        // but flashsieve guarantees finding it if fully inside a block.
        // For span cases, the overlapping logic in candidates should be robust enough,
        // or we check if the start offset block is included.
        let block_idx = actual_start / 256;
        let block_offset = block_idx * 256;

        let is_found = candidates.iter().any(|c| c.offset <= block_offset && c.offset + c.length > block_offset);

        // This is a relaxed property because flashsieve explicitly does NOT guarantee
        // finding patterns that span boundaries UNLESS the caller uses overlapping reads or merges.
        // But if the pattern is FULLY contained in one block, it MUST be found.
        let pattern_end = actual_start + actual_len;
        if actual_start / 256 == (pattern_end - 1) / 256 {
            assert!(is_found, "Pattern strictly inside a block must be found");
        }
    }

    #[test]
    fn legendary_property_streaming_vs_contiguous(
        data in prop::collection::vec(any::<u8>(), 256..1024),
    ) {
        // Pad data to exact block size multiple
        let mut padded = data;
        let rem = padded.len() % 256;
        if rem != 0 {
            padded.extend(vec![0; 256 - rem]);
        }

        let builder = BlockIndexBuilder::new().block_size(256).bloom_bits(1024);
        let contiguous_index = builder.build(&padded).unwrap();

        let chunks: Vec<Vec<u8>> = padded.chunks(256).map(|c| c.to_vec()).collect();
        let streaming_index = builder.build_streaming(chunks.into_iter()).unwrap();

        assert_eq!(contiguous_index.to_bytes(), streaming_index.to_bytes());
    }

    #[test]
    fn legendary_property_serialization_roundtrip(
        data in prop::collection::vec(any::<u8>(), 256..1024),
    ) {
        let index = BlockIndexBuilder::new().block_size(256).bloom_bits(512).build(&data).unwrap();
        let serialized = index.to_bytes();
        let deserialized = flashsieve::BlockIndex::from_bytes_checked(&serialized).unwrap();

        assert_eq!(index.block_size(), deserialized.block_size());
        assert_eq!(index.block_count(), deserialized.block_count());
        assert_eq!(index.total_data_length(), deserialized.total_data_length());
    }
}
