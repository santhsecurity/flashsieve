use flashsieve::{BlockIndex, BlockIndexBuilder, IncrementalBuilder, NgramBloom, NgramFilter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = vec![0xAB; 2048];
    let index = BlockIndexBuilder::new().block_size(1024).build(&data)?;
    let serialized = index.to_bytes();
    let new_data = vec![0xCD; 1024];
    let new_serialized = IncrementalBuilder::append_blocks(&serialized, &[&new_data])?;
    let updated = BlockIndex::from_bytes_checked(&new_serialized)?;

    // We can't access blooms directly, but we can serialize a single bloom and deserialize it.
    // Instead, let's just use candidate_blocks_ngram which uses maybe_contains_exact.
    let filter = NgramFilter::from_patterns(&[b"\xCD\xCD"]);
    let ngram_only = updated.candidate_blocks_ngram(&filter);
    println!("ngram candidates: {ngram_only:?}");

    // Let's also manually build a bloom and round-trip it.
    let bloom = NgramBloom::from_block(&new_data, 65536)?;
    println!(
        "before round-trip: maybe_contains_exact={}",
        bloom.maybe_contains_exact(0xCD, 0xCD)
    );
    let (num_bits, words, exact_pairs) = bloom.serialize_with_exact_pairs();
    let rt = NgramBloom::from_serialized_parts(
        num_bits,
        words.to_vec(),
        exact_pairs.map(|p| Box::new(*p)),
    )?;
    println!(
        "after round-trip: maybe_contains_exact={}",
        rt.maybe_contains_exact(0xCD, 0xCD)
    );
    Ok(())
}
