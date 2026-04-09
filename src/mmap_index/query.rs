use super::views::{ByteHistogramRef, NgramBloomRef};
use super::MmapBlockIndex;
use crate::filter::{ByteFilter, NgramFilter};
use crate::index::CandidateRange;

pub(super) fn candidate_blocks(
    index: &MmapBlockIndex,
    byte_filter: &ByteFilter,
    ngram_filter: &NgramFilter,
) -> Vec<CandidateRange> {
    let paired_compact = byte_filter.compact_requirements();
    let paired_ngrams = ngram_filter.pattern_ngrams();
    let is_paired = paired_compact.len() == paired_ngrams.len();
    let use_exact = index
        .block_metas
        .first()
        .is_some_and(|meta| index.block_bloom(*meta).uses_exact_pairs());

    let block_count = index.block_metas.len();
    if block_count == 0 {
        return Vec::new();
    }

    let window_blocks = ngram_filter
        .max_pattern_bytes()
        .div_ceil(index.block_size)
        .max(1)
        .saturating_add(1);
    let mut seen = vec![false; block_count];

    for idx in 0..block_count {
        let block_meta = index.block_metas[idx];
        let histogram = index.block_histogram(block_meta.offset);
        let bloom = index.block_bloom(block_meta);

        let single_match = if is_paired {
            if use_exact {
                paired_compact
                    .iter()
                    .zip(paired_ngrams)
                    .any(|(required_bytes, ngrams)| {
                        required_bytes.iter().all(|&b| histogram.count(b) > 0)
                            && ngrams
                                .iter()
                                .all(|&(first, second)| bloom.maybe_contains_exact(first, second))
                    })
            } else {
                paired_compact
                    .iter()
                    .zip(paired_ngrams)
                    .any(|(required_bytes, ngrams)| {
                        required_bytes.iter().all(|&b| histogram.count(b) > 0)
                            && ngrams
                                .iter()
                                .all(|&(first, second)| bloom.maybe_contains_bloom(first, second))
                    })
            }
        } else {
            byte_filter_matches_histogram(byte_filter, histogram)
                && ngram_filter_matches_bloom(ngram_filter, bloom)
        };

        if single_match {
            seen[idx] = true;
        }

        if idx == 0 {
            continue;
        }

        let prev_meta = index.block_metas[idx - 1];
        let prev_histogram = index.block_histogram(prev_meta.offset);
        let prev_bloom = index.block_bloom(prev_meta);

        let pair_match = if is_paired {
            if use_exact {
                paired_compact
                    .iter()
                    .zip(paired_ngrams)
                    .any(|(required_bytes, ngrams)| {
                        required_bytes
                            .iter()
                            .all(|&b| histogram.count(b) > 0 || prev_histogram.count(b) > 0)
                            && ngrams.iter().all(|&(first, second)| {
                                bloom.maybe_contains_exact(first, second)
                                    || prev_bloom.maybe_contains_exact(first, second)
                            })
                    })
            } else {
                paired_compact
                    .iter()
                    .zip(paired_ngrams)
                    .any(|(required_bytes, ngrams)| {
                        required_bytes
                            .iter()
                            .all(|&b| histogram.count(b) > 0 || prev_histogram.count(b) > 0)
                            && ngrams.iter().all(|&(first, second)| {
                                bloom.maybe_contains_bloom(first, second)
                                    || prev_bloom.maybe_contains_bloom(first, second)
                            })
                    })
            }
        } else {
            byte_filter_matches_histogram_pair(byte_filter, prev_histogram, histogram)
                && ngram_filter_matches_bloom_pair(ngram_filter, prev_bloom, bloom)
        };

        if pair_match {
            seen[idx - 1] = true;
            seen[idx] = true;
            continue;
        }

        // Multi-block window fallback for patterns spanning 3+ blocks
        let earliest_start = idx.saturating_sub(window_blocks - 1);
        for window_start in earliest_start..idx.saturating_sub(1) {
            let end = idx + 1;
            let h_refs: Vec<_> = (window_start..end)
                .map(|i| index.block_histogram(index.block_metas[i].offset))
                .collect();
            let b_refs: Vec<_> = (window_start..end)
                .map(|i| index.block_bloom(index.block_metas[i]))
                .collect();

            let multi_match = if is_paired {
                if use_exact {
                    paired_compact
                        .iter()
                        .zip(paired_ngrams)
                        .any(|(required_bytes, ngrams)| {
                            required_bytes
                                .iter()
                                .all(|&b| h_refs.iter().any(|h| h.count(b) > 0))
                                && ngrams.iter().all(|&(first, second)| {
                                    b_refs
                                        .iter()
                                        .any(|bloom| bloom.maybe_contains_exact(first, second))
                                })
                        })
                } else {
                    paired_compact
                        .iter()
                        .zip(paired_ngrams)
                        .any(|(required_bytes, ngrams)| {
                            required_bytes
                                .iter()
                                .all(|&b| h_refs.iter().any(|h| h.count(b) > 0))
                                && ngrams.iter().all(|&(first, second)| {
                                    b_refs
                                        .iter()
                                        .any(|bloom| bloom.maybe_contains_bloom(first, second))
                                })
                        })
                }
            } else {
                byte_filter_matches_histogram_multi(byte_filter, &h_refs)
                    && ngram_filter_matches_bloom_multi(ngram_filter, &b_refs)
            };

            if multi_match {
                for item in seen.iter_mut().take(end).skip(window_start) {
                    *item = true;
                }
                break;
            }
        }
    }

    let mut results = Vec::new();
    for (idx, is_seen) in seen.into_iter().enumerate() {
        if is_seen {
            if let Some(c) = index.candidate_for_index(idx) {
                results.push(c);
            }
        }
    }
    crate::BlockIndex::merge_adjacent(&results)
}

fn byte_filter_matches_histogram(filter: &ByteFilter, histogram: ByteHistogramRef<'_>) -> bool {
    if filter.compact_requirements().is_empty() {
        return false;
    }

    filter
        .compact_requirements()
        .iter()
        .any(|required_bytes| required_bytes.iter().all(|&byte| histogram.count(byte) > 0))
}

fn byte_filter_matches_histogram_pair(
    filter: &ByteFilter,
    h1: ByteHistogramRef<'_>,
    h2: ByteHistogramRef<'_>,
) -> bool {
    let requirements = filter.compact_requirements();
    if requirements.is_empty() {
        return false;
    }
    requirements.iter().any(|required_bytes| {
        required_bytes
            .iter()
            .all(|&b| h1.count(b) > 0 || h2.count(b) > 0)
    })
}

fn byte_filter_matches_histogram_multi(
    filter: &ByteFilter,
    histograms: &[ByteHistogramRef<'_>],
) -> bool {
    let requirements = filter.compact_requirements();
    if requirements.is_empty() {
        return false;
    }
    requirements.iter().any(|required_bytes| {
        required_bytes
            .iter()
            .all(|&b| histograms.iter().any(|h| h.count(b) > 0))
    })
}

fn ngram_filter_matches_bloom_pair(
    filter: &NgramFilter,
    b1: NgramBloomRef<'_>,
    b2: NgramBloomRef<'_>,
) -> bool {
    let ngrams_list = filter.pattern_ngrams();
    if ngrams_list.is_empty() {
        return false;
    }

    if b1.uses_exact_pairs() && b2.uses_exact_pairs() {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                b1.maybe_contains_exact(first, second) || b2.maybe_contains_exact(first, second)
            })
        })
    } else {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                b1.maybe_contains_bloom(first, second) || b2.maybe_contains_bloom(first, second)
            })
        })
    }
}

fn ngram_filter_matches_bloom_multi(filter: &NgramFilter, blooms: &[NgramBloomRef<'_>]) -> bool {
    let ngrams_list = filter.pattern_ngrams();
    if ngrams_list.is_empty() {
        return false;
    }

    let use_exact = blooms.first().is_some_and(NgramBloomRef::uses_exact_pairs);
    if use_exact {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                blooms
                    .iter()
                    .any(|bloom| bloom.maybe_contains_exact(first, second))
            })
        })
    } else {
        ngrams_list.iter().any(|ngrams| {
            ngrams.iter().all(|&(first, second)| {
                blooms
                    .iter()
                    .any(|bloom| bloom.maybe_contains_bloom(first, second))
            })
        })
    }
}

fn ngram_filter_matches_bloom(filter: &NgramFilter, bloom: NgramBloomRef<'_>) -> bool {
    if filter.pattern_ngrams().is_empty() {
        return false;
    }

    // Fast early rejection: check union n-grams first (O(union_size) vs O(patterns × ngrams))
    let union_ngrams = filter.union_ngrams();
    if !union_ngrams.is_empty() && !bloom.maybe_contains_any(union_ngrams) {
        return false;
    }

    if bloom.uses_exact_pairs() {
        filter.pattern_ngrams().iter().any(|ngrams| {
            ngrams
                .iter()
                .all(|&(first, second)| bloom.maybe_contains_exact(first, second))
        })
    } else {
        filter.pattern_ngrams().iter().any(|ngrams| {
            ngrams
                .iter()
                .all(|&(first, second)| bloom.maybe_contains_bloom(first, second))
        })
    }
}
