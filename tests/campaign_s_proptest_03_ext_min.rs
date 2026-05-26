use flashsieve::NgramBloom;
use proptest::prelude::*;

fn bloom_size_strategy() -> impl Strategy<Value = usize> {
    prop_oneof![Just(64usize), 128usize..=1024]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn smoke(block in prop::collection::vec(any::<u8>(), 0..32), size in bloom_size_strategy()) {
        let _ = NgramBloom::new(size);
        let _ = block;
    }
}
