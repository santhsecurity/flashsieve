#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use flashsieve::BlockIndexBuilder;
use std::sync::{Arc, Mutex};
use std::thread;

#[test]
fn test_multi_writer_append_to_shared_state() {
    // Though flashsieve structures are mostly immutable, if users share an IncrementalBuilder
    // behind a mutex, it must not corrupt data.
    let shared_data = Arc::new(Mutex::new(Vec::new()));

    let mut handles = vec![];
    for i in 0..10 {
        let data = Arc::clone(&shared_data);
        handles.push(thread::spawn(move || {
            let chunk = vec![u8::try_from(i).unwrap(); 1024];
            let mut guard = data.lock().unwrap();
            guard.extend_from_slice(&chunk);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let final_data = shared_data.lock().unwrap();
    assert_eq!(final_data.len(), 10240);

    let index = BlockIndexBuilder::new()
        .block_size(1024)
        .build(&final_data)
        .unwrap();
    assert_eq!(index.block_count(), 10);
}
