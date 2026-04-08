use flashsieve::{BlockIndexBuilder, ByteFilter, ByteHistogram};

fn main() {
    let block_size = 256;
    let pattern = b"boundary";
    let mut data = vec![b'x'; block_size * 3];
    let offset1 = block_size - 2;
    let offset2 = block_size * 2 - 3;
    data[offset1..offset1 + pattern.len()].copy_from_slice(pattern);
    data[offset2..offset2 + pattern.len()].copy_from_slice(pattern);

    let index = BlockIndexBuilder::new()
        .block_size(block_size)
        .bloom_bits(1024)
        .build(&data)
        .unwrap();

    let bf = ByteFilter::from_patterns(&[pattern.as_slice()]);
    
    for i in 0..3 {
        let start = i * block_size;
        let block = &data[start..(start+block_size).min(data.len())];
        let hist = ByteHistogram::from_block(block);
        println!("block {} matches_histogram={} bytes=b:{} o:{} u:{} n:{} d:{} a:{} r:{} y:{}",
            i,
            bf.matches_histogram(&hist),
            hist.count(b'b'),
            hist.count(b'o'),
            hist.count(b'u'),
            hist.count(b'n'),
            hist.count(b'd'),
            hist.count(b'a'),
            hist.count(b'r'),
            hist.count(b'y'),
        );
    }
    
    println!("byte candidates: {:?}", index.candidate_blocks_byte(&bf));
}
