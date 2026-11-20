//! Dependency-free deterministic mutation fuzzing; not coverage-guided fuzzing.
use sifr_inflate::{decompress_gzip, decompress_gzip_reader, inflate_raw};

const FIXED: &[u8] = include_bytes!("fixtures/fixed.gz");
const DYNAMIC: &[u8] = include_bytes!("fixtures/dynamic.gz");

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(20_000);
    let mut state = 0x51f1_2d3e_a4b5_c697;
    let seed = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x01\x05\x00\xfa\xffhello\x86\xa6\x10\x36\x05\x00\x00\x00";
    assert_eq!(decompress_gzip(FIXED, 4096).unwrap().len(), 2576);
    assert_eq!(decompress_gzip(DYNAMIC, 4096).unwrap().len(), 2181);
    for iteration in 0..iterations {
        let source = match iteration % 4 {
            0 => seed.as_slice(),
            1 => FIXED,
            2 => DYNAMIC,
            _ => &[],
        };
        let size = (next(&mut state) as usize) % 128;
        let mut data = if source.is_empty() {
            vec![0u8; size]
        } else {
            source.to_vec()
        };
        for _ in 0..(next(&mut state) % 8) {
            if !data.is_empty() {
                let index = (next(&mut state) as usize) % data.len();
                data[index] ^= next(&mut state) as u8;
            }
        }
        if next(&mut state) & 1 != 0 && !data.is_empty() {
            data.truncate((next(&mut state) as usize) % data.len());
        }
        let _ = decompress_gzip(&data, 1024);
        let _ = decompress_gzip_reader(&data[..], 1024, 4096);
        let _ = inflate_raw(&data, 1024);
    }
    println!("PASS {iterations} deterministic arbitrary/mutation inputs (seed 0x51f12d3ea4b5c697)");
}
