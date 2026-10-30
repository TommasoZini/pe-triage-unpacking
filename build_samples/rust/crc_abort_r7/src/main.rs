// crc_abort_r7 - Rust build variant: panic = "abort" (release profile).
use std::env;

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let msg = if args.is_empty() { "abort-profile sample".to_string() } else { args.join(" ") };
    println!("input : {msg:?}");
    println!("crc32 : 0x{:08X}", crc32(msg.as_bytes()));
}
