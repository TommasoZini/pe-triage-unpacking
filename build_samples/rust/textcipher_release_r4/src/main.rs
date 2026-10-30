// textcipher_release_r4 - Rust build variant: RELEASE (cargo build --release).
use std::env;

fn caesar(s: &str, shift: u8) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (b'A' + (c as u8 - b'A' + shift) % 26) as char,
            'a'..='z' => (b'a' + (c as u8 - b'a' + shift) % 26) as char,
            _ => c,
        })
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let text = if args.is_empty() { "The quick brown fox".to_string() } else { args.join(" ") };
    let shift = 3u8;
    let enc = caesar(&text, shift);
    println!("input : {text}");
    println!("words : {}", text.split_whitespace().count());
    println!("cipher: {enc}");
    println!("back  : {}", caesar(&enc, 26 - shift));
}
