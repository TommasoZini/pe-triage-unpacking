// apiclient_deps_r10 - Rust build variant: REAL DEPENDENCIES (serde + reqwest).
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;

#[derive(Debug, Serialize)]
struct Event {
    id: String,
    kind: String,
    payload: String,
    checksum: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload = "hello from apiclient".to_string();
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let checksum = hex::encode(hasher.finalize());

    let ev = Event {
        id: format!("evt-{}", &checksum[..8]),
        kind: "sample".to_string(),
        payload,
        checksum,
    };
    let json = serde_json::to_string_pretty(&ev)?;
    println!("payload:\n{json}");

    let url = env::args().nth(1).unwrap_or_else(|| "https://httpbin.org/post".to_string());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    match client.post(&url).json(&ev).send() {
        Ok(resp) => println!("post status: {}", resp.status()),
        Err(e) => eprintln!("post skipped (offline?): {e}"),
    }
    Ok(())
}
