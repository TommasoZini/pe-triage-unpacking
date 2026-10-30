// netjson_deps_r9 - Rust build variant: REAL DEPENDENCIES (serde + reqwest).
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;

#[derive(Debug, Deserialize)]
struct Todo {
    #[serde(rename = "userId")]
    user_id: u32,
    id: u32,
    title: String,
    completed: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| "https://jsonplaceholder.typicode.com/todos/1".to_string());

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client.get(&url).send()?;
    let status = resp.status();
    let body = resp.bytes()?;

    let mut hasher = Sha256::new();
    hasher.update(&body);
    let digest = hasher.finalize();

    let todo: Todo = serde_json::from_slice(&body)?;
    println!("status : {status}");
    println!("user   : {}", todo.user_id);
    println!("id     : {}", todo.id);
    println!("title  : {}", todo.title);
    println!("done   : {}", todo.completed);
    println!("sha256 : {}", hex::encode(digest));
    Ok(())
}
