// greeter_debug_r1 - Rust build variant: DEBUG (cargo build).
use std::env;

fn factorial(n: u64) -> u128 {
    (1..=n as u128).product()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let name = if args.is_empty() {
        "world".to_string()
    } else {
        args.join(" ")
    };
    println!("Hello, {name}!");
    for i in 1..=12u64 {
        println!("{:2}! = {}", i, factorial(i));
    }
}
