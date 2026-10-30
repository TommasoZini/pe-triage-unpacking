// primesieve_optz_r6 - Rust build variant: RELEASE + opt-level="z" + lto=true.
use std::env;

fn sieve(n: usize) -> Vec<usize> {
    if n < 2 {
        return Vec::new();
    }
    let mut composite = vec![false; n + 1];
    let mut primes = Vec::new();
    for i in 2..=n {
        if composite[i] {
            continue;
        }
        primes.push(i);
        let mut j = i * i;
        while j <= n {
            composite[j] = true;
            j += i;
        }
    }
    primes
}

fn main() {
    let limit: usize = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(100);
    let primes = sieve(limit);
    let sum: usize = primes.iter().sum();
    println!("primes up to {limit}: count={} sum={sum}", primes.len());
    if let Some(&last) = primes.last() {
        println!("largest={last}");
    }
}
