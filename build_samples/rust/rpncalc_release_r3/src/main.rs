// rpncalc_release_r3 - Rust build variant: RELEASE (cargo build --release).
use std::env;

fn eval_rpn(tokens: &[&str]) -> Result<f64, String> {
    let mut st: Vec<f64> = Vec::new();
    for &t in tokens {
        match t {
            "+" | "-" | "*" | "/" => {
                let b = st.pop().ok_or("stack underflow")?;
                let a = st.pop().ok_or("stack underflow")?;
                st.push(match t {
                    "+" => a + b,
                    "-" => a - b,
                    "*" => a * b,
                    _ => a / b,
                });
            }
            n => st.push(n.parse::<f64>().map_err(|_| format!("bad token {n:?}"))?),
        }
    }
    if st.len() != 1 {
        return Err("malformed expression".into());
    }
    Ok(st[0])
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let expr = if args.is_empty() { "3 4 + 5 *".to_string() } else { args.join(" ") };
    let tokens: Vec<&str> = expr.split_whitespace().collect();
    match eval_rpn(&tokens) {
        Ok(v) => println!("{expr} = {v}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
