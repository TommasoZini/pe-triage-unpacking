// sysinfo_debug_r2 - Rust build variant: DEBUG (cargo build).
use std::env;

fn main() {
    println!("=== build/target info ===");
    println!("target_os   : {}", env::consts::OS);
    println!("target_arch : {}", env::consts::ARCH);
    println!("family      : {}", env::consts::FAMILY);
    println!("exe_suffix  : '{}'", env::consts::EXE_SUFFIX);
    println!("pointer     : {} bit", usize::BITS);
    match env::current_exe() {
        Ok(p) => println!("current_exe : {}", p.display()),
        Err(e) => println!("current_exe : <err: {e}>"),
    }
    let cwd = env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
    println!("cwd         : {cwd}");
}
