// filewalk_optz_r5 - Rust build variant: RELEASE + opt-level="z" + lto=true.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

fn walk(dir: &Path, files: &mut u64, dirs: &mut u64, bytes: &mut u64, ext: &mut BTreeMap<String, u64>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            *dirs += 1;
            walk(&path, files, dirs, bytes, ext);
        } else {
            *files += 1;
            if let Ok(meta) = entry.metadata() {
                *bytes += meta.len();
            }
            let e = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| format!(".{s}"))
                .unwrap_or_else(|| "(none)".to_string());
            *ext.entry(e).or_insert(0) += 1;
        }
    }
}

fn main() {
    let root = env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let (mut files, mut dirs, mut bytes) = (0u64, 0u64, 0u64);
    let mut ext = BTreeMap::new();
    walk(Path::new(&root), &mut files, &mut dirs, &mut bytes, &mut ext);
    println!("root={root} dirs={dirs} files={files} bytes={bytes}");
    for (e, c) in ext {
        println!("  {e:<8} {c}");
    }
}
