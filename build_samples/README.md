# Build_Samples — ground-truth benign binaries across toolchain variants

20 benign source programs (10 Go + 10 Rust) used to test the unpacking/packing
pipeline against different build configurations. Each program is functionally
distinct so the produced binaries have distinct content hashes.

Column layout requested: **left = Go, right = Rust**, different names on each side.

## Go (10) — `go/`

| # | Directory / name          | Build characteristic              | Build command |
|---|---------------------------|-----------------------------------|---------------|
| 1 | `hello_default_g1`        | build default                     | `go build` |
| 2 | `sysinfo_default_g2`      | build default                     | `go build` |
| 3 | `rpncalc_stripped_g3`     | stripped `-ldflags="-s -w"`       | `go build -ldflags "-s -w"` |
| 4 | `textcipher_stripped_g4`  | stripped `-ldflags="-s -w"`       | `go build -ldflags "-s -w"` |
| 5 | `filewalk_static_g5`      | pure static `CGO_ENABLED=0`       | `CGO_ENABLED=0 go build` |
| 6 | `primesieve_static_g6`    | pure static `CGO_ENABLED=0`       | `CGO_ENABLED=0 go build` |
| 7 | `crc_cgo_g7`              | `CGO_ENABLED=1` (uses `import "C"`) | `CGO_ENABLED=1 go build` (needs C compiler) |
| 8 | `mathstats_cgo_g8`       | `CGO_ENABLED=1` (libm via cgo)    | `CGO_ENABLED=1 go build` (needs C compiler) |
| 9 | `netjson_deps_g9`        | real deps: HTTP + JSON + crypto   | `go mod tidy && go build` |
|10 | `apiclient_deps_g10`     | real deps: HTTP + JSON + crypto   | `go mod tidy && go build` |

- g7/g8 genuinely exercise cgo (embedded C), so the resulting binary is a real
  cgo image — they require a C compiler on PATH (e.g. mingw-w64 `gcc`).
- g9/g10 use stdlib `net/http` + `encoding/json` + `crypto/*` plus the external
  module `github.com/google/uuid`, so they are true module builds.

## Rust (10) — `rust/`

The profile is encoded in each crate's own `Cargo.toml`.

| # | Directory / name          | Build characteristic                    | Build command |
|---|---------------------------|-----------------------------------------|---------------|
| 1 | `greeter_debug_r1`        | debug                                    | `cargo build` |
| 2 | `sysinfo_debug_r2`        | debug                                    | `cargo build` |
| 3 | `rpncalc_release_r3`      | release                                  | `cargo build --release` |
| 4 | `textcipher_release_r4`   | release                                  | `cargo build --release` |
| 5 | `filewalk_optz_r5`        | release + `opt-level="z"` + `lto=true`   | `cargo build --release` |
| 6 | `primesieve_optz_r6`      | release + `opt-level="z"` + `lto=true`   | `cargo build --release` |
| 7 | `crc_abort_r7`            | `panic = "abort"` (release)              | `cargo build --release` |
| 8 | `matrix_abort_r8`         | `panic = "abort"` (release)              | `cargo build --release` |
| 9 | `netjson_deps_r9`         | real deps: `serde` + `reqwest` (+`sha2`) | `cargo build --release` |
|10 | `apiclient_deps_r10`      | real deps: `serde` + `reqwest` (+`sha2`) | `cargo build --release` |

## Build everything

```powershell
# from Build_Samples\
.\build_rust.ps1     # -> out\rust\*.exe
.\build_go.ps1       # -> out\go\*.exe  (needs Go installed)
```

## Toolchain notes for THIS machine (checked 2026-09-24)

- `cargo` 1.98.1 present; host toolchain is **x86_64-pc-windows-gnu**.
- Rust r1–r8 build and run cleanly.
- Rust **r9/r10 fail** until a mingw-w64 toolchain is installed: reqwest pulls
  `windows-sys`, whose gnu build invokes `dlltool.exe`, which is missing.
  Fix (MSYS2): `pacman -S mingw-w64-x86_64-toolchain` (gives `gcc` + `dlltool`),
  or switch Rust to the MSVC toolchain (`x86_64-pc-windows-msvc` + VS Build Tools).
- **Go is not installed / not on PATH** — install Go to build g1–g10.
- Go **g7/g8 (cgo)** additionally need a C compiler (`gcc`); the same mingw-w64
  install above covers it.
