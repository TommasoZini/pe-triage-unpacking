# build_rust.ps1 - builds the 10 Rust samples, each with its own profile variant.
# The profile (debug / release / opt-level=z+lto / panic=abort) is encoded in each
# crate's Cargo.toml, so the command is just the right profile flag.
# Output is copied to Build_Samples\out\rust\<name>.exe
# Requires: Rust toolchain (cargo). r9/r10 need network to fetch serde/reqwest.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$src  = Join-Path $root "rust"
$out  = Join-Path $root "out\rust"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# name -> "debug" or "release" (which target/<profile>/ dir the exe lands in)
$plan = [ordered]@{
    "greeter_debug_r1"     = "debug"    # debug
    "sysinfo_debug_r2"     = "debug"    # debug
    "rpncalc_release_r3"   = "release"  # release
    "textcipher_release_r4"= "release"  # release
    "filewalk_optz_r5"     = "release"  # release + opt-level=z + lto
    "primesieve_optz_r6"   = "release"  # release + opt-level=z + lto
    "crc_abort_r7"         = "release"  # panic=abort (release)
    "matrix_abort_r8"      = "release"  # panic=abort (release)
    "netjson_deps_r9"      = "release"  # real deps (serde, reqwest)
    "apiclient_deps_r10"   = "release"  # real deps (serde, reqwest)
}

foreach ($name in $plan.Keys) {
    $profile = $plan[$name]
    $dir = Join-Path $src $name
    Write-Host "==> $name ($profile)" -ForegroundColor Cyan
    Push-Location $dir
    try {
        if ($profile -eq "release") {
            & cargo build --release
        } else {
            & cargo build
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   FAILED" -ForegroundColor Red
        } else {
            $exe = Join-Path (Join-Path $dir "target\$profile") "$name.exe"
            $dst = Join-Path $out "$name.exe"
            Copy-Item $exe $dst -Force
            Write-Host "   -> $dst" -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
}
Write-Host "`nDone. Binaries in $out" -ForegroundColor Yellow
