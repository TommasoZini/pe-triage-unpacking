# build_go.ps1 - builds the 10 Go samples, each with its own toolchain variant.
# Output goes to Build_Samples\out\go\<name>.exe
# Requires: Go toolchain. Samples g7/g8 (cgo) require a C compiler (e.g. mingw gcc).
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$src  = Join-Path $root "go"
$out  = Join-Path $root "out\go"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# name -> @{ cgo = "0"/"1"/""(default); ldflags = "..."; tidy = $true/$false }
$plan = [ordered]@{
    "hello_default_g1"     = @{ cgo = "";  ldflags = "";        tidy = $false }  # default
    "sysinfo_default_g2"   = @{ cgo = "";  ldflags = "";        tidy = $false }  # default
    "rpncalc_stripped_g3"  = @{ cgo = "";  ldflags = "-s -w";   tidy = $false }  # stripped
    "textcipher_stripped_g4" = @{ cgo = ""; ldflags = "-s -w";  tidy = $false }  # stripped
    "filewalk_static_g5"   = @{ cgo = "0"; ldflags = "";        tidy = $false }  # CGO_ENABLED=0
    "primesieve_static_g6" = @{ cgo = "0"; ldflags = "";        tidy = $false }  # CGO_ENABLED=0
    "crc_cgo_g7"           = @{ cgo = "1"; ldflags = "";        tidy = $false }  # CGO_ENABLED=1
    "mathstats_cgo_g8"     = @{ cgo = "1"; ldflags = "";        tidy = $false }  # CGO_ENABLED=1
    "netjson_deps_g9"      = @{ cgo = "";  ldflags = "";        tidy = $true  }  # real deps
    "apiclient_deps_g10"   = @{ cgo = "";  ldflags = "";        tidy = $true  }  # real deps
}

foreach ($name in $plan.Keys) {
    $cfg = $plan[$name]
    $dir = Join-Path $src $name
    Write-Host "==> $name (CGO='$($cfg.cgo)' ldflags='$($cfg.ldflags)')" -ForegroundColor Cyan
    Push-Location $dir
    try {
        if ($cfg.cgo -ne "") { $env:CGO_ENABLED = $cfg.cgo } else { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue }
        if ($cfg.tidy) { & go mod tidy }
        $exe = Join-Path $out "$name.exe"
        if ($cfg.ldflags -ne "") {
            & go build -trimpath=false -ldflags "$($cfg.ldflags)" -o $exe .
        } else {
            & go build -o $exe .
        }
        if ($LASTEXITCODE -ne 0) { Write-Host "   FAILED" -ForegroundColor Red } else { Write-Host "   -> $exe" -ForegroundColor Green }
    } finally {
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
        Pop-Location
    }
}
Write-Host "`nDone. Binaries in $out" -ForegroundColor Yellow
