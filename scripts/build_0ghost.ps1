$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    $DistDir = Join-Path $Root "dist"
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

    Write-Host "[1/3] Running GOOS=linux GOARCH=arm64 go vet..."
    $env:GOOS = "linux"
    $env:GOARCH = "arm64"
    $env:CGO_ENABLED = "0"
    go vet ./...

    Write-Host "[2/3] Building static linux/arm64 binary dist/0ghost-linux-arm64..."
    $BinOut = Join-Path $DistDir "0ghost-linux-arm64"
    go build -trimpath -ldflags="-s -w" -o $BinOut ./cmd/0ghost

    Write-Host "[3/3] Staging OpenWrt offline bundle dist/0ghost-istoreos-arm64.tar.gz..."
    $Stage = Join-Path $DistDir "_stage_0ghost"
    if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
    New-Item -ItemType Directory -Force -Path (Join-Path $Stage "usr/bin") | Out-Null
    Copy-Item $BinOut (Join-Path $Stage "usr/bin/0ghost")

    $PkgSrc = Join-Path $Root "openwrt/luci-app-0ghost"
    Copy-Item -Recurse -Force (Join-Path $PkgSrc "etc") $Stage
    Copy-Item -Recurse -Force (Join-Path $PkgSrc "usr/*") (Join-Path $Stage "usr")
    Copy-Item -Recurse -Force (Join-Path $PkgSrc "www") $Stage
    Copy-Item (Join-Path $PkgSrc "install-local.sh") (Join-Path $Stage "install-local.sh")

    # Ensure LF endings for all shell/JSON/JS files inside tarball
    Get-ChildItem -Recurse -File $Stage | Where-Object { $_.Extension -in ".sh",".js",".json","" -and $_.Name -ne "0ghost" } | ForEach-Object {
        $txt = [System.IO.File]::ReadAllText($_.FullName).Replace("`r`n", "`n")
        [System.IO.File]::WriteAllText($_.FullName, $txt, (New-Object System.Text.UTF8Encoding($false)))
    }

    $TarOut = Join-Path $DistDir "0ghost-istoreos-arm64.tar.gz"
    if (Test-Path $TarOut) { Remove-Item -Force $TarOut }
    tar -czf $TarOut -C $Stage .
    Remove-Item -Recurse -Force $Stage

    $binSize = [math]::Round((Get-Item $BinOut).Length / 1MB, 2)
    $tarSize = [math]::Round((Get-Item $TarOut).Length / 1MB, 2)
    Write-Host "[OK] Built dist/0ghost-linux-arm64 (${binSize} MB) and dist/0ghost-istoreos-arm64.tar.gz (${tarSize} MB)"
} finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}
