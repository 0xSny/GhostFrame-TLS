param(
    [string]$TlsSource = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-TLS-main",
    [string]$ProTarget = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-Pro-Source",
    [string]$IosTarget = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-iOS",
    [string]$ZeroGhostTarget = "C:\Users\64520\Desktop\自研协议工作站\0Ghost-Source",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

$SharedCoreDirs = @(
    "internal\gft",
    "internal\gftrtc",
    "internal\netbind",
    "internal\client"
)
$SharedRootFiles = @(
    "go.mod",
    "go.sum",
    "LICENSE",
    "configs\client.example.json"
)

function Copy-ExactFile([string]$Src, [string]$Dst) {
    $parent = Split-Path -Parent $Dst
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $Src -Destination $Dst -Force
}

function Sync-SharedCoreIntoTarget {
    param(
        [string]$Name,
        [string]$TargetRoot,
        [string[]]$IncludeRootFiles,
        [string[]]$ProtectedExclusivePaths
    )

    if (-not (Test-Path -LiteralPath $TargetRoot)) {
        throw "Target repository directory not found: $TargetRoot"
    }

    # Record existence of product-exclusive directories/files before syncing to prove they are untouched.
    $beforeProtected = @{}
    foreach ($p in $ProtectedExclusivePaths) {
        $full = Join-Path $TargetRoot $p
        $beforeProtected[$p] = (Test-Path -LiteralPath $full)
    }

    $syncedFiles = New-Object 'System.Collections.Generic.List[string]'

    foreach ($dirRel in $SharedCoreDirs) {
        $srcDir = Join-Path $TlsSource $dirRel
        $dstDir = Join-Path $TargetRoot $dirRel
        if (-not (Test-Path -LiteralPath $srcDir)) {
            throw "Missing shared core directory in GhostFrame-TLS-main: $dirRel"
        }

        $expectedRelSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Get-ChildItem -LiteralPath $srcDir -Recurse -Force -File | ForEach-Object {
            $rel = $_.FullName.Substring($TlsSource.Length).TrimStart('\', '/')
            $null = $expectedRelSet.Add($rel)
            $syncedFiles.Add($rel)
            Copy-ExactFile $_.FullName (Join-Path $TargetRoot $rel)
        }

        # Prune stale files ONLY inside the shared core subtrees (never touching exclusive directories).
        if (Test-Path -LiteralPath $dstDir) {
            Get-ChildItem -LiteralPath $dstDir -Recurse -Force -File | ForEach-Object {
                $rel = $_.FullName.Substring($TargetRoot.Length).TrimStart('\', '/')
                if (-not $expectedRelSet.Contains($rel)) {
                    Remove-Item -LiteralPath $_.FullName -Force
                }
            }
        }
    }

    foreach ($fileRel in $IncludeRootFiles) {
        $srcFile = Join-Path $TlsSource $fileRel
        if (-not (Test-Path -LiteralPath $srcFile)) {
            throw "Missing shared file in GhostFrame-TLS-main: $fileRel"
        }
        $syncedFiles.Add($fileRel)
        Copy-ExactFile $srcFile (Join-Path $TargetRoot $fileRel)
    }

    # Verify exclusive paths remained intact and verify SHA-256 parity across all synced files.
    foreach ($p in $ProtectedExclusivePaths) {
        if ($beforeProtected[$p] -and -not (Test-Path -LiteralPath (Join-Path $TargetRoot $p))) {
            throw "Protected exclusive path disappeared after sync in ${Name}: $p"
        }
    }

    $mismatch = 0
    foreach ($rel in $syncedFiles) {
        $hSrc = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $TlsSource $rel)).Hash
        $hDst = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $TargetRoot $rel)).Hash
        if ($hSrc -ne $hDst) {
            Write-Error "SHA-256 mismatch in ${Name} for ${rel}: $hSrc vs $hDst"
            $mismatch++
        }
    }
    if ($mismatch -gt 0) {
        throw "SHA-256 parity check failed for ${Name}: mismatch=$mismatch"
    }

    return $syncedFiles.Count
}

if (-not (Test-Path -LiteralPath $TlsSource)) {
    throw "Source of truth GhostFrame-TLS-main does not exist: $TlsSource"
}

$cPro = Sync-SharedCoreIntoTarget -Name "GhostFrame-Pro-Source" -TargetRoot $ProTarget `
    -IncludeRootFiles $SharedRootFiles `
    -ProtectedExclusivePaths @("cmd\gft-client-gui", "internal\winui", ".github\workflows\build-client.yml")

$cIos = Sync-SharedCoreIntoTarget -Name "GhostFrame-iOS" -TargetRoot $IosTarget `
    -IncludeRootFiles @("go.mod", "go.sum", "LICENSE") `
    -ProtectedExclusivePaths @("ios", "mobile", "internal\tunstack", "tools\ios-repo-sync", ".github\workflows\ios-dual-ipa.yml")

$cZg = Sync-SharedCoreIntoTarget -Name "0Ghost-Source" -TargetRoot $ZeroGhostTarget `
    -IncludeRootFiles $SharedRootFiles `
    -ProtectedExclusivePaths @("cmd\0ghost", "internal\tproxy", "openwrt\luci-app-0ghost", "scripts\build_0ghost.ps1", ".github\workflows\build-0ghost.yml")

Write-Host ("CORE SYNC OK (SHA-256 100% matched from GhostFrame-TLS-main): Pro={0} files, iOS={1} files, 0Ghost={2} files." -f $cPro, $cIos, $cZg)

if (-not $SkipTests) {
    $env:GFT_NO_SYSPROXY = "1"
    $env:CGO_ENABLED = "0"

    Write-Host "[1/4] Verifying GhostFrame-TLS-main..."
    Push-Location $TlsSource
    try {
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "go vet failed in GhostFrame-TLS-main" }
        go test -count=1 ./...
        if ($LASTEXITCODE -ne 0) { throw "go test failed in GhostFrame-TLS-main" }
    } finally { Pop-Location }

    Write-Host "[2/4] Verifying GhostFrame-Pro-Source..."
    Push-Location $ProTarget
    try {
        go vet ./internal/... ./cmd/gft-client-gui
        if ($LASTEXITCODE -ne 0) { throw "go vet failed in GhostFrame-Pro-Source" }
        go test -count=1 ./internal/...
        if ($LASTEXITCODE -ne 0) { throw "go test failed in GhostFrame-Pro-Source" }
    } finally { Pop-Location }

    Write-Host "[3/4] Verifying GhostFrame-iOS..."
    Push-Location $IosTarget
    try {
        $env:GOOS = "darwin"; $env:GOARCH = "arm64"
        go vet ./internal/... ./mobile/...
        if ($LASTEXITCODE -ne 0) { throw "darwin go vet failed in GhostFrame-iOS" }
        Remove-Item Env:GOOS, Env:GOARCH
        go test -count=1 ./internal/netbind ./internal/tunstack ./mobile ./tools/gen-ios-icon ./tools/ios-repo-sync
        if ($LASTEXITCODE -ne 0) { throw "go test failed in GhostFrame-iOS" }
    } finally {
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Pop-Location
    }

    Write-Host "[4/4] Verifying 0Ghost-Source..."
    Push-Location $ZeroGhostTarget
    try {
        $env:GOOS = "linux"; $env:GOARCH = "arm64"
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "linux/arm64 go vet failed in 0Ghost-Source" }
        Remove-Item Env:GOOS, Env:GOARCH
        go test -count=1 ./...
        if ($LASTEXITCODE -ne 0) { throw "go test failed in 0Ghost-Source" }
    } finally {
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Pop-Location
    }

    Write-Host "ALL 4 REPOSITORIES SYNCED, HASH-VERIFIED & PASSED TESTS!"
}
