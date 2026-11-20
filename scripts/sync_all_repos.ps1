param(
    [string]$TlsSource = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-TLS-main",
    [string]$ProTarget = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-Pro-Source",
    [string]$IosTarget = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-iOS",
    [string]$ZeroGhostTarget = "C:\Users\64520\Desktop\自研协议工作站\0Ghost-Source",
    [string]$MainMonorepo = "C:\Users\64520\Desktop\GhostFrame_Project",
    [switch]$SkipTests,
    [switch]$UpdateN1
)

$ErrorActionPreference = "Stop"

$SharedCoreDirs = @(
    "internal\gft",
    "internal\gftrtc",
    "internal\netbind",
    "internal\client"
)
$SharedModuleFiles = @(
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
    -IncludeRootFiles $SharedModuleFiles `
    -ProtectedExclusivePaths @("cmd\gft-client-gui", "internal\winui", "go.mod", "go.sum", ".github\workflows\build-client.yml")

$cIos = Sync-SharedCoreIntoTarget -Name "GhostFrame-iOS" -TargetRoot $IosTarget `
    -IncludeRootFiles @("LICENSE") `
    -ProtectedExclusivePaths @("ios", "mobile", "internal\tunstack", "tools\ios-repo-sync", "go.mod", "go.sum", ".github\workflows\ios-dual-ipa.yml")

$cZg = Sync-SharedCoreIntoTarget -Name "0Ghost-Source" -TargetRoot $ZeroGhostTarget `
    -IncludeRootFiles $SharedModuleFiles `
    -ProtectedExclusivePaths @("cmd\0ghost", "internal\tproxy", "openwrt\luci-app-0ghost", "scripts\build_0ghost.ps1", "go.mod", "go.sum", ".github\workflows\build-0ghost.yml")

foreach ($noGvisorRepo in @($TlsSource, $ProTarget, $ZeroGhostTarget)) {
    if (Select-String -Path (Join-Path $noGvisorRepo "go.mod") -Pattern "gvisor\.dev/gvisor" -Quiet) {
        throw "Unexpected gvisor.dev/gvisor dependency in $noGvisorRepo\go.mod"
    }
}

Write-Host ("CORE SYNC OK (SHA-256 100% matched from GhostFrame-TLS-main): Pro={0} files, iOS={1} files, 0Ghost={2} files." -f $cPro, $cIos, $cZg)

if (-not $SkipTests) {
    $env:GFT_NO_SYSPROXY = "1"
    $gccCmd = Get-Command gcc -ErrorAction SilentlyContinue
    if (-not $gccCmd) {
        foreach ($cand in @("C:\msys64\mingw64\bin", "C:\msys64\ucrt64\bin", "C:\mingw64\bin")) {
            if (Test-Path (Join-Path $cand "gcc.exe")) {
                $env:PATH = "$cand;$env:PATH"
                $gccCmd = Get-Command gcc -ErrorAction SilentlyContinue
                break
            }
        }
    }
    $hasGcc = ($null -ne $gccCmd)

    Write-Host "[1/4] Verifying GhostFrame-TLS-main (vet + early-close/watchdog + unit tests)..."
    Push-Location $TlsSource
    try {
        $env:CGO_ENABLED = "0"
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "go vet failed in GhostFrame-TLS-main" }
        if ($hasGcc) {
            $env:CGO_ENABLED = "1"
            go test -race -count=1 -run "TestEarlyCloseStreamReleasesSessionWindowAndDedup|TestWatchdogDoesNotKillIdleSessionAndClearsOnInbound" ./internal/gftrtc
            if ($LASTEXITCODE -ne 0) { throw "gftrtc -race tests failed in GhostFrame-TLS-main" }
        } else {
            Write-Host "  [note] gcc unavailable on host; running CGO_ENABLED=0 TestEarlyCloseStream + TestWatchdog"
            go test -count=1 -run "TestEarlyCloseStreamReleasesSessionWindowAndDedup|TestWatchdogDoesNotKillIdleSessionAndClearsOnInbound" ./internal/gftrtc
            if ($LASTEXITCODE -ne 0) { throw "gftrtc early-close/watchdog tests failed in GhostFrame-TLS-main" }
        }
        $env:CGO_ENABLED = "0"
        go test -count=1 ./internal/client ./internal/gft ./internal/netbind ./internal/qr ./internal/server ./internal/sni ./internal/tui
        if ($LASTEXITCODE -ne 0) { throw "go test failed in GhostFrame-TLS-main" }
    } finally { Pop-Location }

    Write-Host "[2/4] Verifying GhostFrame-Pro-Source..."
    Push-Location $ProTarget
    try {
        $env:CGO_ENABLED = "0"
        go vet ./internal/... ./cmd/gft-client-gui
        if ($LASTEXITCODE -ne 0) { throw "go vet failed in GhostFrame-Pro-Source" }
        go test -count=1 ./internal/client ./internal/gft ./internal/netbind ./internal/winui
        if ($LASTEXITCODE -ne 0) { throw "go test failed in GhostFrame-Pro-Source" }
    } finally { Pop-Location }

    Write-Host "[3/4] Verifying GhostFrame-iOS..."
    Push-Location $IosTarget
    try {
        $env:GOOS = "darwin"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
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

    Write-Host "[4/4] Verifying 0Ghost-Source (linux/arm64 vet + ProbeDualConnectivity + unit tests)..."
    Push-Location $ZeroGhostTarget
    try {
        $env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "linux/arm64 go vet failed in 0Ghost-Source" }
        Remove-Item Env:GOOS, Env:GOARCH
        if ($hasGcc) {
            $env:CGO_ENABLED = "1"
            go test -race -count=1 ./internal/tproxy ./cmd/0ghost
        } else {
            $env:CGO_ENABLED = "0"
            go test -count=1 ./internal/tproxy ./cmd/0ghost
        }
        if ($LASTEXITCODE -ne 0) { throw "0Ghost tests failed in 0Ghost-Source" }
    } finally {
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
        Pop-Location
    }

    Write-Host "ALL 4 REPOSITORIES SYNCED, HASH-VERIFIED & PASSED TESTS!"
}

if ($UpdateN1) {
    $sshTool = Join-Path $MainMonorepo ".local\n1_ssh.exe"
    if (Test-Path -LiteralPath $sshTool) {
        $binTmp = Join-Path $env:TEMP "0ghost-linux-arm64"
        Push-Location $ZeroGhostTarget
        try {
            $env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
            go build -trimpath -ldflags="-s -w" -o $binTmp ./cmd/0ghost
            if ($LASTEXITCODE -ne 0) { throw "0ghost build failed" }
        } finally {
            Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
            Pop-Location
        }
        Push-Location $MainMonorepo
        try {
            & $sshTool -put $binTmp -to "/usr/bin/0ghost" -mode "0755"
            & $sshTool -cmd "/etc/init.d/0ghost restart && sleep 3 && /etc/init.d/0ghost status"
        } finally {
            Pop-Location
            Remove-Item $binTmp -ErrorAction SilentlyContinue
        }
    }
}
