param(
    [string]$MainSrc = "C:\Users\64520\Desktop\GhostFrame_Project",
    [string]$TlsWork = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-TLS-main",
    [string]$ProWork = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-Pro-Source",
    [string]$ProExeOut = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-Pro.exe"
)

$ErrorActionPreference = "Stop"

$ForbiddenNames = @(
    "client.json",
    "server.json",
    "sysproxy_backup.json",
    "deploy_record.json"
)
$ForbiddenExts = @(".exe", ".dll", ".syso", ".log", ".test", ".out")
$ForbiddenDirs = @("dist", "build", ".gft")

function Assert-NoForbiddenFiles([string]$Root, [bool]$AllowDistInMain) {
    if (-not (Test-Path $Root)) { return }
    Get-ChildItem -LiteralPath $Root -Recurse -Force | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length).TrimStart('\', '/')
        $segs = $rel -split '[\\/]'
        if ($segs[0] -eq ".git") { return }
        if ($AllowDistInMain -and $segs[0] -eq "dist") { return }
        if ($_.PSIsContainer) {
            if ($ForbiddenDirs -contains $_.Name) {
                throw "Forbidden runtime/build directory found in ${Root}: $rel"
            }
            return
        }
        $nameLower = $_.Name.ToLowerInvariant()
        if ($ForbiddenNames -contains $nameLower) {
            throw "Forbidden secret/runtime file found in ${Root}: $rel"
        }
        if ($ForbiddenExts -contains $_.Extension.ToLowerInvariant()) {
            throw "Forbidden binary/log artifact found in ${Root}: $rel"
        }
    }
}

function Copy-ExactFile([string]$SrcFile, [string]$DstFile) {
    $parent = Split-Path -Parent $DstFile
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $SrcFile -Destination $DstFile -Force
}

function Remove-EmptyDirs([string]$Root) {
    Get-ChildItem -LiteralPath $Root -Recurse -Force -Directory |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object {
            if (@(Get-ChildItem -LiteralPath $_.FullName -Force).Count -eq 0) {
                Remove-Item -LiteralPath $_.FullName -Force
            }
        }
}

Assert-NoForbiddenFiles $MainSrc $true

# 1. Mirror GhostFrame_Project -> GhostFrame-TLS-main (excluding .git & dist)
if (-not (Test-Path $TlsWork)) {
    New-Item -ItemType Directory -Path $TlsWork -Force | Out-Null
}
$mainRelSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
Get-ChildItem -LiteralPath $MainSrc -Recurse -Force -File | ForEach-Object {
    $rel = $_.FullName.Substring($MainSrc.Length).TrimStart('\', '/')
    $segs = $rel -split '[\\/]'
    if ($segs[0] -eq ".git" -or $segs[0] -eq "dist" -or $segs[0] -eq "build" -or $segs[0] -eq ".gft") { return }
    $null = $mainRelSet.Add($rel)
    Copy-ExactFile $_.FullName (Join-Path $TlsWork $rel)
}
Get-ChildItem -LiteralPath $TlsWork -Recurse -Force -File | ForEach-Object {
    $rel = $_.FullName.Substring($TlsWork.Length).TrimStart('\', '/')
    if (-not $mainRelSet.Contains($rel)) {
        Remove-Item -LiteralPath $_.FullName -Force
    }
}
Remove-EmptyDirs $TlsWork

# 2. Mirror shared client tree -> GhostFrame-Pro-Source (preserving Pro-exclusive files)
if (-not (Test-Path $ProWork)) {
    New-Item -ItemType Directory -Path $ProWork -Force | Out-Null
}
$SharedDirs = @(
    "internal\gftrtc",
    "internal\gft",
    "internal\client",
    "internal\winui",
    "cmd\gft-client-gui"
)
$SharedSingleFiles = @(
    "configs\client.example.json",
    "go.mod",
    "go.sum",
    "LICENSE"
)
$ProReservedFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
@(
    ".gitignore",
    "README.md",
    ".github\workflows\build-client.yml"
) | ForEach-Object { $null = $ProReservedFiles.Add($_) }

foreach ($rf in $ProReservedFiles) {
    $p = Join-Path $ProWork $rf
    if (-not (Test-Path $p)) {
        throw "Missing client-exclusive file in GhostFrame-Pro-Source: $rf"
    }
}

$sharedRelList = New-Object 'System.Collections.Generic.List[string]'
foreach ($d in $SharedDirs) {
    $dirPath = Join-Path $MainSrc $d
    if (-not (Test-Path $dirPath)) {
        throw "Missing shared dir in main repo: $d"
    }
    Get-ChildItem -LiteralPath $dirPath -Recurse -Force -File | ForEach-Object {
        $rel = $_.FullName.Substring($MainSrc.Length).TrimStart('\', '/')
        $sharedRelList.Add($rel)
    }
}
foreach ($f in $SharedSingleFiles) {
    $fp = Join-Path $MainSrc $f
    if (-not (Test-Path $fp)) {
        throw "Missing shared file in main repo: $f"
    }
    $sharedRelList.Add($f)
}

$proAllowedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($rf in $ProReservedFiles) { $null = $proAllowedSet.Add($rf) }
foreach ($rel in $sharedRelList) {
    $null = $proAllowedSet.Add($rel)
    Copy-ExactFile (Join-Path $MainSrc $rel) (Join-Path $ProWork $rel)
}

Get-ChildItem -LiteralPath $ProWork -Recurse -Force -File | ForEach-Object {
    $rel = $_.FullName.Substring($ProWork.Length).TrimStart('\', '/')
    if (-not $proAllowedSet.Contains($rel)) {
        Remove-Item -LiteralPath $_.FullName -Force
    }
}
Remove-EmptyDirs $ProWork

# 3. Verify zero forbidden files in both workstation repos
Assert-NoForbiddenFiles $TlsWork $false
Assert-NoForbiddenFiles $ProWork $false

# 4. Verify 100% SHA-256 byte-level parity across all mirrored & shared files
$fullMismatch = 0
foreach ($rel in $mainRelSet) {
    $hMain = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $MainSrc $rel)).Hash
    $hTls  = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $TlsWork $rel)).Hash
    if ($hMain -ne $hTls) {
        Write-Error "SHA-256 mismatch in TLS-main for $rel ($hMain vs $hTls)"
        $fullMismatch++
    }
}

$sharedMismatch = 0
foreach ($rel in $sharedRelList) {
    $hMain = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $MainSrc $rel)).Hash
    $hTls  = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $TlsWork $rel)).Hash
    $hPro  = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ProWork $rel)).Hash
    if ($hMain -ne $hTls -or $hMain -ne $hPro) {
        Write-Error "SHA-256 mismatch in shared client file $rel ($hMain / $hTls / $hPro)"
        $sharedMismatch++
    }
}

if ($fullMismatch -gt 0 -or $sharedMismatch -gt 0) {
    throw "Sync verification failed: fullMismatch=$fullMismatch sharedMismatch=$sharedMismatch"
}

# 5. Copy rebuilt Windows client executable to workstation root if built
$builtExe = Join-Path $MainSrc "dist\GhostFrame-Pro.exe"
if (Test-Path $builtExe) {
    Copy-ExactFile $builtExe $ProExeOut
    Write-Host "Updated $ProExeOut ($((Get-Item $ProExeOut).Length) bytes)"
}

Write-Host "SYNC OK: GhostFrame-TLS-main=$($mainRelSet.Count) files (SHA-256 100% match), GhostFrame-Pro-Source shared=$($sharedRelList.Count) files (SHA-256 100% match across all 3 trees)."
