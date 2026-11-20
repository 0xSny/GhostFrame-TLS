param(
    [string]$MainSrc = "C:\Users\64520\Desktop\GhostFrame_Project",
    [string]$TlsWork = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-TLS-main",
    [string]$ProExeOut = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-Pro.exe"
)

$ErrorActionPreference = "Stop"

$ForbiddenNames = @(
    "client.json",
    "server.json",
    "0ghost.json",
    "sysproxy_backup.json",
    "deploy_record.json"
)
$ForbiddenExts = @(".exe", ".dll", ".syso", ".log", ".test", ".out", ".ipa")
$ForbiddenDirs = @("dist", "build", ".gft")
$IgnoredLocalDirs = @(".git", ".local", ".ios-dist")

function Assert-NoForbiddenFiles([string]$Root, [bool]$AllowDistInMain) {
    if (-not (Test-Path -LiteralPath $Root)) { return }
    Get-ChildItem -LiteralPath $Root -Recurse -Force | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length).TrimStart('\', '/')
        $segs = $rel -split '[\\/]'
        if ($IgnoredLocalDirs -contains $segs[0]) { return }
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
    if (-not (Test-Path -LiteralPath $parent)) {
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

if (-not (Test-Path -LiteralPath $TlsWork)) {
    New-Item -ItemType Directory -Path $TlsWork -Force | Out-Null
}

$expectedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
Get-ChildItem -LiteralPath $MainSrc -Recurse -Force -File | ForEach-Object {
    $rel = $_.FullName.Substring($MainSrc.Length).TrimStart('\', '/')
    $segs = $rel -split '[\\/]'
    if (($IgnoredLocalDirs -contains $segs[0]) -or ($ForbiddenDirs -contains $segs[0])) { return }
    $null = $expectedSet.Add($rel)
    Copy-ExactFile $_.FullName (Join-Path $TlsWork $rel)
}

Get-ChildItem -LiteralPath $TlsWork -Recurse -Force -File | ForEach-Object {
    $rel = $_.FullName.Substring($TlsWork.Length).TrimStart('\', '/')
    $segs = $rel -split '[\\/]'
    if ($segs[0] -eq ".git") { return }
    if (-not $expectedSet.Contains($rel)) {
        Remove-Item -LiteralPath $_.FullName -Force
    }
}
Remove-EmptyDirs $TlsWork

Assert-NoForbiddenFiles $TlsWork $false

$requiredWorkflows = @(
    ".github\workflows\ci.yml",
    ".github\workflows\build-client.yml",
    ".github\workflows\build-0ghost.yml",
    ".github\workflows\ios-dual-ipa.yml",
    ".github\workflows\release-dist.yml"
)
foreach ($wf in $requiredWorkflows) {
    if (-not (Test-Path -LiteralPath (Join-Path $TlsWork $wf))) {
        throw "Missing workflow in unified GhostFrame-TLS-main: $wf"
    }
}

$mismatch = 0
foreach ($rel in $expectedSet) {
    $hMain = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $MainSrc $rel)).Hash
    $hTls  = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $TlsWork $rel)).Hash
    if ($hMain -ne $hTls) {
        Write-Error "SHA-256 mismatch in GhostFrame-TLS-main for $rel ($hMain vs $hTls)"
        $mismatch++
    }
}
if ($mismatch -gt 0) {
    throw "Sync verification failed: mismatch=$mismatch"
}

$builtExe = Join-Path $MainSrc "dist\GhostFrame-Pro.exe"
if (Test-Path -LiteralPath $builtExe) {
    try {
        Copy-ExactFile $builtExe $ProExeOut
        Write-Host "Updated $ProExeOut ($((Get-Item $ProExeOut).Length) bytes)"
    } catch {
        Write-Warning "Skipped overwriting locked $ProExeOut (close running GhostFrame-Pro.exe to replace): $($_.Exception.Message)"
    }
}

Write-Host ("MONOREPO SYNC OK (SHA-256 100% match): GhostFrame-TLS-main={0} files, 5 isolated workflows verified." -f $expectedSet.Count)
