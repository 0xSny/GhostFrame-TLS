param(
    [string]$MainSrc = "C:\Users\64520\Desktop\GhostFrame_Project",
    [string]$TlsWork = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-TLS-main",
    [string]$ProWork = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-Pro-Source",
    [string]$ZeroGhostWork = "C:\Users\64520\Desktop\自研协议工作站\0Ghost-Source",
    [string]$IosWork = "C:\Users\64520\Desktop\自研协议工作站\GhostFrame-iOS",
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
    if (-not (Test-Path $Root)) { return }
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

function Assert-NoDisallowedPaths([string]$Root, [string]$Label, [string[]]$DisallowedPrefixes) {
    foreach ($prefix in $DisallowedPrefixes) {
        $target = Join-Path $Root $prefix
        if (Test-Path -LiteralPath $target) {
            throw "Cross-product contamination in ${Label}: disallowed path still exists: $prefix"
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

function Sync-ProductWorkspace {
    param(
        [string]$Label,
        [string]$DstRoot,
        [string[]]$Dirs,
        [string[]]$Files,
        [string[]]$ReservedFiles,
        [string[]]$DisallowedPrefixes
    )

    if (-not (Test-Path $DstRoot)) {
        New-Item -ItemType Directory -Path $DstRoot -Force | Out-Null
    }

    $reservedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rf in $ReservedFiles) {
        $null = $reservedSet.Add($rf)
        $p = Join-Path $DstRoot $rf
        if (-not (Test-Path -LiteralPath $p)) {
            throw "Missing product-reserved file in ${Label}: $rf"
        }
    }

    $syncRelList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($d in $Dirs) {
        $dirPath = Join-Path $MainSrc $d
        if (-not (Test-Path -LiteralPath $dirPath)) {
            throw "Missing source dir for ${Label}: $d"
        }
        Get-ChildItem -LiteralPath $dirPath -Recurse -Force -File | ForEach-Object {
            $rel = $_.FullName.Substring($MainSrc.Length).TrimStart('\', '/')
            if (-not $reservedSet.Contains($rel)) {
                $syncRelList.Add($rel)
            }
        }
    }
    foreach ($f in $Files) {
        $fp = Join-Path $MainSrc $f
        if (-not (Test-Path -LiteralPath $fp)) {
            throw "Missing source file for ${Label}: $f"
        }
        if (-not $reservedSet.Contains($f)) {
            $syncRelList.Add($f)
        }
    }

    $allowedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rf in $ReservedFiles) { $null = $allowedSet.Add($rf) }
    foreach ($rel in $syncRelList) {
        $null = $allowedSet.Add($rel)
        Copy-ExactFile (Join-Path $MainSrc $rel) (Join-Path $DstRoot $rel)
    }

    # Prune any extraneous or cross-product files outside $allowedSet (never touching .git if initialized).
    Get-ChildItem -LiteralPath $DstRoot -Recurse -Force -File | ForEach-Object {
        $rel = $_.FullName.Substring($DstRoot.Length).TrimStart('\', '/')
        $segs = $rel -split '[\\/]'
        if ($segs[0] -eq ".git") { return }
        if (-not $allowedSet.Contains($rel)) {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }
    Remove-EmptyDirs $DstRoot

    Assert-NoForbiddenFiles $DstRoot $false
    Assert-NoDisallowedPaths $DstRoot $Label $DisallowedPrefixes

    $mismatch = 0
    foreach ($rel in $syncRelList) {
        $hMain = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $MainSrc $rel)).Hash
        $hDst  = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $DstRoot $rel)).Hash
        if ($hMain -ne $hDst) {
            Write-Error "SHA-256 mismatch in ${Label} for $rel ($hMain vs $hDst)"
            $mismatch++
        }
    }
    if ($mismatch -gt 0) {
        throw "Sync verification failed for ${Label}: mismatch=$mismatch"
    }

    return $syncRelList.Count
}

Assert-NoForbiddenFiles $MainSrc $true

# 1. GhostFrame-TLS-main (Protocol Core + Server + Headless Core)
$tlsCount = Sync-ProductWorkspace -Label "GhostFrame-TLS-main" -DstRoot $TlsWork `
    -Dirs @(
        "cmd\gft-server",
        "cmd\gft-core",
        "internal\gftrtc",
        "internal\gft",
        "internal\netbind",
        "internal\server",
        "internal\sni",
        "internal\qr",
        "internal\tui",
        "internal\client",
        "configs",
        "docs"
    ) `
    -Files @("install.sh", "scripts\sync_all_repos.ps1", "go.mod", "go.sum", "LICENSE") `
    -ReservedFiles @(".gitignore", "README.md", "Makefile", ".github\workflows\ci.yml", ".github\workflows\release.yml") `
    -DisallowedPrefixes @(
        "cmd\gft-client-gui", "cmd\0ghost",
        "internal\winui", "internal\tproxy", "internal\tunstack",
        "openwrt", "ios", "mobile", "tools", "scripts\build_0ghost.ps1",
        ".github\workflows\ios-dual-ipa.yml", ".github\workflows\build-client.yml", ".github\workflows\build-0ghost.yml"
    )

# 2. GhostFrame-Pro-Source (Windows Desktop Client Only)
$proCount = Sync-ProductWorkspace -Label "GhostFrame-Pro-Source" -DstRoot $ProWork `
    -Dirs @(
        "cmd\gft-client-gui",
        "internal\winui",
        "internal\client",
        "internal\gft",
        "internal\gftrtc",
        "internal\netbind"
    ) `
    -Files @("configs\client.example.json", "go.mod", "go.sum", "LICENSE") `
    -ReservedFiles @(".gitignore", "README.md", ".github\workflows\build-client.yml") `
    -DisallowedPrefixes @(
        "cmd\gft-server", "cmd\gft-core", "cmd\0ghost",
        "internal\server", "internal\tui", "internal\sni", "internal\qr", "internal\tproxy", "internal\tunstack",
        "openwrt", "ios", "mobile", "tools",
        ".github\workflows\ios-dual-ipa.yml", ".github\workflows\ci.yml", ".github\workflows\release.yml", ".github\workflows\build-0ghost.yml"
    )

# 3. 0Ghost-Source (iStoreOS / OpenWrt Side-Router Gateway Only)
$zgCount = Sync-ProductWorkspace -Label "0Ghost-Source" -DstRoot $ZeroGhostWork `
    -Dirs @(
        "cmd\0ghost",
        "internal\tproxy",
        "internal\client",
        "internal\gft",
        "internal\gftrtc",
        "internal\netbind",
        "openwrt\luci-app-0ghost"
    ) `
    -Files @("scripts\build_0ghost.ps1", "configs\client.example.json", "go.mod", "go.sum", "LICENSE") `
    -ReservedFiles @(".gitignore", "README.md", "Makefile", ".github\workflows\build-0ghost.yml") `
    -DisallowedPrefixes @(
        "cmd\gft-server", "cmd\gft-core", "cmd\gft-client-gui",
        "internal\server", "internal\tui", "internal\sni", "internal\qr", "internal\winui", "internal\tunstack",
        "ios", "mobile", "tools", "install.sh",
        ".github\workflows\ios-dual-ipa.yml", ".github\workflows\ci.yml", ".github\workflows\release.yml", ".github\workflows\build-client.yml"
    )

# 4. GhostFrame-iOS (iOS Dual Editions & OmniSign Sync Only)
$iosCount = Sync-ProductWorkspace -Label "GhostFrame-iOS" -DstRoot $IosWork `
    -Dirs @(
        "ios",
        "mobile",
        "internal\tunstack",
        "internal\client",
        "internal\gft",
        "internal\gftrtc",
        "internal\netbind",
        "tools\gen-ios-icon",
        "tools\ios-repo-sync"
    ) `
    -Files @(".github\workflows\ios-dual-ipa.yml", "go.mod", "go.sum", "LICENSE") `
    -ReservedFiles @(".gitignore", "README.md") `
    -DisallowedPrefixes @(
        "cmd\gft-server", "cmd\gft-core", "cmd\gft-client-gui", "cmd\0ghost",
        "internal\server", "internal\tui", "internal\sni", "internal\qr", "internal\winui", "internal\tproxy",
        "openwrt", "install.sh",
        ".github\workflows\ci.yml", ".github\workflows\release.yml", ".github\workflows\build-client.yml", ".github\workflows\build-0ghost.yml"
    )

# 5. Copy rebuilt Windows client executable to workstation root if built
$builtExe = Join-Path $MainSrc "dist\GhostFrame-Pro.exe"
if (Test-Path $builtExe) {
    try {
        Copy-ExactFile $builtExe $ProExeOut
        Write-Host "Updated $ProExeOut ($((Get-Item $ProExeOut).Length) bytes)"
    } catch {
        Write-Warning "Skipped overwriting locked $ProExeOut (close running GhostFrame-Pro.exe to replace): $($_.Exception.Message)"
    }
}

Write-Host ("SYNC OK (SHA-256 100% isolated & verified): TLS-main={0} files, Pro-Source={1} files, 0Ghost-Source={2} files, GhostFrame-iOS={3} files." -f $tlsCount, $proCount, $zgCount, $iosCount)
