# Prepare install dir so NSIS can overwrite onedir files without Abort/Retry/Ignore.
# Classic Windows pattern: rename locked tree aside, write fresh files, delete stale later.
# ASCII-only (installer PRE-KILL safety).
#
# Usage:
#   prepare-install-dir.ps1 -InstallDir "C:\Program Files\YesNext\Cloud Honeypot Client"
#   prepare-install-dir.ps1 -InstallDir "..." -KillScript "C:\...\kill-honeypot.ps1"

param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [string]$KillScript = "",
    [switch]$SkipDefender
)

$ErrorActionPreference = "SilentlyContinue"
$InstallDir = $InstallDir.TrimEnd('\', '/')

function Write-PrepLog([string]$msg) {
    Write-Host ("[PREP-DIR] " + $msg)
}

function Invoke-KillHelper {
    if ($KillScript -and (Test-Path $KillScript)) {
        Write-PrepLog "Running kill helper..."
        try {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $KillScript -Force
        } catch {}
    }
    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
}

function Stop-ProcessesUnderInstallDir {
    if (-not $InstallDir) { return }
    $needle = $InstallDir.ToLowerInvariant()
    try {
        $list = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    } catch {
        $list = @()
    }
    foreach ($p in $list) {
        try {
            $path = [string]($p.ExecutablePath)
            if (-not $path) { continue }
            if ($path.ToLowerInvariant().StartsWith($needle)) {
                Write-PrepLog ("Stopping PID {0} ({1})" -f $p.ProcessId, $path)
                try { & taskkill.exe /F /T /PID $p.ProcessId 2>$null | Out-Null } catch {}
                try { Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction SilentlyContinue } catch {}
            }
        } catch {}
    }
}

function Add-DefenderExclusionFast {
    if ($SkipDefender) { return }
    if (-not $InstallDir) { return }
    Write-PrepLog "Defender exclusion (best-effort)..."
    try {
        Add-MpPreference -ExclusionPath $InstallDir -Force -ErrorAction SilentlyContinue
    } catch {}
    try {
        $exe = Join-Path $InstallDir "honeypot-client.exe"
        Add-MpPreference -ExclusionProcess $exe -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Move-Aside([string]$path) {
    if (-not (Test-Path $path)) { return $true }
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    $rnd = Get-Random -Maximum 9999
    $dest = "{0}.stale_{1}_{2}" -f $path, $stamp, $rnd
    for ($i = 0; $i -lt 5; $i++) {
        try {
            Move-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop
            Write-PrepLog ("Moved aside: {0} -> {1}" -f $path, (Split-Path $dest -Leaf))
            return $true
        } catch {
            Start-Sleep -Milliseconds (120 * ($i + 1))
            Stop-ProcessesUnderInstallDir
            try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
        }
    }
    # Last resort: clear attributes and try delete contents
    try {
        Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                try { $_.Attributes = 'Normal' } catch {}
            }
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        Write-PrepLog ("Removed: {0}" -f $path)
        return $true
    } catch {
        Write-PrepLog ("WARN: still locked: {0}" -f $path)
        return $false
    }
}

function Clear-StaleAsync {
    # Best-effort cleanup of previous .stale_* leftovers (non-blocking)
    try {
        $parent = Split-Path $InstallDir -Parent
        if (-not $parent) { return }
        Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '\.stale_\d+' } |
            ForEach-Object {
                $target = $_.FullName
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c","rmdir","/s","/q","`"$target`"" -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            }
    } catch {}
}

Write-PrepLog ("InstallDir={0}" -f $InstallDir)
if (-not (Test-Path $InstallDir)) {
    try { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null } catch {}
    Write-PrepLog "Created empty install dir"
    exit 0
}

# Order matters: stop respawn, kill, exclude AV, then rename locked trees.
Invoke-KillHelper
Stop-ProcessesUnderInstallDir
Start-Sleep -Milliseconds 200
Stop-ProcessesUnderInstallDir
Add-DefenderExclusionFast

$okInternal = Move-Aside (Join-Path $InstallDir "_internal")
$okExe = Move-Aside (Join-Path $InstallDir "honeypot-client.exe")

# Also clear common lock-prone helpers next to exe
Move-Aside (Join-Path $InstallDir "honeypot-client.exe.manifest") | Out-Null

Clear-StaleAsync

if (-not $okInternal -or -not $okExe) {
    Write-PrepLog "WARN: some paths remain; NSIS may still hit FileInUse (retry/ignore)"
    exit 2
}

Write-PrepLog "Ready for NSIS file extract."
exit 0
