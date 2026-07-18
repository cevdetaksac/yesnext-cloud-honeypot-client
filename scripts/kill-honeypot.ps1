# Kill all Cloud Honeypot Client processes (installer / updater helper)
# Handles: DACL self-protection, watchdog respawn, HoneypotClientGuard task
# Requires: elevated (admin) for SeDebugPrivilege
#
# Usage:
#   kill-honeypot.ps1           — respects update_in_progress.lock (interactive download)
#   kill-honeypot.ps1 -Force    — kill even during download (installer after download done)

param(
    [switch]$Force
)

$ErrorActionPreference = "SilentlyContinue"

function Test-UpdateLockBlocksKill {
    if ($Force) { return $false }
    $candidates = @(
        (Join-Path $env:ProgramData "YesNext\CloudHoneypotClient\update_in_progress.lock"),
        (Join-Path $env:APPDATA "YesNext\CloudHoneypotClient\update_in_progress.lock")
    )
    foreach ($lock in $candidates) {
        if (-not (Test-Path $lock)) { continue }
        try {
            $ageSec = ((Get-Date) - (Get-Item $lock).LastWriteTime).TotalSeconds
            if ($ageSec -gt 7200) { continue }
            $reason = ""
            try { $reason = (Get-Content $lock -TotalCount 1 -ErrorAction SilentlyContinue) } catch {}
            # interactive / silent download in progress — never kill mid-download
            if ($reason -match "download|interactive|silent") {
                Write-Host "[KILL] Abort — update lock present ($reason, age=${ageSec}s). Use -Force only after download."
                return $true
            }
            # any fresh lock without install reason still blocks casual kills
            if ($reason -notmatch "install|preparing") {
                Write-Host "[KILL] Abort — update_in_progress.lock present (age=${ageSec}s)"
                return $true
            }
        } catch {}
    }
    return $false
}

if (Test-UpdateLockBlocksKill) {
    exit 0
}

function Write-StopFlags {
    $paths = @(
        (Join-Path $env:TEMP "honeypot_watchdog_token.txt"),
        (Join-Path $env:APPDATA "YesNext\CloudHoneypot\watchdog_token.txt"),
        (Join-Path $env:APPDATA "YesNext\CloudHoneypotClient\watchdog.token"),
        (Join-Path $env:ProgramData "YesNext\CloudHoneypot\watchdog_stop.flag")
    )
    foreach ($p in $paths) {
        try {
            $dir = Split-Path $p -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Set-Content -Path $p -Value "stop" -Encoding ASCII -Force
        } catch {}
    }
}

function Stop-HoneypotTasks {
    $names = @(
        "CloudHoneypot-Background",
        "CloudHoneypot-Tray",
        "CloudHoneypot-Watchdog",
        "CloudHoneypot-Updater",
        "CloudHoneypot-SilentUpdater",
        "CloudHoneypot-MemoryRestart",
        "CloudHoneypotClientBoot",
        "CloudHoneypotClientLogon",
        "HoneypotClientGuard",
        "HoneypotClientAutostart",
        "Cloud Honeypot Client"
    )
    foreach ($n in $names) {
        schtasks /end /tn $n 2>$null | Out-Null
        schtasks /change /tn $n /disable 2>$null | Out-Null
    }
    # Wildcard catch-all (CloudHoneypot* + HoneypotClient*)
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -like "CloudHoneypot*" -or $_.TaskName -like "HoneypotClient*" } |
        ForEach-Object {
            schtasks /end /tn $_.TaskName 2>$null | Out-Null
            Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
}

function Send-QuitCommand {
    # Ask running client to exit itself (bypasses process DACL)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", 58632, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(800)
        if ($ok -and $client.Connected) {
            $stream = $client.GetStream()
            $bytes = [Text.Encoding]::ASCII.GetBytes("QUIT`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            Start-Sleep -Milliseconds 400
        }
        $client.Close()
    } catch {}
}

function Enable-SeDebugPrivilege {
    $def = @"
using System;
using System.Runtime.InteropServices;
public class HpTok {
  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr h, int access, out IntPtr t);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool LookupPrivilegeValue(string host, string name, out long luid);
  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  public static extern bool AdjustTokenPrivileges(IntPtr t, bool dis, ref TP neu, int len, IntPtr prev, IntPtr rel);
  [StructLayout(LayoutKind.Sequential, Pack=1)]
  public struct TP { public int Count; public long Luid; public int Attr; }
  [DllImport("kernel32.dll", ExactSpelling=true)]
  public static extern IntPtr GetCurrentProcess();
}
"@
    try {
        Add-Type -TypeDefinition $def -ErrorAction Stop | Out-Null
    } catch {}
    try {
        $tok = [IntPtr]::Zero
        [void][HpTok]::OpenProcessToken([HpTok]::GetCurrentProcess(), 0x28, [ref]$tok)
        $tp = New-Object HpTok+TP
        $tp.Count = 1
        $tp.Attr = 2  # SE_PRIVILEGE_ENABLED
        [void][HpTok]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tp.Luid)
        [void][HpTok]::AdjustTokenPrivileges($tok, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    } catch {}
}

function Stop-HoneypotProcesses {
    $kdef = @"
using System;
using System.Runtime.InteropServices;
public class HpKill {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
"@
    try { Add-Type -TypeDefinition $kdef -ErrorAction Stop | Out-Null } catch {}

    $pids = @()
    Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue | ForEach-Object { $pids += $_.Id }
    Get-CimInstance Win32_Process -Filter "Name='honeypot-client.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { if ($pids -notcontains $_.ProcessId) { $pids += $_.ProcessId } }

    foreach ($pid in $pids) {
        try {
            # PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE = 0x0015; with SeDebug use ALL_ACCESS
            $h = [HpKill]::OpenProcess(0x1F0FFF, $false, [int]$pid)
            if ($h -ne [IntPtr]::Zero) {
                [void][HpKill]::TerminateProcess($h, 1)
                [void][HpKill]::CloseHandle($h)
            }
        } catch {}
        try { Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } catch {}
        try { & taskkill.exe /F /T /PID $pid 2>$null | Out-Null } catch {}
    }
    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
}

Write-Host "[KILL] Writing stop flags..."
Write-StopFlags

Write-Host "[KILL] Stopping/removing scheduled tasks (incl. HoneypotClientGuard)..."
Stop-HoneypotTasks

Write-Host "[KILL] Sending QUIT to control port..."
Send-QuitCommand
Start-Sleep -Milliseconds 600

Write-Host "[KILL] Enabling SeDebugPrivilege..."
Enable-SeDebugPrivilege

$round = 0
do {
    $round++
    Write-Host "[KILL] Force terminate round $round..."
    Stop-HoneypotProcesses
    Start-Sleep -Milliseconds 350
    $left = @(Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue)
} while ($left.Count -gt 0 -and $round -lt 8)

if ($left.Count -gt 0) {
    Write-Host "[KILL] WARNING: $($left.Count) process(es) still running"
    exit 1
}

Write-Host "[KILL] All honeypot-client processes stopped."
exit 0
