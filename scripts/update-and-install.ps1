# Cloud Honeypot - safe update/install orchestrator
# Runs elevated (UAC). Survives killing honeypot-client.exe because it is a separate powershell.exe.
#
# Flow:
#   1) Disable/end scheduled tasks (no respawn)
#   2) Wait for caller PID to exit (graceful QUIT)
#   3) Force-kill any remaining honeypot-client.exe (SeDebug)
#   4) Verify processes are gone (abort install if not - avoid corrupting onefile exe)
#   5) Run NSIS installer and WAIT
#   6) Re-create tasks / launch GUI
#
# Usage (elevated):
#   update-and-install.ps1 -InstallerPath "C:\Users\..\Downloads\cloud-client-installer-vX.exe" `
#       -ExpectExitPid 1234 -Silent -ShowGuiAfter
# NOTE: Keep this file ASCII-only (Windows PowerShell encoding).

param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [int]$ExpectExitPid = 0,

    [switch]$Silent,

    [switch]$ShowGuiAfter,

    [string]$InstallDir = "",

    [int]$GraceWaitSec = 20,

    [int]$KillRounds = 4
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

function Write-UpLog([string]$Message) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $Message"
    Write-Host $line
    try {
        $dir = Join-Path $env:ProgramData "YesNext\CloudHoneypotClient"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path (Join-Path $dir "update-install.log") -Value $line -Encoding UTF8
    } catch {}
}

function Set-UpdateLock([string]$Reason) {
    try {
        $dir = Join-Path $env:ProgramData "YesNext\CloudHoneypotClient"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $path = Join-Path $dir "update_in_progress.lock"
        Set-Content -Path $path -Value "$Reason`n$PID`n$((Get-Date).ToFileTimeUtc())" -Encoding ASCII -Force
    } catch {}
}

function Clear-UpdateLock {
    try {
        $path = Join-Path $env:ProgramData "YesNext\CloudHoneypotClient\update_in_progress.lock"
        if (Test-Path $path) { Remove-Item $path -Force }
    } catch {}
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
            $d = Split-Path $p -Parent
            if ($d -and -not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
            Set-Content -Path $p -Value "stop" -Encoding ASCII -Force
        } catch {}
    }
}

function Stop-HoneypotTasks {
    $names = @(
        "HoneypotClientGuard",
        "CloudHoneypot-Watchdog",
        "CloudHoneypot-Background",
        "CloudHoneypot-Tray",
        "CloudHoneypot-MemoryRestart",
        "CloudHoneypot-Updater",
        "CloudHoneypot-SilentUpdater"
    )
    foreach ($n in $names) {
        schtasks /end /tn $n 2>$null | Out-Null
        schtasks /change /tn $n /disable 2>$null | Out-Null
    }
}

function Restore-HoneypotTasks {
    # Re-enable core tasks after aborted update so agents are not stuck forever
    $names = @(
        "CloudHoneypot-SilentUpdater",
        "CloudHoneypot-Updater",
        "CloudHoneypot-Watchdog",
        "CloudHoneypot-Background",
        "CloudHoneypot-MemoryRestart",
        "CloudHoneypot-Tray"
    )
    foreach ($n in $names) {
        schtasks /change /tn $n /enable 2>$null | Out-Null
    }
    Write-UpLog "Scheduled tasks re-enabled (recovery)"
}

function Fail-Update([int]$Code, [string]$Message) {
    Write-UpLog $Message
    Clear-UpdateLock
    Restore-HoneypotTasks
    # Best-effort: restart daemon so protection continues on old build
    try {
        $exe = Join-Path ${env:ProgramFiles} "YesNext\Cloud Honeypot Client\honeypot-client.exe"
        if (-not (Test-Path -LiteralPath $exe)) {
            $exe = Join-Path ${env:ProgramFiles} "YesNext\CloudHoneypotClient\honeypot-client.exe"
        }
        if (Test-Path -LiteralPath $exe) {
            Start-Process -FilePath $exe -ArgumentList "--mode=daemon","--silent" -WindowStyle Hidden
        }
    } catch {}
    exit $Code
}

function Send-QuitCommand {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", 58632, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(200)
        if ($ok -and $client.Connected) {
            $stream = $client.GetStream()
            $bytes = [Text.Encoding]::ASCII.GetBytes("QUIT`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        }
        $client.Close()
    } catch {}
}

function Enable-SeDebugPrivilege {
    $def = @"
using System;
using System.Runtime.InteropServices;
public class HpTokUp {
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
    try { Add-Type -TypeDefinition $def -ErrorAction Stop | Out-Null } catch {}
    try {
        $tok = [IntPtr]::Zero
        [void][HpTokUp]::OpenProcessToken([HpTokUp]::GetCurrentProcess(), 0x28, [ref]$tok)
        $tp = New-Object HpTokUp+TP
        $tp.Count = 1
        $tp.Attr = 2
        [void][HpTokUp]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tp.Luid)
        [void][HpTokUp]::AdjustTokenPrivileges($tok, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    } catch {}
}

function Get-HoneypotPids {
    $list = @()
    Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue | ForEach-Object { $list += $_.Id }
    return $list
}

function Stop-HoneypotProcesses {
    $kdef = @"
using System;
using System.Runtime.InteropServices;
public class HpKillUp {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
"@
    try { Add-Type -TypeDefinition $kdef -ErrorAction Stop | Out-Null } catch {}

    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
    $pids = Get-HoneypotPids
    foreach ($procId in $pids) {
        try {
            $h = [HpKillUp]::OpenProcess(0x1F0FFF, $false, [int]$procId)
            if ($h -ne [IntPtr]::Zero) {
                [void][HpKillUp]::TerminateProcess($h, 1)
                [void][HpKillUp]::CloseHandle($h)
            }
        } catch {}
        try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {}
        try { & taskkill.exe /F /T /PID $procId 2>$null | Out-Null } catch {}
    }
}

function Wait-ProcessesGone([int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $left = @(Get-HoneypotPids)
        if ($left.Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return (@(Get-HoneypotPids).Count -eq 0)
}

function Wait-CallerExit([int]$PidToWait, [int]$TimeoutSec) {
    if ($PidToWait -le 0) { return }
    Write-UpLog "Waiting for caller PID $PidToWait to exit (max ${TimeoutSec}s)..."
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Id $PidToWait -ErrorAction SilentlyContinue)) {
            Write-UpLog "Caller PID $PidToWait exited."
            return
        }
        Start-Sleep -Milliseconds 200
    }
    Write-UpLog "Caller PID $PidToWait still running after grace - will force-kill."
}

# -- Main --
Write-UpLog "=== update-and-install start ==="
Write-UpLog "Installer=$InstallerPath Silent=$Silent ShowGui=$ShowGuiAfter ExpectExitPid=$ExpectExitPid Grace=$GraceWaitSec"

if (-not (Test-Path -LiteralPath $InstallerPath)) {
    Fail-Update 2 "ERROR: Installer not found: $InstallerPath"
}

Set-UpdateLock "installing"
Write-StopFlags
Write-UpLog "Stopping/disabling scheduled tasks..."
Stop-HoneypotTasks

Write-UpLog "Sending QUIT to control port..."
Send-QuitCommand

Wait-CallerExit -PidToWait $ExpectExitPid -TimeoutSec $GraceWaitSec

Write-UpLog "Enabling SeDebugPrivilege + force terminate..."
Enable-SeDebugPrivilege
$round = 0
do {
    $round++
    Write-UpLog "Kill round $round..."
    Stop-HoneypotProcesses
    $left = @(Get-HoneypotPids)
    if ($left.Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while ($round -lt $KillRounds)

if (-not (Wait-ProcessesGone -TimeoutSec 5)) {
    $still = @(Get-HoneypotPids)
    Fail-Update 3 "ERROR: honeypot-client still running (PIDs=$($still -join ',')). Aborting install to avoid corrupting onefile EXE."
}

Write-UpLog "Processes gone - settling 0.8s before installer..."
Start-Sleep -Milliseconds 800

$argList = @()
if ($Silent) {
    $argList = @("/S", "/NCRC")
}

Write-UpLog "Starting installer (wait)..."
try {
    # Interactive: show NSIS UI. Silent: /S args above.
    $p = Start-Process -FilePath $InstallerPath -ArgumentList $argList -PassThru -Wait
    $code = $p.ExitCode
    Write-UpLog "Installer exit code: $code"
} catch {
    Fail-Update 4 "ERROR: Installer failed to start: $($_.Exception.Message)"
}

if ($InstallDir -eq "") {
    $InstallDir = Join-Path ${env:ProgramFiles} "YesNext\Cloud Honeypot Client"
}
$exe = Join-Path $InstallDir "honeypot-client.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    $alt = Join-Path ${env:ProgramFiles} "YesNext\CloudHoneypotClient\honeypot-client.exe"
    if (Test-Path -LiteralPath $alt) { $exe = $alt; $InstallDir = Split-Path $alt -Parent }
}

if (-not (Test-Path -LiteralPath $exe)) {
    Fail-Update 5 "ERROR: honeypot-client.exe missing after install at $InstallDir"
}

$size = (Get-Item -LiteralPath $exe).Length
Write-UpLog "Installed exe OK ($size bytes): $exe"
if ($size -lt 1000000) {
    Fail-Update 6 "ERROR: Installed exe suspiciously small - abort launch"
}

Write-UpLog "Creating scheduled tasks..."
try {
    Start-Process -FilePath $exe -ArgumentList "--create-tasks" -Wait -WindowStyle Hidden
} catch {
    Write-UpLog "WARN: --create-tasks failed: $($_.Exception.Message)"
    Restore-HoneypotTasks
}

Clear-UpdateLock

if ($ShowGuiAfter -or -not $Silent) {
    Write-UpLog "Launching GUI..."
    try {
        Start-Process -FilePath $exe -ArgumentList "--show-gui" -WorkingDirectory $InstallDir
    } catch {
        Write-UpLog "WARN: GUI launch failed: $($_.Exception.Message)"
    }
} else {
    Write-UpLog "Silent mode - starting daemon..."
    try {
        Start-Process -FilePath $exe -ArgumentList "--mode=daemon","--silent" -WorkingDirectory $InstallDir -WindowStyle Hidden
    } catch {
        Write-UpLog "WARN: daemon launch failed: $($_.Exception.Message)"
    }
}

Write-UpLog "=== update-and-install done ==="
exit 0
