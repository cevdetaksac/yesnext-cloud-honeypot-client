# ===============================================================================
# 🔄 Honeypot Memory Restart Script
# Task Scheduler tarafından 8 saatte bir çalıştırılır
# Registry'den son mode'u okur, process'i kill eder, aynı mode'da restart eder
# ===============================================================================

param(
    [string]$InstallPath = "C:\Program Files\YesNext\CloudHoneypotClient"
)

# Logging
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logPath = "$env:TEMP\honeypot_memory_restart.log"
    "[$timestamp] $Message" | Tee-Object -FilePath $logPath -Append
}

Write-Log "🔄 Starting memory restart process..."

# 1. Registry'den son mode'u oku
function Get-LastModeFromRegistry {
    try {
        $regPath = "HKCU:\Software\YesNext\CloudHoneypot"
        if (Test-Path $regPath) {
            $lastMode = Get-ItemProperty -Path $regPath -Name "LastMode" -ErrorAction SilentlyContinue
            if ($lastMode -and $lastMode.LastMode) {
                Write-Log "📋 Registry'den mode: $($lastMode.LastMode)"
                return $lastMode.LastMode
            }
        }
        Write-Log "⚠️ Registry'de LastMode bulunamadı"
        return $null
    }
    catch {
        Write-Log "❌ Registry error: $($_.Exception.Message)"
        return $null
    }
}

# 2. Smart mode detection
function Get-SmartMode {
    try {
        # User session kontrolü
        $sessions = quser 2>$null
        if ($sessions) {
            Write-Log "👤 User session aktif"
            # Explorer process var mı?
            $explorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
            if ($explorer) {
                Write-Log "🖥️ Desktop -> GUI mode"
                return "--mode=gui"
            } else {
                Write-Log "📱 No desktop -> Tray mode"
                return "--mode=tray"
            }
        } else {
            Write-Log "🤖 No user session -> Daemon mode"
            return "--mode=daemon"
        }
    }
    catch {
        Write-Log "❌ Smart detection error: $($_.Exception.Message)"
        return "--mode=daemon"
    }
}

# 3. Mode belirleme
$targetMode = Get-LastModeFromRegistry
if (-not $targetMode) {
    $targetMode = Get-SmartMode
}
Write-Log "✅ Target mode: $targetMode"

# 4. Process kill
Write-Log "🛑 Killing honeypot processes..."
try {
    Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    Write-Log "✅ Processes killed"
}
catch {
    Write-Log "⚠️ Kill error: $($_.Exception.Message)"
}

# 5. Restart
Write-Log "🚀 Starting new instance: $targetMode"
try {
    # Executable path
    $exePath = ""
    if (Test-Path "$InstallPath\honeypot-client.exe") {
        $exePath = "$InstallPath\honeypot-client.exe"
    } elseif (Test-Path ".\honeypot-client.exe") {
        $exePath = ".\honeypot-client.exe"
    } else {
        Write-Log "❌ honeypot-client.exe not found!"
        exit 1
    }
    
    # Start process
    $arguments = "$targetMode --silent"
    Write-Log "📂 Exe: $exePath"
    Write-Log "⚙️ Args: $arguments"
    
    Start-Process -FilePath $exePath -ArgumentList $arguments -WindowStyle Hidden
    Write-Log "✅ New instance started!"
}
catch {
    Write-Log "❌ Restart error: $($_.Exception.Message)"
    exit 1
}

Write-Log "🎉 Memory restart completed successfully!"
exit 0