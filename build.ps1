# Cloud Honeypot Client v2.8.0 - Memory Optimization Build Script
# Single script to build complete installer with memory optimization features

param(
    [switch]$Clean = $false
)

Write-Host "===============================================" -ForegroundColor Green
Write-Host "  Cloud Honeypot Client v2.8.0 Builder      " -ForegroundColor Green
Write-Host "  🛡️ Memory Optimization Edition             " -ForegroundColor Green  
Write-Host "===============================================" -ForegroundColor Green

# Clean previous builds if requested
if ($Clean) {
    Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Yellow
    Remove-Item -Path "build", "dist", "__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "cloud-client-installer.exe" -Force -ErrorAction SilentlyContinue
    Write-Host "   ✅ Cleanup completed" -ForegroundColor Green
}

# Step 1: Build Python executable
Write-Host "[1/4] Building Python executable..." -ForegroundColor Yellow
try {
    & python -m PyInstaller --onefile --noconsole --icon="certs/honeypot_256.ico" --name="honeypot-client" --distpath="dist" --add-data="certs/*.ico;certs" --add-data="certs/*.png;certs" --add-data="certs/*.bmp;certs" --add-data="client_config.json;." --add-data="client_lang.json;." client.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   SUCCESS: Executable built successfully" -ForegroundColor Green
    } else {
        throw "PyInstaller failed"
    }
} catch {
    Write-Host "   ERROR: Failed to build executable: $_" -ForegroundColor Red
    exit 1
}

# Step 2: Copy config files to dist
Write-Host "[2/4] Copying configuration files..." -ForegroundColor Yellow
try {
    Copy-Item -Path "client_config.json", "client_lang.json", "LICENSE", "README.md" -Destination "dist" -Force
    Write-Host "   SUCCESS: Configuration files copied" -ForegroundColor Green
} catch {
    Write-Host "   ERROR: Failed to copy files: $_" -ForegroundColor Red
    exit 1
}

# Step 3: Check for NSIS
Write-Host "[3/4] Checking for NSIS..." -ForegroundColor Yellow
$nsisPath = Get-Command makensis -ErrorAction SilentlyContinue
if (-not $nsisPath) {
    Write-Host "   WARNING: NSIS not found, installing via Scoop..." -ForegroundColor Yellow
    try {
        & scoop install nsis
        Write-Host "   SUCCESS: NSIS installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "   ERROR: Failed to install NSIS. Please install manually." -ForegroundColor Red
        Write-Host "      Run: scoop install nsis" -ForegroundColor White
        exit 1
    }
} else {
    Write-Host "   SUCCESS: NSIS found at $($nsisPath.Source)" -ForegroundColor Green
}

# Step 4: Build installer
Write-Host "[4/4] Building installer..." -ForegroundColor Yellow
try {
    & makensis installer.nsi
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   SUCCESS: Installer built successfully" -ForegroundColor Green
    } else {
        throw "NSIS compilation failed"
    }
} catch {
    Write-Host "   ERROR: Failed to build installer: $_" -ForegroundColor Red
    exit 1
}

# Step 5: Show results
Write-Host "`nBuild completed successfully!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

$installerFile = Get-Item "cloud-client-installer.exe" -ErrorAction SilentlyContinue
if ($installerFile) {
    $sizeMB = [math]::Round($installerFile.Length / 1MB, 1)
    Write-Host "Installer: cloud-client-installer.exe ($sizeMB MB)" -ForegroundColor Cyan
    Write-Host "Built: $($installerFile.LastWriteTime)" -ForegroundColor Cyan
    Write-Host "Ready for distribution!" -ForegroundColor Green
} else {
    Write-Host "ERROR: Installer file not found!" -ForegroundColor Red
    exit 1
}

Write-Host "`nUsage Instructions:" -ForegroundColor White
Write-Host "   - Run cloud-client-installer.exe as Administrator" -ForegroundColor Gray
Write-Host "   - Automatic UAC elevation will prompt for admin rights" -ForegroundColor Gray
Write-Host "   - Application will self-configure on first run" -ForegroundColor Gray

Write-Host "`n===============================================" -ForegroundColor Green
