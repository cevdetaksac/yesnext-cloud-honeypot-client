# Cloud Honeypot Client - Build Script
# Version is read automatically from client_constants.py (single source of truth)

param(
    [switch]$Clean = $false
)

# ===================== VERSION AUTO-DETECTION ===================== #
# Read VERSION from client_constants.py — the ONLY place version is defined
$versionLine = Select-String -Path "client_constants.py" -Pattern '^VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $versionLine) {
    Write-Host "ERROR: Could not read VERSION from client_constants.py" -ForegroundColor Red
    exit 1
}
$VERSION = $versionLine.Matches[0].Groups[1].Value
$parts = $VERSION.Split('.')
$VMAJOR = $parts[0]
$VMINOR = $parts[1]
$VBUILD = $parts[2]

Write-Host "===============================================" -ForegroundColor Green
Write-Host "  Cloud Honeypot Client v$VERSION Builder     " -ForegroundColor Green
Write-Host "  Optimized Build                             " -ForegroundColor Green  
Write-Host "===============================================" -ForegroundColor Green

# ===================== VERSION PROPAGATION ===================== #
# Sync version into all files that embed it (installer.nsi, manifest, config, README)
Write-Host "[0/5] Propagating version v$VERSION to all files..." -ForegroundColor Yellow

# installer.nsi — update !define VERSIONMAJOR/MINOR/BUILD
$nsiContent = Get-Content "installer.nsi" -Raw
$nsiContent = $nsiContent -replace '(!define VERSIONMAJOR )\d+', "`${1}$VMAJOR"
$nsiContent = $nsiContent -replace '(!define VERSIONMINOR )\d+', "`${1}$VMINOR"
$nsiContent = $nsiContent -replace '(!define VERSIONBUILD )\d+', "`${1}$VBUILD"
Set-Content "installer.nsi" -Value $nsiContent -NoNewline

# installer.manifest — update version="X.Y.Z.0"
$manifestContent = Get-Content "installer.manifest" -Raw
$manifestContent = $manifestContent -replace 'version="\d+\.\d+\.\d+\.\d+"', "version=`"$VERSION.0`""
Set-Content "installer.manifest" -Value $manifestContent -NoNewline

# client_config.json — update "version": "X.Y.Z"
$configContent = Get-Content "client_config.json" -Raw
$configContent = $configContent -replace '"version":\s*"[^"]+"', "`"version`": `"$VERSION`""
Set-Content "client_config.json" -Value $configContent -NoNewline

# README.md — update **Current Version: X.Y.Z**
$readmeContent = Get-Content "README.md" -Raw
$readmeContent = $readmeContent -replace '\*\*Current Version: [^*]+\*\*', "**Current Version: $VERSION**"
Set-Content "README.md" -Value $readmeContent -NoNewline

Write-Host "   SUCCESS: Version v$VERSION propagated to all files" -ForegroundColor Green

# Clean previous builds if requested
if ($Clean) {
    Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
    Remove-Item -Path "build", "dist", "__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "cloud-client-installer.exe" -Force -ErrorAction SilentlyContinue
    Write-Host "   Cleanup completed" -ForegroundColor Green
}

# Step 1: Build Python executable with performance optimizations
Write-Host "[1/5] Building Python executable..." -ForegroundColor Yellow
try {
    & python -m PyInstaller honeypot-client.spec --clean
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
Write-Host "[2/5] Copying configuration files..." -ForegroundColor Yellow
try {
    Copy-Item -Path "client_config.json", "client_lang.json", "LICENSE", "README.md" -Destination "dist" -Force
    Write-Host "   SUCCESS: Configuration files copied" -ForegroundColor Green
} catch {
    Write-Host "   ERROR: Failed to copy files: $_" -ForegroundColor Red
    exit 1
}

# Step 3: Check for NSIS
Write-Host "[3/5] Checking for NSIS..." -ForegroundColor Yellow
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
Write-Host "[4/5] Building installer..." -ForegroundColor Yellow
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
Write-Host "`n[5/5] Build completed successfully!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

$installerFile = Get-Item "cloud-client-installer.exe" -ErrorAction SilentlyContinue
if ($installerFile) {
    $sizeMB = [math]::Round($installerFile.Length / 1MB, 1)
    Write-Host "Version:   v$VERSION" -ForegroundColor Cyan
    Write-Host "Installer: cloud-client-installer.exe ($sizeMB MB)" -ForegroundColor Cyan
    Write-Host "Built:     $($installerFile.LastWriteTime)" -ForegroundColor Cyan
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
