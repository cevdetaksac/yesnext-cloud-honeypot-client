# Build script for Cloud Honeypot Client v2.2.4+
# Modern installer-only build system (no onedir)
$ErrorActionPreference = 'Stop'

Write-Host "🚀 Building Cloud Honeypot Client v2.2.4..." -ForegroundColor Green

# Clean previous builds
Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Yellow
Remove-Item -Path "dist" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "cloud-client-installer.exe" -Force -ErrorAction SilentlyContinue

# Install required packages
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Create high-quality icons from PNG sources
Write-Host "🎨 Converting PNG to high-quality ICO..." -ForegroundColor Yellow
python scripts\png_to_ico_converter.py

# Build single executable
Write-Host "🔧 Building single executable..." -ForegroundColor Yellow
$env:PYTHONPATH = "$PWD"
pyinstaller client.spec

# Copy required files to dist
Write-Host "📋 Copying configuration files..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "dist\honeypot-client"
Copy-Item "service_wrapper.py" "dist\honeypot-client\"
Copy-Item "client_config.json" "dist\honeypot-client\"  
Copy-Item "client_lang.json" "dist\honeypot-client\"
Copy-Item "setup_defender_exclusions.ps1" "dist\honeypot-client\"

# Copy complete high-resolution icon set
Write-Host "🖼️ Copying complete high-resolution icon set..." -ForegroundColor Yellow
Copy-Item "certs\honeypot*.ico" "dist\honeypot-client\" -ErrorAction SilentlyContinue

# Copy essential documentation
Copy-Item "README.md" "dist\honeypot-client\"
Copy-Item "RELEASE_NOTES_v2.2.5.md" "dist\honeypot-client\"

# Build the installer
Write-Host "🔧 Building NSIS installer..." -ForegroundColor Yellow
& 'C:\Program Files (x86)\NSIS\makensis.exe' /V4 installer.nsi

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Build completed successfully!" -ForegroundColor Green
    Write-Host "📦 Installer: cloud-client-installer.exe" -ForegroundColor Cyan
    
    # Show file size
    if (Test-Path "cloud-client-installer.exe") {
        $size = (Get-Item "cloud-client-installer.exe").Length
        $sizeKB = [math]::Round($size / 1024, 1)
        $sizeMB = [math]::Round($size / 1024 / 1024, 1)
        Write-Host "📊 Size: $($size) bytes ($($sizeKB) KB / $($sizeMB) MB)" -ForegroundColor Gray
    }
} else {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}
