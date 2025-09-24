# Build script for Cloud Honeypot Client
$ErrorActionPreference = 'Stop'

Write-Host "Building Cloud Honeypot Client..." -ForegroundColor Green

# Clean previous builds
Remove-Item -Path "dist" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "*.exe" -Force -ErrorAction SilentlyContinue

# Install required packages
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Build the onedir version
Write-Host "Building OneDir version..." -ForegroundColor Yellow
$env:PYTHONPATH = "$PWD"
pyinstaller client-onedir.spec

# Copy service wrapper and config files
Write-Host "Copying service wrapper and config files..." -ForegroundColor Yellow
Copy-Item "service_wrapper.py" "dist\honeypot-client\"
Copy-Item "client_config.json" "dist\honeypot-client\"
Copy-Item "client_lang.json" "dist\honeypot-client\"

# Copy service management batch files
Write-Host "Copying service management batch files..." -ForegroundColor Yellow
Copy-Item "install_service.bat" "dist\honeypot-client\"
Copy-Item "remove_service.bat" "dist\honeypot-client\"
Copy-Item "check_service_status.bat" "dist\honeypot-client\"
Copy-Item "SERVICE_MANAGEMENT.md" "dist\honeypot-client\"
Copy-Item "RELEASE_NOTES_v2.2.0.md" "dist\honeypot-client\"

# Update icons from custom PNGs
Write-Host "Converting custom PNG icons to ICO..." -ForegroundColor Yellow
python scripts\convert_png_to_ico.py

# Run Defender compatibility helper
Write-Host "Setting up Windows Defender compatibility..." -ForegroundColor Yellow
python scripts\defender_helper.py

# Copy icon if not exists
if (!(Test-Path "certs\honeypot.ico")) {
    New-Item -ItemType Directory -Force -Path "certs"
    Copy-Item "dist\client\honeypot.ico" "certs\honeypot.ico" -ErrorAction SilentlyContinue
}

# Build the installer
Write-Host "Building installer..." -ForegroundColor Yellow
& 'C:\Program Files (x86)\NSIS\makensis.exe' /V4 installer.nsi

Write-Host "Build completed!" -ForegroundColor Green
