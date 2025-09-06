Param()

$ErrorActionPreference = 'Stop'

function Ensure-PyInstaller {
    try {
        python -m PyInstaller --version | Out-Null
    } catch {
        Write-Host "[build] PyInstaller not found, installing..." -ForegroundColor Yellow
        pip install --upgrade pyinstaller | Write-Host
    }
}

Ensure-PyInstaller

Write-Host "[build-onedir] Clean build (client-onedir.spec) starting..." -ForegroundColor Cyan
python -m PyInstaller --clean "client-onedir.spec"
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build error (exit $LASTEXITCODE)" }

$outDir = Join-Path (Resolve-Path "dist").Path "client-onedir"
if (-not (Test-Path $outDir)) { throw "Output folder not found: $outDir" }
$exe = Join-Path $outDir "client-onedir.exe"
if (-not (Test-Path $exe)) { throw "Expected exe not found: $exe" }

# Zip onedir folder to dist\client-onedir.zip
Write-Host "[build-onedir] Zipping output..." -ForegroundColor Cyan
$zipPath = Join-Path (Resolve-Path "dist").Path "client-onedir.zip"
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $zipPath)

# Write hashes.txt with sha256 of zip
Write-Host "[build-onedir] Writing hashes.txt..." -ForegroundColor Cyan
$hash = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
$hashFile = Join-Path (Resolve-Path "dist").Path "hashes.txt"
"$hash  client-onedir.zip" | Out-File -FilePath $hashFile -Encoding ascii -Force

Write-Host "[build-onedir] Done: $zipPath" -ForegroundColor Green

