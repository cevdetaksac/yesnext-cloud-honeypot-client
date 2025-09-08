Param(
    [string]$Version = "1.5.9"
)

$ErrorActionPreference = 'Stop'

# 1. PyInstaller ile onedir exe üret
Write-Host "[BUILD] PyInstaller ile exe oluşturuluyor..." -ForegroundColor Cyan
pyinstaller --clean --noconfirm --onefile --name client-onedir client.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build error (exit $LASTEXITCODE)" }

# 2. NSIS ile installer üret
Write-Host "[NSIS] Installer derleniyor..." -ForegroundColor Cyan
& "C:\Program Files (x86)\NSIS\makensis.exe" "${PSScriptRoot}\..\installer.nsi"
if ($LASTEXITCODE -ne 0) { throw "NSIS build error (exit $LASTEXITCODE)" }

# 3. Zip dosyasını oluştur
Write-Host "[ZIP] client-onedir.zip hazırlanıyor..." -ForegroundColor Cyan
Compress-Archive -Path dist\client-onedir.exe -DestinationPath dist\client-onedir.zip -Force

# 4. Hashes.txt oluştur
$hash = (Get-FileHash -Algorithm SHA256 -Path dist\client-onedir.zip).Hash.ToLower()
"$hash  client-onedir.zip" | Out-File -FilePath dist\hashes.txt -Encoding ascii -Force

Write-Host "[DONE] Build, installer ve zip dosyası hazır." -ForegroundColor Green
