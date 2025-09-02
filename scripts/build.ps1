Param(
    [string]$Spec = "client.spec"
)

$ErrorActionPreference = 'Stop'

function Require-Tool([string]$cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "Gereken arac bulunamadi: $cmd"
    }
}

# PyInstaller kontrolu
try {
    python -m PyInstaller --version | Out-Null
} catch {
    Write-Host "[build] PyInstaller bulunamadi, yukleniyor..." -ForegroundColor Yellow
    pip install --upgrade pyinstaller | Write-Host
}

Write-Host "[build] Temiz derleme basliyor..." -ForegroundColor Cyan
python -m PyInstaller --clean $Spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build hatasi (exit $LASTEXITCODE)" }

$exe = Join-Path (Resolve-Path "dist").Path "client.exe"
if (-not (Test-Path $exe)) {
    throw "Beklenen cikti bulunamadi: $exe"
}

Write-Host "[build] Cikti: $exe" -ForegroundColor Green

