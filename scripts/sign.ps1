Param(
    [Parameter(Mandatory=$true)] [string]$File,
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$Sha1,
    [switch]$Auto,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = 'Stop'

function Require-Tool([string]$name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Gereken arac bulunamadi: $name. Lutfen Windows SDK (signtool) yuklu oldugundan emin olun."
    }
}

Require-Tool signtool

if (-not (Test-Path -Path $File)) {
    throw "Imzalanacak dosya bulunamadi: $File"
}

Write-Host "[sign] File: $File" -ForegroundColor Cyan
Write-Host "[sign] Timestamp: $TimestampUrl" -ForegroundColor Cyan

$sigArgs = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', '/v')

if ($Auto.IsPresent) {
    $sigArgs += '/a'
} elseif ($PfxPath) {
    if (-not (Test-Path -Path $PfxPath)) { throw "PFX bulunamadi: $PfxPath" }
    $sigArgs += @('/f', $PfxPath)
    if ($PfxPassword) { $sigArgs += @('/p', $PfxPassword) }
} elseif ($Sha1) {
    $sigArgs += @('/sha1', $Sha1)
} else {
    throw "Parametre eksik: -Auto veya -PfxPath/-PfxPassword ya da -Sha1 verilmelidir."
}

$sigArgs += @($File)

& signtool @sigArgs
if ($LASTEXITCODE -ne 0) { throw "Imzalama basarisiz (exit $LASTEXITCODE)" }

Write-Host "[sign] Dogrulama calisiyor..." -ForegroundColor Yellow
& signtool verify /pa /all /v $File
if ($LASTEXITCODE -ne 0) { throw "Dogrulama basarisiz (exit $LASTEXITCODE)" }

Write-Host "[sign] Tamamlandi." -ForegroundColor Green

