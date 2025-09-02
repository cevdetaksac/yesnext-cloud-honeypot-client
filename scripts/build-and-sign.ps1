Param(
    [string]$Spec = "client.spec",
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$Sha1,
    [switch]$Auto,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = 'Stop'

& $PSScriptRoot/build.ps1 -Spec $Spec

$exe = Join-Path (Resolve-Path "$PSScriptRoot/..\dist").Path "client.exe"
if (-not (Test-Path $exe)) { throw "EXE bulunamadi: $exe" }

$signArgs = @('-File', $exe, '-TimestampUrl', $TimestampUrl)
if ($Auto) {
    $signArgs += '-Auto'
} elseif ($PfxPath) {
    $signArgs += @('-PfxPath', $PfxPath)
    if ($PfxPassword) { $signArgs += @('-PfxPassword', $PfxPassword) }
} elseif ($Sha1) {
    $signArgs += @('-Sha1', $Sha1)
} else {
    throw "Imzalama parametreleri eksik: -Auto veya -PfxPath/-PfxPassword ya da -Sha1 verin."
}

& $PSScriptRoot/sign.ps1 @signArgs
Write-Host "[build+sign] Tamamlandi: $exe" -ForegroundColor Green

