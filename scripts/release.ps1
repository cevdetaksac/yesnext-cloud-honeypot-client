Param(
    [string]$Tag,
    [string]$Name,
    [string]$Notes = "",
    [switch]$Draft = $false,
    [switch]$Prerelease = $false
)

$ErrorActionPreference = 'Stop'

function Read-Config {
    $cfgPath = Join-Path (Resolve-Path "$PSScriptRoot/.." ).Path "config.json"
    if (-not (Test-Path $cfgPath)) { throw "config.json not found: $cfgPath" }
    return Get-Content $cfgPath | ConvertFrom-Json
}

function Get-Token {
    $tok = $env:GITHUB_TOKEN
    if (-not $tok) { $tok = $env:GH_TOKEN }
    if (-not $tok) { throw "Set GITHUB_TOKEN environment variable with repo permissions." }
    return $tok
}

if (-not $Tag) { throw "-Tag vX.Y.Z is required" }
if (-not $Name) { $Name = $Tag }

$cfg = Read-Config
$owner = $cfg.github_owner
$repo  = $cfg.github_repo
$token = Get-Token

$headers = @{ Authorization = "token $token"; "User-Agent" = "cloud-client-release" }

# Create or fetch release
$apiBase = "https://api.github.com/repos/$owner/$repo"
Write-Host "[release] Creating release $Tag for $owner/$repo" -ForegroundColor Cyan

$release = $null
try {
    $release = Invoke-RestMethod -Headers $headers -Method Get -Uri "$apiBase/releases/tags/$Tag"
} catch {
    # not found
}

if ($null -eq $release) {
    $payload = @{ tag_name = $Tag; name = $Name; body = $Notes; draft = [bool]$Draft; prerelease = [bool]$Prerelease }
    $release = Invoke-RestMethod -Headers $headers -Method Post -Uri "$apiBase/releases" -Body ($payload | ConvertTo-Json) -ContentType "application/json"
} else {
    # Update body/name if provided
    $payload = @{ name = $Name; body = $Notes; draft = [bool]$Draft; prerelease = [bool]$Prerelease }
    $release = Invoke-RestMethod -Headers $headers -Method Patch -Uri "$apiBase/releases/$($release.id)" -Body ($payload | ConvertTo-Json) -ContentType "application/json"
}

$uploadUrl = $release.upload_url -replace "\{.*\}", ""

# Upload assets dist/client-onedir.zip and dist/hashes.txt
$dist = Resolve-Path "$PSScriptRoot/..\dist"
$zip = Join-Path $dist "client-onedir.zip"
$hashes = Join-Path $dist "hashes.txt"
if (-not (Test-Path $zip)) { throw "Asset not found: $zip (run build-onedir.ps1)" }
if (-not (Test-Path $hashes)) { throw "Asset not found: $hashes (run build-onedir.ps1)" }

function Remove-AssetIfExists([string]$name) {
    $assets = Invoke-RestMethod -Headers $headers -Method Get -Uri "$apiBase/releases/$($release.id)/assets"
    $existing = $assets | Where-Object { $_.name -eq $name }
    if ($existing) {
        Write-Host "[release] Removing existing asset $name" -ForegroundColor Yellow
        Invoke-RestMethod -Headers $headers -Method Delete -Uri "$apiBase/releases/assets/$($existing[0].id)"
    }
}

Remove-AssetIfExists -name "client-onedir.zip"
Remove-AssetIfExists -name "hashes.txt"

Write-Host "[release] Uploading client-onedir.zip" -ForegroundColor Cyan
$u1 = "$uploadUrl?name=client-onedir.zip"
Invoke-RestMethod -Headers $headers -Method Post -Uri $u1 -InFile $zip -ContentType "application/zip"

Write-Host "[release] Uploading hashes.txt" -ForegroundColor Cyan
$u2 = "$uploadUrl?name=hashes.txt"
Invoke-RestMethod -Headers $headers -Method Post -Uri $u2 -InFile $hashes -ContentType "text/plain"

Write-Host "[release] Release $Tag updated." -ForegroundColor Green

