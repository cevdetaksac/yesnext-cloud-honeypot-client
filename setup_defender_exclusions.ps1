# Windows Defender Exclusion Script for Cloud Honeypot Client
# Kullanıcı tarafından manuel çalıştırılmalıdır

Write-Host "🛡️ Windows Defender Exclusion Setup" -ForegroundColor Green
Write-Host "Application: Cloud Honeypot Client" -ForegroundColor Cyan

$AppPath = "$env:PROGRAMFILES\YesNext Technology\Cloud Honeypot Client"
$AppDataPath = "$env:APPDATA\YesNext\CloudHoneypotClient"

Write-Host "Setting up exclusions for legitimate security software..." -ForegroundColor Yellow

try {
    # Process exclusions
    Add-MpPreference -ExclusionProcess "$AppPath\honeypot-client.exe"
    Write-Host "✅ Process exclusion added" -ForegroundColor Green
    
    # Path exclusions
    Add-MpPreference -ExclusionPath $AppPath
    Add-MpPreference -ExclusionPath $AppDataPath
    Write-Host "✅ Path exclusions added" -ForegroundColor Green
    
    Write-Host "🎉 Defender exclusions configured successfully!" -ForegroundColor Green
    Write-Host "Note: This is a legitimate security monitoring application." -ForegroundColor Yellow
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please run as Administrator" -ForegroundColor Yellow
}
