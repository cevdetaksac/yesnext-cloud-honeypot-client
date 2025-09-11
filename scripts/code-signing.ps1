# Code Signing Script for Cloud Honeypot Client
# Windows Defender güven için executable imzalama

param(
    [string]$CertPath = "certs\dev-codesign.pfx",
    [string]$Password = "",
    [string]$Executable = "dist\honeypot-client\honeypot-client.exe"
)

Write-Host "🔐 Code Signing Process Starting..." -ForegroundColor Green

# Self-signed certificate oluştur (geliştirme için)
if (!(Test-Path $CertPath)) {
    Write-Host "📜 Creating self-signed certificate..." -ForegroundColor Yellow
    
    $cert = New-SelfSignedCertificate -DnsName "YesNext Technology" -Type CodeSigning -CertStoreLocation "Cert:\CurrentUser\My" -Subject "CN=YesNext Technology, O=YesNext, C=TR"
    
    # Certificate'i PFX olarak export et
    $password = ConvertTo-SecureString -String "YesNext2024!" -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $CertPath -Password $password
    
    Write-Host "✅ Self-signed certificate created: $CertPath" -ForegroundColor Green
}

# Executable'ı imzala
if (Test-Path $Executable) {
    Write-Host "✍️ Signing executable: $Executable" -ForegroundColor Yellow
    
    try {
        # SignTool kullanarak imzala
        $signToolPath = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe"
        $signTool = Get-ChildItem $signToolPath | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        
        if ($signTool) {
            & $signTool.FullName sign /f $CertPath /p "YesNext2024!" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Executable
            Write-Host "✅ Executable signed successfully!" -ForegroundColor Green
        } else {
            Write-Host "⚠️ SignTool not found. Install Windows SDK." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "⚠️ Code signing failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Executable not found: $Executable" -ForegroundColor Red
}

Write-Host "🔐 Code signing process completed!" -ForegroundColor Green
