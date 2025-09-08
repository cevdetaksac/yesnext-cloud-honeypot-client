:: Signtool komutu ile dijital imzalama örneği
:: installer ve exe dosyalarını .pfx ile imzalar
:: Windows SDK'nın yüklü olması gerekir

set SIGNTOOL="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
set PFX_PATH="certs\dev-codesign.pfx"
set PFX_PASS="tqq7d8qx8c"

%SIGNTOOL% sign /f %PFX_PATH% /p %PFX_PASS% /tr http://timestamp.digicert.com /td sha256 /fd sha256 client-onedir.exe
%SIGNTOOL% sign /f %PFX_PATH% /p %PFX_PASS% /tr http://timestamp.digicert.com /td sha256 /fd sha256 cloud-client-installer.exe
