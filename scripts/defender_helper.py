#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Defender Exclusion Helper
Cloud Honeypot Client için Defender uyumluluğu
"""

import os
import sys
import winreg
import subprocess
import hashlib
from pathlib import Path

class DefenderHelper:
    """Windows Defender uyumluluk yardımcısı"""
    
    def __init__(self):
        self.app_name = "Cloud Honeypot Client"
        self.company = "YesNext Technology"
        self.app_dir = Path(__file__).parent.parent
        
    def create_security_manifest(self):
        """Güvenlik manifestosu oluştur"""
        manifest_content = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <assemblyIdentity
        version="2.1.0.0"
        processorArchitecture="*"
        name="{self.company}.{self.app_name}"
        type="win32"/>
    <description>{self.app_name} - Network Security Monitor</description>
    <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
        <application>
            <supportedOS Id="{{e2011457-1546-43c5-a5fe-008deee3d3f0}}"/>
            <supportedOS Id="{{35138b9a-5d96-4fbd-8e2d-a2440225f93a}}"/>
            <supportedOS Id="{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}"/>
            <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}"/>
            <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
        </application>
    </compatibility>
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
            <requestedPrivileges>
                <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
            </requestedPrivileges>
        </security>
    </trustInfo>
</assembly>"""
        
        manifest_path = self.app_dir / "client.manifest"
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write(manifest_content)
        
        print(f"✅ Security manifest created: {manifest_path}")
        return manifest_path
    
    def create_file_hash_info(self):
        """Dosya hash bilgileri oluştur (güven için)"""
        exe_path = self.app_dir / "dist" / "honeypot-client" / "honeypot-client.exe"
        if not exe_path.exists():
            return None
            
        # SHA256 hash hesapla
        sha256_hash = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        hash_info = {
            "file": str(exe_path),
            "sha256": sha256_hash.hexdigest(),
            "size": exe_path.stat().st_size,
            "company": self.company,
            "product": self.app_name,
            "version": "2.1.0"
        }
        
        # Hash bilgisini dosyaya yaz
        hash_file = self.app_dir / "file_hashes.json"
        import json
        with open(hash_file, 'w') as f:
            json.dump(hash_info, f, indent=2)
        
        print(f"✅ File hash info saved: {hash_file}")
        return hash_info
    
    def create_defender_exclusion_script(self):
        """Defender exclusion script oluştur"""
        script_content = f"""# Windows Defender Exclusion Script for {self.app_name}
# Kullanıcı tarafından manuel çalıştırılmalıdır

Write-Host "🛡️ Windows Defender Exclusion Setup" -ForegroundColor Green
Write-Host "Application: {self.app_name}" -ForegroundColor Cyan

$AppPath = "$env:PROGRAMFILES\\{self.company}\\{self.app_name}"
$AppDataPath = "$env:APPDATA\\YesNext\\CloudHoneypotClient"

Write-Host "Setting up exclusions for legitimate security software..." -ForegroundColor Yellow

try {{
    # Process exclusions
    Add-MpPreference -ExclusionProcess "$AppPath\\honeypot-client.exe"
    Write-Host "✅ Process exclusion added" -ForegroundColor Green
    
    # Path exclusions
    Add-MpPreference -ExclusionPath $AppPath
    Add-MpPreference -ExclusionPath $AppDataPath
    Write-Host "✅ Path exclusions added" -ForegroundColor Green
    
    Write-Host "🎉 Defender exclusions configured successfully!" -ForegroundColor Green
    Write-Host "Note: This is a legitimate security monitoring application." -ForegroundColor Yellow
    
}} catch {{
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please run as Administrator" -ForegroundColor Yellow
}}
"""
        
        script_path = self.app_dir / "setup_defender_exclusions.ps1"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        print(f"✅ Defender exclusion script created: {script_path}")
        return script_path
    
    def create_legitimate_app_markers(self):
        """Meşru uygulama işaretleri oluştur"""
        markers = []
        
        # 1. Version info dosyası
        version_info = {
            "CompanyName": self.company,
            "FileDescription": f"{self.app_name} - Network Security Monitor",
            "FileVersion": "2.1.0",
            "InternalName": "honeypot-client",
            "LegalCopyright": f"Copyright © 2024 {self.company}",
            "OriginalFilename": "honeypot-client.exe",
            "ProductName": self.app_name,
            "ProductVersion": "2.1.0",
            "Purpose": "Network Security and Threat Detection",
            "Category": "Security Software"
        }
        
        version_file = self.app_dir / "version_info.json"
        import json
        with open(version_file, 'w') as f:
            json.dump(version_info, f, indent=2)
        markers.append(version_file)
        
        # 2. License dosyası güncelle
        license_content = f"""MIT License

Copyright (c) 2024 {self.company}

{self.app_name} is a legitimate network security monitoring application
designed to help organizations detect and analyze potential security threats.

This software is intended for authorized use only on networks where
the user has explicit permission to monitor security events.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

SECURITY SOFTWARE NOTICE:
This application is designed for network security monitoring and is intended
for use by cybersecurity professionals and system administrators.
"""
        
        license_file = self.app_dir / "LICENSE_SECURITY"
        with open(license_file, 'w') as f:
            f.write(license_content)
        markers.append(license_file)
        
        print(f"✅ Legitimate app markers created: {len(markers)} files")
        return markers
    
    def run_all_defender_helpers(self):
        """Tüm Defender yardımcılarını çalıştır"""
        print(f"🛡️ Setting up Windows Defender compatibility for {self.app_name}")
        print("=" * 60)
        
        try:
            self.create_security_manifest()
            self.create_file_hash_info()
            self.create_defender_exclusion_script()
            self.create_legitimate_app_markers()
            
            print("\n🎉 All Defender compatibility helpers created!")
            print("\n📋 Next Steps:")
            print("1. Run setup_defender_exclusions.ps1 as Administrator")
            print("2. Submit application for Microsoft SmartScreen allowlist")
            print("3. Consider purchasing code signing certificate")
            print("4. Add digital signatures to all executables")
            
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    helper = DefenderHelper()
    helper.run_all_defender_helpers()
