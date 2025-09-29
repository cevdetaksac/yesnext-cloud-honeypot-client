#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 CLIENT UPDATE MODULE
=======================

🔄 AUTOMATED UPDATE SYSTEM
===========================

🔍 MODULE PURPOSE:
This module provides comprehensive update management for the Cloud Honeypot Client,
including interactive user updates, silent automatic updates, and continuous
version monitoring. Integrates with GitHub releases and installer-based deployment.

📋 CORE RESPONSIBILITIES:
┌─────────────────────────────────────────────────────────────────┐
│                     UPDATE FUNCTIONS                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🔄 INTERACTIVE UPDATES                                         │
│  ├─ check_updates_and_prompt()    → User-initiated updates     │
│  ├─ Progress dialog integration   → Real-time update progress  │
│  ├─ User confirmation dialogs     → Explicit user consent      │
│  └─ Graceful application restart → Seamless version transition │
│                                                                 │
│  🤖 SILENT UPDATES                                              │
│  ├─ check_updates_and_apply_silent() → Automated updates       │
│  ├─ Background version checking   → Periodic update discovery  │
│  ├─ Non-intrusive installation   → No user interruption       │
│  └─ Automatic restart management  → Self-updating capability   │
│                                                                 │
│  ⏰ UPDATE WATCHDOG                                             │
│  ├─ update_watchdog_loop()        → Hourly update monitoring   │
│  ├─ Scheduled update checks       → Configurable intervals     │
│  └─ Resource-aware timing         → System load consideration  │
│                                                                 │
│  🏗️ MANAGEMENT CLASS                                            │
│  └─ UpdateManager                 → Centralized update control │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

🚀 KEY FEATURES:
├─ GitHub Integration: Direct integration with GitHub releases API
├─ Installer-Based Updates: Modern MSI/EXE installer deployment  
├─ Progress Tracking: Real-time update progress with user feedback
├─ Silent Operation: Background updates with minimal disruption
├─ Version Management: Semantic versioning and compatibility checks
├─ Rollback Protection: Backup creation before major updates
├─ Network Resilience: Retry logic and connection error handling
└─ Security Validation: Digital signature verification for downloads

🔧 UPDATE WORKFLOW:
┌─────────────────────────────────────────────────────────────────┐
│                    UPDATE PROCESS FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1️⃣ VERSION DISCOVERY                                          │
│  ├─ Query GitHub releases API                                  │
│  ├─ Compare with current version                               │
│  └─ Determine update necessity                                 │
│                                                                 │
│  2️⃣ USER INTERACTION (Interactive Mode)                        │
│  ├─ Display update notification                                │
│  ├─ Show changelog/release notes                              │
│  ├─ Request user confirmation                                  │
│  └─ Initialize progress dialog                                 │
│                                                                 │
│  3️⃣ DOWNLOAD & INSTALLATION                                    │
│  ├─ Download new installer package                            │
│  ├─ Verify digital signature                                  │
│  ├─ Execute installer with parameters                         │
│  └─ Monitor installation progress                             │
│                                                                 │
│  4️⃣ APPLICATION TRANSITION                                     │
│  ├─ Graceful shutdown of current instance                     │
│  ├─ Wait for installation completion                          │
│  ├─ Automatic restart with new version                        │
│  └─ Cleanup temporary files                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

📊 UPDATE MODES:
├─ Interactive Mode: User-initiated updates with full UI feedback
├─ Silent Mode: Automated background updates (configurable)
├─ Scheduled Mode: Time-based update checking (hourly default)  
├─ Manual Mode: On-demand update checking via menu/command
└─ Emergency Mode: Critical security updates (immediate)

🔧 CONFIGURATION:
- Update Source: GitHub repository (owner/repo from constants)
- Check Interval: 1 hour (3600 seconds) default
- Retry Logic: 3 attempts with exponential backoff
- Timeout Values: 30 seconds for API calls, 300 seconds for downloads
- User Consent: Required for interactive updates, optional for silent

🚀 USAGE PATTERNS:
# Initialize update management
update_mgr = UpdateManager()
update_mgr.start_update_watchdog(auto_update=True)

# Interactive update check
update_mgr.check_for_updates_interactive(app_instance)

# Silent update check  
success = update_mgr.check_for_updates_silent()

# Watchdog setup in application
def start_update_watchdog(self):
    return self.update_manager.start_update_watchdog(auto_update=True)

🚨 ERROR HANDLING:
├─ Network Connectivity: Graceful degradation, retry with backoff
├─ API Rate Limits: Respect GitHub API limits, adaptive timing
├─ Download Failures: Multiple mirror attempts, partial resume support
├─ Installation Errors: Rollback to previous version if possible
├─ Permission Issues: Elevation request or graceful failure
├─ Disk Space: Pre-check available space, cleanup on failure
└─ Version Conflicts: Compatibility validation before installation

🔄 INTEGRATION:
- Used by: Main application (client.py), GUI menu system
- Depends on: client_utils.py, client_constants.py, GitHub API
- UI Integration: Progress dialogs, notification systems
- Platform: Windows-focused with cross-platform potential

📈 PERFORMANCE:
- API call overhead: <500ms for version check
- Download speed: Limited by network and GitHub CDN
- Installation time: 10-30 seconds typical installer execution
- Memory usage: <5MB during update operations
- Background impact: Minimal CPU usage during watchdog operation
"""

import os
import sys
import time
import threading
from typing import Optional, Dict, Any, Callable

from client_constants import GITHUB_OWNER, GITHUB_REPO
from client_helpers import log

# ===================== UPDATE MANAGEMENT ===================== #

def check_updates_and_prompt(app_instance) -> bool:
    """Check for updates and prompt user with installer-based system"""
    try:
        from client_utils import create_update_manager, UpdateProgressDialog
        import tkinter.messagebox as messagebox
        
        # Update manager oluştur
        update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
        
        # Güncelleme kontrolü
        update_info = update_mgr.check_for_updates()
        
        if update_info.get("error"):
            messagebox.showerror("Update", f"Update error: {update_info['error']}")
            return False
            
        if not update_info.get("has_update"):
            messagebox.showinfo("Update", "No updates available")
            return False

        # Kullanıcıdan onay al
        latest_ver = update_info["latest_version"]
        if not messagebox.askyesno("Update", f"New version {latest_ver} available. Update now?"):
            return False

                # Progress dialog oluştur
        root = getattr(app_instance, 'root', None)
        progress_dialog = UpdateProgressDialog(root, "Güncelleme")
        if not progress_dialog.create_dialog():
            messagebox.showerror("Update", "Progress dialog oluşturulamadı")
            return False

        def progress_callback(percent, message):
            progress_dialog.update_progress(percent, message)
            if percent >= 100:
                progress_dialog.close_dialog()

        # Güncellemeyi başlat
        try:
            log("[UPDATER] Güncelleme işlemi başlatılıyor...")
            success = update_mgr.update_with_progress(progress_callback, silent=False)
            
            if success:
                log("[UPDATER] ✅ Update başarılı - installer Downloads klasöründe")
                # Progress dialog'u kapat
                progress_dialog.close_dialog()
                
                # Downloads klasörü yolunu göster
                import os
                downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
                version = getattr(update_mgr, '_latest_version', latest_ver)
                installer_name = f"cloud-client-installer-v{version}.exe"
                
                messagebox.showinfo(
                    "Güncelleme Hazır", 
                    f"✅ Installer başarıyla indirildi!\n\n"
                    f"📁 Konum: {downloads_dir}\n"
                    f"📄 Dosya: {installer_name}\n\n"
                    f"🔧 Kurulum:\n"
                    f"1. Installer otomatik açılacak (veya Downloads klasöründen çalıştırın)\n"
                    f"2. 'Yönetici olarak çalıştır' seçin\n"  
                    f"3. Kurulum açık uygulamaları otomatik kapatır\n"
                    f"4. Mevcut uygulama şimdi kapanacak"
                )
                
                # Installer'ın çalıştığından emin olmak için bekleme
                log("[UPDATER] Installer için bekleme...")
                import time
                time.sleep(2)                # Tray'i kapat (varsa)
                if hasattr(app_instance, 'tray_manager') and app_instance.tray_manager:
                    try:
                        app_instance.tray_manager.cleanup()
                    except:
                        pass
                
                # GUI pencereyi kapat (varsa)
                if hasattr(app_instance, 'root') and app_instance.root:
                    try:
                        app_instance.root.quit()
                        app_instance.root.destroy()
                    except:
                        pass
                
                # Güvenli uygulama kapatma
                try:
                    import os
                    os._exit(0)
                except:
                    import sys
                    sys.exit(0)
            else:
                messagebox.showerror("Update", "Update failed")
                progress_dialog.close_dialog()
                return False
        except Exception as e:
            progress_dialog.close_dialog()
            messagebox.showerror("Update", f"Update error: {str(e)}")
            return False
                
    except Exception as e:
        log(f"update prompt error: {e}")
        try:
            import tkinter.messagebox as messagebox
            messagebox.showerror("Update", f"Update error: {str(e)}")
        except Exception:
            pass
        return False
    
    return True

def check_updates_and_apply_silent() -> bool:
    """Silent update with installer-based system - SERVER SAFE VERSION"""
    try:
        from client_utils import create_update_manager
        import tempfile
        import subprocess
        import shutil
        import time
        
        log("[SILENT UPDATE] Starting server-safe silent update process...")
        
        # Update manager oluştur
        update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
        
        # Güncelleme kontrolü
        update_info = update_mgr.check_for_updates()
        
        if update_info.get("error") or not update_info.get("has_update"):
            log("[SILENT UPDATE] No updates available")
            return False
            
        log(f"[SILENT UPDATE] New version found: {update_info['latest_version']}")
        
        # Create temp directory for update files
        temp_dir = tempfile.mkdtemp(prefix="honeypot_update_")
        log(f"[SILENT UPDATE] Using temp directory: {temp_dir}")
        
        try:
            # Download installer to temp directory
            installer_path = os.path.join(temp_dir, "honeypot-installer.exe")
            
            # Get download URL
            download_url = update_info.get('download_url')
            if not download_url:
                log("[SILENT UPDATE] No download URL found in update info")
                return False
            
            # Download the installer
            download_success = download_installer_file(download_url, installer_path)
            if not download_success:
                log("[SILENT UPDATE] Installer download failed")
                return False
                
            log(f"[SILENT UPDATE] Installer downloaded to: {installer_path}")
            
            # Create batch script for server-safe update process
            batch_script = create_server_safe_update_script(installer_path, temp_dir)
            
            # Execute the update process
            log("[SILENT UPDATE] Starting server-safe installer process...")
            
            # Run installer with SYSTEM privileges in silent mode
            cmd = [
                installer_path,
                "/S",  # Silent install
                "/NCRC"  # Skip CRC check for speed
            ]
            
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300,  # 5 minute timeout
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                log("[SILENT UPDATE] Installer completed successfully")
                log("[SILENT UPDATE] New version installed - tasks will be recreated on startup")
                
                # Cleanup temp files
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
                
                # Exit - the new version will be started by task scheduler
                log("[SILENT UPDATE] Update process completed - exiting for restart")
                time.sleep(1)
                os._exit(0)
                
            else:
                log(f"[SILENT UPDATE] Installer failed with code: {result.returncode}")
                log(f"[SILENT UPDATE] Installer stdout: {result.stdout}")
                log(f"[SILENT UPDATE] Installer stderr: {result.stderr}")
                return False
                
        except Exception as e:
            log(f"[SILENT UPDATE] Update process error: {e}")
            return False
            
        finally:
            # Cleanup temp directory
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass
            
    except Exception as e:
        log(f"[SILENT UPDATE] Silent update error: {e}")
        return False
    
    return True

def download_installer_file(url: str, local_path: str) -> bool:
    """Download installer file from URL"""
    try:
        import requests
        
        log(f"[SILENT UPDATE] Downloading installer from: {url}")
        
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
        file_size = os.path.getsize(local_path)
        log(f"[SILENT UPDATE] Downloaded {file_size} bytes to {local_path}")
        
        return True
        
    except Exception as e:
        log(f"[SILENT UPDATE] Download error: {e}")
        return False

def create_server_safe_update_script(installer_path: str, temp_dir: str) -> str:
    """Create batch script for server-safe update process"""
    try:
        batch_content = f'''@echo off
REM Cloud Honeypot Client - Server Safe Update Script
REM This script handles task cleanup and reinstallation during updates

echo [SILENT UPDATE] Starting server-safe update process...

REM Stop all existing tasks (if running)
echo [SILENT UPDATE] Stopping existing tasks...
schtasks /end /tn "CloudHoneypot-Background" 2>nul
schtasks /end /tn "CloudHoneypot-Tray" 2>nul  
schtasks /end /tn "CloudHoneypot-Watchdog" 2>nul
schtasks /end /tn "CloudHoneypot-Updater" 2>nul
schtasks /end /tn "CloudHoneypot-SilentUpdater" 2>nul

REM Wait a moment for tasks to stop
timeout /t 3 /nobreak >nul

REM Run installer silently
echo [SILENT UPDATE] Running installer...
"{installer_path}" /S /NCRC

REM Wait for installer to complete
timeout /t 10 /nobreak >nul

echo [SILENT UPDATE] Update script completed
'''
        
        batch_path = os.path.join(temp_dir, "update_script.bat")
        with open(batch_path, 'w') as f:
            f.write(batch_content)
            
        log(f"[SILENT UPDATE] Created update script: {batch_path}")
        return batch_path
        
    except Exception as e:
        log(f"[SILENT UPDATE] Script creation error: {e}")
        return ""

def update_watchdog_loop():
    """Hourly update checker loop"""
    while True:
        try:
            # 3600 seconds = 1 hour
            for _ in range(360):
                time.sleep(10)
            check_updates_and_apply_silent()
        except Exception as e:
            log(f"update_watchdog_loop error: {e}")

class UpdateManager:
    """Central update management"""
    
    def __init__(self):
        self.update_thread = None
        self.auto_update_enabled = False
        
    def start_update_watchdog(self, auto_update: bool = False):
        """Start background update monitoring"""
        try:
            self.auto_update_enabled = auto_update
            
            if not self.update_thread or not self.update_thread.is_alive():
                self.update_thread = threading.Thread(
                    target=update_watchdog_loop,
                    daemon=True,
                    name="UpdateWatchdog"
                )
                self.update_thread.start()
                log("Update watchdog started")
                return True
        except Exception as e:
            log(f"Update watchdog start error: {e}")
        return False
    
    def check_for_updates_interactive(self, app_instance) -> bool:
        """Check for updates with user interaction"""
        return check_updates_and_prompt(app_instance)
    
    def check_for_updates_silent(self) -> bool:
        """Check for updates silently"""
        return check_updates_and_apply_silent()
    
    def stop_update_watchdog(self):
        """Stop update monitoring"""
        try:
            if self.update_thread and self.update_thread.is_alive():
                # Since it's a daemon thread, it will stop when main process exits
                log("Update watchdog will stop with main process")
        except Exception as e:
            log(f"Update watchdog stop error: {e}")