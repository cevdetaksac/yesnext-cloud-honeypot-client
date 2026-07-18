#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Updater — Installer-based update system via GitHub releases.

Interactive & silent update modes with progress dialogs.
Hourly watchdog loop for automatic background updates.

Key exports:
  UpdateManager                    — start_update_watchdog(), interactive/silent checks
  check_updates_and_prompt(app)    — interactive update with UI dialogs
  check_updates_and_apply_silent() — background NSIS silent install
  update_watchdog_loop()           — hourly update check (daemon thread)
"""

import os
import sys
import time
import threading
from typing import Optional, Dict, Any, Callable

from client_constants import GITHUB_OWNER, GITHUB_REPO
from client_helpers import log

# ===================== UPDATE MANAGEMENT ===================== #

def show_completion_dialog(installer_path: str, version: str):
    """İndirme tamamlandığında özel dialog göster"""
    import tkinter as tk
    import tkinter.ttk as ttk
    from tkinter import messagebox
    import os
    import subprocess
    import webbrowser
    
    try:
        # Ana dialog penceresi
        dialog = tk.Toplevel()
        dialog.title("Güncelleme Tamamlandı")
        dialog.resizable(False, False)
        dialog.grab_set()  # Modal yap
        
        # Ana frame - önce oluştur
        main_frame = ttk.Frame(dialog, padding="15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Dialog grid konfigürasyonu
        dialog.grid_rowconfigure(0, weight=1)
        dialog.grid_columnconfigure(0, weight=1)
        
        # Başlık
        title_label = ttk.Label(main_frame, text="✅ İndirme Tamamlandı!", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Bilgi metni - daha kompakt
        info_text = f"""📥 Yeni sürüm başarıyla indirildi: v{version}
📁 Konum: Downloads klasörü
📄 Dosya: {os.path.basename(installer_path)}

🔧 İlerlemek için aşağıdaki seçeneklerden birini kullanın:"""
        
        info_label = ttk.Label(main_frame, text=info_text, justify="left", wraplength=420)
        info_label.grid(row=1, column=0, columnspan=2, pady=(0, 15), sticky="ew")
        
        # Butonlar frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(5, 0), sticky="ew")
        
        def run_installer():
            """Installer'ı çalıştır — önce başlat, sonra süreçleri kapat."""
            try:
                from client_utils import prepare_client_for_installer, release_update_lock

                # Installer önce açılsın; QUIT/kill sonrası Start-Process kaçmasın
                cmd = f'powershell -Command "Start-Process -FilePath \\"{installer_path}\\" -Verb RunAs"'
                subprocess.run(cmd, shell=True, check=False,
                              creationflags=subprocess.CREATE_NO_WINDOW)

                release_update_lock(resume_updaters=False)
                prepare_client_for_installer(kill_processes=True)

                messagebox.showinfo(
                    "Installer Başlatıldı",
                    "Installer başlatıldı.\n\n"
                    "UAC onayını verin; mevcut uygulama otomatik kapanacak ve kurulum tamamlanacak."
                )
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Hata", f"Installer başlatılamadı:\n{str(e)}")
        
        def open_downloads():
            """Downloads klasörünü aç"""
            try:
                from client_utils import release_update_lock
                release_update_lock()
                os.startfile(os.path.dirname(installer_path))
                messagebox.showinfo(
                    "Klasör Açıldı", 
                    f"📁 Downloads klasörü açıldı!\n\n"
                    f"🔧 Manuel kurulum:\n"
                    f"1. {os.path.basename(installer_path)} dosyasına sağ tıklayın\n"
                    f"2. 'Yönetici olarak çalıştır' seçin\n"
                    f"3. UAC onayını verin"
                )
            except Exception as e:
                messagebox.showerror("Hata", f"Klasör açılamadı:\n{str(e)}")
        
        def open_github():
            """GitHub releases sayfasını aç"""
            try:
                github_url = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tag/v{version}"
                webbrowser.open(github_url)
                messagebox.showinfo(
                    "GitHub Açıldı", 
                    f"🌐 GitHub releases sayfası açıldı!\n\n"
                    f"Alternatif olarak oradan da indirebilirsiniz:\n"
                    f"{github_url}"
                )
            except Exception as e:
                messagebox.showerror("Hata", f"GitHub açılamadı:\n{str(e)}")
        
        def close_dialog():
            """Dialog'u kapat"""
            try:
                from client_utils import release_update_lock
                release_update_lock()
            except Exception:
                pass
            dialog.destroy()
        
        # Ana installer butonu
        install_btn = ttk.Button(button_frame, text="🚀 Installer'ı Çalıştır", 
                                command=run_installer, width=25)
        install_btn.grid(row=0, column=0, columnspan=2, pady=(5, 3), sticky="ew")
        
        # Alternatif butonlar
        downloads_btn = ttk.Button(button_frame, text="📁 Downloads Klasörü", 
                                  command=open_downloads, width=20)
        downloads_btn.grid(row=1, column=0, padx=(0, 3), pady=3, sticky="ew")
        
        github_btn = ttk.Button(button_frame, text="🌐 GitHub Alternatif", 
                               command=open_github, width=20)
        github_btn.grid(row=1, column=1, padx=(3, 0), pady=3, sticky="ew")
        
        # Kapat butonu
        close_btn = ttk.Button(button_frame, text="❌ Şimdi Değil", 
                              command=close_dialog, width=25)
        close_btn.grid(row=2, column=0, columnspan=2, pady=(8, 5), sticky="ew")
        
        # Grid weights
        main_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        
        # İçerik yüklendikten sonra boyutu ayarla
        dialog.update_idletasks()
        
        # Gereken minimum boyutu hesapla
        req_width = main_frame.winfo_reqwidth() + 30
        req_height = main_frame.winfo_reqheight() + 30
        
        # Minimum ve maksimum boyutları belirle
        min_width = max(req_width, 450)
        min_height = max(req_height, 300)
        max_width = min(min_width, 600)
        max_height = min(min_height, 500)
        
        # Dialog boyutunu ayarla
        dialog.geometry(f"{max_width}x{max_height}")
        
        # Pencereyi ortala
        x = (dialog.winfo_screenwidth() // 2) - (max_width // 2)
        y = (dialog.winfo_screenheight() // 2) - (max_height // 2)
        dialog.geometry(f"{max_width}x{max_height}+{x}+{y}")
        
        # Ana installer butonuna focus ver
        install_btn.focus()
        
        # Dialog'u çalıştır
        dialog.wait_window()
        
    except Exception as e:
        # Fallback - basit messagebox
        log(f"[UPDATE] Dialog error: {e}")
        result = messagebox.askyesno(
            "Güncelleme Hazır",
            f"✅ v{version} indirildi!\n\n"
            f"📁 {installer_path}\n\n"
            f"Installer'ı şimdi çalıştırmak ister misiniz?"
        )
        if result:
            try:
                cmd = f'powershell -Command "Start-Process -FilePath \\"{installer_path}\\" -Verb RunAs"'
                subprocess.run(cmd, shell=True, check=False,
                              creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e2:
                messagebox.showerror("Hata", f"Installer başlatılamadı: {e2}")

def check_updates_and_prompt(app_instance) -> bool:
    """Check for updates with immediate progress UI; installer starts only on user action."""
    import threading
    import tkinter.messagebox as messagebox
    from client_utils import (
        create_update_manager,
        UpdateProgressDialog,
        acquire_update_lock,
        release_update_lock,
        pause_competing_updaters,
    )

    root = getattr(app_instance, "root", None)
    gui_safe = getattr(app_instance, "_gui_safe", lambda fn: fn())

    progress_dialog = UpdateProgressDialog(root, "Güncelleme")
    if not progress_dialog.create_dialog():
        messagebox.showerror("Güncelleme", "İlerleme penceresi açılamadı")
        return False

    progress_dialog.update_progress(5, "Güncelleme kontrol ediliyor...")
    update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)

    def _close_progress():
        progress_dialog.close_dialog()

    def _start_download(latest_ver: str, update_info: dict):
        # SilentUpdater / kill-honeypot indirme ortasında süreçleri öldürmesin
        acquire_update_lock("interactive-download")
        pause_competing_updaters()
        progress_dialog.update_progress(10, f"v{latest_ver} indiriliyor...")

        def _download_worker():
            try:
                def _progress(percent, message):
                    gui_safe(lambda p=percent, m=message: progress_dialog.update_progress(p, m))

                def _download_progress(percent):
                    _progress(15 + int(percent * 0.8), f"İndiriliyor... %{percent}")

                installer_path = update_mgr.download_installer(
                    update_info["installer_url"],
                    _download_progress,
                )

                def _on_download_done():
                    _close_progress()
                    if installer_path:
                        log("[UPDATER] İndirme tamamlandı — kullanıcı onayı bekleniyor")
                        show_completion_dialog(installer_path, latest_ver)
                    else:
                        release_update_lock()
                        messagebox.showerror(
                            "Güncelleme",
                            "Installer indirilemedi. Lütfen daha sonra tekrar deneyin.",
                        )

                gui_safe(_on_download_done)
            except Exception as exc:
                log(f"[UPDATER] İndirme hatası: {exc}")
                release_update_lock()
                gui_safe(lambda: (_close_progress(), messagebox.showerror("Güncelleme", str(exc))))

        threading.Thread(target=_download_worker, daemon=True, name="UpdateDownload").start()

    def _check_worker():
        try:
            update_info = update_mgr.check_for_updates()

            def _on_check_done():
                if update_info.get("error"):
                    _close_progress()
                    messagebox.showerror("Güncelleme", f"Hata: {update_info['error']}")
                    return

                if not update_info.get("has_update"):
                    _close_progress()
                    messagebox.showinfo("Güncelleme", "Yüklü sürüm güncel.")
                    return

                latest_ver = update_info["latest_version"]
                _close_progress()
                if messagebox.askyesno(
                    "Güncelleme",
                    f"Yeni sürüm v{latest_ver} mevcut.\n\nŞimdi indirmek ister misiniz?",
                ):
                    if not progress_dialog.create_dialog():
                        messagebox.showerror("Güncelleme", "İlerleme penceresi açılamadı")
                        return
                    _start_download(latest_ver, update_info)

            gui_safe(_on_check_done)
        except Exception as exc:
            log(f"update prompt error: {exc}")
            gui_safe(lambda: (_close_progress(), messagebox.showerror("Güncelleme", str(exc))))

    threading.Thread(target=_check_worker, daemon=True, name="UpdateCheck").start()
    return True

def check_updates_and_apply_silent() -> bool:
    """Silent update with installer-based system - SERVER SAFE VERSION"""
    try:
        from client_utils import create_update_manager, is_update_in_progress
        import tempfile
        import subprocess
        import shutil
        import time
        
        log("[SILENT UPDATE] Starting server-safe silent update process...")

        if is_update_in_progress():
            log("[SILENT UPDATE] Skipped — interactive update download in progress")
            return False
        
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
            download_url = update_info.get('installer_url') or update_info.get('download_url')
            if not download_url:
                log("[SILENT UPDATE] No download URL found in update info")
                return False
            
            # Download the installer
            download_success = download_installer_file(download_url, installer_path)
            if not download_success:
                log("[SILENT UPDATE] Installer download failed")
                return False
                
            log(f"[SILENT UPDATE] Installer downloaded to: {installer_path}")
            
            from client_utils import prepare_client_for_installer
            prepare_client_for_installer()
            
            # Execute the update process
            # Installer kendi task management'ini yapacak
            log("[SILENT UPDATE] Starting installer process...")
            
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
                log("[SILENT UPDATE] New version will be started automatically by installer")
                
                # Cleanup temp files
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
                
                # Installer başarılı - uygulama açık kalır
                # Installer kendi restart işlemini yapacak
                log("[SILENT UPDATE] ✅ Silent update completed - installer will handle app restart")
                return True
                
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

def download_installer_file(url: str, local_path: str, expected_sha256: str = "") -> bool:
    """Download installer file from URL with optional SHA-256 verification."""
    try:
        import hashlib
        import requests
        from client_security_utils import resolve_tls_verify
        from client_utils import get_from_config

        verify_checksum = bool(get_from_config("updates.verify_checksum", True))
        log(f"[SILENT UPDATE] Downloading installer from: {url}")

        response = requests.get(url, stream=True, timeout=60, verify=resolve_tls_verify())
        response.raise_for_status()

        sha = hashlib.sha256()
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                sha.update(chunk)

        file_size = os.path.getsize(local_path)
        digest = sha.hexdigest()
        log(f"[SILENT UPDATE] Downloaded {file_size} bytes, sha256={digest[:16]}…")

        if verify_checksum and expected_sha256:
            if digest.lower() != expected_sha256.lower():
                log("[SILENT UPDATE] Checksum mismatch — aborting install")
                try:
                    os.remove(local_path)
                except OSError:
                    pass
                return False

        return True

    except Exception as e:
        log(f"[SILENT UPDATE] Download error: {e}")
        return False



def update_watchdog_loop():
    """Hourly update checker loop"""
    while True:
        try:
            # 3600 seconds = 1 hour
            for _ in range(360):
                time.sleep(10)
            try:
                from client_utils import is_update_in_progress
                if is_update_in_progress():
                    log("[UPDATE WATCHDOG] Skipped — interactive update in progress")
                    continue
            except Exception:
                pass
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