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
            """Installer'ı çalıştır"""
            try:
                # PowerShell admin escalation ile başlat
                # Installer kendi task management'ini yapacak
                cmd = f'powershell -Command "Start-Process -FilePath \\"{installer_path}\\" -Verb RunAs"'
                subprocess.run(cmd, shell=True, check=False,
                              creationflags=subprocess.CREATE_NO_WINDOW)
                
                messagebox.showinfo(
                    "Installer Başlatıldı",
                    "✅ Installer başlatıldı!\n\n"
                    "UAC onayını verin ve kurulum sürecini takip edin.\n"
                    "Kurulum tamamlandıktan sonra bu uygulama otomatik kapatılacak."
                )
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Hata", f"Installer başlatılamadı:\n{str(e)}")
        
        def open_downloads():
            """Downloads klasörünü aç"""
            try:
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
                
                # Downloads klasörü yolunu al
                import os
                downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
                version = getattr(update_mgr, '_latest_version', latest_ver)
                installer_name = f"cloud-client-installer-v{version}.exe"
                installer_path = os.path.join(downloads_dir, installer_name)
                
                # Özel tamamlanma dialog'u göster
                show_completion_dialog(installer_path, version)
                
                # Installer başlatıldı - uygulama açık kalacak
                log("[UPDATER] ✅ Interactive update tamamlandı - kullanıcı installer'ı çalıştırabilir")
                return True
            else:
                progress_dialog.close_dialog()
                
                # Update başarısız - kullanıcıya alternatif sunalım
                log("[UPDATER] ⚠️ Installer otomatik başlatılamadı - manuel seçenekler sunuluyor")
                
                # Downloads klasöründeki dosya var mı kontrol et
                import os
                downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
                version = getattr(update_mgr, '_latest_version', latest_ver)
                installer_name = f"cloud-client-installer-v{version}.exe"
                installer_path = os.path.join(downloads_dir, installer_name)
                
                if os.path.exists(installer_path):
                    # Dosya var - manuel çalıştırma seçenekleri sun
                    result = messagebox.askyesnocancel(
                        "Manuel Kurulum Gerekli",
                        f"⚠️ Installer otomatik başlatılamadı\n\n"
                        f"📁 Ancak dosya başarıyla indirildi:\n"
                        f"{installer_path}\n\n"
                        f"📋 Seçenekleriniz:\n"
                        f"• EVET: Downloads klasörünü aç (manuel çalıştırma)\n"
                        f"• HAYIR: GitHub'dan direkt indir\n"
                        f"• İPTAL: Güncellemeyi ertele\n\n"
                        f"Downloads klasörünü açmak istiyor musunuz?"
                    )
                    
                    if result is True:  # YES - Downloads klasörünü aç
                        try:
                            os.startfile(downloads_dir)
                            messagebox.showinfo(
                                "Manuel Kurulum",
                                f"📁 Downloads klasörü açıldı!\n\n"
                                f"🔧 Kurulum adımları:\n"
                                f"1. {installer_name} dosyasına çift tıklayın\n"
                                f"2. 'Yönetici olarak çalıştır' seçin\n"
                                f"3. UAC onayını verin\n"
                                f"4. Kurulum otomatik tamamlanacak"
                            )
                            return True
                        except Exception as e:
                            log(f"[UPDATER] Downloads klasörü açma hatası: {e}")
                            
                    elif result is False:  # NO - GitHub'a yönlendir
                        github_url = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tag/v{version}"
                        
                        try:
                            import webbrowser
                            webbrowser.open(github_url)
                            messagebox.showinfo(
                                "GitHub İndirme",
                                f"🌐 GitHub releases sayfası açıldı!\n\n"
                                f"📋 Adımlar:\n"
                                f"1. 'cloud-client-installer.exe' linkine tıklayın\n"
                                f"2. İndirme tamamlandıktan sonra dosyayı çalıştırın\n"
                                f"3. 'Yönetici olarak çalıştır' seçin\n\n"
                                f"🔗 Link: {github_url}"
                            )
                            return True
                        except Exception as e:
                            log(f"[UPDATER] GitHub açma hatası: {e}")
                            messagebox.showerror("Hata", f"GitHub sayfası açılamadı.\n\nManuel link:\n{github_url}")
                    
                    # İptal durumunda hiçbir şey yapma
                    return False
                    
                else:
                    # Dosya da yok - sadece GitHub'a yönlendir
                    github_url = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tag/v{version}"
                    
                    result = messagebox.askyesno(
                        "İndirme Başarısız",
                        f"❌ Güncelleme indirilemedi\n\n"
                        f"🌐 GitHub'dan manuel indirebilirsiniz:\n"
                        f"{github_url}\n\n"
                        f"GitHub sayfasını açmak istiyor musunuz?"
                    )
                    
                    if result:
                        try:
                            import webbrowser
                            webbrowser.open(github_url)
                            return True
                        except Exception as e:
                            log(f"[UPDATER] GitHub açma hatası: {e}")
                            messagebox.showerror("Hata", f"GitHub sayfası açılamadı.\n\nManuel link:\n{github_url}")
                    
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