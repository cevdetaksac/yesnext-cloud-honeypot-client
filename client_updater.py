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

def _updater_t(key: str, **kwargs) -> str:
    """i18n helper for updater dialogs (no app instance required)."""
    try:
        from client_utils import load_i18n, resolve_app_language
        lang = resolve_app_language()
        i18n = load_i18n(language=lang)
        if isinstance(i18n, dict) and lang in i18n:
            table = i18n[lang]
        elif isinstance(i18n, dict):
            table = i18n.get("tr") or i18n.get("en") or {}
        else:
            table = {}
        text = table.get(key) or (i18n.get("en", {}) or {}).get(key) or key
        if kwargs:
            try:
                return text.format(**kwargs)
            except Exception:
                return text
        return text
    except Exception:
        return key

# ===================== UPDATE MANAGEMENT ===================== #

def show_completion_dialog(installer_path: str, version: str, parent=None):
    """After download: offer install now (primary) with reliable elevated launch."""
    import tkinter as tk
    import tkinter.ttk as ttk
    from tkinter import messagebox

    def _exit_for_update():
        """Quit quickly so NSIS can overwrite the onefile EXE."""
        try:
            import socket as _sock
            try:
                with _sock.create_connection(("127.0.0.1", 58632), timeout=0.4) as s:
                    s.sendall(b"QUIT\n")
            except Exception:
                pass
            threading.Thread(
                target=lambda: (time.sleep(0.8), os._exit(0)),
                daemon=True,
            ).start()
        except Exception:
            os._exit(0)

    def _start_install(dialog_widget=None):
        """Open NSIS installer visibly first; exit client after it starts."""
        from client_utils import (
            launch_interactive_installer_and_exit_prep,
            launch_safe_update_install,
            release_update_lock,
        )
        try:
            if not installer_path or not os.path.isfile(installer_path):
                messagebox.showerror(
                    _updater_t("error"),
                    _updater_t("update_download_fail"),
                )
                return False

            log(f"[UPDATER] Starting interactive installer: {installer_path}")

            # Primary: open the NSIS wizard NOW (what the user expects after Yes)
            ok = launch_interactive_installer_and_exit_prep(installer_path)
            if ok:
                log("[UPDATER] Installer process started (visible)")
                if dialog_widget is not None:
                    try:
                        dialog_widget.destroy()
                    except Exception:
                        pass
                # Exit immediately — NSIS is already visible; do not block on messagebox
                _exit_for_update()
                return True

            # Secondary: elevated helper (silent-style orchestrator)
            log("[UPDATER] Direct installer launch failed — trying safe helper")
            ok = launch_safe_update_install(
                installer_path,
                silent=False,
                show_gui_after=True,
                expect_exit_pid=os.getpid(),
                elevate=True,
                grace_wait_sec=15,
            )
            if ok:
                if dialog_widget is not None:
                    try:
                        dialog_widget.destroy()
                    except Exception:
                        pass
                _exit_for_update()
                return True

            release_update_lock()
            messagebox.showerror(
                _updater_t("error"),
                _updater_t("update_helper_failed"),
            )
            # Last resort: open Downloads folder
            try:
                os.startfile(os.path.dirname(installer_path))
            except Exception:
                pass
            return False
        except Exception as e:
            log(f"[UPDATER] start install error: {e}")
            try:
                release_update_lock()
            except Exception:
                pass
            messagebox.showerror(
                _updater_t("error"),
                _updater_t("update_installer_fail", err=str(e)),
            )
            return False

    try:
        # Primary path: ask immediately after download (installer must start on Yes)
        if messagebox.askyesno(
            _updater_t("update_ready"),
            _updater_t("update_ready_ask", version=version, path=installer_path),
            parent=parent,
        ):
            _start_install(None)
            return

        dialog = tk.Toplevel(parent) if parent is not None else tk.Toplevel()
        dialog.title(_updater_t("update_done_title"))
        dialog.resizable(False, False)
        try:
            dialog.transient(parent)
        except Exception:
            pass
        dialog.grab_set()

        main_frame = ttk.Frame(dialog, padding="15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        dialog.grid_rowconfigure(0, weight=1)
        dialog.grid_columnconfigure(0, weight=1)

        ttk.Label(
            main_frame,
            text=f"✅ {_updater_t('update_download_done')}",
            font=("Arial", 16, "bold"),
        ).grid(row=0, column=0, columnspan=2, pady=(0, 12))

        ttk.Label(
            main_frame,
            text=_updater_t(
                "update_download_info",
                version=version,
                filename=os.path.basename(installer_path),
            ),
            justify="left",
            wraplength=420,
        ).grid(row=1, column=0, columnspan=2, pady=(0, 12), sticky="ew")

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(5, 0), sticky="ew")

        def run_installer():
            _start_install(dialog)

        def open_downloads():
            try:
                from client_utils import release_update_lock
                release_update_lock()
                os.startfile(os.path.dirname(installer_path))
                messagebox.showinfo(
                    _updater_t("folder_opened_title"),
                    _updater_t(
                        "update_folder_opened",
                        filename=os.path.basename(installer_path),
                    ),
                )
            except Exception as e:
                messagebox.showerror(
                    _updater_t("error"),
                    _updater_t("update_folder_fail", err=str(e)),
                )

        def open_github():
            import webbrowser
            try:
                github_url = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tag/v{version}"
                webbrowser.open(github_url)
            except Exception as e:
                messagebox.showerror(
                    _updater_t("error"),
                    _updater_t("update_github_fail", err=str(e)),
                )

        def close_dialog():
            try:
                from client_utils import release_update_lock
                release_update_lock()
            except Exception:
                pass
            dialog.destroy()

        install_btn = ttk.Button(
            button_frame,
            text=f"🚀 {_updater_t('update_run_installer')}",
            command=run_installer,
            width=28,
        )
        install_btn.grid(row=0, column=0, columnspan=2, pady=(5, 3), sticky="ew")

        ttk.Button(
            button_frame,
            text=f"📁 {_updater_t('update_open_downloads')}",
            command=open_downloads,
            width=20,
        ).grid(row=1, column=0, padx=(0, 3), pady=3, sticky="ew")

        ttk.Button(
            button_frame,
            text=f"🌐 {_updater_t('update_open_github_alt')}",
            command=open_github,
            width=20,
        ).grid(row=1, column=1, padx=(3, 0), pady=3, sticky="ew")

        ttk.Button(
            button_frame,
            text=f"❌ {_updater_t('update_not_now')}",
            command=close_dialog,
            width=28,
        ).grid(row=2, column=0, columnspan=2, pady=(8, 5), sticky="ew")

        main_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        dialog.update_idletasks()
        req_width = max(main_frame.winfo_reqwidth() + 30, 450)
        req_height = max(main_frame.winfo_reqheight() + 30, 280)
        x = (dialog.winfo_screenwidth() // 2) - (req_width // 2)
        y = (dialog.winfo_screenheight() // 2) - (req_height // 2)
        dialog.geometry(f"{req_width}x{req_height}+{x}+{y}")

        try:
            dialog.lift()
            dialog.attributes("-topmost", True)
            dialog.after(400, lambda: dialog.attributes("-topmost", False))
        except Exception:
            pass

        install_btn.focus_set()
        dialog.bind("<Return>", lambda _e: run_installer())
        dialog.wait_window()

    except Exception as e:
        log(f"[UPDATE] Dialog error: {e}")
        result = messagebox.askyesno(
            _updater_t("update_ready"),
            _updater_t("update_ready_ask", version=version, path=installer_path),
        )
        if result:
            _start_install(None)


def check_updates_and_prompt(app_instance) -> bool:
    """Check for updates with immediate progress UI; then download + install start."""
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

    progress_dialog = UpdateProgressDialog(root, _updater_t("update_title"))
    if not progress_dialog.create_dialog():
        messagebox.showerror(_updater_t("update_title"), _updater_t("update_progress_fail"))
        return False

    progress_dialog.update_progress(5, _updater_t("update_checking"))
    update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)

    def _close_progress():
        progress_dialog.close_dialog()

    def _start_download(latest_ver: str, update_info: dict):
        acquire_update_lock("interactive-download")
        pause_competing_updaters()
        progress_dialog.update_progress(10, _updater_t("update_downloading", version=latest_ver))

        def _download_worker():
            try:
                def _progress(percent, message):
                    gui_safe(lambda p=percent, m=message: progress_dialog.update_progress(p, m))

                def _download_progress(percent):
                    _progress(
                        15 + int(percent * 0.8),
                        _updater_t("update_downloading_pct", percent=percent),
                    )

                installer_path = update_mgr.download_installer(
                    update_info["installer_url"],
                    _download_progress,
                )

                def _on_download_done():
                    _close_progress()
                    if installer_path:
                        log(f"[UPDATER] Download complete: {installer_path}")
                        show_completion_dialog(installer_path, latest_ver, parent=root)
                    else:
                        release_update_lock()
                        messagebox.showerror(
                            _updater_t("update_title"),
                            _updater_t("update_download_fail"),
                        )

                gui_safe(_on_download_done)
            except Exception as exc:
                log(f"[UPDATER] Download error: {exc}")
                release_update_lock()
                gui_safe(lambda: (
                    _close_progress(),
                    messagebox.showerror(_updater_t("update_title"), str(exc)),
                ))

        threading.Thread(target=_download_worker, daemon=True, name="UpdateDownload").start()

    def _check_worker():
        try:
            update_info = update_mgr.check_for_updates()

            def _on_check_done():
                if update_info.get("error"):
                    _close_progress()
                    messagebox.showerror(
                        _updater_t("update_title"),
                        _updater_t("update_error_fmt", err=update_info["error"]),
                    )
                    return

                if not update_info.get("has_update"):
                    _close_progress()
                    messagebox.showinfo(
                        _updater_t("update_title"),
                        _updater_t("update_uptodate"),
                    )
                    return

                latest_ver = update_info["latest_version"]
                _close_progress()
                if messagebox.askyesno(
                    _updater_t("update_title"),
                    _updater_t("update_found_ask", version=latest_ver),
                ):
                    if not progress_dialog.create_dialog():
                        messagebox.showerror(
                            _updater_t("update_title"),
                            _updater_t("update_progress_fail"),
                        )
                        return
                    _start_download(latest_ver, update_info)

            gui_safe(_on_check_done)
        except Exception as exc:
            log(f"update prompt error: {exc}")
            gui_safe(lambda: (
                _close_progress(),
                messagebox.showerror(_updater_t("update_title"), str(exc)),
            ))

    threading.Thread(target=_check_worker, daemon=True, name="UpdateCheck").start()
    return True

def check_updates_and_apply_silent() -> bool:
    """Silent update with installer-based system - SERVER SAFE VERSION"""
    try:
        from client_utils import (
            create_update_manager,
            is_update_in_progress,
            acquire_update_lock,
            release_update_lock,
            touch_update_lock,
            pause_competing_updaters,
        )
        import tempfile
        import subprocess
        import shutil
        import time
        
        log("[SILENT UPDATE] Starting server-safe silent update process...")

        if is_update_in_progress():
            log("[SILENT UPDATE] Skipped — another update download/install in progress")
            return False
        
        # Update manager oluştur
        update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
        
        # Güncelleme kontrolü
        update_info = update_mgr.check_for_updates()
        
        if update_info.get("error") or not update_info.get("has_update"):
            log("[SILENT UPDATE] No updates available")
            return False
            
        log(f"[SILENT UPDATE] New version found: {update_info['latest_version']}")

        # Claim machine-wide lock BEFORE download so GUI download cannot be killed
        acquire_update_lock("silent-download")
        pause_competing_updaters()
        
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
            
            # Download the installer (heartbeat via touch inside loop)
            def _silent_progress(pct):
                if pct % 10 == 0:
                    touch_update_lock()
                    log(f"[SILENT UPDATE] Download {pct}%")

            # Prefer UpdateManager download with progress when possible
            downloaded_path = update_mgr.download_installer(download_url, _silent_progress)
            if downloaded_path and os.path.isfile(downloaded_path):
                try:
                    shutil.copy2(downloaded_path, installer_path)
                except Exception:
                    installer_path = downloaded_path
            else:
                download_success = download_installer_file(download_url, installer_path)
                if not download_success:
                    log("[SILENT UPDATE] Installer download failed")
                    return False
                
            log(f"[SILENT UPDATE] Installer downloaded to: {installer_path}")
            touch_update_lock()

            # Detached elevated helper waits for THIS process to exit, then kills leftovers,
            # runs installer, recreates tasks. Never overwrite a live onefile EXE.
            from client_utils import launch_safe_update_install, release_update_lock

            # Detect interactive desktop → show GUI after; else daemon
            show_gui = False
            try:
                import ctypes
                show_gui = bool(ctypes.windll.user32.GetForegroundWindow())
            except Exception:
                show_gui = False

            ok = launch_safe_update_install(
                installer_path,
                silent=True,
                show_gui_after=show_gui,
                expect_exit_pid=os.getpid(),
                elevate=True,
            )
            if not ok:
                log("[SILENT UPDATE] Failed to launch update helper — falling back to inline install")
                from client_utils import prepare_client_for_installer
                prepare_client_for_installer(kill_processes=True)
                time.sleep(3)
                cmd = [installer_path, "/S", "/NCRC"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    release_update_lock(resume_updaters=False)
                    return True
                log(f"[SILENT UPDATE] Fallback installer failed: {result.returncode}")
                return False

            log("[SILENT UPDATE] Helper launched — exiting so install can overwrite EXE safely")
            # Keep update lock; helper clears it after install. Do NOT resume tasks yet.
            time.sleep(1.5)
            os._exit(0)
                
        except Exception as e:
            log(f"[SILENT UPDATE] Update process error: {e}")
            return False
            
        finally:
            try:
                # Success path already released without resume; failure → unlock + resume
                # (os._exit skips finally — OK; helper owns lock)
                if is_update_in_progress():
                    release_update_lock(resume_updaters=True)
            except Exception:
                pass
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
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
        last_touch = time.time()
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                sha.update(chunk)
                now = time.time()
                if now - last_touch >= 15:
                    last_touch = now
                    try:
                        from client_utils import touch_update_lock
                        touch_update_lock()
                    except Exception:
                        pass

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
    """Periodic update checker — interval from config (default 30 min)."""
    from client_utils import get_from_config

    while True:
        try:
            # Prefer minutes; fall back to hours (legacy config)
            minutes = get_from_config("updates.check_interval_minutes", None)
            if minutes is None:
                hours = float(get_from_config("updates.check_interval_hours", 0.5) or 0.5)
                minutes = max(15, int(hours * 60))
            else:
                minutes = max(15, int(minutes))
            # Sleep in 10s slices so lock / shutdown stay responsive
            for _ in range(max(1, minutes * 6)):
                time.sleep(10)
            try:
                from client_utils import is_update_in_progress
                if is_update_in_progress():
                    log("[UPDATE WATCHDOG] Skipped — update already in progress")
                    continue
            except Exception:
                pass
            if not bool(get_from_config("updates.auto_check", True)):
                continue
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