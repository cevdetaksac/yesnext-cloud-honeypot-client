#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLIENT TRAY MODULE — System tray integration for Cloud Honeypot Client.
Version: See client_constants.VERSION

Provides:
  - TrayManager class: centralized tray icon lifecycle, context menu, window show/hide/exit
  - Dynamic status icons: green (active tunnels) / red (inactive) via pystray + PIL
  - Fallback: programmatic icon generation if .ico files are missing
  - Thread model: daemon thread for tray loop, thread-safe UI coordination

Used by: client.py (initialize_tray_manager, update_tray_icon, on_close)
Depends on: client_constants, client_helpers, pystray, PIL
"""

import os
import ctypes
import threading
from typing import Optional, Callable, Any

from client_constants import TRY_TRAY, __version__
from client_helpers import log

# Optional tray support - import after constants are loaded
if TRY_TRAY:
    try:
        import pystray
        from pystray import MenuItem as TrayItem
        from PIL import Image, ImageDraw
    except ImportError:
        TRY_TRAY = False

# ===================== TRAY MANAGEMENT ===================== #

def tray_make_image(active: bool) -> Image.Image:
    """Load appropriate tray icon based on protection status"""
    try:
        from client_utils import get_resource_path
        
        # Determine icon file based on state
        if active:
            icon_file = get_resource_path("certs/honeypot_active_16.ico")
        else:
            icon_file = get_resource_path("certs/honeypot_inactive_16.ico")
        
        # Try to load from file system first
        if os.path.exists(icon_file):
            from PIL import Image
            log(f"Loading tray icon: {icon_file}")
            return Image.open(icon_file)
        
        # Fallback to programmatic generation
        from PIL import Image, ImageDraw
        size = 16
        bg_color = (76, 175, 80, 255) if active else (244, 67, 54, 255)  # Green or Red
        
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw background circle
        center = size // 2
        radius = int(size * 0.4)
        draw.ellipse([center - radius, center - radius, 
                      center + radius, center + radius], 
                     fill=bg_color)
        
        # Draw simplified cloud shape
        cloud_color = (255, 255, 255, 255)  # White
        cloud_radius = int(size * 0.2)
        draw.ellipse([center - cloud_radius, center - cloud_radius,
                      center + cloud_radius, center + cloud_radius],
                     fill=cloud_color)
        
        return img
        
    except Exception as e:
        # Ultimate fallback - simple colored circle
        from PIL import Image, ImageDraw
        col = "green" if active else "red"
        img = Image.new('RGB', (16, 16), "white")
        d = ImageDraw.Draw(img)
        d.ellipse((2, 2, 14, 14), fill=col)
        return img

def update_window_icon(root, is_active: bool):
    """Update window icon based on protection status"""
    if not root: return
    try:
        from client_utils import get_resource_path
        
        if is_active:
            window_icon_path = get_resource_path('certs/honeypot_active_32.ico')
        else:
            window_icon_path = get_resource_path('certs/honeypot_inactive_32.ico')
        
        if os.path.exists(window_icon_path):
            root.iconbitmap(window_icon_path)
            
    except Exception as e:
        log(f"Window icon update error: {e}")

class TrayManager:
    """System tray management"""
    
    def __init__(self, app_instance, translation_func: Callable[[str], str]):
        self.app_instance = app_instance
        self.t = translation_func
        self.tray_icon = None
        self.tray_thread = None
        self.show_callback = None
        self.minimize_callback = None
        

    def is_protection_active(self) -> bool:
        """Check if any honeypot service is currently active via ServiceManager"""
        try:
            if hasattr(self.app_instance, 'service_manager'):
                running = self.app_instance.service_manager.running_services
                if not running:
                    log("[TRAY] ⚠️ WARNING: Honeypot servisleri başlatılamadı! Hiçbir aktif servis yok.")
                return len(running) > 0
        except Exception as e:
            log(f"[TRAY] Protection status check error: {e}")
        
        return False

    def update_tray_icon(self):
        """Update tray icon to reflect current protection status"""
        is_active = self.is_protection_active()
        
        # Update tray icon
        if TRY_TRAY and self.tray_icon:
            try:
                new_icon = tray_make_image(is_active)
                self.tray_icon.icon = new_icon
                
                # Update title with status
                status = self.t("protection_active") if is_active else self.t("protection_inactive")
                self.tray_icon.title = f"{self.t('app_title')} - {status}"
                
            except Exception as e:
                log(f"Tray icon update error: {e}")
                
        # Update window icon as well
        if hasattr(self.app_instance, 'root') and self.app_instance.root:
            update_window_icon(self.app_instance.root, is_active)
    
    def show_window(self):
        """Show main window from tray (must run on Tk main thread)."""
        def _do_show():
            try:
                root = getattr(self.app_instance, 'root', None)
                if not root or not root.winfo_exists():
                    return

                self.app_instance._tray_mode.clear()
                root.deiconify()
                root.update_idletasks()
                root.lift()
                root.attributes("-topmost", True)
                root.after(150, lambda: root.attributes("-topmost", False))
                root.focus_force()

                # Windows: bring window to foreground (focus_force alone is often ignored)
                if os.name == "nt":
                    try:
                        hwnd = root.winfo_id()
                        # CTk may need parent HWND on some setups
                        parent = ctypes.windll.user32.GetParent(hwnd)
                        target = parent if parent else hwnd
                        ctypes.windll.user32.SetForegroundWindow(target)
                    except Exception:
                        pass

                from client_constants import WINDOW_WIDTH, WINDOW_HEIGHT
                sw = root.winfo_screenwidth()
                sh = root.winfo_screenheight()
                cx = int(sw / 2 - WINDOW_WIDTH / 2)
                cy = int(sh / 2 - WINDOW_HEIGHT / 2)
                root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{cx}+{cy}")
            except Exception as e:
                log(f"Show window error: {e}")

        try:
            if hasattr(self.app_instance, '_gui_safe'):
                self.app_instance._gui_safe(_do_show)
            elif getattr(self.app_instance, 'root', None):
                self.app_instance.root.after(0, _do_show)
        except Exception as e:
            log(f"Show window schedule error: {e}")
                
    def minimize_to_tray(self):
        """Minimize window to tray (Tk main thread)."""
        def _do_minimize():
            try:
                # Onboarding / no token → keep window visible for dashboard registration
                try:
                    from client_utils import should_force_gui_visible
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    if should_force_gui_visible(bool(tok)):
                        log("[TRAY] Skip minimize — onboarding / registration required")
                        self.show_window()
                        return
                except Exception:
                    pass
                root = getattr(self.app_instance, 'root', None)
                if root and root.winfo_exists():
                    self.app_instance._tray_mode.set()
                    root.withdraw()
            except Exception as e:
                log(f"Minimize error: {e}")

        try:
            if hasattr(self.app_instance, '_gui_safe'):
                self.app_instance._gui_safe(_do_minimize)
            elif getattr(self.app_instance, 'root', None):
                self.app_instance.root.after(0, _do_minimize)
        except Exception as e:
            log(f"Minimize schedule error: {e}")
                
    def exit_app(self):
        """Exit application from tray"""
        # ServiceManager üzerinden aktif servis kontrolü
        active_services_exist = False
        try:
            if hasattr(self.app_instance, 'service_manager'):
                running = self.app_instance.service_manager.running_services
                if running:
                    active_services_exist = True
                    log(f"[EXIT] Aktif servisler bulundu: {running}")
        except Exception as e:
            log(f"[EXIT] Servis durumu kontrol hatası: {e}")
        
        if active_services_exist:
            try:
                import tkinter.messagebox as messagebox
                messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
            except:
                pass
            return
        
        # Son offline heartbeat gönder
        try:
            self.app_instance.send_heartbeat_once("offline")
            log("[EXIT] Offline heartbeat sent before exit")
        except Exception as e:
            log(f"[EXIT] Heartbeat error during exit: {e}")
        
        # Cleanup heartbeat file
        try:
            from client_monitoring import cleanup_heartbeat_file
            cleanup_heartbeat_file(getattr(self.app_instance, 'heartbeat_path', ''))
        except Exception as e:
            log(f"[EXIT] Heartbeat cleanup error: {e}")
            
        # Watchdog'u durdur
        try:
            from client_utils import write_watchdog_token
            from client_constants import WATCHDOG_TOKEN_FILE
            write_watchdog_token('stop', WATCHDOG_TOKEN_FILE)
        except Exception as e:
            log(f"Watchdog stop error: {e}")
            
        # Tray ikonunu kaldır
        try:
            if self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass
            
        # Merkezi temiz çıkış
        self.app_instance.graceful_exit(0)
    
    def tray_loop(self):
        """Main tray loop - runs in background thread"""
        if not TRY_TRAY: return
        # Tray ikonu oluştur
        icon = pystray.Icon("honeypot_client")
        self.tray_icon = icon
        icon.title = f"{self.t('app_title')} v{__version__}"
        icon.icon = tray_make_image(self.app_instance.state.get("running", False))
        
        # Callback'leri kaydet
        self.show_callback = self.show_window
        self.minimize_callback = self.minimize_to_tray
        
        # Tray menüsünü oluştur
        try:
            def _open_dashboard():
                try:
                    import webbrowser
                    from client_constants import API_URL
                    base = API_URL.rsplit("/api", 1)[0]
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    url = f"{base}/dashboard?token={tok}" if tok else f"{base}/dashboard"
                    webbrowser.open(url)
                    try:
                        from client_utils import clear_force_gui_onboarding
                        if tok:
                            clear_force_gui_onboarding()
                    except Exception:
                        pass
                except Exception as e:
                    log(f"tray dashboard open error: {e}")

            def _copy_token():
                try:
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    root = getattr(self.app_instance, "root", None)
                    if root and tok:
                        def _clip():
                            root.clipboard_clear()
                            root.clipboard_append(tok)
                            root.update()
                        if hasattr(self.app_instance, "_gui_safe"):
                            self.app_instance._gui_safe(_clip)
                        else:
                            root.after(0, _clip)
                        self.notify(self.t("copy"), self.t("token_copied_toast"))
                except Exception as e:
                    log(f"tray copy token error: {e}")

            def _link_account():
                try:
                    self.show_window()
                    gui = getattr(self.app_instance, "gui", None)
                    if gui and hasattr(gui, "_open_link_account"):
                        tok = ""
                        if hasattr(self.app_instance, "get_token"):
                            tok = self.app_instance.get_token() or ""
                        tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                        # Schedule on Tk thread after window shown
                        root = getattr(self.app_instance, "root", None)
                        if root:
                            root.after(200, lambda: gui._open_link_account(tok))
                        else:
                            gui._open_link_account(tok)
                        return
                    # Fallback: browser
                    import webbrowser
                    from client_constants import API_URL
                    base = API_URL.rsplit("/api", 1)[0]
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    if tok:
                        _copy_token()
                    webbrowser.open(f"{base}/servers" if tok else f"{base}/?login=1")
                except Exception as e:
                    log(f"tray link account error: {e}")

            from client_constants import SERVER_NAME
            from client_utils import is_account_linked, refresh_account_link_status
            # Prefer API truth when tray menu is built (short timeout inside)
            try:
                tok = ""
                if hasattr(self.app_instance, "get_token"):
                    tok = self.app_instance.get_token() or ""
                tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                if tok:
                    refresh_account_link_status(
                        tok,
                        api_client=getattr(self.app_instance, "api_client", None),
                    )
            except Exception:
                pass
            host_label = f"{SERVER_NAME}"[:40]
            account_item = (
                TrayItem(self.t('btn_account_linked'), lambda: _link_account())
                if is_account_linked()
                else TrayItem(self.t('btn_link_account'), lambda: _link_account())
            )
            menu = pystray.Menu(
                TrayItem(self.t('tray_show'), lambda: self.show_window(), default=True),
                TrayItem(host_label, lambda: None, enabled=False),
                TrayItem(self.t('tray_dashboard'), lambda: _open_dashboard()),
                account_item,
                TrayItem(self.t('menu_copy_token'), lambda: _copy_token()),
                TrayItem(self.t('tray_exit'), lambda: self.exit_app())
            )
            icon.menu = menu
        except Exception as e:
            log(f"Tray menu error: {e}")
            # Fallback: basit menü
            icon.menu = (
                TrayItem(self.t('tray_show'), lambda: self.show_window()),
                TrayItem(self.t('tray_exit'), lambda: self.exit_app())
            )
            
        # Tray ikonunu başlat    
        icon.run()

    def start_tray_system(self):
        """Start tray system in background thread"""
        if not TRY_TRAY:
            log("Tray support not available")
            return False
            
        try:
            self.tray_thread = threading.Thread(
                target=self.tray_loop, 
                daemon=True,
                name="TrayManager"
            )
            self.tray_thread.start()
            log("Tray system started")
            return True
        except Exception as e:
            log(f"Tray system start error: {e}")
            return False
    
    def stop_tray_system(self):
        """Stop tray system"""
        try:
            if self.tray_icon:
                self.tray_icon.stop()
            log("Tray system stopped")
        except Exception as e:
            log(f"Tray system stop error: {e}")

    def notify(self, title: str, message: str):
        """Tray balloon / notification (thread-safe)."""
        if not TRY_TRAY or not self.tray_icon:
            return
        try:
            # pystray 0.19+ notify
            if hasattr(self.tray_icon, "notify"):
                self.tray_icon.notify(message, title)
                return
        except Exception as e:
            log(f"Tray notify error: {e}")
        # Fallback: Windows balloon via ctypes
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes
                NIIF_INFO = 0x01
                NIM_MODIFY = 0x01
                class NOTIFYICONDATAW(ctypes.Structure):
                    _fields_ = [
                        ("cbSize", wintypes.DWORD),
                        ("hWnd", wintypes.HWND),
                        ("uID", wintypes.UINT),
                        ("uFlags", wintypes.UINT),
                        ("uCallbackMessage", wintypes.UINT),
                        ("hIcon", wintypes.HICON),
                        ("szTip", wintypes.WCHAR * 128),
                        ("dwState", wintypes.DWORD),
                        ("dwStateMask", wintypes.DWORD),
                        ("szInfo", wintypes.WCHAR * 256),
                        ("uVersion", wintypes.UINT),
                        ("szInfoTitle", wintypes.WCHAR * 64),
                        ("dwInfoFlags", wintypes.DWORD),
                    ]
                flags = 0x10  # NIF_INFO
                nid = NOTIFYICONDATAW()
                nid.cbSize = ctypes.sizeof(nid)
                nid.uID = 1
                nid.uFlags = flags
                nid.szInfoTitle = title[:63]
                nid.szInfo = message[:255]
                nid.dwInfoFlags = NIIF_INFO
                ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
            except Exception as ex:
                log(f"Tray balloon fallback error: {ex}")
    
    def on_window_close(self):
        """Handle main window close event"""
        try:
            # Tray ikonu varsa minimize et
            if TRY_TRAY and self.tray_icon:
                if self.minimize_callback:
                    self.minimize_callback()
            # Tray yoksa normal kapat
            else:
                if self.app_instance.state.get("running", False):
                    try:
                        import tkinter.messagebox as messagebox
                        messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
                    except:
                        pass
                    return
                    
                if hasattr(self.app_instance, 'root') and self.app_instance.root:
                    self.app_instance.root.destroy()
                    
                self.app_instance.graceful_exit(0)
        except Exception as e:
            log(f"Window close error: {e}")