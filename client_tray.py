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
    if not root:
        return
        
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
        """Check if any enabled tunnel service is currently active"""
        active_enabled_services = 0
        total_enabled_services = 0
        
        try:
            # Config'den enabled servisleri al
            from client_constants import get_app_config
            config = get_app_config()
            default_ports = config.get("tunnels", {}).get("default_ports", [])
            
            # Aktif tunnels'ları al  
            active_tunnels = self.app_instance.get_active_tunnels()
            # Port mapping dictionary'si oluştur (local_port -> tunnel object)
            tunnel_ports = {}
            if active_tunnels:
                for tunnel in active_tunnels:
                    if 'local_port' in tunnel:
                        tunnel_ports[tunnel['local_port']] = tunnel
            
            # Her enabled servis için kontrol
            for port_config in default_ports:
                if not port_config.get("enabled", False):
                    continue  # Disabled servis - atla
                    
                service_name = port_config["service"]
                local_port = port_config["local"]
                total_enabled_services += 1
                
                # Bu servis için aktif tünel var mı?
                tunnel = tunnel_ports.get(local_port)
                if tunnel:
                    # Tunnel aktif mi kontrol et
                    status = tunnel.get('status', 'unknown')
                    if status == 'active':
                        active_enabled_services += 1
            
            # En az bir enabled service aktifse protection aktif
            has_active_protection = active_enabled_services > 0
            
            # Tünel başlatma başarısızsa log ekle
            if total_enabled_services > 0 and active_enabled_services == 0:
                log("[TRAY] ⚠️ WARNING: Tünel servisleri başlatılamadı! Hiçbir aktif tünel yok.")
                    
        except Exception as e:
            log(f"[TRAY] Protection status check error: {e}")
            has_active_protection = False
        
        return has_active_protection

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
        """Show main window from tray"""
        try:
            if hasattr(self.app_instance, 'root') and self.app_instance.root:
                # Clear tray mode flag
                self.app_instance._tray_mode.clear()
                
                # Pencereyi göster ve öne getir
                self.app_instance.root.deiconify()
                self.app_instance.root.lift()
                self.app_instance.root.focus_force()
                
                # Pencere konumunu merkeze al
                from client_constants import WINDOW_WIDTH, WINDOW_HEIGHT
                screen_width = self.app_instance.root.winfo_screenwidth()
                screen_height = self.app_instance.root.winfo_screenheight()
                window_width = WINDOW_WIDTH
                window_height = WINDOW_HEIGHT
                center_x = int(screen_width/2 - window_width/2)
                center_y = int(screen_height/2 - window_height/2)
                self.app_instance.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        except Exception as e:
            log(f"Show window error: {e}")
                
    def minimize_to_tray(self):
        """Minimize window to tray"""
        try:
            if hasattr(self.app_instance, 'root') and self.app_instance.root:
                # Mark as intentionally in tray to prevent auto-show
                self.app_instance._tray_mode.set()
                self.app_instance.root.withdraw()
        except Exception as e:
            log(f"Minimize error: {e}")
                
    def exit_app(self):
        """Exit application from tray"""
        # Gerçek tünel durumunu kontrol et - TÜNEL AKTIF Mİ, PORT DURUMU DEĞİL
        active_tunnels_exist = False
        try:
            if hasattr(self.app_instance, 'state') and self.app_instance.state.get("servers"):
                servers = self.app_instance.state["servers"]
                
                # Tüm aktif tunnelleri kontrol et
                for port, server_thread in servers.items():
                    if hasattr(server_thread, 'is_running') and server_thread.is_running():
                        active_tunnels_exist = True
                        log(f"[EXIT] Aktif tunnel bulundu: port {port}")
                        break
                    elif hasattr(server_thread, 'server') and server_thread.server:
                        active_tunnels_exist = True
                        log(f"[EXIT] Aktif tunnel server bulundu: port {port}")
                        break
                        
        except Exception as e:
            log(f"[EXIT] Tünel durumu kontrol hatası: {e}")
        
        if active_tunnels_exist:
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
        if not TRY_TRAY:
            return
            
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
            menu = pystray.Menu(
                TrayItem(self.t('tray_show'), lambda: self.show_window(), default=True),
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