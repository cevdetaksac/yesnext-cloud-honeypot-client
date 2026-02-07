#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 CLOUD HONEYPOT CLIENT v2.9.3 - PERFORMANCE & STABILITY OVERHAUL
=======================================================

📊 VERSION HISTORY:
├─ v2.9.3 (Feb 2026) - Performance fixes: ThreadPoolExecutor, shared SSL, session API, GUI safety
├─ v2.9.2 (Feb 2026) - Installer overhaul, task name fixes, dead autostart code removal
├─ v2.9.1 (Feb 2026) - Dead code cleanup, 661 lines removed
├─ v2.9.0 (Feb 2026) - Stability fixes, thread-safety, graceful exit
├─ v2.8.5 (Dec 2025) - Performance optimizations, thread reduction
├─ v2.8.4 (Dec 2025) - Task Scheduler memory restart (95% code reduction)
├─ v2.8.0 (Sep 2025) - Modular architecture implementation
└─ v1.x.x (2024)     - Initial release

🚀 PERFORMANCE OPTIMIZATIONS (v2.8.5):
┌─────────────────────────────────────────────────────────────────┐
│  ⚡ Thread Optimization    → Reduced ~8,640 threads/day        │
│  📁 I/O Optimization       → 92% reduction in file operations  │
│  🌐 Network Optimization   → 80% reduction in HTTP calls       │
│  🖼️ GUI Optimization       → Removed blocking gc.collect()     │
│  🔄 Loop Consolidation     → Merged watchdog into sync loop    │
│  💾 IP Caching             → 5 minute cache for public IP      │
└─────────────────────────────────────────────────────────────────┘

🏗️ MODULAR SYSTEM ARCHITECTURE:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  📦 CORE APPLICATION (client.py)                               │
│  ├─ Main application orchestrator and GUI                      │
│  ├─ Business logic coordination                                │
│  ├─ Tunnel management and RDP operations                       │
│  └─ API communication and data synchronization                 │
│                                                                 │
│  📦 MODULAR COMPONENTS:                                         │
│  ├─ client_monitoring.py    → Health/Heartbeat systems         │
│  ├─ client_instance.py      → Singleton control                │
│  ├─ client_logging.py       → Centralized logging              │
│  ├─ client_security.py      → Windows Defender compatibility   │
│  ├─ client_updater.py       → Update management                │
│  ├─ client_tray.py          → System tray integration          │
│  ├─ client_api.py           → API communication layer          │
│  ├─ client_networking.py    → Tunnel/network operations        │
│  ├─ client_rdp.py           → RDP port management              │
│  ├─ client_firewall.py      → Firewall automation             │
│  ├─ client_tokens.py        → Token management                 │
│  ├─ client_task_scheduler.py → Windows Task Scheduler          │
│  ├─ client_memory_restart.py → Memory management (simple)      │
│  ├─ client_utils.py         → Utility functions               │
│  ├─ client_helpers.py       → Helper functions + IP cache      │
│  └─ client_constants.py     → Configuration constants          │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ 🔄 AUTO-UPDATE SYSTEM:                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GUI/Tray Mode: UpdateWatchdog thread (every 1 hour)           │
│  Daemon Mode: Task Scheduler (every 2 hours, no login needed)  │
│  Silent Update: Background download & install                  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ 🏗️ MANAGER PATTERN IMPLEMENTATION:                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📊 MonitoringManager  → Heartbeat & health monitoring         │
│  🔒 InstanceManager    → Singleton & process control           │
│  📝 LoggingManager     → Centralized logging system            │
│  🛡️ SecurityManager    → Windows Defender & trust signals      │
│  🔄 UpdateManager      → Automated update system               │
│  📱 TrayManager        → System tray & notifications           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

EXIT CODES:
┌──────────┬─────────────────────────────────────────────────────┐
│ Code     │ Meaning                                             │
├──────────┼─────────────────────────────────────────────────────┤
│ 0        │ Normal exit                                         │
│ 1        │ Unhandled exception / critical error               │
│ 2        │ Mutex taken (another instance running)             │
│ 3        │ Health check failed                                │
└──────────┴─────────────────────────────────────────────────────┘

INSTALLATION & SETUP:
1. Run installer → Sets up Task Scheduler rules & registry entries
2. Daemon task → Auto-starts on boot for background operation
3. GUI task → Auto-starts on user logon for desktop interaction
4. Singleton protection → Prevents conflicts between instances

DEVELOPMENT NOTES:
- Migrated from monolithic 3097-line file to 14+ modular components
- Manager pattern ensures clean separation of concerns
- All legacy Windows Service code removed (Task Scheduler preferred)
- Backward compatibility maintained for existing configurations
- Plugin architecture ready for future extensions

MIGRATION STATUS: COMPLETE (September 2025)
- Core functionality: Fully modularized
- Manager patterns: Implemented across all subsystems  
- Testing: All modules validated and working
- Performance: 15% memory reduction, improved startup time
"""

# Standard library imports
import os, sys, socket, threading, time, json, subprocess, ctypes, argparse
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any, Union
import webbrowser, logging

# Local module imports  
from client_firewall import FirewallAgent
from client_helpers import log, ClientHelpers, run_cmd
import client_helpers
from client_networking import TunnelServerThread, NetworkingHelpers, TunnelManager, set_config_function, load_network_config
from client_api import HoneypotAPIClient, api_request_with_token, report_tunnel_action_api
from client_tokens import create_token_manager, get_token_file_paths
from client_task_scheduler import perform_comprehensive_task_management
from client_utils import (ServiceController, load_i18n, install_excepthook, 
                         load_config, get_config_value, set_config_value,
                         get_from_config, start_watchdog_if_needed, get_port_table,
                         update_language_config, watchdog_main, ensure_firewall_allow_for_port)

# Import constants from central configuration
from client_constants import (
    GUI_MODE, DAEMON_MODE, API_URL, APP_DIR, LOG_FILE,
    TRY_TRAY, RDP_SECURE_PORT, HONEYPOT_IP, 
    HONEYPOT_TUNNEL_PORT, SERVER_NAME, DEFAULT_TUNNELS,
    API_STARTUP_DELAY, API_RETRY_INTERVAL, API_SLOW_RETRY_DELAY,
    API_HEARTBEAT_INTERVAL, ATTACK_COUNT_REFRESH, RECONCILE_LOOP_INTERVAL,
    CONSENT_FILE, STATUS_FILE,
    WATCHDOG_TOKEN_FILE, __version__, GITHUB_OWNER, GITHUB_REPO,
    WINDOW_WIDTH, WINDOW_HEIGHT, CONTROL_HOST, CONTROL_PORT
)

# Import RDP management module
from client_rdp import RDPManager, RDPPopupManager

# Import new modular components
from client_monitoring import MonitoringManager, perform_health_check
from client_instance import InstanceManager, check_singleton
from client_logging import LoggingManager, setup_logging
from client_security import SecurityManager
from client_updater import UpdateManager
from client_tray import TrayManager

# ===================== SIMPLE MEMORY MANAGEMENT ===================== #
# Basit memory restart sistemi
try:
    from client_memory_restart import enable_simple_memory_restart, get_current_memory_mb, check_previous_restart_state
    MEMORY_RESTART_AVAILABLE = True
except ImportError:
    MEMORY_RESTART_AVAILABLE = False
    # Define dummy functions to prevent errors
    def enable_simple_memory_restart(*args, **kwargs): pass
    def get_current_memory_mb(): return 0
    def check_previous_restart_state(): return None

# ===================== MODULAR SYSTEM INITIALIZED ===================== #
# Heartbeat, Singleton, Logging systems moved to separate modules

def get_operation_mode(args) -> str:
    """Determine operation mode from arguments - SIMPLIFIED"""
    if getattr(args, 'mode', None) == "daemon" or getattr(args, 'daemon', False):
        return DAEMON_MODE
    elif getattr(args, 'mode', None) == "watchdog" or getattr(args, 'watchdog', False):
        return "watchdog"
    else:
        # Both default and tray mode use GUI_MODE
        # The difference is handled in the tray_mode flag
        return GUI_MODE

# ===================== SINGLETON SYSTEM END ===================== #

# ===================== MODULAR INITIALIZATION ===================== #

# Initialize global logger
LOGGER = None

# Initialize logging through modular system
logging_manager = LoggingManager()
if logging_manager.initialize():
    LOGGER = logging_manager.get_logger()

# Initialize tray system (handled by TrayManager)
# Tray setup moved to client_tray module

# ===================== WINDOWS DEFENDER COMPATIBILITY ===================== #
# Windows Defender compatibility moved to client_security module

# ===================== INTERNATIONALIZATION ===================== #
# Purpose: Load and manage multi-language support

# Load I18N messages from JSON
I18N = load_i18n()

# ===================== ANA UYGULAMA ===================== #
class CloudHoneypotClient:
    # Port mappings loaded from configuration
    @property
    def PORT_TABLOSU(self):
        """Get port table from configuration file"""
        if not hasattr(self, '_port_table_cache'):
            self._port_table_cache = get_port_table()
        return self._port_table_cache

    def log(self, message: str):
        """Log message using global logger with class context"""
        log(f"[CLIENT] {message}")

    def _gui_safe(self, func):
        """Thread-safe GUI çağrısı — root yoksa veya yok edilmişse sessizce atlar"""
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(0, func)
        except Exception:
            pass  # root destroyed veya erişilemez

    def get_token(self) -> Optional[str]:
        """Kaydedilmiş token'ı yükler"""
        return self.token_manager.get_token()

    def api_request(self, method: str, endpoint: str, data: Dict = None,
                    params: Dict = None, timeout: int = 8, json: Dict = None) -> Optional[Dict]:
        """API request wrapper using modular API client"""
        token = self.state.get("token")
        return api_request_with_token(
            self.api_client, token, method, endpoint, data, params, timeout, json
        )

    def __init__(self):
        install_excepthook()
        
        # Initialize modular managers
        self.monitoring_manager = MonitoringManager(APP_DIR)
        self.security_manager = SecurityManager()
        self.update_manager = UpdateManager()
        self.instance_manager = InstanceManager()
        
        # Initialize security system
        try:
            log("Initializing security systems...")
            self.security_manager.initialize()
            log("Security systems initialized successfully")
        except Exception as e:
            log(f"Security initialization warning: {e}")
        
        # Load configuration directly - pure config-driven architecture
        self.config = load_config()
        
        # Initialize networking configuration
        set_config_function(get_from_config)
        load_network_config()
        log(f"Network configuration loaded: {HONEYPOT_IP}:{HONEYPOT_TUNNEL_PORT}")
        
        # Initialize language with safe fallback from config
        try:
            lang = self.config["language"]["selected"]
            self.lang = "tr" if not isinstance(lang, str) else lang
        except Exception as e:
            self.lang = "tr"

        # Initialize core components
        self.api_client = HoneypotAPIClient(str(API_URL), log)
        
        # Initialize token manager
        token_file_new, token_file_old = get_token_file_paths(APP_DIR)
        self.token_manager = create_token_manager(str(API_URL), SERVER_NAME, token_file_new, token_file_old)
        
        # Set global logger for helper functions
        if LOGGER:
            client_helpers.set_logger(LOGGER)
        self.reconciliation_lock = threading.Lock()
        self.rdp_transition_complete = threading.Event()
        
        # Initialize application state FIRST
        self.state = {
            "running": False, "servers": {}, "token": None,
            "public_ip": None, "tray": None, "selected_rows": [],
            "selected_ports_map": None, "ctrl_sock": None,
            "reconciliation_paused": False, "remote_desired": {}
        }
        
        # Initialize RDP Management modules
        self.rdp_manager = RDPManager(main_app=self)
        self.rdp_popup_manager = RDPPopupManager(main_app=self, translation_func=self.t)
        
        # Load token early - before any API operations
        try:
            token = self.token_manager.load_token(self.root if hasattr(self, 'root') else None, self.t)
            self.state["token"] = token
            if token:
                pass
        except Exception as e:
            log(f"Token yükleme hatası: {e}")
            self.state["token"] = None
        
        # Initialize heartbeat system through monitoring manager
        if self.monitoring_manager.start_heartbeat_system(self):
            self.heartbeat_path = self.monitoring_manager.get_heartbeat_path()
        else:
            self.heartbeat_path = ""
        
        # Check if daemon is already running (for tray UI-only mode)
        self.daemon_is_active = False
        try:
            self.daemon_is_active = ClientHelpers.is_daemon_running()
            if self.daemon_is_active:
                log("🔄 Daemon detected - Tray will run in UI-only mode (no duplicate background tasks)")
        except Exception as e:
            log(f"⚠️ Daemon detection failed: {e}")
        
        # Initialize GUI elements
        self.root = self.btn_primary = self.tree = None
        self.attack_entry = self.ip_entry = self.show_cb = None
        
        # Tray mode tracking - thread-safe flag (prevents window from auto-showing)
        self._tray_mode = threading.Event()  # set() = in tray, clear() = visible
        
        # GUI health monitoring
        self.gui_health = {
            'update_count': 0,
            'health_check_interval': 60  # seconds
        }
        
        # Check initial RDP state and report to API
        # RDP modülünü kullanarak başlangıç durumunu kontrol et
        self.rdp_manager.check_initial_rdp_state()
        
        # Registry'ye current mode'u kaydet (Task Scheduler için)
        self._update_registry_mode()
        
        # Comprehensive Task Scheduler management - delegated to modular system
        from client_task_scheduler import perform_comprehensive_task_management
        task_result = perform_comprehensive_task_management(log_func=log, app_state=self.state)
        
        # ===================== SIMPLE MEMORY RESTART ===================== #
        # Basit memory management - 8 saatte bir restart
        if MEMORY_RESTART_AVAILABLE:
            try:
                # Check if this is a restart from previous session
                previous_state = check_previous_restart_state()
                if previous_state:
                    gui_state = previous_state.get('gui_state', 'unknown')
                    log(f"🔄 Restart detected - previous state: {gui_state}")
                
                current_memory = get_current_memory_mb()
                
                # Her durumda restart schedule aktif (basit ve etkili)
                enable_simple_memory_restart(restart_hours=8)
                
                log(f"� Simple memory restart enabled: Current {current_memory:.1f}MB, Restart every 8h")
                
            except Exception as e:
                log(f"⚠️ Memory restart setup failed: {e}")
        else:
            log("⚠️ Memory restart disabled - module not available")

    def _update_registry_mode(self):
        """Current mode'u registry'ye kaydet (Task Scheduler için)"""
        try:
            current_mode = self._detect_current_mode()
            
            # Registry key oluştur/aç
            import winreg
            key_path = r"Software\YesNext\CloudHoneypot"
            
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            except FileNotFoundError:
                # Key yoksa oluştur
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            
            # Mode'u kaydet
            winreg.SetValueEx(key, "LastMode", 0, winreg.REG_SZ, current_mode)
            winreg.CloseKey(key)
            
            log(f"📋 Registry mode updated: {current_mode}")
            
        except Exception as e:
            log(f"⚠️ Registry update failed: {e}")
    
    def _detect_current_mode(self):
        """Mevcut çalışma modunu tespit et"""
        try:
            # Command line arguments'dan mode'u anla
            for arg in sys.argv:
                if "--mode=daemon" in arg:
                    return "--mode=daemon"
                elif "--mode=tray" in arg:
                    return "--mode=tray"
                elif "--mode=gui" in arg:
                    return "--mode=gui"
            
            # Default: GUI varsa gui, yoksa daemon
            if hasattr(self, 'root') and self.root:
                return "--mode=gui"
            else:
                return "--mode=daemon"
                
        except Exception as e:
            log(f"⚠️ Mode detection error: {e}")
            return "--mode=daemon"  # Safe fallback

    def monitor_user_sessions(self):
        """Monitor for user logon sessions in daemon mode (optimized subprocess usage)"""
        import subprocess
        import time
        
        log("Daemon: User session monitoring started")
        check_interval = 30  # seconds
        
        while True:
            try:
                # Check for active user sessions using query session
                result = subprocess.run(
                    ['query', 'session'], 
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode != 0:
                    # query session failed (e.g. RDS not installed) — skip silently
                    time.sleep(check_interval)
                    continue
                
                # Look for Active sessions (interactive logon)
                has_active = any(
                    'Active' in line and 'console' in line.lower()
                    for line in result.stdout.split('\n')[1:]
                )
                
                if has_active:
                    log("Daemon: Active user session detected, gracefully shutting down for tray handover...")
                    time.sleep(3)
                    log("Daemon: Exiting for user session handover")
                    os._exit(0)
                    
            except subprocess.TimeoutExpired:
                log("Session monitoring: query session timed out")
            except Exception as e:
                log(f"Session monitoring error: {e}")
            
            time.sleep(check_interval)

    def start_delayed_api_sync(self):
        """Start API synchronization with delay in background thread
        
        NOTE: When daemon is running, skip background tasks to avoid duplication.
        Tray mode in UI-only configuration only provides the interface.
        """
        # Skip background tasks if daemon is already handling them
        if getattr(self, 'daemon_is_active', False):
            log("🔄 UI-only mode: Skipping background API sync (daemon handles this)")
            return
            
        def delayed_api_start():
            log(f"API senkronizasyonu {API_STARTUP_DELAY} saniye bekletiliyor (manuel işlemler için)...")
            time.sleep(API_STARTUP_DELAY)
            log("API senkronizasyonu başlatılıyor...")
            # API retry thread'ini başlat
            threading.Thread(target=self.api_retry_loop, daemon=True).start()
            
            # Dashboard tunnel sync başlat
            if not any(t.name == "tunnel_sync_loop" and t.is_alive() for t in threading.enumerate()):
                from client_networking import TunnelManager
                threading.Thread(target=TunnelManager.tunnel_sync_loop, args=(self,), name="tunnel_sync_loop", daemon=True).start()
                log("Dashboard tunnel sync loop başlatıldı (8s interval, 3s check)")

        # Geciktirilmiş API başlangıcını başlat
        threading.Thread(target=delayed_api_start, daemon=True).start()

        # Setup persistent high-privilege operation for critical security monitoring
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                log("🛡️ Application running with administrative privileges - Security monitoring active")
                # Task Scheduler setup handled in main startup sequence
            else:
                log("⚠️ Application running with limited privileges - Some security features may be restricted")
                log("💡 For full security monitoring capabilities, restart as Administrator")
        except Exception as e:
            log(f"Privilege detection error: {e}")

    # ---------- First-run notice ---------- #
    def _read_status_raw(self):
        try:
            if os.path.exists(STATUS_FILE):
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    return d if isinstance(d, dict) else {}
        except Exception as e:
            log(f"read status raw error: {e}")
        return {}

    def _write_status_raw(self, data: dict):
        try:
            with open(STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump(data or {}, f, ensure_ascii=False)
        except Exception as e:
            log(f"write status raw error: {e}")

    # ---------- I18N ---------- #
    def t(self, key: str) -> str:
        try:
            # Ensure self.lang is a string, not dict
            lang = self.lang
            if isinstance(lang, dict):
                lang = "tr"  # Fallback if corrupted
            elif not isinstance(lang, str):
                lang = "tr"
                
            # Get language dictionary
            lang_dict = I18N.get(lang, I18N.get("tr", {}))
            if not isinstance(lang_dict, dict):
                lang_dict = I18N.get("tr", {})
                
            result = lang_dict.get(key, key)
            return result
        except Exception as e:
            log(f"Translation error for key '{key}': {e}")
            return key  # Return key itself as fallback

    # ---------- Helper Methods ---------- #
    def require_admin_for_operation(self, operation_name: str) -> bool:
        """Check and request admin privileges for critical operations"""
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
            
        log(f"'{operation_name}' işlemi admin yetkisi gerektiriyor ama mevcut değil")
        
        try:
            if hasattr(self, 'root') and self.root:
                messagebox.showwarning(
                    self.t("admin_operation_failed"),
                    self.t("admin_operation_message").format(operation=operation_name)
                )
        except Exception as e:
            log(f"Admin warning dialog error: {e}")
        
        return False

    def ensure_admin(self, force_request: bool = False) -> Union[bool, str]:
        """Ensure admin privileges with optional elevation request"""
        try:
            if os.name != "nt" or ctypes.windll.shell32.IsUserAnAdmin():
                return True
            
            if force_request:
                log("🔧 Security monitoring requires elevated privileges...")
                try:
                    exe = sys.executable
                    params = " ".join(sys.argv[1:]) if getattr(sys, 'frozen', False) else \
                            f'"{os.path.abspath(sys.argv[0])}" ' + " ".join(sys.argv[1:])
                    
                    # Smart elevation strategy - appears as legitimate security software
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
                    log("🛡️ Elevation request sent for network security monitoring")
                    return "restarting"
                except Exception as e:
                    log(f"❌ Privilege elevation failed: {e}")
                    return False
            
            log("⚠️ Limited privileges mode - some security features may be restricted")
            return False
        except Exception as e:
            log(f"ensure_admin error: {e}")
            return False

    # ---------- API Connection ---------- #
    def try_api_connection(self, show_error: bool = True) -> bool:
        """Check API connection using modular client"""
        try:
            return self.api_client.check_connection(max_attempts=1, delay=0)
        except Exception as e:
            log(f"API connection check error: {e}")
            if show_error and hasattr(self, 'root') and self.root:
                messagebox.showwarning("Uyarı", f"API bağlantı kontrolünde hata: {e}")
            return False

    def api_retry_loop(self):
        # Arkaplanda API bağlantısını sürekli dener
        retry_count = 0
        max_quick_retries = 3  # Number of quick retries before slowing down
        
        while True:
            if not self.try_api_connection(show_error=(retry_count == 0)):
                retry_count += 1
                
                # For the first few failures, retry quickly
                if retry_count <= max_quick_retries:
                    logging.warning(f"API connection failed (attempt {retry_count}/{max_quick_retries}), retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    # After max_quick_retries, slow down to avoid overwhelming the network/server
                    logging.warning(f"API connection still failing after {retry_count} attempts, will retry in 60 seconds...")
                    time.sleep(API_SLOW_RETRY_DELAY)
                continue
                
            # Reset retry count on successful connection
            if retry_count > 0:
                logging.info(f"API connection restored after {retry_count} retries")
                retry_count = 0
                
            time.sleep(API_RETRY_INTERVAL)  # Check connection every minute when healthy

# ---------- IP & Heartbeat Management ---------- #
    def update_client_ip(self, new_ip: str):
        """Update client IP address via session-based API client"""
        token = self.state.get("token")
        if token:
            self.api_client.update_client_ip(token, new_ip)

    def get_intelligent_status(self) -> str:
        """Determine intelligent status based on program and tunnel state"""
        # Program açık olduğu kesin (çünkü bu kod çalışıyor)
        active_servers = self.state.get("servers", {})
        
        # En az bir tunnel aktifse → online
        if active_servers:
            return "online"
        
        # Program açık ama tunnel yok → idle
        return "idle"

    def send_heartbeat_once(self, status_override: Optional[str] = None):
        """Send single heartbeat to API with intelligent status detection (session-based)"""
        token = self.state.get("token")
        if token:
            ip = self.state.get("public_ip") or ClientHelpers.get_public_ip()
            
            # Status override yoksa akıllı status belirle
            if status_override is None:
                status_override = self.get_intelligent_status()
            
            self.api_client.send_heartbeat(
                token, ip, SERVER_NAME,
                self.state.get("running", False), status_override
            )

    def heartbeat_loop(self):
        """Optimized heartbeat loop with IP caching"""
        last_ip = None
        last_gui_ip = None  # Track last GUI-updated IP to avoid redundant updates
        
        while True:
            try:
                token = self.state.get("token")
                if token:
                    # IP is now cached in ClientHelpers (5 min cache)
                    ip = ClientHelpers.get_public_ip()
                    
                    # Only update API if IP changed
                    if ip and ip != last_ip and ip != "0.0.0.0":
                        self.update_client_ip(ip)
                        last_ip = ip
                        
                    self.state["public_ip"] = ip
                    
                    # GUI update only if IP actually changed (performance optimization)
                    if ip != last_gui_ip and self.ip_entry:
                        last_gui_ip = ip
                        self._gui_safe(lambda i=ip: ClientHelpers.safe_set_entry(self.ip_entry, f"{SERVER_NAME} ({i})"))
                    
                    # Akıllı heartbeat gönder (online/idle/offline)
                    self.send_heartbeat_once()
            except Exception as e:
                log(f"heartbeat error: {e}")
            time.sleep(API_HEARTBEAT_INTERVAL)

    # ---------- Attack Count ---------- #
    def fetch_attack_count_sync(self, token):
        """Honeypot sunucusundan toplam saldırı sayısını sorgular - now uses modular API client"""
        try:
            return self.api_client.get_attack_count(token)
        except Exception as e:
            log(f"[API] Saldırı sayısı sorgulama hatası: {e}")
            return None

    def check_gui_health(self):
        """Periodic GUI health check — tray icon sync & session monitoring"""
        if not self.root:
            return
            
        try:
            self.root.winfo_exists()
            self.gui_health['update_count'] += 1
            
            # Tray icon update — only if tunnel state changed
            if hasattr(self, 'tray_manager'):
                current_state = bool(self.state.get("servers"))
                if not hasattr(self, '_last_tray_state') or current_state != self._last_tray_state:
                    self._last_tray_state = current_state
                    self.update_tray_icon()
            
            # Windows Server session check — every 5th cycle (~5 min)
            if self.gui_health['update_count'] % 5 == 0:
                self.check_windows_session_state()
            
            # Prevent integer overflow
            if self.gui_health['update_count'] > 1000:
                self.gui_health['update_count'] = 0
                
        except Exception as e:
            log(f"[GUI_HEALTH] Sağlık kontrolü hatası: {e}")
            
        # Schedule next check
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(self.gui_health['health_check_interval'] * 1000, self.check_gui_health)
        except Exception:
            pass

    def check_windows_session_state(self):
        """Windows session durumunu kontrol et"""
        try:
            import subprocess
            
            # Session durumunu kontrol et
            result = subprocess.run(['query', 'session'], 
                                  capture_output=True, text=True, timeout=5,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                # Aktif session var mı kontrol et
                has_active_session = 'Active' in result.stdout
                
                if not has_active_session:
                    log("[GUI_HEALTH] Aktif kullanıcı session'ı yok - GUI minimal modda çalışacak")
                    # Minimize to tray if no active session
                    if hasattr(self, 'tray_manager') and self.tray_manager:
                        self._tray_mode.set()
                        self.root.withdraw()
                        
        except Exception as e:
            log(f"[GUI_HEALTH] Session kontrolü hatası: {e}")

    def refresh_attack_count(self, async_thread=True):
        """GUI'deki saldırı sayacını günceller"""
        token = self.state.get("token")
        if not token:
            return
        if not self.root or not self.attack_entry:
            return
            
        def worker():
            try:
                cnt = self.fetch_attack_count_sync(token)
                if cnt is None:
                    return
                    
                # Skip update if value unchanged (performance optimization)
                if hasattr(self, '_last_attack_count') and self._last_attack_count == cnt:
                    return
                    
                self._last_attack_count = cnt
                    
                # GUI thread-safe güncelleme
                self._gui_safe(lambda c=cnt: ClientHelpers.safe_set_entry(self.attack_entry, str(c)))
            except Exception:
                pass
                
        if async_thread:
            # PERFORMANCE: Reuse existing thread if already running
            if not hasattr(self, '_attack_count_thread') or not self._attack_count_thread.is_alive():
                self._attack_count_thread = threading.Thread(target=worker, daemon=True, name="AttackCountUpdater")
                self._attack_count_thread.start()
        else:
            worker()

    def poll_attack_count(self):
        """Poll attack count with single-chain scheduling guard"""
        # Prevent double scheduling chains
        if hasattr(self, '_poll_chain_active') and self._poll_chain_active:
            return
        self._poll_chain_active = True
        
        self.refresh_attack_count(async_thread=True)
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(ATTACK_COUNT_REFRESH * 1000, self._poll_attack_count_chain)
        except Exception as e:
            self._poll_chain_active = False
            log(f"poll_attack_count scheduling failed: {e}")
    
    def _poll_attack_count_chain(self):
        """Internal polling chain — only runs from a single root.after chain"""
        self.refresh_attack_count(async_thread=True)
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(ATTACK_COUNT_REFRESH * 1000, self._poll_attack_count_chain)
            else:
                self._poll_chain_active = False
        except Exception:
            self._poll_chain_active = False

    # ---------- Single Instance Control ---------- #
    def control_server_loop(self, sock):
        """Handle control server connections for single instance enforcement"""
        MAX_CMD_LEN = 256  # Prevent malicious clients from sending unbounded data
        while True:
            try:
                conn, _ = sock.accept()
                conn.settimeout(2.0)
                
                # Buffered read with size limit (replaces byte-by-byte recv(1))
                buf = conn.recv(MAX_CMD_LEN)
                if not buf:
                    continue
                
                # Extract first line (commands are newline-terminated)
                line = buf.split(b"\n", 1)[0]
                cmd = line.decode("utf-8", "ignore").strip().upper()
                if cmd == "SHOW" and self.show_cb:
                    self._gui_safe(self.show_cb)
                        
            except Exception as e:
                log(f"Control server loop error: {e}")
            finally:
                try: 
                    conn.close()
                except Exception as e: 
                    log(f"Control server conn.close() failed: {e}")

    def start_single_instance_server(self):
        """Start single instance enforcement server"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((CONTROL_HOST, CONTROL_PORT))
        except OSError:
            # Instance already running, send show command and exit
            try:
                with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=1.0) as c:
                    c.sendall(b"SHOW\n")
            except Exception:
                pass
            sys.exit(0)
        
        s.listen(5)
        self.state["ctrl_sock"] = s
        threading.Thread(target=self.control_server_loop, args=(s,), daemon=True).start()

    # ---------- Watchdog & Persistence ---------- #

    def write_status(self, active_rows, running: bool = True):
        """Write current status to persistent storage"""
        self.state["selected_rows"] = [(str(a[0]), str(a[1]), str(a[2])) for a in active_rows]
        data = self._read_status_raw()
        data.update({"active_ports": self.state["selected_rows"], "running": running, "fresh_install": False})
        self._write_status_raw(data)

    def read_status(self):
        """Read status from persistent storage"""
        if not os.path.exists(STATUS_FILE):
            self.write_status([], running=False)
            return [], False
        try:
            data = json.load(open(STATUS_FILE, "r", encoding="utf-8"))
            if data.get("fresh_install", False):  # <-- default artık False
                self.write_status([], running=False)
                return [], False
            rows = data.get("active_ports", [])
            running = bool(data.get("running", False))
            norm = [(str(r[0]), str(r[1]), str(r[2])) for r in rows]
            return norm, running
        except Exception as e:
            log(f"read_status error: {e}")
            return [], False

    # ---------- Consent ---------- #
    def read_consent(self):
        try:
            if os.path.exists(CONSENT_FILE):
                with open(CONSENT_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {
                            "accepted": bool(data.get("accepted", False)),
                            "rdp_move": bool(data.get("rdp_move", True)),
                            "autostart": bool(data.get("autostart", False)),
                        }
        except Exception as e:
            log(f"read_consent error: {e}")
        return {"accepted": False, "rdp_move": True, "autostart": False}

    def write_consent(self, accepted: bool, rdp_move: bool, autostart: bool):
        """Write consent data to storage"""
        try:
            data = {"accepted": bool(accepted), "rdp_move": bool(rdp_move), 
                   "autostart": bool(autostart), "ts": int(time.time()), "app": "CloudHoneypotClient"}
            with open(CONSENT_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as e:
            log(f"write_consent error: {e}")

    def ensure_consent_ui(self):
        """Show consent dialog if not already accepted"""
        cons = self.read_consent()
        if cons.get("accepted"):
            self.state["consent"] = cons
            return cons

        win = tk.Toplevel(self.root)
        win.title(self.t("consent_title"))
        try: win.grab_set(); win.transient(self.root)
        except Exception as e: log(f"Exception: {e}")

        tk.Label(win, text=self.t("consent_msg"), justify="left", font=("Arial", 10)).pack(padx=16, pady=12)

        var_rdp = tk.BooleanVar(value=True)
        var_auto = tk.BooleanVar(value=False)
        tk.Checkbutton(win, text=self.t("consent_rdp"),  variable=var_rdp).pack(anchor="w", padx=16)
        tk.Checkbutton(win, text=self.t("consent_auto"), variable=var_auto).pack(anchor="w", padx=16)

        accepted = {"val": False}

        def do_accept():
            accepted["val"] = True
            self.write_consent(True, var_rdp.get(), var_auto.get())
            self.state["consent"] = self.read_consent()
            try: win.destroy()
            except: pass

        def do_cancel():
            accepted["val"] = False
            self.write_consent(False, var_rdp.get(), var_auto.get())
            self.state["consent"] = self.read_consent()
            try: win.destroy()
            except: pass

        frm = tk.Frame(win); frm.pack(pady=10)
        tk.Button(frm, text=self.t("consent_accept"), bg="#4CAF50", fg="white", command=do_accept).pack(side="left", padx=6)
        tk.Button(frm, text=self.t("consent_cancel"), command=do_cancel).pack(side="left", padx=6)

        win.wait_window()
        return self.state.get("consent", cons)

    # ---------- UI Helpers ---------- #
    # ---------- Update Management ---------- #
    def check_updates_and_prompt(self):
        """Check for updates and prompt user - delegated to update manager"""
        return self.update_manager.check_for_updates_interactive(self)

    def check_updates_and_apply_silent(self):
        """Silent update - delegated to update manager"""
        return self.update_manager.check_for_updates_silent()



    # ---------- RDP Management UI ---------- #
    def rdp_move_popup(self, mode: str, on_confirm):
        """Show RDP port change confirmation popup using modular RDP system"""
        # mode: "secure" (3389->53389) or "rollback" (53389->3389)
        with self.reconciliation_lock:
            self.state["reconciliation_paused"] = True
            log("RDP işlemi için uzlaştırma döngüsü duraklatıldı.RDP geçişi için API senkronizasyonu duraklatıldı.")
        
        def on_confirm_wrapped():
            """Wrapper for confirmation callback with additional handling"""
            try:
                log("✅ Kullanıcı RDP geçişini onayladı, işlem tamamlanıyor...")
                
                # Callback'i çağır (tünelleri başlat vs.)
                on_confirm()
                
                # Update GUI state
                if hasattr(self, 'btn_primary') and self.btn_primary:
                    self.btn_primary.after(0, lambda: ClientHelpers.set_primary_button(
                        self.btn_primary, self.t('btn_stop'), self.remove_tunnels, "#E53935"
                    ))
                
                # Update internal state
                self.state["running"] = True
                
                log("✅ RDP geçiş süreci kullanıcı onayı ile tamamlandı")
                    
            except Exception as e:
                log(f"❌ RDP geçiş callback hatası: {e}")
            finally:
                # Resume reconciliation
                with self.reconciliation_lock:
                    self.state["reconciliation_paused"] = False
                log("RDP işlemi tamamlandı, uzlaştırma döngüsü devam ettiriliyor.")
        
        # Use RDP popup manager from module
        self.rdp_popup_manager.show_rdp_popup(mode, on_confirm_wrapped)

    # ---------- Application Control ---------- #
    def apply_tunnels(self, selected_rows):
        """Apply selected tunnel configurations"""
        started = 0
        clean_rows = []
        for (listen_port, new_port, service) in selected_rows:
            if self.start_single_row(str(listen_port), str(new_port), str(service), manual_action=True):
                clean_rows.append((str(listen_port), str(new_port), str(service)))
                started += 1

        if started == 0:
            try: messagebox.showerror(self.t("error"), "Ports are busy or cannot be listened.")
            except: pass
            return False

        self.write_status(clean_rows, running=True)
        self.state["running"] = True
        self.update_tray_icon()
        self.send_heartbeat_once("online")
        
        # GUI buton durumunu güncelle
        self.sync_gui_with_tunnel_state()
        return True

    def remove_tunnels(self):
        # Normal tünelleri durdur
        for p, st in list(self.state["servers"].items()):
            try: st.stop()
            except: pass
        self.state["servers"].clear()
        self.state["running"] = False
        
        self.update_tray_icon()
        try:
            self.write_status(self.state.get("selected_rows", []), running=False)
        except: pass
        self.send_heartbeat_once("offline")
        
        # GUI buton durumunu güncelle
        self.sync_gui_with_tunnel_state()
    
    def toggle_rdp_protection(self):
        """RDP koruma durumunu tersine çevir - popup ile onay alır"""
        try:
            is_protected, current_port = self.rdp_manager.get_rdp_protection_status()
            
            if is_protected:
                # Korumalı -> Normal (3389'a geri dön) - Pop-up göster
                log("🔄 RDP 3389'a dönüş için popup açılıyor...")
                
                def on_rdp_confirm_rollback():
                    """RDP 3389'a dönüş onaylandığında"""
                    log("✅ RDP 3389'a dönüş onaylandı, geçiş başlatılıyor...")
                    
                    # GUI'yi güncelle
                    self.update_rdp_button()
                    self.sync_gui_with_tunnel_state()
                    self.update_tray_icon()
                    
                    # Heartbeat gönder
                    self.send_heartbeat_once("online")
                
                # Popup göster - 10 saniye sonra onay butonu aktif olacak
                self.rdp_move_popup(mode="rollback", on_confirm=on_rdp_confirm_rollback)
                
            else:
                # Normal -> Korumalı (güvenli porta taşı) - Pop-up göster
                log("🔄 RDP güvenli porta taşıma için popup açılıyor...")
                
                def on_rdp_confirm():
                    """RDP güvenli porta taşıma onaylandığında"""
                    log("✅ RDP güvenli porta taşıma onaylandı, geçiş başlatılıyor...")
                    
                    # GUI'yi güncelle
                    self.update_rdp_button()
                    self.sync_gui_with_tunnel_state()
                    self.update_tray_icon()
                    
                    # Heartbeat gönder
                    self.send_heartbeat_once("online")
                
                # Popup göster - 10 saniye sonra onay butonu aktif olacak
                self.rdp_move_popup(mode="secure", on_confirm=on_rdp_confirm)
            
        except Exception as e:
            log(f"❌ RDP toggle hatası: {e}")
    
    def update_rdp_button(self):
        """RDP butonunun metnini güncel duruma göre güncelle"""
        try:
            # RDP satırındaki RDP butonunu güncelle
            rdp_control = self.row_controls.get(("3389", "RDP"))
            if rdp_control and "rdp_button" in rdp_control:
                rdp_btn = rdp_control["rdp_button"]
                
                is_protected, current_port = self.rdp_manager.get_rdp_protection_status()
                target_port = 3389 if is_protected else RDP_SECURE_PORT
                new_text = f"RDP Taşı : {target_port}"
                
                # Buton rengini de duruma göre ayarla
                if is_protected:
                    # Korumalı durumda - geri dönüş için turuncu
                    rdp_btn.config(text=new_text, bg="#FF9800", fg="white")
                else:
                    # Normal durumda - koruma için mavi
                    rdp_btn.config(text=new_text, bg="#2196F3", fg="white")
                
                # Sadece debug mode'da logla
                # log(f"🔄 RDP butonu güncellendi: {new_text}")
                
                # Tray ikonunu da güncelle
                self.update_tray_icon()
                
        except Exception as e:
            log(f"❌ RDP buton güncelleme hatası: {e}")

    def sync_gui_with_tunnel_state(self):
        """GUI buton durumunu gerçek tunnel durumu ile senkronize et - HER SATIRIN KENDİ BUTONLARI"""
        try:
            # RDP butonunu güncelle
            self.update_rdp_button()
            
            # Tray ikonunu güncelle
            self.update_tray_icon()
                
        except Exception as e:
            log(f"[GUI_SYNC] Senkronizasyon hatası: {e}")
            import traceback
            log(f"[GUI_SYNC] Traceback: {traceback.format_exc()}")

    # ---------- Tünel Durum Yönetimi ---------- #
    def get_tunnel_state(self) -> Dict[str, Any]:
        # API'den güncel tünel durumlarını alır (/api/premium/tunnel-status)
        # Returns:
        #     Dict[str, Any]: Her servis için durum bilgileri
        #     Format: {'RDP': {'desired': 'started', 'new_port': 53389}, ...}
        try:
            token = self.state.get("token")
            if not token:
                log("[TunnelState] Token bulunamadı")
                return {}

            log("[TunnelState] API'den durum bilgisi alınıyor...")
            
            # API'den durumları al
            response = self.api_request(
                method="GET",
                endpoint="premium/tunnel-status",  # /api prefix api_request'te ekleniyor
                params={"token": token}
            )

            if not response:
                log("[TunnelState] API yanıt vermedi")
                return {}
                
            if not isinstance(response, dict):
                log(f"[TunnelState] Geçersiz API yanıtı: {type(response)}")
                return {}
                
            # API yanıtını detaylı logla
            log("[TunnelState] -------- Güncel Durum --------")
            for service, info in response.items():
                status_str = (
                    f"Servis: {service}\n"
                    f"  Durum: {info.get('status', 'unknown')}\n"
                    f"  İstenen: {info.get('desired', 'unknown')}\n"
                    f"  Port: {info.get('listen_port', 'N/A')}\n"
                    f"  Yeni Port: {info.get('new_port', 'N/A')}"
                )
                log(f"[TunnelState] {status_str}")
            log("[TunnelState] ------------------------------")
                    
            return response
                
        except Exception as e:
            log(f"Tünel durumu alınırken hata: {e}")
            return {}

    def save_tunnel_state(self, tunnels: Dict[str, Any]):
        """Save tunnel states to central config"""
        try:
            for service, config in tunnels.items():
                if service in DEFAULT_TUNNELS:
                    # Save tunnel config to central config
                    tunnel_path = f"tunnels.{service}"
                    if 'desired' in config:
                        set_config_value(f"{tunnel_path}.desired", config['desired'])
                    if 'new_port' in config:
                        set_config_value(f"{tunnel_path}.new_port", config['new_port'])
                    log(f"[CONFIG] Saved tunnel state for {service}: {config}")
        except Exception as e:
            log(f"Tünel durumu kaydedilirken hata: {e}")

    def get_local_tunnel_state(self) -> Dict[str, Any]:
        state = {}
        for svc, cfg in DEFAULT_TUNNELS.items():
            lp = int(cfg["listen_port"])
            running = self._is_service_running(lp, svc)
            item = {"status": "started" if running else "stopped", "listen_port": lp}
            if svc == "RDP":
                item["new_port"] = ServiceController.get_rdp_port()
            state[svc] = item
        return state

    def get_active_tunnels(self) -> list:
        """Get list of currently active tunnels for tray status detection"""
        from client_networking import TunnelManager
        return TunnelManager.get_active_tunnels(self)

        # Tunnel state sync moved to TunnelManager


# ---------- Per-row helpers ---------- #
        # Port checking moved to NetworkingHelpers

    def _find_tree_item(self, listen_port: str, service_name: str):
        try:
            for iid in self.tree.get_children(""):
                vals = self.tree.item(iid).get("values") or []
                if len(vals) >= 3 and str(vals[0]) == str(listen_port) and str(vals[2]).upper() == str(service_name).upper():
                    return iid
        except Exception as e:
            log(f"Exception: {e}")
        return None

    def _update_row_ui(self, listen_port: str, service_name: str, active: bool):
        def apply():
            # RDP için ana butonu da güncelle ve logla
            if service_name.upper() == 'RDP':
                if active:
                    ClientHelpers.set_primary_button(self.btn_primary, self.t('btn_stop'), self.remove_tunnels, "#E53935")
                    log(f"[UI] Updating row UI for {service_name}: btn_stop")
                else:
                    ClientHelpers.set_primary_button(self.btn_primary, self.t('btn_row_start'), self.apply_tunnels, "#4CAF50")
                    log(f"[UI] Updating row UI for {service_name}: btn_row_start")
            # Prefer new stacked UI controls
            try:
                key = (str(listen_port), str(service_name).upper())
                rc = getattr(self, 'row_controls', {}).get(key)
                if rc:
                    btn = rc.get("button"); fr = rc.get("frame"); st = rc.get("status")
                    # Hangi butonun güncelleneceğini logla
                    log(f"[UI] Updating row UI for {key}: {'Active' if active else 'Inactive'}")
                    if active:
                        if btn: btn.config(text=self.t('btn_row_stop'), bg="#E53935")
                        if fr: fr.configure(bg="#EEF7EE")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_running')}")
                    else:
                        if btn: btn.config(text=self.t('btn_row_start'), bg="#4CAF50")
                        if fr: fr.configure(bg="#ffffff")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_stopped')}")
                    return
            except Exception:
                pass
            # Fallback to legacy tree view if present
            try:
                iid = self._find_tree_item(listen_port, service_name)
                if iid:
                    self.tree.set(iid, self.t("col_active"), "Stop" if active else "Start")
                    self.tree.item(iid, tags=("aktif",) if active else ())
            except Exception:
                pass
        self._gui_safe(apply)

    def _active_rows_from_servers(self):
        rows = []
        try:
            for (p1, p2, svc) in self.PORT_TABLOSU:
                lp = int(str(p1))
                if self.state["servers"].get(lp):
                    rows.append((str(p1), str(p2), str(svc)))
        except Exception as e:
            log(f"Exception: {e}")
        return rows

    def start_single_row(self, p1: str, p2: str, service: str, manual_action: bool = False) -> bool:
        # Tek bir tünel servisini başlatır
        # 
        # Args:
        #     p1: Dinleme portu
        #     p2: Hedef port
        #     service: Servis adı
        #     manual_action: Kullanıcı tarafından tetiklenip tetiklenmediği
        
        # RDP için her zaman 3389 tünellenir, koruma aktif olsa bile
        if service.upper() == 'RDP':
            listen_port = '3389'
        else:
            listen_port = str(p1)
        service_upper = str(service).upper()

        if service_upper == 'RDP' and listen_port == '3389':
            # RDP özel durumu
            with self.reconciliation_lock:
                self.state["reconciliation_paused"] = True
                log("RDP geçişi için API senkronizasyonu duraklatıldı.")
            
            # RDP port durumunu kontrol et ve tünel mantığını belirle
            current_rdp_port = ServiceController.get_rdp_port()
            is_3389_in_use = NetworkingHelpers.is_port_in_use(3389)
            
            log(f"🔍 RDP DURUM: current_port={current_rdp_port}, secure_port={RDP_SECURE_PORT}, 3389_in_use={is_3389_in_use}, manual_action={manual_action}")
            
            if current_rdp_port == RDP_SECURE_PORT:
                # RDP güvenli portta - 3389'da tünel başlatılabilir
                if not is_3389_in_use:
                    log(f"✅ RDP güvenli portta ({RDP_SECURE_PORT}), 3389 boş - tünel başlatılıyor...")
                    
                    # 3389'da tünel başlat (REACTIVE APPROACH)
                    st = TunnelServerThread(self, listen_port, service)
                    st.start()
                    time.sleep(0.15)
                    
                    if st.is_alive():
                        # Tünel başarıyla başlatıldı
                        self.state["servers"][int(listen_port)] = st
                        self.write_status(self._active_rows_from_servers(), running=True)
                        self.state["running"] = True
                        self.update_tray_icon()
                        self.send_heartbeat_once("online")
                        self._update_row_ui(listen_port, service, True)
                        self.state["remote_desired"][service_upper] = "started"
                        
                        # API'ye koruma aktif bilgisini gönder
                        log("✅ RDP tüneli başarıyla başlatıldı - API'ye bildirim gönderiliyor")
                        self.report_tunnel_action_to_api("RDP", "start", str(RDP_SECURE_PORT))
                        
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = False
                        return True
                    else:
                        # RDP tüneli başarısız - admin yetki ile tekrar deneyelim
                        log("❌ RDP tüneli normal yetki ile başlatılamadı")
                        
                        if manual_action:
                            log("🔓 RDP için admin yetki ile tünel başlatma deneniyor")
                            
                            if self.require_admin_for_operation(f"RDP Tüneli Başlatma (Port 3389)"):
                                log("✅ Admin yetki alındı - RDP tüneli yeniden deneniyor")
                                
                                st_admin = TunnelServerThread(self, listen_port, service)
                                st_admin.start()
                                time.sleep(0.15)
                                
                                if st_admin.is_alive():
                                    log("✅ RDP tüneli admin yetki ile başarıyla başlatıldı")
                                    self.state["servers"][int(listen_port)] = st_admin
                                    self.write_status(self._active_rows_from_servers(), running=True)
                                    self.state["running"] = True
                                    self.update_tray_icon()
                                    self.send_heartbeat_once("online")
                                    self._update_row_ui(listen_port, service, True)
                                    self.state["remote_desired"][service_upper] = "started"
                                    
                                    # API'ye koruma aktif bilgisini gönder
                                    log("✅ RDP tüneli (admin) başarıyla başlatıldı - API'ye bildirim gönderiliyor")
                                    self.report_tunnel_action_to_api("RDP", "start", str(RDP_SECURE_PORT))
                                    
                                    with self.reconciliation_lock:
                                        self.state["reconciliation_paused"] = False
                                    return True
                                else:
                                    log("❌ RDP tüneli admin yetki ile de başlatılamadı!")
                            else:
                                log("👤 Kullanıcı RDP admin yetki vermeyi reddetti")
                        
                        log("❌ RDP tüneli başlatılamadı!")
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = False
                        return False
                else:
                    # Windows Terminal Services bug workaround
                    log("⚠️ RDP Registry'de güvenli portta ama 3389 hala dolu")
                    log("📋 Muhtemel neden: Windows Terminal Services registry değişikliğini tanımadı")
                    log("🔍 Bilinen Windows bug'ı: Registry port değişse de Terminal Services eski portu bırakmaz")
                    
                    if manual_action:
                        # Manuel başlatma - kullanıcıya uyarı göster
                        log("🔄 Manuel RDP tünel başlatma - 3389 port çakışması uyarısı gösteriliyor")
                        
                        # Port çakışması uyarısı
                        def show_port_conflict_warning():
                            import tkinter as tk
                            from tkinter import messagebox
                            
                            root = tk.Tk()
                            root.withdraw()
                            
                            message = (
                                "RDP Tünel Başlatma Sorunu\\n\\n"
                                f"RDP portu güvenli porta ({RDP_SECURE_PORT}) taşınmış\\n"
                                "ancak 3389 portunda hala bir uygulama dinliyor.\\n\\n"
                                "Bu durum Windows Terminal Services bug'ından kaynaklanır.\\n\\n"
                                "Çözüm seçenekleri:\\n"
                                "1. 3389 portunu dinleyen uygulamaları kapatın\\n"
                                "2. Cihazı yeniden başlatın (önerilen)\\n"
                                "3. Terminal Services'ı yeniden başlatın\\n\\n"
                                "Cihazı şimdi yeniden başlatmak istiyor musunuz?"
                            )
                            
                            result = messagebox.askyesno(
                                "Port Çakışması", 
                                message,
                                icon='warning'
                            )
                            
                            root.destroy()
                            
                            if result:  # Yes seçildiyse
                                log("🔄 Kullanıcı sistem yeniden başlatmayı onayladı")
                                import subprocess
                                subprocess.run(['shutdown', '/r', '/t', '30', '/c', 'RDP port çakışması sorunu için sistem yeniden başlatılıyor...'])
                            else:
                                log("👤 Kullanıcı sistem yeniden başlatmayı reddetti")
                        
                        # UI thread'de popup göster
                        import threading
                        threading.Thread(target=show_port_conflict_warning, daemon=True).start()
                    else:
                        log("🤖 API başlatma - port çakışması nedeniyle başarısız")
                    
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    return False
            
            elif current_rdp_port == 3389:
                # RDP standart portta (3389) - port dolu, geçiş gerekli  
                if is_3389_in_use:
                    log(f"⚠️ RDP standart portta (3389) ve port dolu - tünel başlatma için port geçişi gerekli")
                    if manual_action:
                        log(f"🔄 Kullanıcı RDP tünel başlatmak istiyor ama port 3389'da - kullanıcıya uyarı")
                        
                        # Kullanıcıya RDP port taşıma uyarısı göster
                        import tkinter as tk
                        from tkinter import messagebox
                        
                        def show_rdp_port_warning():
                            root = tk.Tk()
                            root.withdraw()
                            
                            message = (
                                "RDP Tünel Başlatma Hatası\\n\\n"
                                "RDP tüneli başlatmak için 3389 portu boş olmalıdır.\\n"
                                "Şu anda RDP servisi 3389 portunda çalışıyor.\\n\\n"
                                "Çözüm:\\n"
                                "• 'RDP Taşı' butonunu kullanarak RDP portunu\\n"
                                f"  güvenli porta ({RDP_SECURE_PORT}) taşıyın\\n"
                                "• Ardından RDP tünelini tekrar başlatın\\n\\n"
                                "RDP portunu şimdi taşımak istiyor musunuz?"
                            )
                            
                            result = messagebox.askyesno(
                                "RDP Port Uyarısı", 
                                message,
                                icon='warning'
                            )
                            
                            root.destroy()
                            
                            if result:  # Yes seçildiyse
                                log("👤 Kullanıcı RDP port taşımayı onayladı")
                                # RDP port taşıma işlemini başlat
                                self.toggle_rdp_protection()
                            else:
                                log("👤 Kullanıcı RDP port taşımayı reddetti")
                        
                        # UI thread'de popup göster
                        import threading
                        threading.Thread(target=show_rdp_port_warning, daemon=True).start()
                        
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = False
                        return False
                    else:
                        log(f"❌ Otomatik mod - port dolu olduğu için tünel başlatılamaz")
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = False
                        return False
                else:
                    # Bu durumda 3389 boş ama RDP servisi hala 3389'da - teorik olarak imkansız
                    log(f"⚠️ RDP 3389'da ama port boş - beklenmeyen durum")
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    return False
            else:
                log(f"⚠️ RDP beklenmeyen portta: {current_rdp_port}")
                with self.reconciliation_lock:
                    self.state["reconciliation_paused"] = False
                return False
            
            # Manuel akış (kullanıcı Başlat butonuna tıklamış)
            if manual_action:
                # Kullanıcı kaynaklı RDP geçişi - onay penceresi göster
                log("🔥 Manuel RDP güvenli port başlatma akışı tetiklendi - POPUP GÖSTERILECEK!")

                def on_rdp_confirm():
                    # RDP port değişikliği onaylandığında çalışacak callback
                    log("RDP port geçişi kullanıcı tarafından onaylandı.")
                    ensure_firewall_allow_for_port(3389, "RDP 3389 (Tunnel)")

                    # Tünel sunucusunu başlat
                    st = TunnelServerThread(self, listen_port, service)
                    st.start()
                    time.sleep(0.15)
                    
                    if st.is_alive():
                        # Tünel başarıyla başlatıldı
                        self.state["servers"][int(listen_port)] = st
                        self.write_status(self._active_rows_from_servers(), running=True)
                        self.state["running"] = True
                        self.update_tray_icon()
                        self.send_heartbeat_once("online")
                        self._update_row_ui(listen_port, service, True)
                        self.state["remote_desired"][service_upper] = "started"
                        
                        # API'ye bildir (ayrı thread'de)
                        threading.Thread(
                            target=self.report_tunnel_action_to_api,
                            args=(service, 'start', p2),
                            daemon=True
                        ).start()
                    else:
                        log("Kullanıcı onayından sonra tünel başlatılamadı.")
                        return False

                self.rdp_move_popup(mode="secure", on_confirm=on_rdp_confirm)
                return True
            else: # API-driven
                # RDP API-driven start (manual_action == False)
                log("API tarafından RDP güvenli port başlatma akışı tetiklendi.")
                try:
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = True
                        log("RDP geçişi için API senkronizasyonu duraklatıldı.")

                    if ServiceController.get_rdp_port() != RDP_SECURE_PORT:
                        if not self.start_rdp_transition("secure"):
                            log(f"API akışı: RDP {RDP_SECURE_PORT}'a taşınamadı.")
                            return False

                    # 3389 (tünel) + RDP güvenli port için firewall
                    ensure_firewall_allow_for_port(3389,  "RDP 3389 (Tunnel)")
                    ensure_firewall_allow_for_port(RDP_SECURE_PORT, f"RDP {RDP_SECURE_PORT}")

                    # 3389 tünel
                    st = TunnelServerThread(self, '3389', service)
                    st.start(); time.sleep(0.15)
                    if not st.is_alive():
                        log("RDP tüneli başlatılamadı.")
                        return False

                    self.state["servers"][3389] = st
                    self.write_status(self._active_rows_from_servers(), running=True)
                    self.state["running"] = True
                    self.update_tray_icon(); self.send_heartbeat_once("online")
                    self._update_row_ui('3389', service, True)
                    self.state["remote_desired"][service_upper] = "started"
                    ClientHelpers.set_primary_button(self.btn_primary, self.t('btn_stop'), self.remove_tunnels, "#E53935")

                    # API bildirimi
                    threading.Thread(target=self.report_tunnel_action_to_api, args=(service, 'start', p2), daemon=True).start()

                    # 8-9: 5 sn bekle, resume
                    def _resume():
                        time.sleep(5)
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = False
                        log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")
                    threading.Thread(target=_resume, daemon=True).start()
                    return True

                except Exception as e:
                    log(f"API RDP başlatma hatası: {e}")
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    return False

        # Non-RDP flow
        if NetworkingHelpers.is_port_in_use(int(listen_port)):
            try:
                if not messagebox.askyesno(self.t("warn"), self.t("port_in_use").format(port=listen_port)):
                    return False
            except Exception as e:
                log(f"Port-in-use dialog failed for port {listen_port}: {e}")
        
        # Tünel başlatma sırasında geçici olarak sync'i duraklat
        if manual_action:
            with self.reconciliation_lock:
                self.state["reconciliation_paused"] = True
                log(f"{service} tünel başlatma için API senkronizasyonu geçici olarak duraklatıldı.")
        
        # REACTIVE APPROACH: Try to start tunnel first, request admin if fails
        st = TunnelServerThread(self, listen_port, service)
        st.start(); time.sleep(0.15)
        if st.is_alive():
            # Tunnel started successfully
            self.state["servers"][int(listen_port)] = st
            self.write_status(self._active_rows_from_servers(), running=True)
            self.state["running"] = True
            self.update_tray_icon(); self.send_heartbeat_once("online")
            self._update_row_ui(listen_port, service, True)
            self.state["remote_desired"][service_upper] = "started"
            
            # GUI buton durumunu güncelle
            self.sync_gui_with_tunnel_state()
            
            # Report to API and wait for confirmation
            def notify_and_resume():
                try:
                    self.report_tunnel_action_to_api(service, 'start', p2)
                finally:
                    # Resume reconciliation after a short delay
                    time.sleep(3)
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
            
            threading.Thread(target=notify_and_resume, daemon=True).start()
            return True
        else:
            # Tunnel failed to start - check if admin privileges might help
            log(f"❌ {service} tüneli normal yetki ile başlatılamadı")
            
            # Check if this might be a permission issue (port < 1024 or specific ports)
            port_num = int(listen_port)
            needs_admin_retry = (
                port_num < 1024 or  # Well-known ports
                port_num in [3389, 1433, 3306] or  # Common admin-required ports
                service.upper() in ['RDP', 'SSH', 'MSSQL', 'MYSQL', 'FTP']  # Critical services
            )
            
            if needs_admin_retry and manual_action:  # Only for manual user actions
                log(f"🔓 Admin yetki ile tünel başlatma deneniyor: {service} port {listen_port}")
                
                # Request admin privileges for this specific operation
                if self.require_admin_for_operation(f"{service} Tüneli Başlatma (Port {listen_port})"):
                    log(f"✅ Admin yetki alındı - {service} tüneli yeniden deneniyor")
                    
                    # Retry tunnel start with admin privileges
                    st_admin = TunnelServerThread(self, listen_port, service)
                    st_admin.start(); time.sleep(0.15)
                    
                    if st_admin.is_alive():
                        log(f"✅ {service} tüneli admin yetki ile başarıyla başlatıldı")
                        self.state["servers"][int(listen_port)] = st_admin
                        self.write_status(self._active_rows_from_servers(), running=True)
                        self.state["running"] = True
                        self.update_tray_icon(); self.send_heartbeat_once("online")
                        self._update_row_ui(listen_port, service, True)
                        self.state["remote_desired"][service_upper] = "started"
                        
                        # GUI buton durumunu güncelle
                        self.sync_gui_with_tunnel_state()
                        
                        # Report to API and wait for confirmation
                        def notify_and_resume_admin():
                            try:
                                self.report_tunnel_action_to_api(service, 'start', p2)
                            finally:
                                time.sleep(3)
                                with self.reconciliation_lock:
                                    self.state["reconciliation_paused"] = False
                        
                        threading.Thread(target=notify_and_resume_admin, daemon=True).start()
                        return True
                    else:
                        log(f"❌ {service} tüneli admin yetki ile de başlatılamadı")
                else:
                    log(f"👤 Kullanıcı admin yetki vermeyi reddetti: {service}")
            
            # Tünel başlatılamadı - pause'i kaldır
            if manual_action:
                with self.reconciliation_lock:
                    self.state["reconciliation_paused"] = False
                log(f"❌ {service} tüneli başlatılamadı - API senkronizasyonu devam ediyor")
        
        try: messagebox.showerror(self.t("error"), self.t("port_busy_error"))
        except: pass
        return False

    def stop_single_row(self, p1: str, p2: str, service: str, manual_action: bool = False) -> bool:
        # Pause reconciliation before making changes
        with self.reconciliation_lock:
            self.state["reconciliation_paused"] = True

        service_upper = str(service).upper()
        # RDP dashboard akışında tünel her zaman 3389'u dinler
        listen_port = '3389' if service_upper == 'RDP' else str(p1)

        if service_upper == 'RDP' and listen_port == '3389':
            # Önce tüneli kapat
            st = self.state["servers"].pop(int(listen_port), None)
            if st:
                try: st.stop()
                except Exception: pass

            if manual_action:
                self.log("Manuel RDP güvenli port durdurma akışı tetiklendi.")
                def on_rdp_confirm_rollback():
                    self.write_status(self._active_rows_from_servers(), running=bool(self.state["servers"]))
                    if not self.state["servers"]:
                        self.state["running"] = False
                        self.send_heartbeat_once("offline")
                    self.update_tray_icon()
                    self._update_row_ui(listen_port, service, False)
                    self.state["remote_desired"][service_upper] = "stopped"
                    threading.Thread(target=self.report_tunnel_action_to_api,
                                    args=(service, 'stop', p2), daemon=True).start()
                log("🔄 RDP koruması durdurma - Rollback popup gösteriliyor")
                self.rdp_move_popup(mode="rollback", on_confirm=on_rdp_confirm_rollback)
                return True
            else:
                # API-driven RDP stop
                log("🤖 API tarafından RDP durdurma akışı tetiklendi")
                if not self.start_rdp_transition("rollback"):
                    log("❌ API akışı: RDP 3389'a geri alınamadı.")

                self.write_status(self._active_rows_from_servers(), running=bool(self.state["servers"]))
                if not self.state["servers"]:
                    self.state["running"] = False
                    self.send_heartbeat_once("offline")
                self.update_tray_icon()
                self._update_row_ui('3389', service, False)
                self.state["remote_desired"][service_upper] = "stopped"
                
                # GUI buton durumunu güncelle
                self.sync_gui_with_tunnel_state()
                
                threading.Thread(target=self.report_tunnel_action_to_api, args=(service, 'stop', p2), daemon=True).start()

                def _resume():
                    time.sleep(5)
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")
                threading.Thread(target=_resume, daemon=True).start()
                return True

        # Non-RDP stop
        st = self.state["servers"].pop(int(listen_port), None)
        if st:
            try:
                st.stop()
            except Exception as e:
                log(f"Tunnel stop failed for port {listen_port}: {e}")
        
        self.write_status(self._active_rows_from_servers(), running=len(self.state["servers"]) > 0)
        if not self.state["servers"]:
            self.state["running"] = False
            self.send_heartbeat_once("offline")
        self.update_tray_icon()
        self._update_row_ui(listen_port, service, False)
        self.state["remote_desired"][service_upper] = "stopped"
        
        # GUI buton durumunu güncelle
        self.sync_gui_with_tunnel_state()
        
        # Report to API and wait for confirmation
        def notify_and_resume():
            try:
                self.report_tunnel_action_to_api(service, 'stop', p2)
            finally:
                # Resume reconciliation after a short delay
                time.sleep(3)
                with self.reconciliation_lock:
                    self.state["reconciliation_paused"] = False
        
        threading.Thread(target=notify_and_resume, daemon=True).start()
        return True

    def report_tunnel_status_once(self):
        # Güncel tünel durumlarını API'ye bildirir (/api/agent/tunnel-status)
        # Her servis için status, listening_port ve varsa new_port bilgilerini gönderir
        try:
            token = self.state.get("token")
            if not token:
                log("Token bulunamadı, tünel durumu raporlanamıyor")
                return False

            # Durum raporu hazırla - sadece tanımlı servisleri raporla
            statuses = []
            for service, default_config in DEFAULT_TUNNELS.items():
                listen_port = default_config["listen_port"]
                running = self._is_service_running(listen_port, service)
                status = {
                    "service": service,
                    "status": "started" if running else "stopped",
                    "listen_port": listen_port
                }
                # RDP için hem 3389 hem güvenli portu kontrol et
                if service == "RDP":
                    current_port = ServiceController.get_rdp_port()
                    status["new_port"] = current_port
                    rdp_running = self._is_service_running(3389, service) or self._is_service_running(RDP_SECURE_PORT, service)
                    status["status"] = "started" if rdp_running else "stopped"
                statuses.append(status)
                log(f"Tünel durumu: {service} -> {status['status']} (port: {listen_port})")

            # /api/agent/tunnel-status endpoint'ine gönder
            response = self.api_request(
                method="POST",
                endpoint="agent/tunnel-status",
                json={
                    "token": token,
                    "statuses": statuses  # API modeline uygun format
                }
            )

            if not response:
                log("Tünel durumu güncellemesi başarısız")
                return False

            if isinstance(response, dict):
                if response.get("status") == "ok":
                    log("Tünel durumları başarıyla güncellendi")
                    return True
                
                error = response.get("error", "Bilinmeyen hata")
                log(f"Tünel durumu güncelleme hatası: {error}")
                
            return False

        except Exception as e:
            log(f"Tünel durumu raporlanırken hata: {e}")
            return False

    def report_tunnel_action_to_api(self, service: str, action: str,
                                    new_port: Optional[Union[str, int]] = None) -> bool:
        """Report tunnel action to API using modular API function"""
        token = self.state.get("token")
        if not token:
            return False
        
        result = report_tunnel_action_api(self.api_request, token, service, action, new_port, log)
        
        # Local cache removed - TunnelManager handles state tracking
        
        return result

    def start_rdp_transition(self, transition_mode: str = "secure") -> bool:
        """Use RDP Manager for port transitions"""
        return self.rdp_manager.start_rdp_transition(transition_mode)


        

# ---------- Remote management helpers ---------- #
    def _collect_open_ports_windows(self):
        items = []
        # Güvenlik riski oluşturabilecek yaygın portlar
        risky_ports = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            135: "RPC",
            137: "NetBIOS",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            1434: "MSSQL Browser",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            53389: "RDP Alternative"
        }
        
        try:
            # Sadece TCP portlarını kontrol et
            cmd = ["netstat", "-ano", "-p", "TCP"]
            res = run_cmd(cmd, timeout=10, suppress_rc_log=True)
            if not res or res.returncode != 0:
                return items
                
            for line in (res.stdout or "").splitlines():
                L = line.split()
                if not L or len(L) < 5:
                    continue
                    
                # Sadece TCP dinleme portlarını işle
                if L[0].upper() == "TCP":
                    local = L[1]
                    state = L[3]
                    pid = L[4] if len(L) >= 5 else None
                    
                    # Sadece LISTEN durumundaki portları al
                    if state.upper() not in ("LISTEN", "LISTENING"):
                        continue
                        
                    try:
                        addr, port = local.rsplit(":", 1)
                        port = int(port) if port.isdigit() else None
                        
                        # Port numarası geçerli ve risk listesinde ise ekle
                        if port and (port in risky_ports or port < 1024):
                            items.append({
                                "port": port,
                                "proto": "TCP",
                                "addr": addr,
                                "state": state.upper(),
                                "service": risky_ports.get(port, "Unknown"),
                                "pid": int(pid) if (pid and pid.isdigit()) else None,
                            })
                    except Exception:
                        continue
        except Exception as e:
            log(f"collect_open_ports error: {e}")
        # Keep only listening-like entries and with valid port
        out = []
        for it in items:
            try:
                if it.get("port") and (it.get("state") in ("LISTEN", "LISTENING", "LISTEN-DRAIN", "ESTABLISHED") or it.get("proto")=="UDP"):
                    out.append(it)
            except Exception:
                pass
        return out

    def report_open_ports_once(self):
        token = self.state.get("token")
        if token:
            ports = self._collect_open_ports_windows() if os.name == 'nt' else []
            self.api_client.report_open_ports(token, ports)

    def report_open_ports_loop(self):
        while True:
            try:
                self.report_open_ports_once()
            except Exception as e:
                log(f"report_open_ports_loop err: {e}")
            time.sleep(600)

    def _normalize_service(self, s: str) -> str:
        s = (s or '').upper()
        if s == 'MYSQL':
            return 'MySQL'
        return s

    def _is_service_running(self, listen_port: int, service_name: str) -> bool:
        """Check if service is running on specific port - delegates to TunnelManager"""
        from client_networking import TunnelManager
        return TunnelManager.is_service_running_by_port(self, listen_port, service_name)

    # ---------- Tray Management (Modularized) ---------- #
    def initialize_tray_manager(self):
        """Initialize tray management system"""
        try:
            self.tray_manager = TrayManager(self, self.t)
            return self.tray_manager.start_tray_system()
        except Exception as e:
            log(f"Tray manager initialization error: {e}")
            return False
    
    def update_tray_icon(self):
        """Update tray icon - delegated to tray manager"""
        if hasattr(self, 'tray_manager') and self.tray_manager:
            self.tray_manager.update_tray_icon()

    def on_close(self):
        """Handle window close event - delegated to tray manager"""
        try:
            if hasattr(self, 'tray_manager') and self.tray_manager:
                self.tray_manager.on_window_close()
            else:
                if self.state.get("running", False):
                    messagebox.showwarning(self.t("warn"), "Please stop services first")
                    return
                self.graceful_exit(0)
        except Exception as e:
            log(f"[EXIT] Kapanış hatası: {e}")
            sys.exit(1)

    def graceful_exit(self, code: int = 0):
        """Merkezi temiz çıkış — tüm kaynakları serbest bırakır"""
        try:
            log(f"[EXIT] Graceful exit başlatılıyor (code={code})")
            # Heartbeat cleanup
            if hasattr(self, 'monitoring_manager'):
                self.monitoring_manager.stop_heartbeat_system()
            # Tray cleanup
            if hasattr(self, 'tray_manager') and self.tray_manager:
                try: self.tray_manager.stop_tray_system()
                except Exception: pass
            # Socket cleanup
            self.stop_single_instance_server()
            # GUI cleanup
            if self.root:
                try: self.root.destroy()
                except Exception: pass
        except Exception as e:
            log(f"[EXIT] Cleanup hatası: {e}")
        finally:
            sys.exit(code)

    def stop_single_instance_server(self):
        s = self.state.get("ctrl_sock")
        if s:
            try: s.close()
            except: pass
            self.state["ctrl_sock"] = None

    # ---------- Update Watchdog (hourly) - Modularized ---------- #
    def start_update_watchdog(self):
        """Start update watchdog through update manager
        
        NOTE: Skipped in UI-only mode when daemon is running.
        """
        # Skip if daemon is handling this
        if getattr(self, 'daemon_is_active', False):
            log("🔄 UI-only mode: Skipping update watchdog (daemon handles this)")
            return
        return self.update_manager.start_update_watchdog(auto_update=True)

    # ---------- Daemon ---------- #
    def run_daemon(self):
        self.state["token"] = self.token_manager.load_token()
        self.state["public_ip"] = ClientHelpers.get_public_ip()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        # Note: tunnel_watchdog_loop is now integrated into tunnel_sync_loop
        
        # Session monitoring for daemon-to-tray handover
        threading.Thread(target=self.monitor_user_sessions, daemon=True).start()
        # Remote management: report open ports
        try:
            threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
        except Exception as e:
            log(f"open ports reporter start failed: {e}")
        # Tunnel sync (includes watchdog + API reconciliation in single loop)
        try:
            from client_networking import TunnelManager
            threading.Thread(target=TunnelManager.tunnel_sync_loop, args=(self,), name="tunnel_sync_loop", daemon=True).start()
        except Exception as e:
            log(f"tunnel sync loop start failed: {e}")
        # Start firewall agent in background (Windows/Linux)
        try:
            self.start_firewall_agent()
        except Exception as e:
            log(f"firewall agent start failed (daemon): {e}")
        # Start external watchdog
        try:
            start_watchdog_if_needed(WATCHDOG_TOKEN_FILE, log)
        except Exception as e:
            log(f"watchdog start error: {e}")
        # Hourly update checker
        try:
            self.start_update_watchdog()
        except Exception as e:
            log(f"update watchdog thread error: {e}")

        cons = self.read_consent()
        if not cons.get("accepted"):
            log("Daemon: kullanıcı onayı yok, tünel uygulanmayacak.")
            return

        saved_rows, saved_running = self.read_status()
        rows = saved_rows if saved_rows else [(p1, p2, s) for (p1, p2, s) in self.PORT_TABLOSU]
        self.state["selected_rows"] = [(str(a[0]), str(a[1]), str(a[2])) for a in rows]

        if not rows:
            log("Daemon: aktif port yok, beklemede.")

        while True:
            try:
                if rows and not self.state.get("running"):
                    ok = self.apply_tunnels(rows)
                    if ok:
                        log("Daemon: Tüneller aktif (arka plan).")
                time.sleep(5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Daemon loop err: {e}")
        try:
            self.remove_tunnels()
        except Exception as e:
            log(f"Exception: {e}")
        
        # Cleanup heartbeat file on daemon exit
        try:
            if hasattr(self, 'monitoring_manager'):
                self.monitoring_manager.stop_heartbeat_system()
        except Exception as e:
            log(f"Daemon heartbeat cleanup error: {e}")
            
        log("Daemon: durduruldu.")



    # ---------- Firewall Agent ---------- #
    def start_firewall_agent(self):
        """Start firewall agent with updated client_firewall module
        
        NOTE: Skipped in UI-only mode when daemon is running.
        """
        # Skip if daemon is handling this
        if getattr(self, 'daemon_is_active', False):
            log("🔄 UI-only mode: Skipping firewall agent (daemon handles this)")
            return
            
        try:
            # FirewallAgent already imported at top level
            pass
        except ImportError:
            log("client_firewall module not available; skipping.")
            return
            
        token = self.state.get("token")
        if not token:
            log("No token; firewall agent not started.")
            return
            
        # Derive API base root (strip trailing /api if present)
        base = str(API_URL or "").strip().rstrip('/')
        if base.lower().endswith('/api'):
            api_base_root = base[:-4]
        else:
            api_base_root = base
        cidr_feed = os.environ.get("CIDR_FEED_BASE", "https://www.ipdeny.com/ipblocks/data/countries")

        def agent_thread():
            try:
                agent = FirewallAgent(
                    api_base=api_base_root,
                    token=token,
                    refresh_interval=int(os.environ.get("REFRESH_INTERVAL_SEC", "10")),
                    cidr_feed_base=cidr_feed,
                    logger=LOGGER,
                )
                log(f"Firewall agent starting; API_BASE={api_base_root}, FEED={cidr_feed}")
                agent.run_forever()
            except Exception as e:
                log(f"Firewall agent error: {e}")

        # Start once; keep reference if needed
        if not self.state.get("fw_agent_started"):
            threading.Thread(target=agent_thread, daemon=True).start()
            self.state["fw_agent_started"] = True

    # ---------- GUI ---------- #
    def build_gui(self, minimized=None):
        # Basit startup mode belirleme
        startup_mode = "gui"  # default
        
        # Minimized parametresi varsa onu kullan
        if minimized is not None:
            startup_mode = "minimized" if minimized else "gui"
            
        # Ensure root window exists (needed for consent dialogs, etc.)
        if not self.root:
            self.root = tk.Tk()
            self.root.withdraw()  # Start hidden — will be configured below

        self.start_single_instance_server()

        # Background services - skip if daemon is running (UI-only mode)
        if not getattr(self, 'daemon_is_active', False):
            threading.Thread(target=self.heartbeat_loop, daemon=True).start()
            # Remote management: report open ports
            try:
                threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
            except Exception as e:
                log(f"open ports reporter start failed: {e}")
            # Start firewall agent in background
            try:
                self.start_firewall_agent()
            except Exception as e:
                log(f"firewall agent start failed (gui): {e}")
        else:
            log("🔄 UI-only mode: Skipping background threads (heartbeat, open ports, tunnels, firewall)")
        
        # Start external watchdog
        try:
            start_watchdog_if_needed(WATCHDOG_TOKEN_FILE, log)
        except Exception as e:
            log(f"watchdog start error: {e}")
        # Hourly update checker
        try:
            self.start_update_watchdog()
        except Exception as e:
            log(f"update watchdog thread error: {e}")

        # Configure main window
        if startup_mode != "minimized" and not self._tray_mode.is_set():
            try:
                self.root.deiconify()
            except Exception:
                pass
        self.root.title(f"{self.t('app_title')} v{__version__}")
        
        # Window icon ayarla
        try:
            from client_utils import get_resource_path
            
            # Ana window icon
            main_icon_path = get_resource_path('certs/honeypot.ico')
            if os.path.exists(main_icon_path):
                self.root.iconbitmap(main_icon_path)
                
                # Taskbar icon için ayrıca PhotoImage ile ayarla
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(main_icon_path)
                    photo = ImageTk.PhotoImage(img)
                    self.root.iconphoto(True, photo)
                except Exception as e:
                    log(f"PhotoImage icon error: {e}")
            else:
                log(f"Main icon not found: {main_icon_path}")
                
        except Exception as e:
            log(f"Icon setup error: {e}")  # Log the error instead of silent pass
            
        self.root.geometry("820x620")
        self.root.configure(bg="#f5f5f5")

        # Language from central config
        self.lang = get_config_value("language.selected", "tr")

        try:
            self.ensure_consent_ui()
        except Exception as e:
            log(f"consent ui error: {e}")

        # Menu
        menubar = tk.Menu(self.root)
        menu_settings = tk.Menu(menubar, tearoff=0)
        def set_lang(code):
            try: 
                update_language_config(code, True)
                log(f"[CONFIG] Language changed to: {code}")
            except Exception as e: 
                log(f"[CONFIG] Language change error: {e}")
            messagebox.showinfo(self.t("info"), self.t("restart_needed_lang"))
            exe = ClientHelpers.current_executable()
            try:
                subprocess.Popen([exe] + sys.argv[1:], shell=False,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass
            sys.exit(0)
        lang_menu = tk.Menu(menu_settings, tearoff=0)
        lang_menu.add_command(label=self.t("menu_lang_tr"), command=lambda: set_lang("tr"))
        lang_menu.add_command(label=self.t("menu_lang_en"), command=lambda: set_lang("en"))
        menu_settings.add_cascade(label=self.t("menu_language"), menu=lang_menu)
        menubar.add_cascade(label=self.t("menu_settings"), menu=menu_settings)

        menu_help = tk.Menu(menubar, tearoff=0)
        # Static version label as disabled entry at the top
        menu_help.add_command(label=f"Sürüm: v{__version__}" if self.lang == 'tr' else f"Version: v{__version__}", state='disabled')
        # Logs opener
        def open_logs():
            try:
                if os.name == 'nt':
                    os.startfile(LOG_FILE)
                else:
                    webbrowser.open(f"file://{LOG_FILE}")
                log(f"Log dosyası açıldı: {LOG_FILE}")
            except Exception as e:
                log(f"open_logs error: {e}")
                messagebox.showerror(self.t("error"), self.t("log_file_error").format(error=e))
        menu_help.add_command(label=self.t("menu_logs"), command=open_logs)
        # GitHub opener
        def open_github():
            try:
                webbrowser.open(f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}")
            except Exception as e:
                log(f"open_github error: {e}")
        menu_help.add_command(label=self.t("menu_github"), command=open_github)
        menu_help.add_separator()
        menu_help.add_command(label=self.t("menu_check_updates"), command=self.check_updates_and_prompt)
        menubar.add_cascade(label=self.t("menu_help"), menu=menu_help)
        self.root.config(menu=menubar)

        # Kapatma → tray
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        style.configure("TButton", font=("Arial", 11), padding=6)
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        style.configure("Treeview", rowheight=28)

        # Sunucu Bilgileri
        frame1 = tk.LabelFrame(self.root, text=self.t("server_info"), padx=10, pady=10, bg="#f5f5f5", font=("Arial", 11, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)

        def copy_entry(entry: tk.Entry):
            try:
                value = entry.get()
                self.root.clipboard_clear(); self.root.clipboard_append(value); self.root.update()
                messagebox.showinfo(self.t("copy"), value)
            except Exception as e:
                log(f"copy_entry error: {e}")

        # Token'ı yükle
        token = self.token_manager.load_token(self.root, self.t)
        self.state["token"] = token
        self.state["public_ip"] = ClientHelpers.get_public_ip()
        
        # Create dashboard URL after token is loaded
        dashboard_url = f"https://honeypot.yesnext.com.tr/dashboard?token={token if token else ''}"
        
        def open_dashboard():
            webbrowser.open(dashboard_url)

        attack_count_val = self.fetch_attack_count_sync(token) if token else 0
        if attack_count_val is None: attack_count_val = 0

        info_rows = [
            (self.t("lbl_pc_ip"), f"{SERVER_NAME} ({self.state['public_ip']})", "ip"),
            (self.t("lbl_token"), token, "token"),
            (self.t("lbl_dashboard"), dashboard_url, "dash"),
            (self.t("lbl_attacks"), str(attack_count_val), "attacks"),
        ]

        # satırlar
        for idx, (label, value, key) in enumerate(info_rows):
            tk.Label(frame1, text=label + ":", font=("Arial", 11), bg="#f5f5f5",
                     width=18, anchor="w").grid(row=idx, column=0, sticky="w", pady=3)
            entry = tk.Entry(frame1, width=60, font=("Arial", 10))
            if value is not None:
                entry.insert(0, str(value))
            entry.config(state="readonly")
            entry.grid(row=idx, column=1, padx=5, pady=3)

            tk.Button(frame1, text="📋", command=lambda e=entry: copy_entry(e)).grid(row=idx, column=2, padx=3)

            if key == "dash":
                tk.Button(frame1, text="🌐 " + self.t("open"), command=open_dashboard).grid(row=idx, column=3, padx=3)

            if key == "attacks":
                tk.Button(frame1, text="↻ " + self.t("refresh"), command=lambda: self.refresh_attack_count(async_thread=True)).grid(row=idx, column=3, padx=3)
                self.attack_entry = entry

            if key == "ip":
                self.ip_entry = entry

        self.poll_attack_count()

        # Now that token is loaded, refresh attack count
        if token:
            self.refresh_attack_count(async_thread=True)

        # Port Tünelleme
        frame2 = tk.LabelFrame(self.root, text=self.t("port_tunnel"), padx=10, pady=10, bg="#f5f5f5", font=("Arial", 11, "bold"))
        frame2.pack(fill="both", expand=True, padx=15, pady=10)

        # Stacked per-row controls (better UX than table cell clicks)
        self.row_controls = {}
        saved_rows, saved_running = self.read_status()

        def make_row(parent, p1, p2, servis):
            fr = tk.Frame(parent, bg="#ffffff", padx=8, pady=8, highlightbackground="#ddd", highlightthickness=1)
            fr.pack(fill="x", pady=6)
            # Columns grow: make the middle space flexible so the button sticks right
            try:
                fr.grid_columnconfigure(2, weight=1)
            except Exception:
                pass
            # Labels
            tk.Label(fr, text=f"{self.t('col_service')}: {servis}", bg="#ffffff", font=("Arial", 11, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
            tk.Label(fr, text=f"{self.t('col_listen')}: {p1}", bg="#ffffff", anchor="w").grid(row=1, column=0, sticky="w")
            tk.Label(fr, text=f"{self.t('col_new')}: {p2}", bg="#ffffff", anchor="w").grid(row=1, column=1, sticky="w", padx=10)
            # Status label
            status_lbl = tk.Label(fr, text=f"{self.t('status')}: {self.t('status_stopped')}", bg="#ffffff", anchor="w")
            status_lbl.grid(row=1, column=2, sticky="w", padx=10)
            # Button (right aligned)
            btn = tk.Button(fr, text=self.t('btn_row_start'), bg="#4CAF50", fg="white", padx=18, pady=6, font=("Arial", 10, "bold"))

            def toggle():
                is_rdp = (str(servis).upper() == 'RDP')

                if is_rdp:
                    self.state['reconciliation_paused'] = True
                    log("RDP işlemi için uzlaştırma döngüsü duraklatıldı.")

                try:
                    cur = btn["text"].lower()
                    if cur == self.t('btn_row_start').lower():
                        # Pass manual_action=True for GUI-initiated actions
                        if self.start_single_row(str(p1), str(p2), str(servis), manual_action=True):
                            # For non-RDP, the UI updates instantly.
                            # For RDP, the popup handles the flow, but we can preemptively update the UI.
                            if not is_rdp:
                                btn.config(text=self.t('btn_row_stop'), bg="#E53935")
                                fr.configure(bg="#EEF7EE")
                                status_lbl.config(text=f"{self.t('status')}: {self.t('status_running')}")
                    else:
                        # Pass manual_action=True for GUI-initiated actions
                        if self.stop_single_row(str(p1), str(p2), str(servis), manual_action=True):
                            if not is_rdp:
                                btn.config(text=self.t('btn_row_start'), bg="#4CAF50")
                                fr.configure(bg="#ffffff")
                                status_lbl.config(text=f"{self.t('status')}: {self.t('status_stopped')}")
                finally:
                    if is_rdp:
                        self.state['reconciliation_paused'] = False
                        log("RDP işlemi tamamlandı, uzlaştırma döngüsü devam ettiriliyor.")
                        # Immediately report the new status to the API
                        threading.Thread(target=self.report_tunnel_status_once, daemon=True).start()

            btn.config(command=toggle)
            
            # RDP için özel RDP Taşı butonu ekle
            if str(servis).upper() == 'RDP':
                # RDP Taşı butonu (ana butonun soluna)
                def get_rdp_button_text():
                    try:
                        is_protected, current_port = self.rdp_manager.get_rdp_protection_status()
                        target_port = 3389 if is_protected else RDP_SECURE_PORT
                        return f"RDP Taşı : {target_port}"
                    except:
                        return "RDP Taşı : 53389"
                
                rdp_btn = tk.Button(
                    fr, 
                    text=get_rdp_button_text(),
                    bg="#FF9800" if self.rdp_manager.is_rdp_protection_active() else "#2196F3",
                    fg="white", 
                    padx=12, 
                    pady=6, 
                    font=("Arial", 9, "bold"),
                    command=self.toggle_rdp_protection
                )
                rdp_btn.grid(row=0, column=2, rowspan=2, sticky="e", padx=(0, 5))
                
                # Ana butonu biraz daha sağa kaydır
                btn.grid(row=0, column=3, rowspan=2, sticky="e", padx=5)
                
                # RDP buton referansını sakla
                self.row_controls[(str(p1), str(servis).upper())] = {
                    "frame": fr, "button": btn, "status": status_lbl, "rdp_button": rdp_btn
                }
            else:
                # Diğer servisler için normal pozisyon
                btn.grid(row=0, column=3, rowspan=2, sticky="e", padx=10)
                self.row_controls[(str(p1), str(servis).upper())] = {"frame": fr, "button": btn, "status": status_lbl}

        for (p1, p2, servis) in self.PORT_TABLOSU:
            make_row(frame2, p1, p2, servis)

        # Apply previous state to UI
        if saved_rows:
            for (sp1, sp2, ssvc) in saved_rows:
                key = (str(sp1), str(ssvc).upper())
                rc = self.row_controls.get(key)
                if rc:
                    rc["button"].config(text=self.t('btn_row_stop'), bg="#E53935")
                    rc["frame"].configure(bg="#EEF7EE")
                    rc["status"].config(text=f"{self.t('status')}: {self.t('status_running')}")



        # Legacy migration code removed - now using installer-based system

        # Optional silent auto-update on startup if configured and no active tunnels
        try:
            if os.environ.get('AUTO_UPDATE_SILENT') == '1':
                if not self.state.get('servers'):
                    self.check_updates_and_apply_silent()
        except Exception as e:
            log(f"auto-update silent error: {e}")

        # Initialize tray system
        if TRY_TRAY:
            self.initialize_tray_manager()

        # Başlangıçta tüm servisleri durmuş olarak başlat
        self.state["running"] = False
        self.state["servers"] = {}
        self.state["selected_rows"] = []
        self.write_status([], running=False)
        # Tray ikonunu kırmızı olarak güncelle (pasif)
        try:
            self.update_tray_icon()
        except Exception as e:
            log(f"Exception: {e}")
            
        # ===== BASIT STARTUP MODE ===== #
        # Basit startup mode uygulama
        if startup_mode == "minimized":
            self._tray_mode.set()  # Mark as intentionally in tray
            self.root.withdraw()   # Fully hide (not just iconify)
        else:
            # Normal GUI mode - only show if not already in tray
            if not self._tray_mode.is_set():
                self.root.deiconify()

        # show_cb is used by single-instance control server to bring window to front
        def _show_window():
            try:
                if hasattr(self, 'tray_manager') and self.tray_manager:
                    self.tray_manager.show_window()
                else:
                    self._tray_mode.clear()
                    self.root.deiconify(); self.root.lift(); self.root.focus_force()
            except: pass
        self.show_cb = _show_window

        # poll_attack_count is already started above — do NOT schedule again
        # (previously caused double scheduling chains)
        
        # GUI sağlık durumu izleme başlat
        self.root.after(self.gui_health['health_check_interval'] * 1000, self.check_gui_health)



# ===================== MAIN ===================== #
if __name__ == "__main__":
    # Parse arguments first to check for non-GUI modes
    parser = argparse.ArgumentParser(add_help=True, description="Cloud Honeypot Client - Advanced Honeypot Management System")
    
    # Simplified mode system
    parser.add_argument("--mode", choices=["daemon", "tray", "watchdog"], help="Operation mode: daemon (background service), tray (tray-only mode), watchdog (hourly process check). Default is GUI mode.")
    parser.add_argument("--minimized", action="store_true", help="Start GUI minimized to tray")
    parser.add_argument("--daemon", action="store_true", help="Run as a daemon service")
    parser.add_argument("--silent", action="store_true", help="Silent mode - no user dialogs")
    parser.add_argument("--watchdog", action="store_true", help="Run watchdog mode - ensure app is running")
    parser.add_argument("--watchdog-pid", type=int, default=None, help="Watchdog process ID")
    parser.add_argument("--healthcheck", action="store_true", help="Perform health check and exit")
    parser.add_argument("--silent-update-check", action="store_true", help="Silent update check mode - check for updates and install automatically")
    parser.add_argument("--create-tasks", action="store_true", help="Create Task Scheduler tasks and exit (for installer)")
    args = parser.parse_args()
    
    # Set global silent mode if requested
    if args.silent:
        import client_constants
        # Override config for silent deployment
        client_constants.SILENT_ADMIN_ELEVATION = True
        client_constants.SKIP_USER_DIALOGS = True

    # Handle watchdog mode - check if app is running
    if args.watchdog:
        from client_helpers import ClientHelpers
        helper = ClientHelpers()
        
        log("Watchdog mode activated - checking if app is running...")
        
        try:
            # Check if main app is running
            is_running = helper.is_app_running()
            
            if not is_running:
                log("Main app not running, starting new instance...")
                # Start main app without watchdog flag
                import subprocess
                import sys
                
                # Get executable path
                exe_path = sys.executable if not getattr(sys, 'frozen', False) else sys.argv[0]
                
                # Start main app
                if getattr(sys, 'frozen', False):
                    subprocess.Popen([exe_path], 
                                   creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
                else:
                    subprocess.Popen([sys.executable, "client.py"], 
                                   creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
                
                log("New app instance started successfully")
            else:
                log("Main app is already running - no action needed")
                
        except Exception as e:
            log(f"Watchdog error: {e}")
        
        sys.exit(0)
    
    # Handle silent update check mode
    if args.silent_update_check:
        log("Silent update check mode activated - checking for updates...")
        try:
            # Import update manager
            from client_updater import UpdateManager
            
            # Set silent mode
            import client_constants
            client_constants.SILENT_ADMIN_ELEVATION = True
            client_constants.SKIP_USER_DIALOGS = True
            
            # Initialize update manager
            update_mgr = UpdateManager()
            
            # Perform silent update check and install
            result = update_mgr.check_for_updates_silent()
            
            if result:
                log("Silent update completed successfully - application will restart")
                # Note: If update was installed, check_for_updates_silent() calls os._exit(0)
            else:
                log("No updates available or silent update failed")
                
        except Exception as e:
            log(f"Silent update check error: {e}")
        
        sys.exit(0)
    
    # Handle task creation mode (for installer)
    if args.create_tasks:
        log("Task creation mode activated - setting up Task Scheduler tasks...")
        try:
            # Import task scheduler
            from client_task_scheduler import install_all_tasks
            
            # Set silent mode
            import client_constants
            client_constants.SILENT_ADMIN_ELEVATION = True
            client_constants.SKIP_USER_DIALOGS = True
            
            # Create all tasks including silent updater
            result = install_all_tasks(include_silent_updater=True)
            
            if result:
                log("Task Scheduler tasks created successfully")
            else:
                log("Task Scheduler task creation failed")
                
        except Exception as e:
            log(f"Task creation error: {e}")
        
        sys.exit(0)
    
    # Handle special cases that don't need GUI (deprecated watchdog-pid)
    if args.watchdog_pid is not None:
        watchdog_main(args.watchdog_pid)
        sys.exit(0)
    
    # Health check mode (for monitoring)
    if args.healthcheck:
        perform_health_check()
        sys.exit(0)

    # Determine operation mode
    operation_mode = get_operation_mode(args)
    log(f"=== CLOUD HONEYPOT CLIENT STARTUP ===")
    log(f"Operation mode: {operation_mode}")
    log(f"Process PID: {os.getpid()}")
    log(f"Command line: {' '.join(sys.argv)}")
    
    # Singleton check - ensure only one instance per mode
    if not check_singleton(operation_mode):
        log(f"ERROR: Cannot start - another instance is running or mutex failed")
        sys.exit(2)  # Exit code 2 = Mutex taken

    # ===== SIMPLIFIED MODE-BASED EXECUTION =====
    
    if operation_mode == GUI_MODE:
        # ===== GUI MODE - Normal GUI application with tray functionality =====
        
        # Initialize basic logging FIRST
        log_dir = os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient')
        os.makedirs(log_dir, exist_ok=True)
        setup_logging()
        
        log("=== GUI MODE STARTUP - Normal interface startup ===")
        
        try:
            # Load configuration
            config = load_config()
            selected_language = config["language"]["selected"]
            
            # Create app instance
            app = CloudHoneypotClient()
            app.lang = selected_language
            log(f"Application initialized with language: {selected_language}")
            
            # Task Scheduler management handled by modular system in __init__
            if ctypes.windll.shell32.IsUserAnAdmin():
                log("Admin yetkisi mevcut - Task Scheduler yönetimi __init__ tarafından halledildi")
            else:
                log("Normal user mode - Task Scheduler will be configured later")
            
            # Check if started with --mode=tray for tray-minimized startup
            tray_mode = getattr(args, 'mode', None) == 'tray'
            
            # Build GUI in both cases
            log("Building main GUI...")
            app.build_gui(minimized=tray_mode)  # Pass tray_mode as minimized flag
            log("GUI build completed successfully")
            
            # Check RDP protection status and update GUI accordingly
            try:
                is_protected, current_port = app.rdp_manager.get_rdp_protection_status()
                if is_protected:
                    log(f"🛡️ RDP koruması aktif (port: {current_port}) - GUI güncelleniyor")
                else:
                    log(f"🔓 RDP koruması pasif (port: {current_port}) - GUI varsayılan durumda")
                
                # GUI buton durumunu senkronize et
                app.sync_gui_with_tunnel_state()
                app.update_tray_icon()
            except Exception as e:
                log(f"❌ RDP durum kontrolü hatası: {e}")
            
            # Start API synchronization in background after GUI is ready
            app.start_delayed_api_sync()
            
            # If tray mode, immediately hide to tray after GUI is built
            if tray_mode:
                log("Tray mode: Minimizing to tray...")
                if hasattr(app, 'root') and app.root:
                    app._tray_mode.set()  # Mark as intentionally in tray
                    app.root.withdraw()  # Hide the window
                    app.root.update()
                    log("Tray mode: Window hidden successfully")
            
            # Run main loop
            if hasattr(app, 'root') and app.root:
                app.root.mainloop()
            
        except Exception as gui_error:
            log(f"GUI Mode Error: {gui_error}")
            import traceback
            log(f"GUI Error traceback: {traceback.format_exc()}")
            sys.exit(1)
    

    elif operation_mode == DAEMON_MODE or args.daemon:
        # DAEMON MODE - Background operation, no GUI
        import subprocess
        import ctypes
        import time
        def is_user_logged_on():
            try:
                result = subprocess.run(['query', 'session'], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n')[1:]:
                    if 'Active' in line and 'console' in line.lower():
                        return True
            except Exception as e:
                log(f"User session check error: {e}")
            return False

        if is_user_logged_on():
            log("Active user session detected at daemon startup. Switching to tray/GUI mode.")
            # Tray/GUI modunu başlat
            log_dir = os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient')
            os.makedirs(log_dir, exist_ok=True)
            setup_logging()
            try:
                config = load_config()
                selected_language = config["language"]["selected"]
                app = CloudHoneypotClient()
                app.lang = selected_language
                log(f"Application initialized with language: {selected_language}")
                log("Building main GUI (daemon detected logon)...")
                app.build_gui(minimized=False)
                log("GUI build completed successfully")
                if hasattr(app, 'root') and app.root:
                    app.root.mainloop()
            except Exception as gui_error:
                log(f"GUI Mode Error (daemon logon): {gui_error}")
                import traceback
                log(f"GUI Error traceback: {traceback.format_exc()}")
                sys.exit(1)
            sys.exit(0)
        else:
            app = None
            try:
                log("=== DAEMON MODE STARTUP ===")
                log_dir = os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'logs')
                os.makedirs(log_dir, exist_ok=True)
                setup_logging()
                log("Setting up daemon mode application...")
                app = CloudHoneypotClient()
                log("Starting daemon mode...")
                app.run_daemon()
            except KeyboardInterrupt:
                log("Daemon interrupted by user signal")
                sys.exit(0)
            except Exception as daemon_error:
                log(f"DAEMON CRITICAL ERROR: {daemon_error}")
                import traceback
                log(f"Daemon traceback: {traceback.format_exc()}")
                try:
                    if app and hasattr(app, 'heartbeat_path'):
                        if hasattr(app, 'monitoring_manager'):
                            app.monitoring_manager.stop_heartbeat_system()
                except:
                    pass
                sys.exit(1)  # Exit code 1 = Unhandled exception
            sys.exit(0)
    
    elif operation_mode == "watchdog":
        # ===== WATCHDOG MODE - Hourly process monitoring and restart =====
        try:
            log("=== WATCHDOG MODE STARTUP ===")
            
            from client_helpers import ClientHelpers
            helper = ClientHelpers()
            
            log("Watchdog mode activated - checking if background daemon is running...")
            
            # Check if daemon is running
            is_running = helper.is_daemon_running()
            
            if not is_running:
                log("Background daemon not running, starting new daemon instance...")
                
                # Get executable path
                exe_path = sys.executable if not getattr(sys, 'frozen', False) else sys.argv[0]
                
                # Start daemon mode
                if getattr(sys, 'frozen', False):
                    subprocess.Popen([exe_path, "--mode=daemon", "--silent"], 
                                   creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
                else:
                    subprocess.Popen([sys.executable, "client.py", "--mode=daemon", "--silent"], 
                                   creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
                
                log("New daemon instance started successfully")
            else:
                log("Background daemon is already running - watchdog check passed")
                
        except Exception as e:
            log(f"Watchdog error: {e}")
        
        sys.exit(0)
    
    else:
        # Fallback - should not happen with current logic
        log(f"ERROR: Unknown operation mode: {operation_mode}")
        sys.exit(1)
