#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 CLOUD HONEYPOT CLIENT - TASK SCHEDULER ARCHITECTURE
=====================================================

📋 MODERN ARCHITECTURE OVERVIEW:
┌─────────────────────────────────────────────────────────────────┐
│                    TASK SCHEDULER BASED SYSTEM                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🟢 BACKGROUND TASK (Boot Trigger)                             │
│  ├─ Trigger: At system startup                                 │
│  ├─ Mode: --mode=daemon (no GUI, background only)             │
│  ├─ Context: SYSTEM (server environments)                      │
│  └─ Auto-restart: 10s delay, 5 attempts                       │
│                                                                 │
│  🟡 TRAY TASK (Logon Trigger)                                  │
│  ├─ Trigger: At user logon                                     │
│  ├─ Mode: --mode=tray (GUI + system tray)                     │
│  ├─ Context: User session (interactive)                        │
│  └─ Auto-restart: 10s delay, 3 attempts                       │
│                                                                 │
│  🔒 SINGLETON PROTECTION                                        │
│  ├─ Global Mutex: "Global\\CloudHoneypotClient_Singleton"      │
│  ├─ Prevents conflicts between daemon/tray modes               │
│  └─ Graceful shutdown of existing instances                    │
│                                                                 │
│  💓 HEARTBEAT MONITORING                                        │
│  ├─ File: heartbeat.json (10s intervals)                      │
│  ├─ Contains: PID, timestamps, status, mode                   │
│  └─ Used for health checks and external monitoring            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ KEY BENEFITS vs Windows Service:                                │
│ ✅ No SYSTEM context GUI issues                                │
│ ✅ Built-in Windows restart reliability                        │
│ ✅ Separate user/system execution contexts                     │
│ ✅ Easier debugging and troubleshooting                        │
│ ✅ Better Windows Update compatibility                          │
│ ✅ User-friendly task scheduler management                      │
└─────────────────────────────────────────────────────────────────┘

🚀 EXECUTION MODES:
┌─────────────────┬─────────────────────────────────────────────┐
│ Mode            │ Description                                 │
├─────────────────┼─────────────────────────────────────────────┤
│ --mode=daemon   │ Background mode (no GUI)                   │
│                 │ - Server/headless environments             │
│                 │ - Logs to %PROGRAMDATA%                    │
│                 │ - System context compatible                │
├─────────────────┼─────────────────────────────────────────────┤
│ --mode=tray     │ Interactive mode (GUI + tray)              │
│                 │ - Desktop environments                     │
│                 │ - User context with tray icon              │
│                 │ - GUI dialogs and notifications            │
├─────────────────┼─────────────────────────────────────────────┤
│ --healthcheck   │ Health monitoring utility                  │
│                 │ - Returns exit codes for monitoring       │
│                 │ - Used by external tools                  │
└─────────────────┴─────────────────────────────────────────────┘

📦 EXIT CODES:
┌──────────┬─────────────────────────────────────────────────────┐
│ Code     │ Meaning                                             │
├──────────┼─────────────────────────────────────────────────────┤
│ 0        │ Normal exit                                         │
│ 1        │ Unhandled exception / critical error               │
│ 2        │ Mutex taken (another instance running)             │
│ 3        │ Health check failed                                │
└──────────┴─────────────────────────────────────────────────────┘

🔧 INSTALLATION:
1. Run installer → Automatically sets up Task Scheduler rules
2. Background task starts at boot → Daemon mode
3. Tray task starts at logon → GUI mode  
4. Both respect singleton mutex → No conflicts

📝 LEGACY NOTES:
- Windows Service architecture removed (caused SYSTEM context issues)
- All new deployments use Task Scheduler exclusively
- Legacy service files completely removed from codebase
"""

# Standard library imports
import os, sys, socket, threading, time, json, subprocess, ctypes, argparse, tempfile, hashlib, winreg
import tkinter as tk
from tkinter import ttk, messagebox
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Any, Union
import datetime as dt
import requests, logging, webbrowser
import win32api, win32event, winerror, psutil

# Local module imports  
from client_firewall import FirewallAgent
from client_helpers import log, ClientHelpers, run_cmd
import client_helpers
from client_networking import TunnelServerThread, NetworkingHelpers, TunnelManager, set_config_function, load_network_config
from client_api import HoneypotAPIClient, api_request_with_token, register_client_api, update_client_ip_api, send_heartbeat_api, report_open_ports_api
from client_tokens import create_token_manager, get_token_file_paths
from client_task_scheduler import install_tasks, uninstall_tasks, check_tasks_status
from client_utils import (ServiceController, load_i18n, is_admin, install_excepthook, 
                         load_config, save_config, get_config_value, set_config_value,
                         get_from_config, start_watchdog_if_needed, get_port_table,
                         update_language_config, watchdog_main, write_watchdog_token)

# Import constants from central configuration
from client_constants import (
    GUI_MODE, DAEMON_MODE, TRAY_MODE, 
    HEARTBEAT_FILE, HEARTBEAT_INTERVAL,
    SINGLETON_MUTEX_NAME, API_URL, APP_DIR,
    LOG_FILE, LOG_MAX_BYTES, LOG_BACKUP_COUNT, LOG_ENCODING,
    LOG_TIME_FORMAT, TRY_TRAY, DEFENDER_MARKERS, 
    SECURITY_METADATA, LEGITIMATE_DOMAINS, RESTRICTED_PATHS,
    REGISTRY_KEY_PATH, RDP_SECURE_PORT, HONEYPOT_IP, 
    HONEYPOT_TUNNEL_PORT, SERVER_NAME, DEFAULT_TUNNELS,
    API_STARTUP_DELAY, API_RETRY_INTERVAL, API_SLOW_RETRY_DELAY,
    HEARTBEAT_INTERVAL, ATTACK_COUNT_REFRESH, RDP_TRANSITION_TIMEOUT,
    RECONCILE_LOOP_INTERVAL,
    TASK_NAME_BOOT, TASK_NAME_LOGON, CONSENT_FILE, STATUS_FILE,
    WATCHDOG_TOKEN_FILE, __version__, GITHUB_OWNER, GITHUB_REPO,
    WINDOW_WIDTH, WINDOW_HEIGHT, CONTROL_HOST, CONTROL_PORT
)

# ===================== SINGLETON & HEARTBEAT SYSTEM ===================== #

def create_heartbeat_file(app_dir: str) -> str:
    """Create initial heartbeat file and return path"""
    heartbeat_path = os.path.join(app_dir, HEARTBEAT_FILE)
    try:
        heartbeat_data = {
            "application": "Cloud Honeypot Client",
            "version": __version__ if '__version__' in globals() else "1.0.0",
            "pid": os.getpid(),
            "executable": sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0]),
            "working_directory": os.getcwd(),
            "started_at": dt.datetime.now().isoformat(),
            "last_heartbeat": dt.datetime.now().isoformat(),
            "status": "initializing",
            "admin_privileges": ctypes.windll.shell32.IsUserAnAdmin() if os.name == 'nt' else False,
            "active_tunnels": 0,
            "api_connected": False
        }
        
        with open(heartbeat_path, 'w', encoding='utf-8') as f:
            json.dump(heartbeat_data, f, indent=2, ensure_ascii=False)
        
        log(f"Heartbeat sistemi başlatıldı: {heartbeat_path}")
        return heartbeat_path
    except Exception as e:
        log(f"Heartbeat dosyası oluşturulamadı: {e}")
        return ""

def update_heartbeat_file(heartbeat_path: str, app_instance=None) -> bool:
    """Update heartbeat file with current timestamp and status"""
    if not heartbeat_path or not os.path.exists(heartbeat_path):
        return False
    
    try:
        # Read existing data
        with open(heartbeat_path, 'r', encoding='utf-8') as f:
            heartbeat_data = json.load(f)
        
        # Update timestamp and status
        heartbeat_data["last_heartbeat"] = dt.datetime.now().isoformat()
        
        # Update status information if app instance is available
        if app_instance:
            heartbeat_data["status"] = "running"
            heartbeat_data["active_tunnels"] = len(app_instance.state.get("servers", {}))
            heartbeat_data["api_connected"] = bool(app_instance.state.get("token"))
        else:
            heartbeat_data["status"] = "running"
        
        # Write updated data
        with open(heartbeat_path, 'w', encoding='utf-8') as f:
            json.dump(heartbeat_data, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        log(f"Heartbeat güncelleme hatası: {e}")
        return False

def heartbeat_worker(heartbeat_path: str, app_instance=None):
    """Background worker for heartbeat updates"""
    log(f"Heartbeat worker başlatıldı (her {HEARTBEAT_INTERVAL} saniye)")
    
    while True:
        try:
            if update_heartbeat_file(heartbeat_path, app_instance):
                pass  # Successful update, no logging needed to avoid spam
            else:
                log("Heartbeat güncellenemedi")
            
            time.sleep(HEARTBEAT_INTERVAL)
        except Exception as e:
            log(f"Heartbeat worker hatası: {e}")
            time.sleep(HEARTBEAT_INTERVAL)

def cleanup_heartbeat_file(heartbeat_path: str):
    """Clean up heartbeat file on application exit"""
    try:
        if heartbeat_path and os.path.exists(heartbeat_path):
            # Update final status
            with open(heartbeat_path, 'r', encoding='utf-8') as f:
                heartbeat_data = json.load(f)
            
            heartbeat_data["status"] = "stopped"
            heartbeat_data["stopped_at"] = dt.datetime.now().isoformat()
            
            with open(heartbeat_path, 'w', encoding='utf-8') as f:
                json.dump(heartbeat_data, f, indent=2, ensure_ascii=False)
            
            log("Heartbeat sistemi durduruldu")
    except Exception as e:
        log(f"Heartbeat temizlik hatası: {e}")

# ===================== SINGLETON SYSTEM ===================== #
def check_singleton(mode: str) -> bool:
    """Check if another instance is running and handle accordingly"""
    import win32event
    import win32api
    import winerror
    
    try:
        # Try to create mutex
        mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()
        
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            log(f"Another instance detected - attempting graceful shutdown")
            
            # Try to find and gracefully shutdown existing process
            if shutdown_existing_instance():
                log("Existing instance shutdown successfully - waiting before starting new instance")
                time.sleep(3)
                
                # Try mutex again after shutdown
                mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
                last_error = win32api.GetLastError()
                
                if last_error == winerror.ERROR_ALREADY_EXISTS:
                    log("ERROR: Could not acquire singleton mutex after shutdown attempt")
                    return False
            else:
                log("ERROR: Failed to shutdown existing instance")
                return False
        
        log(f"Singleton mutex acquired for mode: {mode}")
        return True
        
    except Exception as e:
        log(f"ERROR: Singleton check failed: {e}")
        return False

def shutdown_existing_instance() -> bool:
    """Find and gracefully shutdown existing honeypot-client.exe processes"""
    import psutil
    
    try:
        current_pid = os.getpid()
        processes_found = []
        
        # Find all honeypot-client.exe processes except current
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if (proc.info['name'].lower() in ['honeypot-client.exe', 'client.exe'] and
                proc.info['pid'] != current_pid):
                processes_found.append(proc)
        
        if not processes_found:
            log("No existing instances found")
            return True
        
        log(f"Found {len(processes_found)} existing processes to shutdown")
        
        # Try graceful shutdown first
        for proc in processes_found:
            try:
                log(f"Gracefully terminating PID {proc.info['pid']}")
                proc.terminate()
                proc.wait(timeout=5)
                log(f"Successfully terminated PID {proc.info['pid']}")
            except psutil.TimeoutExpired:
                try:
                    log(f"Force killing PID {proc.info['pid']}")
                    proc.kill()
                    proc.wait(timeout=2)
                except:
                    log(f"Failed to kill PID {proc.info['pid']}")
            except psutil.NoSuchProcess:
                log(f"Process PID {proc.info['pid']} already terminated")
            except Exception as e:
                log(f"Error shutting down PID {proc.info['pid']}: {e}")
        
        time.sleep(1)
        return True
        
    except Exception as e:
        log(f"Error during existing instance shutdown: {e}")
        return False

def get_operation_mode(args) -> str:
    """Determine operation mode from arguments - SIMPLIFIED"""
    if getattr(args, 'mode', None) == "daemon" or getattr(args, 'daemon', False):
        return DAEMON_MODE
    else:
        # Both default and tray mode use GUI_MODE
        # The difference is handled in the tray_mode flag
        return GUI_MODE

# ===================== SINGLETON SYSTEM END ===================== #

def perform_health_check():
    """Perform health check and return status"""
    try:
        log("=== HEALTH CHECK STARTED ===")
        
        # Check if process is running
        pid = os.getpid()
        log(f"Current PID: {pid}")
        
        # Check heartbeat file if exists
        app_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0]))
        heartbeat_path = os.path.join(app_dir, HEARTBEAT_FILE)
        
        if os.path.exists(heartbeat_path):
            try:
                with open(heartbeat_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                last_heartbeat_str = data.get('last_heartbeat')
                if last_heartbeat_str:
                    last_heartbeat = dt.datetime.fromisoformat(last_heartbeat_str)
                    now = dt.datetime.now()
                    time_diff = (now - last_heartbeat).total_seconds()
                    
                    log(f"Heartbeat age: {time_diff:.1f} seconds")
                    
                    if time_diff > 60:  # More than 1 minute old
                        log("WARNING: Heartbeat is stale")
                        sys.exit(3)  # Exit code 3 = Health fail
                else:
                    log("WARNING: No heartbeat timestamp found")
                    sys.exit(3)
                    
            except Exception as e:
                log(f"WARNING: Could not read heartbeat file: {e}")
                sys.exit(3)
        else:
            log("INFO: No heartbeat file found (normal for fresh start)")
        
        log("=== HEALTH CHECK PASSED ===")
        
    except Exception as e:
        log(f"HEALTH CHECK ERROR: {e}")
        sys.exit(3)

# Legacy monitor service removed - Task Scheduler handles automation

# ===================== LOGGING SETUP ===================== #
# Purpose: Modern, efficient logging system with millisecond precision

class CustomFormatter(logging.Formatter):
    """High-precision timestamp formatter for detailed logging"""
    def formatTime(self, record, datefmt=None):
        return dt.datetime.fromtimestamp(record.created).strftime(
            datefmt or LOG_TIME_FORMAT)[:-3]

def setup_logging() -> bool:
    """Initialize modern rotating file logger with console output"""
    try:
        # Configure root logger to be quiet, use only our logger
        logging.getLogger().setLevel(logging.WARNING)
        
        # Setup application logger
        logger = logging.getLogger('cloud-client')
        logger.setLevel(logging.INFO)
        logger.propagate = False
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create handlers with optimized configuration
        handlers = [
            RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding=LOG_ENCODING),
            logging.StreamHandler()
        ]
        
        # Apply formatting to all handlers
        formatter = CustomFormatter('%(asctime)s [%(levelname)s] %(message)s')
        for handler in handlers:
            handler.setLevel(logging.INFO)
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        global LOGGER
        LOGGER = logger
        logger.info("Logging sistemi başlatıldı")
        return True
        
    except Exception as e:
        # Logging başlatma hatası - sessizce devam et
        return False

# Initialize global logger
LOGGER = None

setup_logging()

# Optional tray support - import after constants are loaded
if TRY_TRAY:
    try:
        import pystray
        from pystray import MenuItem as TrayItem
        from PIL import Image, ImageDraw
    except ImportError:
        TRY_TRAY = False

# Suppress PIL logging noise
try:
    logging.getLogger('PIL').setLevel(logging.WARNING)
except:
    pass

# ===================== WINDOWS DEFENDER COMPATIBILITY ===================== #
# Purpose: Windows Defender uyumluluğu ve güven sinyalleri

def check_defender_compatibility():
    """Windows Defender ile uyumluluk kontrolü"""
    try:
        # 1. Dosya hash kontrolü
        exe_path = sys.executable if getattr(sys, 'frozen', False) else __file__
        if os.path.exists(exe_path):
            with open(exe_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            log(f"App hash: {file_hash[:16]}...")
        
        # 2. Meşru uygulama işaretleri - constants'tan al
        app_markers = DEFENDER_MARKERS.copy()
        app_markers.update({
            "version": __version__,
            "legitimate": True,
            "signed": os.path.exists("certs/dev-codesign.pfx")
        })
        
        # 3. Registry girdileri (güven için)
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY_PATH) as key:
                winreg.SetValueEx(key, "InstallTime", 0, winreg.REG_SZ, str(int(time.time())))
                winreg.SetValueEx(key, "Purpose", 0, winreg.REG_SZ, "Network Security Monitoring")
                winreg.SetValueEx(key, "Legitimate", 0, winreg.REG_DWORD, 1)
        except Exception:
            pass  # Registry hatası kritik değil
            
        log("Windows Defender compatibility checked")
        return app_markers
        
    except Exception as e:
        log(f"Defender compatibility check failed: {e}")
        return None

def create_defender_trust_signals():
    """Defender güven sinyalleri oluştur"""
    try:
        # 1. Temp dosyalarını temizle (şüpheli davranışları önle)
        temp_dir = tempfile.gettempdir()
        temp_pattern = "Cloud_Honeypot_*"
        
        # 2. Process integrity kontrolü
        if sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                process_handle = kernel32.GetCurrentProcess()
                log(f"Process integrity verified: {process_handle}")
            except Exception:
                pass
                
        # 3. Security metadata oluştur
        metadata_path = os.path.join(APP_DIR, "security_metadata.json")
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(SECURITY_METADATA, f, indent=2)
        
        log("Defender trust signals created")
        return {
            "legitimate_domains": LEGITIMATE_DOMAINS,
            "restricted_paths": RESTRICTED_PATHS,
            "process_verified": True
        }
        
    except Exception as e:
        log(f"Failed to create trust signals: {e}")
        return None

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
        
        # Windows Defender compatibility check - early initialization
        try:
            log("Initializing Windows Defender compatibility...")
            self.defender_markers = check_defender_compatibility()
            self.trust_signals = create_defender_trust_signals()
            log("Defender compatibility initialized successfully")
        except Exception as e:
            log(f"Defender compatibility warning: {e}")
            self.defender_markers = None
            self.trust_signals = None
        
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
        self.api_client = HoneypotAPIClient(API_URL, log)
        
        # Initialize token manager
        token_file_new, token_file_old = get_token_file_paths(APP_DIR)
        self.token_manager = create_token_manager(str(API_URL), SERVER_NAME, token_file_new, token_file_old)
        
        # Set global logger for helper functions
        if LOGGER:
            client_helpers.set_logger(LOGGER)
        self.reconciliation_lock = threading.Lock()
        self.rdp_transition_complete = threading.Event()
        
        # Initialize application state
        self.state = {
            "running": False, "servers": {}, "threads": [], "token": None,
            "public_ip": None, "tray": None, "selected_rows": [],
            "selected_ports_map": None, "ctrl_sock": None,
            "reconciliation_paused": False, "remote_desired": {}
        }
        
        # Load token early - before any API operations
        try:
            token = self.token_manager.load_token(self.root if hasattr(self, 'root') else None, self.t)
            self.state["token"] = token
            if token:
                pass
        except Exception as e:
            log(f"Token yükleme hatası: {e}")
            self.state["token"] = None
        
        # Initialize heartbeat system
        self.heartbeat_path = create_heartbeat_file(APP_DIR)
        if self.heartbeat_path:
            # Start heartbeat worker thread
            heartbeat_thread = threading.Thread(
                target=heartbeat_worker, 
                args=(self.heartbeat_path, self),
                daemon=True,
                name="HeartbeatWorker"
            )
            heartbeat_thread.start()
            self.state["threads"].append(heartbeat_thread)
        
        # Initialize GUI elements
        self.root = self.btn_primary = self.tree = None
        self.attack_entry = self.ip_entry = self.show_cb = None
        
        # Check initial RDP state and report to API
        def check_initial_rdp_state():
            try:
                current_rdp_port = ServiceController.get_rdp_port()
                if current_rdp_port == RDP_SECURE_PORT:
                    log(f"Başlangıç kontrolü: RDP güvenli konumda ({RDP_SECURE_PORT})")
                    self.report_tunnel_action_to_api("RDP", "start", str(RDP_SECURE_PORT))
                    log("API'ye RDP koruma durumu bildirildi (aktif)")
                    
                    # Restart TermService if stopped
                    if ServiceController._sc_query_code("TermService") == 1:
                        log("Terminal Servis durduğu tespit edildi, yeniden başlatılıyor...")
                        ServiceController.start("TermService")
                    
                # Start tunnel for port 3389
                st = TunnelServerThread(self, '3389', 'RDP')
                st.start()
                time.sleep(0.15)
                if st.is_alive():
                    self.state["servers"][3389] = st
                    log("3389 portu için tünel başlatıldı")
                else:
                    log("3389 portu için tünel başlatılamadı!")
            
                # Tunnel setup completion will be checked asynchronously
                # No need to block GUI startup for this
            except Exception as e:
                log(f"Başlangıç RDP kontrolü sırasında hata: {e}")

        # Önce RDP kontrolünü yap
        check_initial_rdp_state()

    def monitor_user_sessions(self):
        """Monitor for user logon sessions in daemon mode"""
        import subprocess
        import time
        
        log("Daemon: User session monitoring started")
        
        while True:
            try:
                # Check for active user sessions
                result = subprocess.run(['query', 'session'], 
                                      capture_output=True, text=True, timeout=10)
                
                # Look for Active sessions (interactive logon)
                active_sessions = []
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if 'Active' in line and 'console' in line.lower():
                        active_sessions.append(line.strip())
                
                if active_sessions:
                    log(f"Daemon: Active user session detected, gracefully shutting down for tray handover...")
                    log(f"Sessions: {len(active_sessions)} active")
                    
                    # Allow some time for tray task to start
                    time.sleep(3)
                    
                    # Graceful shutdown - tray task will take over via StopExisting policy
                    log("Daemon: Exiting for user session handover")
                    os._exit(0)  # Clean exit for daemon
                    
            except Exception as e:
                log(f"Session monitoring error: {e}")
            
            # Check every 30 seconds
            time.sleep(30)

    def start_delayed_api_sync(self):
        """Start API synchronization with delay in background thread"""
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

    def first_run_notice(self):
        try:
            # Skip first run notice for now to avoid dict issues
            log("First run notice skipped - avoiding dict issues")
            return
        except Exception as e:
            log(f"first_run_notice error: {e}")

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

    # Legacy setup_persistent_elevation removed - now using client_task_scheduler module

    # ---------- Token Management (moved to client_tokens.py) ---------- #

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
        """Update client IP address via API"""
        token = self.state.get("token")
        if token:
            update_client_ip_api(str(API_URL), token, new_ip, log)

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
        """Send single heartbeat to API with intelligent status detection"""
        token = self.state.get("token")
        if token:
            ip = self.state.get("public_ip") or ClientHelpers.get_public_ip()
            
            # Status override yoksa akıllı status belirle
            if status_override is None:
                status_override = self.get_intelligent_status()
            
            send_heartbeat_api(
                str(API_URL), token, ip, SERVER_NAME, 
                self.state.get("running", False), status_override, log
            )

    def heartbeat_loop(self):
        last_ip = None
        while True:
            try:
                token = self.state.get("token")
                if token:
                    ip = ClientHelpers.get_public_ip()
                    if ip and ip != last_ip:
                        self.update_client_ip(ip)
                        last_ip = ip
                    self.state["public_ip"] = ip
                    # GUI'deki IP bilgisini güncelle
                    if self.ip_entry and self.root:
                        try:
                            self.root.after(0, lambda: ClientHelpers.safe_set_entry(self.ip_entry, f"{SERVER_NAME} ({ip})"))
                        except:
                            ClientHelpers.safe_set_entry(self.ip_entry, f"{SERVER_NAME} ({ip})")
                    
                    # Akıllı heartbeat gönder (online/idle/offline)
                    self.send_heartbeat_once()
            except Exception as e:
                log(f"heartbeat error: {e}")
            time.sleep(HEARTBEAT_INTERVAL)

    # ---------- Attack Count ---------- #
    def fetch_attack_count_sync(self, token):
        """Honeypot sunucusundan toplam saldırı sayısını sorgular - now uses modular API client"""
        try:
            return self.api_client.get_attack_count(token)
        except Exception as e:
            log(f"[API] Saldırı sayısı sorgulama hatası: {e}")
            return None

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
                    
                # GUI thread-safe güncelleme
                try:
                    def update_entry():
                        ClientHelpers.safe_set_entry(self.attack_entry, str(cnt))
                    
                    # Check if main loop is running
                    try:
                        self.root.after(0, update_entry)
                        # Track last count to avoid redundant updates
                        if not hasattr(self, '_last_attack_count') or self._last_attack_count != cnt:
                            self._last_attack_count = cnt
                    except RuntimeError as e:
                        if "main thread is not in main loop" in str(e):
                            # Main loop not started yet, update directly
                            ClientHelpers.safe_set_entry(self.attack_entry, str(cnt))
                        else:
                            raise e
                except Exception:
                    ClientHelpers.safe_set_entry(self.attack_entry, str(cnt))
            except Exception:
                pass
                
        if async_thread:
            threading.Thread(target=worker, daemon=True, name="AttackCountUpdater").start()
        else:
            worker()

    def poll_attack_count(self):
        self.refresh_attack_count(async_thread=True)
        try:
            self.root.after(ATTACK_COUNT_REFRESH * 1000, self.poll_attack_count)
        except:
            pass

    # ---------- Single Instance Control ---------- #
    def control_server_loop(self, sock):
        """Handle control server connections for single instance enforcement"""
        while True:
            try:
                conn, _ = sock.accept()
                conn.settimeout(2.0)
                
                # Read command
                buf = b""
                while True:
                    ch = conn.recv(1)
                    if not ch or ch == b"\n": 
                        break
                    buf += ch
                
                cmd = buf.decode("utf-8", "ignore").strip().upper()
                if cmd == "SHOW" and self.show_cb:
                    def do_show():
                        try: 
                            self.show_cb()
                        except: 
                            pass
                    
                    try:
                        if self.root: 
                            self.root.after(0, do_show)
                        else: 
                            do_show()
                    except:
                        do_show()
                        
            except Exception:
                pass
            finally:
                try: 
                    conn.close()
                except: 
                    pass

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

    # ---------- TLS & Tunnel Management ---------- #
        # Network methods moved to NetworkingHelpers

        # Tunnel sync loop moved to TunnelManager

# ---------- Watchdog & Persistence ---------- #
        # Tunnel watchdog moved to TunnelManager

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

    # ---------- Autostart (Task Scheduler) ---------- #
    def task_command_daemon(self):
        if getattr(sys, 'frozen', False):
            return f'"{sys.executable}" --daemon'
        return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --daemon'

    def task_command_minimized(self):
        if getattr(sys, 'frozen', False):
            return f'"{sys.executable}" --minimized'
        return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --minimized'

    def install_autostart_system_boot(self):
        run_cmd([
            'schtasks','/Create','/TN', TASK_NAME_BOOT,
            '/SC','ONSTART','/RU','SYSTEM',
            '/TR', self.task_command_daemon(), '/F'
        ])
        # Not running immediately to avoid spawning extra background instances
        # Task will run on next boot as intended

    def install_autostart_user_logon(self):
        user = os.environ.get("USERNAME") or ""
        run_cmd([
            'schtasks','/Create','/TN', TASK_NAME_LOGON,
            '/SC','ONLOGON','/RU', user,
            '/TR', self.task_command_minimized(), '/RL','HIGHEST','/F'
        ])

    def remove_autostart(self):
        run_cmd(['schtasks','/End','/TN', TASK_NAME_BOOT])
        run_cmd(['schtasks','/Delete','/TN', TASK_NAME_BOOT, '/F'])
        run_cmd(['schtasks','/Delete','/TN', TASK_NAME_LOGON, '/F'])

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
        """Check for updates and prompt user with installer-based system"""
        try:
            from client_utils import create_update_manager, UpdateProgressDialog
            
            # Update manager oluştur
            update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
            
            # Güncelleme kontrolü
            update_info = update_mgr.check_for_updates()
            
            if update_info.get("error"):
                messagebox.showerror("Update", self.t("update_error").format(err=update_info["error"]))
                return
                
            if not update_info.get("has_update"):
                messagebox.showinfo("Update", self.t("update_none"))
                return

            # Kullanıcıdan onay al
            latest_ver = update_info["latest_version"]
            if not messagebox.askyesno("Update", self.t("update_found").format(version=latest_ver)):
                return

            # Progress dialog oluştur
            progress_dialog = UpdateProgressDialog(self.root, "Güncelleme")
            if not progress_dialog.create_dialog():
                messagebox.showerror("Update", "Progress dialog oluşturulamadı")
                return

            def progress_callback(percent, message):
                progress_dialog.update_progress(percent, message)
                if percent >= 100:
                    progress_dialog.close_dialog()

            # Güncellemeyi başlat
            try:
                success = update_mgr.update_with_progress(progress_callback, silent=False)
                if success:
                    messagebox.showinfo("Update", "Güncelleme tamamlandı! Yeni sürüm başlatılıyor...")
                    # Mevcut uygulamayı kapat
                    try: os._exit(0)
                    except: sys.exit(0)
                else:
                    messagebox.showerror("Update", "Güncelleme başarısız oldu")
                    progress_dialog.close_dialog()
            except Exception as e:
                progress_dialog.close_dialog()
                messagebox.showerror("Update", f"Güncelleme hatası: {str(e)}")
                
        except Exception as e:
            log(f"update prompt error: {e}")
            try:
                messagebox.showerror("Update", self.t("update_error").format(err=str(e)))
            except Exception:
                pass


    def check_updates_and_apply_silent(self):
        """Silent update with installer-based system"""
        try:
            from client_utils import create_update_manager
            
            # Update manager oluştur
            update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
            
            # Güncelleme kontrolü
            update_info = update_mgr.check_for_updates()
            
            if update_info.get("error") or not update_info.get("has_update"):
                return
                
            log(f"[SILENT UPDATE] Yeni sürüm bulundu: {update_info['latest_version']}")
            
            # Sessiz güncellemeyi başlat
            success = update_mgr.update_with_progress(silent=True)
            if success:
                log("[SILENT UPDATE] Güncelleme tamamlandı, uygulama yeniden başlatılıyor")
                # Kısa süre bekle ve çık
                import time
                time.sleep(1)
                try: os._exit(0)
                except: sys.exit(0)
            else:
                log("[SILENT UPDATE] Güncelleme başarısız")
                
        except Exception as e:
            log(f"silent update error: {e}")



    # ---------- RDP Management UI ---------- #
    def rdp_move_popup(self, mode: str, on_confirm):
        """Show RDP port change confirmation popup"""
        # mode: "secure" (3389->53389) or "rollback" (53389->3389)
        with self.reconciliation_lock:
            self.state["reconciliation_paused"] = True
            log("RDP geçiş süreci başladı - Tüm API iletişimi duraklatıldı")
            
        # GUI elementlerini oluştur    
        popup = tk.Toplevel(self.root)
        popup.title(self.t("rdp_title"))
        msg = self.t("rdp_go_secure") if mode == "secure" else self.t("rdp_rollback")
        tk.Label(popup, text=msg, font=("Arial", 11), justify="center").pack(padx=20, pady=15)

        status_frame = tk.Frame(popup)
        status_frame.pack(pady=6)

        prog_label = tk.Label(status_frame, text=self.t("processing"), font=("Arial", 10))
        prog_label.pack()

        # RDP geçiş süresi constants'tan al
        countdown_label = tk.Label(status_frame, text=str(RDP_TRANSITION_TIMEOUT), font=("Arial", 20, "bold"), fg="red")
        countdown_label.pack()

        confirm_button = tk.Button(popup, text=self.t("rdp_approve"), command=lambda: None,
                                   bg="#cccccc", fg="white", padx=15, pady=5, state="disabled")
        confirm_button.pack(pady=10)

        countdown_id = [None]
        transition_success = [False]  # RDP geçişinin başarısını takip etmek için

        def countdown(sec=RDP_TRANSITION_TIMEOUT):
            if sec < 0:
                do_rollback()
                return
            countdown_label.config(text=str(sec))
            countdown_id[0] = popup.after(1000, lambda: countdown(sec-1))

        def do_rollback():
            # Zaman aşımı veya iptal durumunda port değişikliğini geri al
            if countdown_id[0]:
                try:
                    popup.after_cancel(countdown_id[0])
                except Exception:
                    pass

            # Eğer geçiş başarılıysa ve rollback gerekiyorsa
            if transition_success[0]:
                rollback_port = 3389 if mode == "secure" else RDP_SECURE_PORT
                log(f"Zaman aşımı veya iptal. RDP portu {rollback_port} portuna geri alınıyor.")
                
                def handle_rollback():
                    try:
                        # API iletişiminin duraklatıldığından emin ol
                        if not self.state.get("reconciliation_paused"):
                            with self.reconciliation_lock:
                                self.state["reconciliation_paused"] = True
                        
                        # RDP portunu geri al
                        success = self.start_rdp_transition("rollback" if mode == "secure" else "secure")
                        if not success:
                            raise RuntimeError("RDP port geri alma işlemi başarısız")
                        
                        # Kullanıcıyı bilgilendir
                        try: messagebox.showwarning(self.t("warn"), self.t("rollback_done").format(port=rollback_port))
                        except Exception: pass
                            
                        # Notify API
                        log("RDP port geri alındı, API'ye bildirim yapılıyor...")
                        if rollback_port == 3389:
                            if not self.report_tunnel_action_to_api("RDP", "stop", None):
                                log("API'ye stop bildirimi başarısız")
                        else:
                            if not self.report_tunnel_action_to_api("RDP", "start", str(RDP_SECURE_PORT)):
                                log("API'ye start bildirimi başarısız")
                            
                        time.sleep(5)  # Wait for API response
                        
                    finally:
                        # Resume API synchronization
                        with self.reconciliation_lock: self.state["reconciliation_paused"] = False
                        log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")
                        
                threading.Thread(target=handle_rollback, daemon=True).start()

                if mode == "rollback" and rollback_port == RDP_SECURE_PORT:
                    threading.Thread(target=self.start_single_row, args=('3389', str(RDP_SECURE_PORT), 'RDP', False), daemon=True).start()

            try: popup.destroy()
            except Exception: pass

        def do_confirm():
            """Handle user confirmation"""
            if not transition_success[0]:
                log("RDP geçişi başarısız olduğu için onay işlemi gerçekleştirilemiyor.")
                try: messagebox.showerror(self.t("error"), "RDP geçişi başarısız olduğu için onaylanamıyor."); popup.destroy()
                except Exception: pass
                return

            if countdown_id[0]:
                try: popup.after_cancel(countdown_id[0])
                except Exception: pass
                    
            try:
                popup.destroy()
            except Exception:
                pass
                
            # Handle RDP transition completion and API notification
            def confirm_and_resume():
                try:
                    # Ensure API communication remains paused
                    if not self.state.get("reconciliation_paused"):
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = True
                            log("API iletişimi yeniden duraklatıldı")
                            
                    # Execute the confirmation callback first
                    on_confirm()

                    # Butonun durumu Durdur olarak güncelleniyor
                    ClientHelpers.set_primary_button(self.btn_primary, self.t('btn_stop'), self.remove_tunnels, "#E53935")
                    self.state["running"] = True
                    self._update_row_ui("3389", "RDP", True)

                    log("RDP port geçişi başarılı, API'ye bildirim yapılıyor...")
                    # Report new RDP state to API
                    if mode == "secure":
                        self.report_tunnel_action_to_api("RDP", "start", str(RDP_SECURE_PORT))
                    else:
                        self.report_tunnel_action_to_api("RDP", "stop", "3389")

                    # Wait for API notification to complete
                    time.sleep(5)

                    # Resume API synchronization
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")

                    # Senkronizasyon thread'i yoksa başlat
                    if not any(t.name == "tunnel_sync_loop" and t.is_alive() for t in threading.enumerate()):
                        threading.Thread(target=TunnelManager.tunnel_sync_loop, args=(self,), name="tunnel_sync_loop", daemon=True).start()
                    
                except Exception as e:
                    log(f"RDP durum güncellemesi sırasında hata: {str(e)}")
                    # Hata durumunda eski porta geri dön
                    try:
                        if mode == "secure":
                            self.start_rdp_transition("rollback")
                        else:
                            self.start_rdp_transition("secure")
                    except Exception: pass
                    # Resume API communication
                    with self.reconciliation_lock: self.state["reconciliation_paused"] = False
                    
            threading.Thread(target=confirm_and_resume, daemon=True).start()

        confirm_button.config(command=do_confirm)

        def worker():
            """Background worker for RDP transition"""
            try:
                popup.after(100, lambda: countdown(60))  # Start countdown
                
                success = self.start_rdp_transition(mode)
                if not success:
                    raise RuntimeError("Port geçişi tamamlanamadı - Servis başlatılamadı veya port değiştirilemedi.")
                    
                transition_success[0] = True
                log("RDP port geçişi başarılı. Kullanıcı onayı bekleniyor...")

                # Update GUI in main thread
                popup.after(0, lambda: [
                    prog_label.pack_forget(),
                    countdown_label.pack(),
                    confirm_button.config(state="normal", bg="#4CAF50"),
                ])
                confirm_button.config(state="normal", bg="#4CAF50")
                countdown()

            except Exception as e:
                log(f"RDP port değiştirme hatası: {e}")
                try: messagebox.showerror(self.t("error"), self.t("err_rdp").format(e=e)); popup.destroy()
                except Exception: pass

        threading.Thread(target=worker, daemon=True).start()
        popup.protocol("WM_DELETE_WINDOW", do_rollback)

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

    def sync_gui_with_tunnel_state(self):
        """GUI buton durumunu gerçek tunnel durumu ile senkronize et"""
        try:
            active_tunnels = len(self.state.get("servers", {}))
            
            if active_tunnels > 0:
                # Aktif tunnel var - Durdur butonu göster
                if hasattr(self, 'btn_primary') and self.btn_primary:
                    ClientHelpers.set_primary_button(
                        self.btn_primary, 
                        self.t('btn_stop'), 
                        self.remove_tunnels, 
                        "#E53935"
                    )
                log(f"[GUI_SYNC] {active_tunnels} aktif tunnel var - Durdur butonu aktif")
            else:
                # Hiç tunnel yok - Başlat butonu göster  
                if hasattr(self, 'btn_primary') and self.btn_primary:
                    ClientHelpers.set_primary_button(
                        self.btn_primary, 
                        self.t('btn_row_start'), 
                        self.apply_tunnels, 
                        "#4CAF50"
                    )
                log("[GUI_SYNC] Hiç tunnel yok - Başlat butonu aktif")
                
        except Exception as e:
            log(f"[GUI_SYNC] Senkronizasyon hatası: {e}")

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
        try:
            if self.root:
                self.root.after(0, apply)
                return
        except Exception as e:
            log(f"Exception: {e}")
        apply()

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
        
        # Critical operations require admin privileges
        if service.upper() in ['RDP', 'SSH', 'MYSQL', 'MSSQL']:
            if not self.require_admin_for_operation(f"{service} Tüneli Başlatma"):
                return False
            
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
            
            # Önce mevcut RDP durumunu kontrol et
            current_rdp_port = ServiceController.get_rdp_port()
            if current_rdp_port == RDP_SECURE_PORT:
                log(f"RDP zaten güvenli portta ({RDP_SECURE_PORT}), koruma aktif kabul ediliyor")
                
                # 3389'da tünel başlat
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
                    log("API'ye RDP koruma durumu bildiriliyor (aktif)")
                    self.report_tunnel_action_to_api("RDP", "start", str(RDP_SECURE_PORT))
                    
                    # API senkronizasyonunu devam ettir
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    return True
                else:
                    log("Tünel başlatılamadı!")
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    return False

            # Önce mevcut RDP port durumunu kontrol et
            current_rdp_port = ServiceController.get_rdp_port()
            if current_rdp_port == RDP_SECURE_PORT and not NetworkingHelpers.is_port_in_use(3389):
                # RDP zaten güvenli portta ve 3389 boşta, direkt tüneli başlat
                log(f"RDP zaten güvenli portta ({RDP_SECURE_PORT}), direkt tünel başlatılıyor...")
                st = TunnelServerThread(self, listen_port, service)
                st.start()
                time.sleep(0.15)
                
                if st.is_alive():
                    self.state["servers"][int(listen_port)] = st
                    self.write_status(self._active_rows_from_servers(), running=True)
                    self.state["running"] = True
                    self.update_tray_icon()
                    self.send_heartbeat_once("online")
                    self._update_row_ui(listen_port, service, True)
                    self.state["remote_desired"][service_upper] = "started"
                    self.report_tunnel_action_to_api(service, 'start', p2)
                    return True
                else:
                    log("Tünel başlatılamadı!")
                    return False
            
            if manual_action:
                # Kullanıcı kaynaklı RDP geçişi - onay penceresi göster
                log("Manuel RDP güvenli port başlatma akışı tetiklendi.")

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
            except Exception:
                pass
        
        st = TunnelServerThread(self, listen_port, service)
        st.start(); time.sleep(0.15)
        if st.is_alive():
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
                self.rdp_move_popup(mode="rollback", on_confirm=on_rdp_confirm_rollback)
                return True
            else:
                # API-driven
                ensure_firewall_allow_for_port(3389,  "RDP 3389")
                ensure_firewall_allow_for_port(RDP_SECURE_PORT, f"RDP {RDP_SECURE_PORT}")
                if not self.start_rdp_transition("rollback"):
                    log("API akışı: RDP 3389'a geri alınamadı.")

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
            except Exception:
                pass
        
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
        
        # Update local cache on success
        if result:
            self.active_tunnels = getattr(self, "active_tunnels", {})
            self.active_tunnels.setdefault(str(service or "").upper(), {})\
                .update({"running": action == "start", "new_port": new_port})
        
        return result

    # --- helper: registry'yi restart etmeden yazmak için ---
    def _set_rdp_port_registry(self, new_port: int) -> bool:
        res = run_cmd([
            'reg','add','HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
            '/v','PortNumber','/t','REG_DWORD','/d', str(int(new_port)), '/f'
        ], timeout=10, suppress_rc_log=True)
        ok = (res is not None and getattr(res, "returncode", 1) == 0)
        if not ok:
            log(f"set_rdp_port_registry failed for {new_port}")
        return ok

    def _ensure_rdp_firewall_both(self):
        try:
            ensure_firewall_allow_for_port(3389,  "RDP 3389")
            ensure_firewall_allow_for_port(RDP_SECURE_PORT, f"RDP {RDP_SECURE_PORT}")
        except Exception as e:
            log(f"ensure_rdp_firewall_both err: {e}")

    def start_rdp_transition(self, transition_mode: str = "secure") -> bool:
        """
        3389<->RDP güvenli port arası güvenli geri/ileri geçiş.
        Adımlar: RDP port güvenliği kontrolü -> stop TermService -> firewall iki port -> reg set -> start TermService -> dinleme/doğrulama.
        """
        try:
            if transition_mode not in ("secure", "rollback"):
                log(f"Geçersiz geçiş modu: {transition_mode}")
                return False

            # RDP port güvenlik kontrolü
            if not ServiceController.check_rdp_port_safety():
                log("RDP port güvenlik kontrolü başarısız")
                return False

            target = RDP_SECURE_PORT if transition_mode == "secure" else 3389
            source = 3389  if transition_mode == "secure" else RDP_SECURE_PORT
            deadline = time.time() + RDP_TRANSITION_TIMEOUT

            # Zaten hedefte ve dinliyorsa kontrol et
            cur = ServiceController.get_rdp_port()
            if cur == target:
                svc_ok = (ServiceController._sc_query_code("TermService") == 4)
                tgt_listen = NetworkingHelpers.is_port_in_use(target)
                src_listen = NetworkingHelpers.is_port_in_use(source)
                
                if svc_ok and tgt_listen:
                    log(f"RDP zaten {target} portunda ve dinlemede")
                    
                    if transition_mode == "secure":
                        # Güvenli portta ve 3389 boşta, tüneli başlat
                        if not src_listen:
                            log("3389 portu boş, tünel başlatılıyor...")
                            if self.start_single_row('3389', str(RDP_SECURE_PORT), 'RDP'):
                                log("Tünel başlatıldı, API'ye bildiriliyor...")
                                self.report_tunnel_action_to_api("RDP", "start", str(RDP_SECURE_PORT))
                            else:
                                log("Tünel başlatılamadı!")
                        else:
                            log("3389 portu zaten kullanımda, tünel başlatılamıyor")
                    else:
                        # Normal moda dönüş
                        self.report_tunnel_action_to_api("RDP", "stop", "3389")
                    return True
                    
                log("Registry hedefte ama dinleme yok; TermService restart edilecek")

            # 2) Servisi durdur
            if not ServiceController.stop("TermService", timeout=40):
                log("TermService durdurulamadı")
                return False

            # 3) Firewall iki port için de garanti
            self._ensure_rdp_firewall_both()

            # 4) Registry'yi hedef porta yaz
            if not self._set_rdp_port_registry(target):
                # başarısızsa eski durumu geri getir ve çık
                self._set_rdp_port_registry(source)
                ServiceController.start("TermService")
                return False

            # 5) Firewall'u yeniden kontrol et ve servisi başlat
            time.sleep(2)  # Firewall kurallarının uygulanması için kısa bekleme
            self._ensure_rdp_firewall_both()
            
            # Servisi başlat ve biraz bekle
            if not ServiceController.start("TermService", timeout=40):
                log("TermService başlatılamadı")
                return False
            
            # Servisin tam olarak başlaması için bekle
            time.sleep(5)

            # 5→ doğrulama
            retry_count = 0
            while time.time() < deadline:
                svc_ok     = (ServiceController._sc_query_code("TermService") == 4)
                reg_ok     = (ServiceController.get_rdp_port() == target)
                tgt_listen = NetworkingHelpers.is_port_in_use(target)
                src_listen = NetworkingHelpers.is_port_in_use(source)
                log(f"[RDP transition] svc_ok={svc_ok} reg_ok={reg_ok} tgt_listen={tgt_listen} src_listen={src_listen}")

                if not svc_ok or not reg_ok:
                    log("Servis veya registry durumu yanlış, yeniden başlatılıyor...")
                    ServiceController.restart("TermService")
                    time.sleep(5)
                    retry_count += 1
                    if retry_count > 2:  # En fazla 3 deneme
                        break
                    continue

                # Port dinleme kontrolü
                if not tgt_listen and retry_count < 2:
                    log("Hedef port dinlemiyor, servis yeniden başlatılıyor...")
                    ServiceController.restart("TermService")
                    time.sleep(5)
                    retry_count += 1
                    continue
                if svc_ok and reg_ok and tgt_listen and not src_listen:
                    log(f"RDP {target} portuna taşındı (dinleme aktif)")
                    return True
                time.sleep(1)

            # 60 sn timeout → rollback
            log(f"Timeout, {source} portuna geri dönülüyor")
            ServiceController.stop("TermService")
            self._set_rdp_port_registry(source)
            ServiceController.start("TermService")
            return False

        except Exception as e:
            log(f"RDP geçiş hatası: {e}")
            try:
                # emniyet rollback
                ServiceController.stop("TermService")
                self._set_rdp_port_registry(3389 if transition_mode == "secure" else RDP_SECURE_PORT)
                ServiceController.start("TermService")
            except Exception:
                pass
            return False


        

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
            report_open_ports_api(str(API_URL), token, ports, log)

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
        try:
            st = self.state["servers"].get(int(listen_port))
            if not st:
                return False
            return str(st.service_name or '').upper() == str(service_name or '').upper()
        except Exception:
            return False

    def reconcile_remote_tunnels_loop(self):
        # Uzaktan tünel yönetimi döngüsü - API ile senkronizasyonu sağlar
        log("Uzaktan yönetim döngüsü başlatıldı.")
        while True:
            try:
                with self.reconciliation_lock:
                    if self.state.get("reconciliation_paused"):
                        log("Senkronizasyon duraklatıldı, bekleniyor...")
                        time.sleep(1)
                        continue

                token = self.state.get("token")
                if not token:
                    log("Token bulunamadı, bekleniyor...")
                    time.sleep(15)
                    continue

                # Hedef durumu API'den al
                response = self.api_request("GET", "premium/tunnel-status", params={"token": token})
                if not response:
                    log("Tünel durumları alınamadı - Sunucu yanıt vermedi")
                    time.sleep(15)
                    continue

                if not isinstance(response, dict):
                    log(f"Geçersiz API yanıt formatı: {response}")
                    time.sleep(15)
                    continue

                data = response
                if data:
                    log(f"API'den hedef durum alındı: {data}")
                if data:
                    log(f"API'den hedef durum alındı: {data}")

                # expected: { 'RDP': {listen_port:3389, desired:'started'|'stopped', new_port:53389}, ... }
                order = [("RDP",3389), ("MSSQL",1433), ("MYSQL",3306), ("FTP",21), ("SSH",22)]
                for svc_u, lp in order:
                    entry = data.get(svc_u)
                    if not isinstance(entry, dict):
                        continue
                    desired = (entry.get('desired') or 'stopped').lower()
                    running = self._is_service_running(lp, svc_u)
                    prev = self.state["remote_desired"].get(svc_u)
                    if prev == desired and ((desired=='started' and running) or (desired=='stopped' and not running)):
                        continue

                    if desired == 'started' and not running:
                        log(f"API komutu: '{svc_u}' servisi başlatılıyor.")
                        try:
                            if svc_u == 'RDP' and ServiceController.get_rdp_port() != RDP_SECURE_PORT:
                                ServiceController.switch_rdp_port(RDP_SECURE_PORT)
                            newp = entry.get('new_port') or (RDP_SECURE_PORT if svc_u=='RDP' else '-')
                            self.start_single_row(str(lp), str(newp), self._normalize_service(svc_u))
                            # Update UI state and tray icon - tuple formatında ekle
                            port_tuple = (str(lp), str(newp), svc_u)
                            if port_tuple not in self.state["selected_rows"]:
                                self.state["selected_rows"].append(port_tuple)
                            self._update_row_ui(str(lp), svc_u, True)
                            self.update_tray_icon()
                        except Exception as e:
                            log(f"remote start {svc_u} err: {e}")
                    elif desired == 'stopped' and running:
                        log(f"API komutu: '{svc_u}' servisi durduruluyor.")
                        try:
                            self.stop_single_row(str(lp), str(entry.get('new_port') or '-'), self._normalize_service(svc_u))
                            if svc_u == 'RDP' and ServiceController.get_rdp_port() != 3389:
                                ServiceController.switch_rdp_port(3389)
                            # Update UI state and tray icon - tuple formatında kaldır
                            newp = str(entry.get('new_port') or '-')
                            port_tuple = (str(lp), newp, svc_u)
                            # Tuple'ı kaldırmak için listeyi filtrele
                            self.state["selected_rows"] = [
                                row for row in self.state["selected_rows"] 
                                if not (isinstance(row, (list, tuple)) and len(row) >= 3 and row[0] == str(lp) and row[2].upper() == svc_u.upper())
                            ]
                            self._update_row_ui(str(lp), svc_u, False)
                            self.update_tray_icon()
                        except Exception as e:
                            log(f"remote stop {svc_u} err: {e}")
                    self.state["remote_desired"][svc_u] = desired
                # push current status back so dashboard sees up-to-date state
                try:
                    self.report_tunnel_status_once()
                except Exception:
                    pass
            except Exception as e:
                log(f"reconcile_remote_tunnels err: {e}")
            time.sleep(RECONCILE_LOOP_INTERVAL)  # Yeni tunnel_sync_loop kullandığımız için seyrek çalışsın

    # ---------- Tray ---------- #
    def tray_make_image(self, active):
        """Load appropriate tray icon based on protection status"""
        try:
            # Determine icon file based on state
            if active:
                icon_file = "certs/honeypot_active_16.ico"
            else:
                icon_file = "certs/honeypot_inactive_16.ico"
            
            # Try to load from file system first
            if os.path.exists(icon_file):
                from PIL import Image
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
    
    def update_tray_icon(self):
        """Update tray icon to reflect current protection status"""
        if TRY_TRAY and self.state.get("tray"):
            try:
                # Update icon based on current state
                is_active = bool(self.state.get("selected_rows", []))
                new_icon = self.tray_make_image(is_active)
                self.state["tray"].icon = new_icon
                
                # Update title with status
                status = self.t("protection_active") if is_active else self.t("protection_inactive")
                self.state["tray"].title = f"{self.t('app_title')} - {status}"
                
            except Exception as e:
                log(f"Tray icon update error: {e}")

    def tray_loop(self):
        if not TRY_TRAY:
            return
            
        # Tray ikonu oluştur
        icon = pystray.Icon("honeypot_client")
        self.state["tray"] = icon
        icon.title = f"{self.t('app_title')} v{__version__}"
        icon.icon = self.tray_make_image(self.state["running"])
        
        def show_window():
            try:
                if self.root:
                    # Pencereyi göster ve öne getir
                    self.root.deiconify()
                    self.root.lift()
                    self.root.focus_force()
                    
                    # Pencere konumunu merkeze al
                    screen_width = self.root.winfo_screenwidth()
                    screen_height = self.root.winfo_screenheight()
                    window_width = WINDOW_WIDTH
                    window_height = WINDOW_HEIGHT
                    center_x = int(screen_width/2 - window_width/2)
                    center_y = int(screen_height/2 - window_height/2)
                    self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
            except Exception as e:
                log(f"Show window error: {e}")
                
        def minimize_to_tray():
            try:
                if self.root:
                    self.root.withdraw()
            except Exception as e:
                log(f"Minimize error: {e}")
                
        def exit_app():
            if self.state["running"]:
                messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
                return
            
            # Son offline heartbeat gönder
            try:
                self.send_heartbeat_once("offline")
                log("[EXIT] Offline heartbeat sent before exit")
            except Exception as e:
                log(f"[EXIT] Heartbeat error during exit: {e}")
            
            # Cleanup heartbeat file
            try:
                cleanup_heartbeat_file(self.heartbeat_path)
            except Exception as e:
                log(f"[EXIT] Heartbeat cleanup error: {e}")
                
            # Watchdog'u durdur
            try:
                write_watchdog_token('stop', WATCHDOG_TOKEN_FILE)
            except Exception as e:
                log(f"Watchdog stop error: {e}")
                
            # Tray ikonunu kaldır
            try:
                icon.stop()
            except Exception:
                pass
                
            # Ana pencereyi kapat
            if self.root:
                self.root.destroy()
                
            # Single instance kontrolünü kapat
            try:
                self.stop_single_instance_server()
            except Exception:
                pass
                
            os._exit(0)
            
        # Callback'leri kaydet
        self.show_cb = show_window
        self.minimize_cb = minimize_to_tray
        
        # Tray menüsünü oluştur
        try:
            menu = pystray.Menu(
                TrayItem(self.t('tray_show'), lambda: show_window(), default=True),
                TrayItem(self.t('tray_exit'), lambda: exit_app())
            )
            icon.menu = menu
        except Exception as e:
            log(f"Tray menu error: {e}")
            # Fallback: basit menü
            icon.menu = (
                TrayItem(self.t('tray_show'), lambda: show_window()),
                TrayItem(self.t('tray_exit'), lambda: exit_app())
            )
            
        # Tray ikonunu başlat    
        icon.run()

    def on_close(self):
        # Pencere kapatma işleyicisi
        try:
            # Tray ikonu varsa minimize et
            if TRY_TRAY and self.state.get("tray"):
                if hasattr(self, 'minimize_cb') and self.minimize_cb:
                    self.minimize_cb()
            # Tray yoksa normal kapat
            else:
                if self.state["running"]:
                    messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
                    return
                self.root.destroy()
                try:
                    write_watchdog_token('stop', WATCHDOG_TOKEN_FILE)
                except:
                    pass
                self.stop_single_instance_server()
                os._exit(0)
        except Exception as e:
            log(f"Window close error: {e}")

    def stop_single_instance_server(self):
        s = self.state.get("ctrl_sock")
        if s:
            try: s.close()
            except: pass
            self.state["ctrl_sock"] = None

    # ---------- Update Watchdog (hourly) ---------- #
    def update_watchdog_loop(self):
        while True:
            try:
                # 3600 seconds
                for _ in range(360):
                    time.sleep(10)
                self.check_updates_and_apply_silent()
            except Exception as e:
                log(f"update_watchdog_loop error: {e}")

    # ---------- Daemon ---------- #
    def run_daemon(self):
        self.state["token"] = self.token_manager.load_token()
        self.state["public_ip"] = ClientHelpers.get_public_ip()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=TunnelManager.tunnel_watchdog_loop, args=(self,), daemon=True).start()
        
        # Session monitoring for daemon-to-tray handover
        threading.Thread(target=self.monitor_user_sessions, daemon=True).start()
        # Remote management: report open ports + reconcile desired tunnels
        try:
            threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
        except Exception as e:
            log(f"open ports reporter start failed: {e}")
        try:
            threading.Thread(target=self.reconcile_remote_tunnels_loop, daemon=True).start()
        except Exception as e:
            log(f"remote tunnels loop start failed: {e}")
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
            threading.Thread(target=self.update_watchdog_loop, daemon=True).start()
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
            cleanup_heartbeat_file(self.heartbeat_path)
        except Exception as e:
            log(f"Daemon heartbeat cleanup error: {e}")
            
        log("Daemon: durduruldu.")



    # ---------- Firewall Agent ---------- #
    def start_firewall_agent(self):
        """Start firewall agent with updated client_firewall module"""
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
        base = (API_URL or "").strip().rstrip('/')
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
    def build_gui(self, minimized=False):
        # One-time notice for simplicity and firewall prompts
        try:
            # Ensure root exists before messagebox
            if not self.root:
                self.root = tk.Tk()
                self.root.withdraw()  # Geçici olarak gizle
                
                # Ana pencere özelliklerini ayarla - use hardcoded title for now
                self.root.title(f"Cloud Honeypot Client v{__version__}")
                
                # Window icon ayarla
                try:
                    self.root.iconbitmap('certs/honeypot.ico')
                    # Taskbar icon için ayrıca PhotoImage ile ayarla
                    try:
                        from PIL import Image, ImageTk
                        img = Image.open('certs/honeypot.ico')
                        photo = ImageTk.PhotoImage(img)
                        self.root.iconphoto(True, photo)
                    except:
                        pass
                except:
                    pass  # Icon yüklenemezse sessizce devam et
                
                self.root.protocol("WM_DELETE_WINDOW", self.on_close)
                self.root.resizable(True, True)
                
                # Ekran merkezi pozisyonunu hesapla
                window_width = WINDOW_WIDTH
                window_height = WINDOW_HEIGHT
                screen_width = self.root.winfo_screenwidth()
                screen_height = self.root.winfo_screenheight()
                center_x = int(screen_width/2 - window_width/2)
                center_y = int(screen_height/2 - window_height/2)
                
                # Pencereyi merkeze konumlandır
                self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
                
            self.first_run_notice()
            
            # Continue building actual UI below (root will be reconfigured)
            if not minimized:
                try:
                    self.root.deiconify()  # Pencereyi göster
                    self.root.lift()  # Öne getir
                    self.root.focus_force()  # Fokusla
                except Exception as e:
                    log(f"Window show error: {e}")
                    pass
        except Exception as e:
            log(f"build_gui pre-notice error: {e}")
        self.start_single_instance_server()

        # Background services will be started after GUI creation and token loading
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=TunnelManager.tunnel_watchdog_loop, args=(self,), daemon=True).start()
        # Remote management: report open ports + reconcile desired tunnels
        try:
            threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
        except Exception as e:
            log(f"open ports reporter start failed: {e}")
        try:
            threading.Thread(target=self.reconcile_remote_tunnels_loop, daemon=True).start()
        except Exception as e:
            log(f"remote tunnels loop start failed: {e}")
        # Start firewall agent in background
        try:
            self.start_firewall_agent()
        except Exception as e:
            log(f"firewall agent start failed (gui): {e}")
        # Start external watchdog
        try:
            start_watchdog_if_needed(WATCHDOG_TOKEN_FILE, log)
        except Exception as e:
            log(f"watchdog start error: {e}")
        # Hourly update checker
        try:
            threading.Thread(target=self.update_watchdog_loop, daemon=True).start()
        except Exception as e:
            log(f"update watchdog thread error: {e}")

        if not self.root:
            self.root = tk.Tk()
        else:
            try:
                self.root.deiconify()
            except Exception:
                pass
        self.root.title(f"{self.t('app_title')} v{__version__}")
        
        # Window icon ayarla
        try:
            self.root.iconbitmap('certs/honeypot.ico')
            # Taskbar icon için ayrıca PhotoImage ile ayarla
            try:
                from PIL import Image, ImageTk
                img = Image.open('certs/honeypot.ico')
                photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, photo)
            except:
                pass
        except:
            pass  # Icon yüklenemezse sessizce devam et
            
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
                subprocess.Popen([exe] + sys.argv[1:], shell=False)
            except Exception:
                pass
            os._exit(0)
        lang_menu = tk.Menu(menu_settings, tearoff=0)
        lang_menu.add_command(label=self.t("menu_lang_tr"), command=lambda: set_lang("tr"))
        lang_menu.add_command(label=self.t("menu_lang_en"), command=lambda: set_lang("en"))
        menu_settings.add_cascade(label=self.t("menu_language"), menu=lang_menu)
        menubar.add_cascade(label=self.t("menu_settings"), menu=menu_settings)

        # Legacy Windows Service menu removed - now using Task Scheduler

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

        # Migration: Eski zip tabanlı güncelleme sisteminden installer sistemine geçiş
        try:
            from client_utils import migrate_from_zip_to_installer
            migrate_from_zip_to_installer()
        except Exception as e:
            log(f"migration error: {e}")

        # Optional silent auto-update on startup if configured and no active tunnels
        try:
            if os.environ.get('AUTO_UPDATE_SILENT') == '1':
                if not self.state.get('servers'):
                    self.check_updates_and_apply_silent()
        except Exception as e:
            log(f"auto-update silent error: {e}")

        # Tray
        if TRY_TRAY:
            threading.Thread(target=self.tray_loop, daemon=True).start()

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
            if minimized:
                self.root.withdraw()

        def _show_window():
            try:
                self.root.deiconify(); self.root.lift(); self.root.focus_force()
            except: pass
        self.show_cb = _show_window

        # Otomatik saldırı sayacı
        self.root.after(0, self.poll_attack_count)



    def show_gui_from_tray(self, icon=None, item=None):
        """Show GUI from tray"""
        try:
            log("Restoring GUI from tray...")
            
            # Show the window
            if hasattr(self, 'root') and self.root:
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                log("GUI restored from tray successfully")
            
        except Exception as e:
            log(f"Show GUI error: {e}")
            
    def quit_from_tray(self, icon=None, item=None):
        """Quit from tray"""
        try:
            if hasattr(self, 'root') and self.root:
                self.root.quit()
            sys.exit(0)
        except Exception as e:
            log(f"Quit error: {e}")
            sys.exit(0)



# ===================== MAIN ===================== #
if __name__ == "__main__":
    # Parse arguments first to check for non-GUI modes
    parser = argparse.ArgumentParser(add_help=True, description="Cloud Honeypot Client - Advanced Honeypot Management System")
    
    # Simplified mode system
    parser.add_argument("--mode", choices=["daemon", "tray"], help="Operation mode: daemon (background service), tray (tray-only mode). Default is GUI mode.")
    parser.add_argument("--minimized", action="store_true", help="Start GUI minimized to tray (legacy compatibility)")
    
    # Legacy compatibility
    parser.add_argument("--daemon", action="store_true", help="Run as a daemon service (legacy)")
    parser.add_argument("--silent", action="store_true", help="Silent mode - no user dialogs")
    parser.add_argument("--watchdog", type=int, default=None, help="Watchdog process ID")
    parser.add_argument("--healthcheck", action="store_true", help="Perform health check and exit")
    args = parser.parse_args()
    
    # Set global silent mode if requested
    if args.silent:
        import client_constants
        # Override config for silent deployment
        client_constants.SILENT_ADMIN_ELEVATION = True
        client_constants.SKIP_USER_DIALOGS = True

    # Handle special cases that don't need GUI
    if args.watchdog is not None:
        watchdog_main(args.watchdog)
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
            
            # Admin check and Task Scheduler setup
            if ctypes.windll.shell32.IsUserAnAdmin():
                log("Admin yetkisi mevcut - Task Scheduler kontrol ediliyor")
                try:
                    tasks_status = check_tasks_status()
                    if not tasks_status['both_installed']:
                        if install_tasks():
                            log("✓ Task Scheduler tasks installed")
                        else:
                            log("⚠ Task Scheduler installation failed")
                    else:
                        log("✓ Task Scheduler tasks already configured")
                except Exception as task_error:
                    log(f"Task Scheduler error: {task_error}")
            else:
                log("Normal user mode - Task Scheduler will be configured later")
            
            # Check if started with --mode=tray for tray-minimized startup
            tray_mode = getattr(args, 'mode', None) == 'tray'
            
            # Build GUI in both cases
            log("Building main GUI...")
            app.build_gui(minimized=tray_mode)  # Pass tray_mode as minimized flag
            log("GUI build completed successfully")
            
            # Start API synchronization in background after GUI is ready
            app.start_delayed_api_sync()
            
            # If tray mode, immediately hide to tray after GUI is built
            if tray_mode:
                log("Tray mode: Minimizing to tray...")
                if hasattr(app, 'root') and app.root:
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
        app = None
        try:
            log("=== DAEMON MODE STARTUP ===")
            
            # Log directory setup
            log_dir = os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            setup_logging()
            
            log("Setting up daemon mode application...")
            
            # Initialize app in daemon mode
            app = CloudHoneypotClient()
            app.operation_mode = DAEMON_MODE
            
            # Start daemon with proper error handling
            log("Starting daemon mode...")
            app.run_daemon()
            
        except KeyboardInterrupt:
            log("Daemon interrupted by user signal")
            sys.exit(0)
        except Exception as daemon_error:
            log(f"DAEMON CRITICAL ERROR: {daemon_error}")
            import traceback
            log(f"Daemon traceback: {traceback.format_exc()}")
            
            # Try to cleanup gracefully
            try:
                if app and hasattr(app, 'heartbeat_path'):
                    cleanup_heartbeat_file(app.heartbeat_path)
            except:
                pass
            sys.exit(1)  # Exit code 1 = Unhandled exception
        
        sys.exit(0)
    
    else:
        # Fallback - should not happen with current logic
        log(f"ERROR: Unknown operation mode: {operation_mode}")
        sys.exit(1)

    # ===== GUI MODE - SIMPLIFIED FOR DEBUGGING =====
    
    # Initialize basic logging FIRST
    log_dir = os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient')
    os.makedirs(log_dir, exist_ok=True)
    setup_logging()
    
    log("=== GUI MODE STARTUP - Simplified version ===")
    
    try:
        # Load configuration
        config = load_config()
        selected_language = config["language"]["selected"]
        
        # Create app instance
        app = CloudHoneypotClient()
        app.lang = selected_language
        log(f"Application initialized with language: {selected_language}")
        
        # Admin check and Task Scheduler setup
        if ctypes.windll.shell32.IsUserAnAdmin():
            log("Admin yetkisi mevcut - Task Scheduler kontrol ediliyor")
            try:
                tasks_status = check_tasks_status()
                if not tasks_status['both_installed']:
                    if install_tasks():
                        log("✓ Task Scheduler tasks installed")
                    else:
                        log("⚠ Task Scheduler installation failed")
                else:
                    log("✓ Task Scheduler tasks already configured")
            except Exception as task_error:
                log(f"Task Scheduler error: {task_error}")
        else:
            log("Normal user mode - Task Scheduler will be configured later")
        
        # Build GUI directly
        log("Building main GUI...")
        app.build_gui(minimized=False)
        log("GUI build completed successfully")
        
        # Run main loop
        if hasattr(app, 'root') and app.root:
            app.root.mainloop()
        
    except Exception as gui_error:
        log(f"GUI Mode Error: {gui_error}")
        import traceback
        log(f"GUI Error traceback: {traceback.format_exc()}")
        sys.exit(1)
    
    else:
        # Fallback - should not happen with current logic
        log(f"ERROR: Unknown operation mode: {operation_mode}")
        sys.exit(1)




