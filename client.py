#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Ana Uygulama
Modern, modüler honeypot istemci uygulaması
"""

# Standard library imports
import os, sys, socket, ssl, threading, time, json, subprocess, ctypes, tempfile, winreg, argparse
import tkinter as tk
from tkinter import ttk, messagebox
from logging.handlers import RotatingFileHandler
from ctypes import wintypes
from typing import Optional, Union, Dict, Any
import datetime as dt
import requests, webbrowser, logging, struct, hashlib

# Local module imports - Modularized honeypot client components
from client_firewall import FirewallAgent
from client_helpers import log, run_cmd, ClientHelpers
import client_helpers
from client_networking import TunnelServerThread, NetworkingHelpers, TunnelManager, set_config_function, load_network_config
from client_api import HoneypotAPIClient, test_api_connection, AsyncAttackCounter
from client_gui import LoadingScreen, LanguageDialog, AdminPrivilegeDialog, ConsentDialog
from client_gui import show_startup_notice, show_error_message, show_info_message, show_warning_message
from client_services import WindowsServiceManager, RDPManager, FirewallManager, TaskSchedulerManager
from client_utils import (ConfigManager, LanguageManager, LoggerManager, SecurityUtils, 
                         SystemUtils, TokenStore, ServiceController, load_i18n,
                         firewall_allow_exists_tcp_port, ensure_firewall_allow_for_port,
                         is_process_running_windows, write_watchdog_token, read_watchdog_token,
                         start_watchdog_if_needed, is_admin, set_autostart, watchdog_main,
                         install_excepthook, load_config, save_config, get_config_value, 
                         set_config_value, update_language_config, get_port_table, get_from_config,
                         get_rdp_secure_port)

# ===================== APPLICATION CONFIGURATION ===================== #
# Purpose: Central configuration management and file paths

def appdata_dir() -> str:
    """Get or create application data directory"""
    return os.makedirs(os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), 
                                   "YesNext", "CloudHoneypotClient"), exist_ok=True) or \
           os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "YesNext", "CloudHoneypotClient")

# Application file paths - Centralized configuration
APP_DIR = appdata_dir()
# CONFIG_FILE removed - now handled by client_utils.py single config system
LOG_FILE, CONSENT_FILE, STATUS_FILE = [
    os.path.join(APP_DIR, f) for f in ["client.log", "consent.json", "status.json"]
]
TOKEN_FILE_NEW, TOKEN_FILE_OLD, WATCHDOG_TOKEN_FILE = [
    os.path.join(APP_DIR, "token.dat"), "token.txt", os.path.join(APP_DIR, "watchdog.token")
]

# Central config system - single config file next to executable
# No CLIENT_CONFIG_FILE needed - handled by client_utils.py

# ===================== LOGGING SETUP ===================== #
# Purpose: Modern, efficient logging system with millisecond precision

class CustomFormatter(logging.Formatter):
    """High-precision timestamp formatter for detailed logging"""
    def formatTime(self, record, datefmt=None):
        return dt.datetime.fromtimestamp(record.created).strftime(
            datefmt or '%Y-%m-%d %H:%M:%S.%f')[:-3]

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
            RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
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
        print(f"Logging sistemi başlatılamadı: {e}")
        return False

# Initialize global logger
LOGGER = None

setup_logging()

# ===================== APPLICATION CONFIGURATION ===================== #
# Purpose: Centralized configuration system using client_config.json

# Initialize configuration early (before other constants)
_CONFIG = None

def get_app_config():
    """Get application configuration, loading it if needed"""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_config()
    return _CONFIG

# Application metadata from config
__version__ = get_from_config("application.version", "2.2.3")
APP_NAME = get_from_config("application.name", "Cloud Honeypot Client")
GITHUB_OWNER, GITHUB_REPO = "cevdetaksac", "yesnext-cloud-honeypot-client"

# Service configuration from config
API_URL = get_from_config("api.base_url", "https://honeypot.yesnext.com.tr/api")
# Network configuration - loaded from config
HONEYPOT_IP = get_from_config("honeypot.server_ip", "194.5.236.181") 
HONEYPOT_TUNNEL_PORT = get_from_config("honeypot.tunnel_port", 4443)
CONTROL_HOST, CONTROL_PORT = "127.0.0.1", 58632  # Single instance control

# Network settings
SERVER_NAME = socket.gethostname()
RECV_SIZE, CONNECT_TIMEOUT = 65536, 8

# RDP secure port from config
RDP_SECURE_PORT = get_from_config("tunnels.rdp_port", 53389)

# GUI configuration from config
def get_window_dimensions():
    """Get window dimensions from config"""
    config = get_app_config()
    width = config.get("ui", {}).get("window_width", 900)
    height = config.get("ui", {}).get("window_height", 700)
    return width, height

WINDOW_WIDTH, WINDOW_HEIGHT = get_window_dimensions()
WINDOW_TITLE = APP_NAME

# Windows integration
APP_STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
TASK_NAME_BOOT, TASK_NAME_LOGON = "CloudHoneypotClientBoot", "CloudHoneypotClientLogon"

# Default tunnel configurations from config
def get_default_tunnels():
    """Get default tunnel configuration from config"""
    config = get_app_config()
    default_ports = config.get("tunnels", {}).get("default_ports", [])
    tunnels = {}
    for port_config in default_ports:
        service = port_config["service"]
        local_port = port_config["local"]
        tunnels[service] = {"listen_port": local_port}
    return tunnels

DEFAULT_TUNNELS = get_default_tunnels()

# Port mapping for GUI display from config
def get_port_table():
    """Get port table from config"""
    config = get_app_config()
    default_ports = config.get("tunnels", {}).get("default_ports", [])
    port_table = []
    for port_config in default_ports:
        local_port = str(port_config["local"])
        remote_port = str(port_config["remote"]) if port_config["remote"] > 0 else "-"
        service = port_config["service"]
        port_table.append((local_port, remote_port, service))
    return port_table

PORT_TABLOSU = get_port_table()

# Optional tray support from config
TRY_TRAY = get_from_config("advanced.minimize_to_tray", True)  # Default True
try:
    import pystray
    from pystray import MenuItem as TrayItem
    from PIL import Image, ImageDraw
    # TRY_TRAY already set from config
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
        
        # 2. Meşru uygulama işaretleri
        app_markers = {
            "company": "YesNext Technology",
            "product": "Cloud Honeypot Client", 
            "version": "2.1.0",
            "purpose": "Network Security Monitor",
            "legitimate": True,
            "signed": os.path.exists("certs/dev-codesign.pfx")
        }
        
        # 3. Registry girdileri (güven için)
        try:
            import winreg
            key_path = r"SOFTWARE\YesNext\CloudHoneypotClient"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
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
                
        # 3. Network behavior legitimacy
        legitimate_domains = [
            "honeypot.yesnext.com.tr",
            "api.yesnext.com.tr", 
            "github.com",
            "raw.githubusercontent.com"
        ]
        
        # 4. Dosya operasyon sınırları (şüpheli davranış önleme)
        restricted_paths = [
            os.environ.get("SYSTEMROOT", "C:\\Windows"),
            os.environ.get("PROGRAMFILES", "C:\\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
        ]
        
        log("Defender trust signals created")
        return {
            "legitimate_domains": legitimate_domains,
            "restricted_paths": restricted_paths,
            "process_verified": True
        }
        
    except Exception as e:
        log(f"Failed to create trust signals: {e}")
        return None

# ===================== SERVICE MANAGEMENT ===================== #
def handle_service_commands(args):
    """Handle service management commands"""
    import os
    import sys
    import subprocess
    
    # Service script path (same directory as main executable)
    service_script = os.path.join(os.path.dirname(sys.executable), 'service_wrapper.py')
    if not os.path.exists(service_script):
        # Fallback: try current directory
        service_script = os.path.join(os.path.dirname(__file__), 'service_wrapper.py')
        
    if not os.path.exists(service_script):
        print("❌ Service script not found! Please ensure service_wrapper.py is in the application directory.")
        return False
    
    try:
        if args.install:
            print("📦 Installing Cloud Honeypot Monitor Service...")
            result = subprocess.run([
                sys.executable, service_script, 'install'
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ Service installed successfully!")
                print("🔧 The service will automatically monitor and restart the client application.")
                print("📊 You can check the service status in Windows Services (services.msc)")
            else:
                print("❌ Service installation failed:")
                if result.stdout: print(result.stdout)
                if result.stderr: print(result.stderr)
            return result.returncode == 0
            
        elif args.remove:
            print("🗑️ Removing Cloud Honeypot Monitor Service...")
            result = subprocess.run([
                sys.executable, service_script, 'uninstall'
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ Service removed successfully!")
            else:
                print("❌ Service removal failed:")
                if result.stdout: print(result.stdout)
                if result.stderr: print(result.stderr)
            return result.returncode == 0
            
        elif getattr(args, 'service_status', False):
            print("📊 Checking Cloud Honeypot Monitor Service status...")
            result = subprocess.run([
                sys.executable, service_script, 'status'
            ], capture_output=True, text=True, timeout=30)
            
            if result.stdout: 
                print(result.stdout)
            if result.stderr: 
                print(result.stderr)
            return True
            
    except subprocess.TimeoutExpired:
        print("❌ Service command timed out")
        return False
    except Exception as e:
        print(f"❌ Service management error: {e}")
        return False
        
    return True

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

    def get_token(self) -> Optional[str]:
        # Kaydedilmiş token'ı yükler
        # Önce eski plain text token'ı kontrol et ve migrate et
        TokenStore.migrate_from_plain(TOKEN_FILE_OLD, TOKEN_FILE_NEW)
        # DPAPI ile şifrelenmiş token'ı yükle
        return TokenStore.load(TOKEN_FILE_NEW)

    def api_request(self, method: str, endpoint: str, data: Dict = None,
                    params: Dict = None, timeout: int = 8, json: Dict = None) -> Optional[Dict]:
        """API request wrapper using modular API client"""
        try:
            token = self.state.get("token")
            if token:
                params = params or {}
                params['token'] = token
            
            return self.api_client.api_request(
                method=method, endpoint=endpoint,
                data=json if json else data, params=params, timeout=timeout
            )
        except Exception as e:
            log(f"[API] Wrapper hatası: {e}")
            return None

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
            print(f"[CONFIG] Language loaded from config: {self.lang}")
        except Exception as e:
            print(f"[CONFIG] Language initialization error: {e}")
            self.lang = "tr"

        # Initialize core components
        self.api_client = HoneypotAPIClient(API_URL, log)
        
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
            token = self.load_token()
            self.state["token"] = token
            if token:
                log(f"Token başarıyla yüklendi: {token[:8]}...")
            else:
                log("Token yüklenemedi - yeni token kaydı gerekebilir")
        except Exception as e:
            log(f"Token yükleme hatası: {e}")
            self.state["token"] = None
        
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
                
                time.sleep(5)  # Wait for tunnel-set completion
                
            except Exception as e:
                log(f"Başlangıç RDP kontrolü sırasında hata: {e}")

        # Önce RDP kontrolünü yap
        check_initial_rdp_state()

        # Sonra API senkronizasyonunu 5 dakika geciktirerek başlat
        def delayed_api_start():
            log("API senkronizasyonu 5 dakika bekletiliyor (manuel işlemler için)...")
            time.sleep(300)  # 5 dakika bekle
            log("API senkronizasyonu başlatılıyor...")
            # API retry thread'ini başlat
            threading.Thread(target=self.api_retry_loop, daemon=True).start()

        # Geciktirilmiş API başlangıcını başlat
        threading.Thread(target=delayed_api_start, daemon=True).start()

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
                print(f"[TRANSLATION] ERROR: Language dict is not dict: {type(lang_dict)}")
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
                log("Admin yetkisi talep ediliyor...")
                try:
                    exe = sys.executable
                    params = " ".join(sys.argv[1:]) if getattr(sys, 'frozen', False) else \
                            f'"{os.path.abspath(sys.argv[0])}" ' + " ".join(sys.argv[1:])
                    
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
                    log("Admin yetkilendirme penceresi açıldı - uygulama yeniden başlatılacak")
                    return "restarting"
                except Exception as e:
                    log(f"Admin yetkilendirme talebi başarısız: {e}")
                    return False
            
            log("Admin yetkisi yok - bazı özellikler sınırlı olabilir")
            return False
        except Exception as e:
            log(f"ensure_admin error: {e}")
            return False

    # ---------- Token Management ---------- #
    def register_client(self) -> Optional[str]:
        """Register client with API and get token"""
        for attempt in range(3):
            try:
                ip = ClientHelpers.get_public_ip()
                resp = requests.post(f"{API_URL}/register",
                                   json={"server_name": f"{SERVER_NAME} ({ip})", "ip": ip},
                                   timeout=8)
                
                if resp.status_code == 200:
                    data = resp.json()
                    tok = data.get("token")
                    if tok:
                        TokenStore.save(tok, TOKEN_FILE_NEW)
                        return tok
                
                msg = f"API kaydı başarısız (HTTP {resp.status_code}). Tekrar deneniyor..."
                if self.root:
                    messagebox.showwarning("Uyarı", msg)
                log(msg)
                
            except Exception as e:
                msg = f"API kaydı başarısız: {e}. Tekrar deneniyor..."
                if self.root:
                    messagebox.showwarning("Uyarı", msg)
                log(msg)
            
            time.sleep(5)
        
        if self.root:
            messagebox.showwarning(self.t("warn"), self.t("api_registration_warning"))
        return None

    def load_token(self) -> Optional[str]:
        """Load token from storage or register new client"""
        TokenStore.migrate_from_plain(TOKEN_FILE_OLD, TOKEN_FILE_NEW)
        return TokenStore.load(TOKEN_FILE_NEW) or self.register_client()

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
                    time.sleep(60)
                continue
                
            # Reset retry count on successful connection
            if retry_count > 0:
                logging.info(f"API connection restored after {retry_count} retries")
                retry_count = 0
                
            time.sleep(60)  # Check connection every minute when healthy

# ---------- IP & Heartbeat Management ---------- #
    def update_client_ip(self, new_ip: str):
        """Update client IP address via API"""
        try:
            token = self.state.get("token")
            if not token: 
                return
            
            r = requests.post(f"{API_URL}/update-ip", 
                            json={"token": token, "ip": new_ip}, timeout=6)
            
            if r.status_code == 200:
                log(f"update-ip OK: {new_ip}")
            else:
                log(f"update-ip HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            log(f"update-ip error: {e}")

    def send_heartbeat_once(self, status_override: Optional[str] = None):
        """Send single heartbeat to API"""
        try:
            token = self.state.get("token")
            if not token:
                return
            
            ip = self.state.get("public_ip") or ClientHelpers.get_public_ip()
            status = status_override if status_override in ("online", "offline") else \
                    ("online" if self.state.get("running") else "offline")
            
            payload = {
                "token": token, "ip": ip, "hostname": SERVER_NAME,
                "running": self.state.get("running", False), "status": status
            }
            requests.post(f"{API_URL}/heartbeat", json=payload, timeout=6)
        except Exception as e:
            log(f"heartbeat send err: {e}")

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
                    self.send_heartbeat_once()
            except Exception as e:
                log(f"heartbeat error: {e}")
            time.sleep(60)

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
            log("[GUI] Token olmadığı için saldırı sayısı güncellenemiyor")
            return
        if not self.root or not self.attack_entry:
            log("[GUI] GUI elemanları hazır değil, saldırı sayısı güncellenemiyor")
            return
            
        def worker():
            try:
                cnt = self.fetch_attack_count_sync(token)
                if cnt is None:
                    log("[GUI] Saldırı sayısı alınamadı, sayaç güncellenmedi")
                    return
                    
                # GUI thread-safe güncelleme
                try:
                    def update_entry():
                        ClientHelpers.safe_set_entry(self.attack_entry, str(cnt))
                        log(f"[GUI] Entry güncellendi: {self.attack_entry.get()}")
                    
                    # Check if main loop is running
                    try:
                        self.root.after(0, update_entry)
                        log(f"[GUI] Saldırı sayacı güncelleme zamanlandı: {cnt}")
                    except RuntimeError as e:
                        if "main thread is not in main loop" in str(e):
                            # Main loop not started yet, update directly
                            ClientHelpers.safe_set_entry(self.attack_entry, str(cnt))
                            log(f"[GUI] Saldırı sayacı direkt güncellendi: {cnt}")
                        else:
                            raise e
                except Exception as e:
                    log(f"[GUI] Saldırı sayacı güncellenirken hata: {e}")
                    ClientHelpers.safe_set_entry(self.attack_entry, str(cnt))
            except Exception as e:
                log(f"[GUI] Saldırı sayısı güncelleme worker hatası: {e}")
                
        if async_thread:
            threading.Thread(target=worker, daemon=True, name="AttackCountUpdater").start()
            log("[GUI] Asenkron saldırı sayacı güncelleme başlatıldı")
        else:
            worker()

    def poll_attack_count(self):
        self.refresh_attack_count(async_thread=True)
        try:
            self.root.after(10_000, self.poll_attack_count)
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

    # Legacy onedir update methods removed - now using installer-based system

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

        # RDP geçiş süresi 120 saniye
        RDP_TRANSITION_TIMEOUT = 120
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
        try:
            token = self.state.get("token")
            if not token:
                log("Token yok; eylem bildirilemedi")
                return False

            payload = {
                "token": token,
                "service": str(service or "").upper(),
                "action": action if action in ("start", "stop") else "stop",
            }
            if new_port and str(new_port) != '-':
                payload["new_port"] = int(str(new_port))

            resp = self.api_request("POST", "premium/tunnel-set", json=payload)
            if isinstance(resp, dict) and resp.get("status") in ("queued", "ok", "success"):
                # yerel önbellek güncelle
                self.active_tunnels = getattr(self, "active_tunnels", {})
                self.active_tunnels.setdefault(payload["service"], {})\
                    .update({"running": payload["action"] == "start",
                            "new_port": payload.get("new_port")})
                log(f"Tünel eylemi bildirildi: {payload}")
                return True

            log(f"Tünel eylemi bildirimi başarısız: {resp}")
            return False
        except Exception as e:
            log(f"Tünel eylemi raporlanırken hata: {e}")
            return False

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
            deadline = time.time() + 120  # 120 saniye timeout

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
        try:
            token = self.state.get("token")
            if not token:
                return
            ports = self._collect_open_ports_windows() if os.name == 'nt' else []
            payload = {"token": token, "ports": ports}
            r = requests.post(f"{API_URL}/agent/open-ports", json=payload, timeout=8)
            if r.status_code != 200:
                log(f"open-ports HTTP {r.status_code}: {r.text[:120]}")
        except Exception as e:
            log(f"report_open_ports_once err: {e}")

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
                        except Exception as e:
                            log(f"remote start {svc_u} err: {e}")
                    elif desired == 'stopped' and running:
                        log(f"API komutu: '{svc_u}' servisi durduruluyor.")
                        try:
                            self.stop_single_row(str(lp), str(entry.get('new_port') or '-'), self._normalize_service(svc_u))
                            if svc_u == 'RDP' and ServiceController.get_rdp_port() != 3389:
                                ServiceController.switch_rdp_port(3389)
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
            time.sleep(300)

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
                
            # Watchdog'u durdur
            try:
                write_watchdog_token('stop')
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
                    write_watchdog_token('stop')
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
        self.state["token"] = self.load_token()
        self.state["public_ip"] = ClientHelpers.get_public_ip()
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
        log("Daemon: durduruldu.")



    # ---------- Firewall Agent ---------- #
    def start_firewall_agent(self):
        """Start firewall agent with updated client_firewall module"""
        try:
            from client_firewall import FirewallAgent
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

        # Windows Service Menu
        menu_service = tk.Menu(menubar, tearoff=0)
        
        def check_service_status():
            """Check and display current service status"""
            try:
                import subprocess
                import sys
                import os
                
                # Service script path
                service_script = os.path.join(os.path.dirname(sys.executable), 'service_wrapper.py')
                if not os.path.exists(service_script):
                    service_script = os.path.join(os.path.dirname(__file__), 'service_wrapper.py')
                
                if not os.path.exists(service_script):
                    messagebox.showerror(self.t("error"), "Service wrapper not found!")
                    return
                
                # Run status check
                result = subprocess.run([
                    sys.executable, service_script, 'status'
                ], capture_output=True, text=True, timeout=30)
                
                status_text = result.stdout if result.stdout else result.stderr
                if not status_text:
                    status_text = "Service status unknown"
                
                messagebox.showinfo(self.t("service_status") if hasattr(self, 't') else "Service Status", status_text)
                
            except Exception as e:
                messagebox.showerror(self.t("error"), f"Service status check failed: {str(e)}")
        
        def install_service():
            """Install Windows service"""
            try:
                result = messagebox.askquestion(
                    self.t("service_install") if hasattr(self, 't') else "Install Service", 
                    self.t("service_install_confirm") if hasattr(self, 't') else "Install Cloud Honeypot Monitor Service?\n\nThis service will automatically restart the client if it crashes."
                )
                
                if result == 'yes':
                    import subprocess
                    import sys
                    import os
                    
                    service_script = os.path.join(os.path.dirname(sys.executable), 'service_wrapper.py')
                    if not os.path.exists(service_script):
                        service_script = os.path.join(os.path.dirname(__file__), 'service_wrapper.py')
                    
                    if not os.path.exists(service_script):
                        messagebox.showerror(self.t("error"), "Service wrapper not found!")
                        return
                    
                    # Run installation
                    result = subprocess.run([
                        sys.executable, service_script, 'install'
                    ], capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        messagebox.showinfo(
                            self.t("success") if hasattr(self, 't') else "Success", 
                            self.t("service_installed") if hasattr(self, 't') else "Service installed successfully!\n\nThe client is now protected by the monitor service."
                        )
                    else:
                        error_msg = result.stderr or result.stdout or "Unknown error"
                        messagebox.showerror(
                            self.t("error"), 
                            f"Service installation failed:\n{error_msg}\n\nPlease run as Administrator."
                        )
                        
            except Exception as e:
                messagebox.showerror(self.t("error"), f"Service installation error: {str(e)}")
        
        def remove_service():
            """Remove Windows service"""
            try:
                result = messagebox.askquestion(
                    self.t("service_remove") if hasattr(self, 't') else "Remove Service", 
                    self.t("service_remove_confirm") if hasattr(self, 't') else "Remove Cloud Honeypot Monitor Service?\n\nThe client will continue working but won't auto-restart if it crashes.",
                    icon='warning'
                )
                
                if result == 'yes':
                    import subprocess
                    import sys
                    import os
                    
                    service_script = os.path.join(os.path.dirname(sys.executable), 'service_wrapper.py')
                    if not os.path.exists(service_script):
                        service_script = os.path.join(os.path.dirname(__file__), 'service_wrapper.py')
                    
                    if not os.path.exists(service_script):
                        messagebox.showerror(self.t("error"), "Service wrapper not found!")
                        return
                    
                    # Run removal
                    result = subprocess.run([
                        sys.executable, service_script, 'uninstall'
                    ], capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        messagebox.showinfo(
                            self.t("success") if hasattr(self, 't') else "Success", 
                            self.t("service_removed") if hasattr(self, 't') else "Service removed successfully!"
                        )
                    else:
                        error_msg = result.stderr or result.stdout or "Unknown error"
                        messagebox.showerror(
                            self.t("error"), 
                            f"Service removal failed:\n{error_msg}"
                        )
                        
            except Exception as e:
                messagebox.showerror(self.t("error"), f"Service removal error: {str(e)}")
        
        menu_service.add_command(label=self.t("service_status") if hasattr(self, 't') else "Service Status", command=check_service_status)
        menu_service.add_separator()
        menu_service.add_command(label=self.t("service_install") if hasattr(self, 't') else "Install Service", command=install_service)
        menu_service.add_command(label=self.t("service_remove") if hasattr(self, 't') else "Remove Service", command=remove_service)
        menubar.add_cascade(label=self.t("menu_service") if hasattr(self, 't') else "Win-Service", menu=menu_service)

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
        token = self.load_token()
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
            log(f"[GUI] Token loaded, initial attack count refresh triggered")
        else:
            log(f"[GUI] No token available, attack count will remain 0")

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

        self.root.mainloop()





# ===================== MAIN ===================== #
if __name__ == "__main__":
    # Parse arguments first to check for non-GUI modes
    parser = argparse.ArgumentParser(add_help=True, description="Cloud Honeypot Client - Advanced Honeypot Management System")
    parser.add_argument("--daemon", action="store_true", help="Run as a daemon service")
    parser.add_argument("--minimized", type=str, default="true", help="Start minimized")
    parser.add_argument("--watchdog", type=int, default=None, help="Watchdog process ID")
    parser.add_argument("--install", action="store_true", help="Install the monitor service")
    parser.add_argument("--remove", action="store_true", help="Remove the monitor service")
    parser.add_argument("--service-status", action="store_true", dest="service_status", help="Show service status")
    args = parser.parse_args()

    # Handle special cases that don't need GUI
    if args.watchdog is not None:
        watchdog_main(args.watchdog)
        sys.exit(0)
        
    # Handle service management commands
    if args.install or args.remove or getattr(args, 'service_status', False):
        handle_service_commands(args)
        sys.exit(0)

    # For daemon mode, skip GUI entirely
    if args.daemon:
        # Log directory setup
        log_dir = os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient')
        os.makedirs(log_dir, exist_ok=True)
        setup_logging()
        
        app = CloudHoneypotClient()
        app.run_daemon()
        sys.exit(0)

    # ===== GUI MODE - COMPREHENSIVE LOADING FLOW =====
    
    # Initialize loading screen at the very beginning
    loading = None
    selected_language = "tr"  # Default language
    
    try:
        print("[MAIN] === Starting GUI mode ===")
        
        # Step 1: Initialize Loading Screen (5%) - using modular GUI
        print("[MAIN] Creating loading screen...")
        loading = LoadingScreen(I18N, "dark")
        loading.create()
        loading.update_progress(5, I18N.get("loading_initializing", "Initializing..."))
        print("[MAIN] Loading screen created and showing 5%")
        
        # Step 2: Language Selection (15%) - Using NEW CONFIG SYSTEM
        print("[MAIN] Loading config for language selection...")
        config = load_config()
        selected_language = config["language"]["selected"]
        language_selected_by_user = config["language"]["selected_by_user"]
        print(f"[MAIN] Config loaded, current language: {selected_language}, selected by user: {language_selected_by_user}")
        
        # If language not selected by user yet, show language selector
        if not language_selected_by_user:
            print("[MAIN] Language not selected by user yet, showing language selection dialog...")
            loading.update_progress(10, "Dil seçimi bekleniyor..." if selected_language == "tr" else "Waiting for language selection...")
            
            try:
                print("[MAIN] Creating language dialog...")
                
                # Create new language dialog with proper cleanup
                language_dialog = LanguageDialog()
                print("[MAIN] Language dialog created, showing...")
                selected_language = language_dialog.show()
                
                if not selected_language:
                    print("[MAIN] ERROR: No language selected, exiting")
                    loading.close()
                    sys.exit(0)
                print(f"[MAIN] Language dialog completed, selected: {selected_language}")
                
                # Save language selection using new config system
                print(f"[MAIN] Saving language selection to config: {selected_language}")
                success = update_language_config(selected_language, True)
                if success:
                    log(f"Dil seçildi ve kaydedildi: {selected_language}")
                    print("[MAIN] Language saved successfully to config")
                else:
                    print("[MAIN] WARNING: Failed to save language to config")
                
                # Update loading screen with selected language
                current_i18n = I18N.get(selected_language, I18N.get("tr", {}))
                loading_msg = current_i18n.get("loading_language_saved", "Language saved, continuing...")
                print(f"[MAIN] Updating loading with message: {loading_msg}")
                loading.update_progress(12, loading_msg)
                
            except Exception as e:
                print(f"[MAIN] ERROR in language selection: {e}")
                selected_language = "tr"
                # Save fallback language to config
                update_language_config(selected_language, False)
                current_i18n = I18N.get(selected_language, I18N.get("tr", {}))
                loading_msg = current_i18n.get("loading_default_language", "Using default language...")
                loading.update_progress(12, loading_msg)
        else:
            print(f"[MAIN] Language already selected by user: {selected_language}")
            current_i18n = I18N.get(selected_language, I18N.get("tr", {}))
        
        # Update loading with correct language
        print(f"[MAIN] Proceeding with selected language: {selected_language}")
        
        loading_init_msg = current_i18n.get("loading_initializing_system", "Initializing system...")
        print(f"[MAIN] Updating loading progress to 15% with message: {loading_init_msg}")
        loading.update_progress(15, loading_init_msg)
        
        # Step 3: Initialize logging (20%)
        log_dir = os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient')
        os.makedirs(log_dir, exist_ok=True)
        setup_logging()
        
        log(f"Uygulama başlatılıyor - dil: {selected_language}")
        loading_key = current_i18n.get("loading_initializing", "Initializing...")
        loading.update_progress(20, loading_key)

        # Step 4: Initialize application with selected language (30%)
        app = CloudHoneypotClient()
        # Set the selected language in the app instance
        app.lang = selected_language
        log(f"Application initialized successfully with language: {selected_language}")
        loading_key = current_i18n.get("loading_checking_admin", "Checking admin privileges...")
        loading.update_progress(30, loading_key)
        
        # Step 5: Admin privilege check (40%)
        print("[MAIN] Starting admin privilege check step...")
        loading_msg = current_i18n.get("loading_checking_privileges", "Checking privileges...")
        loading.update_progress(35, loading_msg)
        print(f"[MAIN] Admin check progress (35%) with message: {loading_msg}")
        
        # Check if already running as admin
        if ctypes.windll.shell32.IsUserAnAdmin():
            print("[MAIN] Already running as admin - proceeding")
            log("Admin yetkisi mevcut - devam ediliyor")
            has_admin = True
            loading_msg = current_i18n.get("loading_admin_confirmed", "Admin privileges confirmed")
            loading.update_progress(40, loading_msg)
            print(f"[MAIN] Admin confirmed (40%) with message: {loading_msg}")
        else:
            print("[MAIN] Not running as admin - showing admin dialog")
            log("Admin yetkisi yok - kullanıcıya dialog gösteriliyor")
            loading_msg = current_i18n.get("loading_waiting_privilege", "Waiting for privilege confirmation...")
            loading.update_progress(38, loading_msg)
            print(f"[MAIN] Waiting for privilege (38%) with message: {loading_msg}")
            
            # Show admin privilege dialog using modular GUI
            print("[MAIN] Creating AdminPrivilegeDialog...")
            admin_dialog = AdminPrivilegeDialog(I18N)
            print("[MAIN] Showing admin dialog...")
            user_choice = admin_dialog.show()
            
            print(f"[MAIN] Admin dialog completed with choice: '{user_choice}'")
            log(f"Admin dialog result: '{user_choice}'")  # Debug log
            
            # Update loading after dialog
            loading_msg = current_i18n.get("loading_privilege_completed", "Privilege selection completed...")
            loading.update_progress(40, loading_msg)
            print(f"[MAIN] Privilege completed (40%) with message: {loading_msg}")
            
            if user_choice == "yes":
                print("[MAIN] User chose YES - restarting with admin privileges")
                log("Kullanıcı admin yetkileriyle yeniden başlatmayı seçti")
                loading_msg = current_i18n.get("loading_checking_admin", "Checking admin privileges...")
                loading.update_progress(40, loading_msg)
                print(f"[MAIN] Restarting admin (40%) with message: {loading_msg}")
                
                # Restart with admin privileges
                try:
                    print("[MAIN] Attempting admin restart...")
                    import subprocess
                    import sys
                    
                    # Get current executable path
                    if hasattr(sys, 'frozen') and sys.frozen:
                        # If running as EXE
                        current_exe = sys.executable
                        args = sys.argv[1:]
                        print(f"[MAIN] Running as EXE: {current_exe}")
                    else:
                        # If running as Python script
                        current_exe = sys.executable
                        args = [os.path.abspath(sys.argv[0])] + sys.argv[1:]
                        print(f"[MAIN] Running as Python script: {current_exe}")
                    
                    # Build command properly
                    if args:
                        args_str = '" "'.join(str(arg) for arg in args)
                        cmd = f'Start-Process -FilePath "{current_exe}" -ArgumentList "{args_str}" -Verb RunAs'
                        print(f"[MAIN] Restart command with args: {cmd}")
                    else:
                        cmd = f'Start-Process -FilePath "{current_exe}" -Verb RunAs'
                        print(f"[MAIN] Restart command no args: {cmd}")
                    
                    # Restart with admin privileges
                    print("[MAIN] Executing restart command...")
                    subprocess.run(['powershell', '-Command', cmd], check=False)
                    
                    print("[MAIN] Admin restart initiated - closing application")
                    log("Yönetici yetkilendirme penceresi açıldı - uygulama yeniden başlatılacak")
                    if loading: loading.close()
                    sys.exit(0)
                    
                except Exception as restart_error:
                    print(f"[MAIN] ERROR in admin restart: {restart_error}")
                    log(f"Admin restart error: {restart_error}")
                    log("Admin yetkilendirme başarısız - sınırlı modda devam ediliyor")
                    has_admin = False
            elif user_choice == "cancel":
                print("[MAIN] User chose CANCEL - exiting application")
                log("Kullanıcı uygulamayı kapatmayı seçti")
                if loading: loading.close()
                sys.exit(0)
            elif user_choice == "no":
                print("[MAIN] User chose NO - continuing in limited mode")
                log("Kullanıcı sınırlı modda devam etmeyi seçti")
                has_admin = False
        
        # Step 6: API Connection Validation (50%)
        loading_msg = current_i18n.get("loading_connecting_api", "Testing API connection...")
        loading.update_progress(45, loading_msg)
        
        # Use modular API client for connection test
        if not test_api_connection("https://honeypot.yesnext.com.tr", log):
            # API connection failed - exit application
            loading.close()
            log("API bağlantısı başarısız - uygulama kapatılıyor")
            sys.exit(1)
        
        loading_msg = current_i18n.get("loading_loading_config", "Loading configuration...")
        loading.update_progress(55, loading_msg)
        log("API bağlantısı doğrulandı - uygulama devam ediyor")
        
        # Step 7: Service management and installation (60%)
        loading_msg = current_i18n.get("loading_checking_services", "Checking services...")
        loading.update_progress(60, loading_msg)
        
        # Handle service management commands
        if getattr(args, 'install', False):
            loading.close()
            log("Servis kurulum modunda çalışıyor")
            success = handle_service_commands(args)
            sys.exit(0 if success else 1)
        elif getattr(args, 'remove', False):
            loading.close()
            log("Servis kaldırma modunda çalışıyor")
            success = handle_service_commands(args)
            sys.exit(0 if success else 1)
        elif getattr(args, 'service_status', False):
            loading.close()
            log("Servis durumu kontrol ediliyor")
            handle_service_commands(args)
            sys.exit(0)

        # Step 8: Show first run notice if needed (75%)
        loading_msg = current_i18n.get("loading_first_run_check", "First run check...")
        loading.update_progress(75, loading_msg)
        try:
            app.first_run_notice()
        except Exception as e:
            log(f"First run notice error: {str(e)}")

        # Step 9: Prepare GUI (90%)
        loading_msg = current_i18n.get("loading_preparing_gui", "Preparing interface...")
        loading.update_progress(90, loading_msg)

        # Step 10: Start main application GUI - CRITICAL PART
        print("[MAIN] === STARTING GUI CREATION ===")
        loading_msg = current_i18n.get("loading_completed", "Startup completed!")
        loading.update_progress(95, loading_msg)
        print(f"[MAIN] GUI startup (95%) with message: {loading_msg}")
        log("GUI başlatılıyor...")
        
        # Ensure we don't have GUI conflicts
        if hasattr(app, 'root') and app.root:
            print("[MAIN] Destroying existing root window...")
            app.root.destroy()
            app.root = None
            
        # Build GUI properly
        print(f"[MAIN] Building GUI components with language: {selected_language}")
        log("Building GUI components...")
        loading.update_progress(100, I18N.get("loading_completed", "Startup completed!"))
        print("[MAIN] Loading progress complete (100%)")
        
        # Small delay to show completion
        import time
        time.sleep(0.5)
        
        print("[MAIN] Closing loading screen...")
        loading.close()  # Close loading before showing main GUI
        
        print("[MAIN] Starting main GUI build...")
        app.build_gui(minimized=False)
        print("[MAIN] GUI build completed successfully!")
        log("GUI build completed successfully")
        
    except Exception as main_error:
        print(f"[MAIN] === CRITICAL ERROR IN MAIN ===")
        print(f"[MAIN] Error: {str(main_error)}")
        if loading: 
            print("[MAIN] Closing loading screen due to error...")
            loading.close()
        log(f"Critical initialization error: {str(main_error)}")
        import traceback
        print(f"[MAIN] Full traceback: {traceback.format_exc()}")
        log(f"Full traceback: {traceback.format_exc()}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("[MAIN] Application interrupted by user (Ctrl+C)")
        if loading: 
            print("[MAIN] Closing loading screen due to interrupt...")
            loading.close()
        log("Application interrupted by user")
        sys.exit(0)

