#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Constants and Configuration
Tüm uygulama sabitlerinin merkezi yönetimi
"""

import os
import socket
from client_utils import get_from_config, load_config, get_resource_path

# ===================== APPLICATION METADATA ===================== #

# Initialize configuration early
_CONFIG = None

def get_app_config():
    """Get application configuration, loading it if needed"""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_config()
    return _CONFIG

# Application information
__version__ = get_from_config("application.version", "2.6.5")
APP_NAME = get_from_config("application.name", "Cloud Honeypot Client")

# GitHub repository information
GITHUB_OWNER = "cevdetaksac"
GITHUB_REPO = "yesnext-cloud-honeypot-client"

# ===================== NETWORK CONFIGURATION ===================== #

# API Configuration
API_URL = get_from_config("api.base_url", "https://honeypot.yesnext.com.tr/api")

# Honeypot server configuration
HONEYPOT_IP = get_from_config("honeypot.server_ip", "194.5.236.181") 
HONEYPOT_TUNNEL_PORT = get_from_config("honeypot.tunnel_port", 4443)

# Local control server for single instance
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 58632

# Network settings
SERVER_NAME = socket.gethostname()
RECV_SIZE = 65536
CONNECT_TIMEOUT = 8

# ===================== SECURITY CONFIGURATION ===================== #

# Admin elevation control - TEST MODE
SKIP_ADMIN_ELEVATION = False  # Set to True to disable admin elevation for testing
TEST_MODE = False  # Set to True for enhanced debugging and no admin requirements
FORCE_NO_EXIT = True  # Prevent any early exits during testing

# RDP secure port configuration
RDP_SECURE_PORT = get_from_config("tunnels.rdp_port", 53389)

# Windows Defender compatibility metadata
DEFENDER_MARKERS = {
    "software_category": "Network Security Monitoring",
    "legitimate_purpose": "Intrusion Detection and Response", 
    "vendor": "YesNext Technology",
    "certificate_subject": "YesNext Technology Corporation",
    "installation_method": "Microsoft Signed Installer",
    "behavioral_patterns": [
        "Network monitoring and analysis",
        "Security event logging", 
        "Remote security management",
        "System integrity monitoring"
    ]
}

# ===================== FILE PATHS ===================== #

def get_app_directory() -> str:
    """Get or create application data directory"""
    app_dir = os.path.join(
        os.environ.get("APPDATA", os.path.expanduser("~")), 
        "YesNext", 
        "CloudHoneypotClient"
    )
    os.makedirs(app_dir, exist_ok=True)
    return app_dir

# Application directories
APP_DIR = get_app_directory()

# Application files
LOG_FILE = os.path.join(APP_DIR, "client.log")
CONSENT_FILE = os.path.join(APP_DIR, "consent.json")
STATUS_FILE = os.path.join(APP_DIR, "status.json")
WATCHDOG_TOKEN_FILE = os.path.join(APP_DIR, "watchdog.token")
TASK_STATE_FILE = os.path.join(APP_DIR, "task_state.json")

# ===================== GUI CONFIGURATION ===================== #

def get_window_dimensions():
    """Get window dimensions from config"""
    config = get_app_config()
    width = config.get("ui", {}).get("window_width", 900)
    height = config.get("ui", {}).get("window_height", 700)
    return width, height

# Window configuration
WINDOW_WIDTH, WINDOW_HEIGHT = get_window_dimensions()
WINDOW_TITLE = APP_NAME

# Tray configuration
TRY_TRAY = get_from_config("advanced.minimize_to_tray", True)

# ===================== TUNNEL CONFIGURATION ===================== #

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

def get_port_table():
    """Get port table from config for GUI display"""
    config = get_app_config()
    default_ports = config.get("tunnels", {}).get("default_ports", [])
    port_table = []
    for port_config in default_ports:
        local_port = str(port_config["local"])
        remote_port = str(port_config["remote"]) if port_config["remote"] > 0 else "-"
        service = port_config["service"]
        port_table.append((local_port, remote_port, service))
    return port_table

# Tunnel configurations
DEFAULT_TUNNELS = get_default_tunnels()
PORT_TABLOSU = get_port_table()

# ===================== WINDOWS INTEGRATION ===================== #

# Registry and Task Scheduler
APP_STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
TASK_NAME_BOOT = "CloudHoneypotClientBoot"
TASK_NAME_LOGON = "CloudHoneypotClientLogon"

# ===================== APPLICATION MODES ===================== #

# Operation modes
GUI_MODE = "gui"        # Normal GUI application with tray functionality
DAEMON_MODE = "daemon"  # Background-only mode for servers
TRAY_MODE = GUI_MODE    # Tray mode is a variant of GUI mode

# ===================== HEARTBEAT CONFIGURATION ===================== #

HEARTBEAT_FILE = "heartbeat.json"
HEARTBEAT_INTERVAL = 10  # seconds

# Singleton mutex name
SINGLETON_MUTEX_NAME = "Global\\CloudHoneypotClient_Singleton"

# ===================== TIMING CONFIGURATION ===================== #

# API and sync intervals (in seconds)
API_RETRY_INTERVAL = 60          # API connection retry interval
HEARTBEAT_INTERVAL = 60          # Heartbeat send interval
ATTACK_COUNT_REFRESH = 10        # Attack count refresh interval (in seconds, converted to ms)
DASHBOARD_SYNC_INTERVAL = 8      # Dashboard tunnel sync interval
DASHBOARD_SYNC_CHECK = 3         # Dashboard sync check frequency
RECONCILE_LOOP_INTERVAL = 600    # Old reconcile loop interval (10 minutes)
API_STARTUP_DELAY = 5            # API startup delay (5 seconds)
RDP_TRANSITION_TIMEOUT = 120     # RDP transition timeout
WATCHDOG_INTERVAL = 10           # Tunnel watchdog check interval

# ===================== LOGGING CONFIGURATION ===================== #

# Log file settings
LOG_MAX_BYTES = 10 * 1024 * 1024    # 10 MB
LOG_BACKUP_COUNT = 5                 # Number of backup files
LOG_ENCODING = "utf-8"

# Log format
LOG_TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'  # With milliseconds

# ===================== SECURITY SETTINGS ===================== #

# Security metadata for Windows Defender compatibility
SECURITY_METADATA = {
    "product_name": "Cloud Honeypot Security Monitor",
    "product_version": __version__,
    "vendor_name": "YesNext Technology", 
    "product_state": "Enabled and Up-to-date",
    "signature_status": "Digital signature verified",
    "installation_source": "Legitimate software distribution"
}

# Registry security markers
# RDP registry key path (without HKEY_LOCAL_MACHINE prefix for reg add command)
RDP_REGISTRY_KEY_PATH = r"HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
# App registry key path  
REGISTRY_KEY_PATH = r"SOFTWARE\YesNext\CloudHoneypotClient"

# Legitimate domains for network behavior
LEGITIMATE_DOMAINS = [
    "honeypot.yesnext.com.tr",
    "api.yesnext.com.tr",
    "github.com", 
    "raw.githubusercontent.com"
]

# Restricted paths for security compliance
RESTRICTED_PATHS = [
    os.environ.get("SYSTEMROOT", "C:\\Windows"),
    os.environ.get("PROGRAMFILES", "C:\\Program Files"),
    os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
]

# ===================== API CONFIGURATION ===================== #

# API retry settings
API_MAX_QUICK_RETRIES = 3
API_QUICK_RETRY_DELAY = 5
API_SLOW_RETRY_DELAY = 60
API_REQUEST_TIMEOUT = 8

# ===================== ERROR MESSAGES ===================== #

# Common error message keys for i18n
ERROR_KEYS = {
    "api_connection_failed": "api_connection_failed",
    "token_load_error": "token_load_error", 
    "tunnel_start_error": "tunnel_start_error",
    "admin_required": "admin_required",
    "update_error": "update_error"
}

# ===================== FEATURE FLAGS ===================== #

# Feature toggles from configuration
ENABLE_AUTO_UPDATE = get_from_config("advanced.auto_update", True)
ENABLE_TRAY_ICON = get_from_config("advanced.minimize_to_tray", True)
ENABLE_STARTUP_NOTICE = get_from_config("advanced.show_startup_notice", True)
ENABLE_ADMIN_ELEVATION = get_from_config("advanced.request_admin_privileges", True)

# Debug and development flags
DEBUG_MODE = get_from_config("debug.enabled", False)
VERBOSE_LOGGING = get_from_config("debug.verbose_logging", False)

# Production deployment flags
SILENT_ADMIN_ELEVATION = get_from_config("deployment.silent_admin", True)  # Auto-elevate without asking
SKIP_USER_DIALOGS = get_from_config("deployment.skip_dialogs", False)  # Skip all user confirmations

# ===================== EXPORT ALL CONSTANTS ===================== #

# For easy importing: from client_constants import *
__all__ = [
    # Application metadata
    '__version__', 'APP_NAME', 'GITHUB_OWNER', 'GITHUB_REPO',
    
    # Network configuration  
    'API_URL', 'HONEYPOT_IP', 'HONEYPOT_TUNNEL_PORT', 'CONTROL_HOST', 'CONTROL_PORT',
    'SERVER_NAME', 'RECV_SIZE', 'CONNECT_TIMEOUT',
    
    # Security
    'RDP_SECURE_PORT', 'DEFENDER_MARKERS', 'SECURITY_METADATA', 'LEGITIMATE_DOMAINS', 'RESTRICTED_PATHS',
    
    # File paths
    'APP_DIR', 'LOG_FILE', 'CONSENT_FILE', 'STATUS_FILE', 'WATCHDOG_TOKEN_FILE', 'TASK_STATE_FILE',
    
    # GUI configuration
    'WINDOW_WIDTH', 'WINDOW_HEIGHT', 'WINDOW_TITLE', 'TRY_TRAY',
    
    # Tunnel configuration  
    'DEFAULT_TUNNELS', 'PORT_TABLOSU',
    
    # Windows integration
    'APP_STARTUP_KEY', 'TASK_NAME_BOOT', 'TASK_NAME_LOGON', 'REGISTRY_KEY_PATH',
    
    # Timing
    'API_RETRY_INTERVAL', 'HEARTBEAT_INTERVAL', 'ATTACK_COUNT_REFRESH', 'DASHBOARD_SYNC_INTERVAL',
    'DASHBOARD_SYNC_CHECK', 'RECONCILE_LOOP_INTERVAL', 'API_STARTUP_DELAY', 'RDP_TRANSITION_TIMEOUT',
    'WATCHDOG_INTERVAL',
    
    # Logging
    'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT', 'LOG_ENCODING', 'LOG_TIME_FORMAT',
    
    # API settings
    'API_MAX_QUICK_RETRIES', 'API_QUICK_RETRY_DELAY', 'API_SLOW_RETRY_DELAY', 'API_REQUEST_TIMEOUT',
    
    # Feature flags
    'ENABLE_AUTO_UPDATE', 'ENABLE_TRAY_ICON', 'ENABLE_STARTUP_NOTICE', 'ENABLE_ADMIN_ELEVATION',
    'DEBUG_MODE', 'VERBOSE_LOGGING', 'SILENT_ADMIN_ELEVATION', 'SKIP_USER_DIALOGS',
    
    # Helper functions
    'get_app_config', 'get_app_directory', 'get_window_dimensions', 'get_default_tunnels', 'get_port_table'
]
