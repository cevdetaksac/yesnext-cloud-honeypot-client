#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Constants and Configuration
Tum uygulama sabitlerinin merkezi yonetimi

Version: Defined as VERSION constant below (single source of truth)

Key Intervals (optimized for performance):
- FILE_HEARTBEAT_INTERVAL: 60s (server heartbeat interval)
- API_HEARTBEAT_INTERVAL: 60s (server heartbeat)
- ATTACK_COUNT_REFRESH: 15s (GUI attack counter)
- SERVICE_SYNC_INTERVAL: 45s (honeypot service sync with dashboard)
- BLOCK_POLL_INTERVAL: 30s (firewall block rule polling)
- PORT_REPORT_INTERVAL: 300s (open port reporting)

Notes:
- Intervals are tuned to reduce CPU/network usage
- All intervals can be overridden in client_config.json
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
VERSION = "4.1.5"  # API block rules: fetch dashboard rules, threshold-based auto-blocking
CLIENT_VERSION = VERSION  # Main version constant
__version__ = VERSION  # Export for compatibility
APP_NAME = get_from_config("application.name", "Cloud Honeypot Client")

# GitHub repository information
GITHUB_OWNER = "cevdetaksac"
GITHUB_REPO = "yesnext-cloud-honeypot-client"

# ===================== NETWORK CONFIGURATION ===================== #

# API Configuration
API_URL = get_from_config("api.base_url", "https://honeypot.yesnext.com.tr/api")

# Local control server for single instance
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 58632

# Network settings
SERVER_NAME = socket.gethostname()
CONNECT_TIMEOUT = 8

# ===================== SECURITY CONFIGURATION ===================== #

# Admin elevation control - TEST MODE
SKIP_ADMIN_ELEVATION = False  # Set to True to disable admin elevation for testing
TEST_MODE = False  # Set to True for enhanced debugging and no admin requirements
FORCE_NO_EXIT = True  # Prevent any early exits during testing

# RDP secure port configuration
RDP_SECURE_PORT = get_from_config("services.rdp_port", 53389)

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

# ===================== HONEYPOT SERVICE CONFIGURATION ===================== #

# Service definitions — each honeypot service the client can run locally
HONEYPOT_SERVICES = {
    "RDP":   {"port": 3389, "protocol": "tcp", "description": "Remote Desktop Protocol"},
    "SSH":   {"port": 22,   "protocol": "tcp", "description": "Secure Shell"},
    "FTP":   {"port": 21,   "protocol": "tcp", "description": "File Transfer Protocol"},
    "MYSQL": {"port": 3306, "protocol": "tcp", "description": "MySQL Database"},
    "MSSQL": {"port": 1433, "protocol": "tcp", "description": "Microsoft SQL Server"},
}

# Honeypot service banners (realistic decoys)
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
FTP_BANNER = "220 (vsFTPd 3.0.5)"
MYSQL_VERSION = "5.7.38-0ubuntu0.22.04.2"
MSSQL_VERSION = "Microsoft SQL Server 2019 (RTM-CU18)"
RDP_CERT_CN = "WIN-HONEYPOT"

# Credential capture limits (anti-abuse / rate limiting)
MAX_CREDENTIAL_LENGTH = 256           # Max length for captured username/password
MAX_ATTEMPTS_PER_IP_PER_MIN = 10      # Rate limit: max reports per IP+service per minute
CREDENTIAL_BATCH_SIZE = 10            # Send credentials in batches of this size
CREDENTIAL_BATCH_INTERVAL = 5         # Seconds between batch sends
HONEYPOT_AUTO_RESTART_MAX = 3         # Max auto-restart attempts for crashed services
HONEYPOT_RESTART_BACKOFF = [5, 15, 60]  # Seconds: exponential backoff for restarts

def get_default_services():
    """Get default service configuration from config file"""
    config = get_app_config()
    services_cfg = config.get("services", {}).get("honeypots", [])
    services = {}
    for svc_cfg in services_cfg:
        service = svc_cfg["service"].upper()
        services[service] = {"listen_port": svc_cfg["port"]}
    return services

def get_service_table():
    """Get service table for GUI display"""
    config = get_app_config()
    services_cfg = config.get("services", {}).get("honeypots", [])
    table = []
    for svc_cfg in services_cfg:
        port = str(svc_cfg["port"])
        service = svc_cfg["service"]
        table.append((port, service))
    return table

# Service configurations (loaded from config)
DEFAULT_SERVICES = get_default_services()
SERVICE_TABLE = get_service_table()

# ===================== WINDOWS INTEGRATION ===================== #

# Registry
APP_STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# ===================== APPLICATION MODES ===================== #

# Operation modes
GUI_MODE = "gui"        # Normal GUI application with tray functionality
DAEMON_MODE = "daemon"  # Background-only mode for servers

# ===================== HEARTBEAT CONFIGURATION ===================== #

HEARTBEAT_FILE = "heartbeat.json"
FILE_HEARTBEAT_INTERVAL = 60  # File heartbeat interval (was 10s, optimized to 60s for performance)

# Singleton mutex name
SINGLETON_MUTEX_NAME = "Global\\CloudHoneypotClient_Singleton"

# ===================== TIMING CONFIGURATION ===================== #

# API and sync intervals (in seconds)
API_RETRY_INTERVAL = 60              # API connection retry interval
API_HEARTBEAT_INTERVAL = 60          # API heartbeat send interval
ATTACK_COUNT_REFRESH = 15            # Attack count refresh interval
SERVICE_SYNC_INTERVAL = 45           # Service sync with dashboard (was DASHBOARD_SYNC_INTERVAL)
SERVICE_SYNC_CHECK = 10              # Service sync check frequency (was DASHBOARD_SYNC_CHECK)
BLOCK_POLL_INTERVAL = 30             # Firewall block rule polling interval
PORT_REPORT_INTERVAL = 300           # Open port reporting interval
API_STARTUP_DELAY = 5                # API startup delay
RDP_TRANSITION_TIMEOUT = 120         # RDP transition timeout
SERVICE_WATCHDOG_INTERVAL = 15       # Service watchdog check interval (was WATCHDOG_INTERVAL)

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

# ===================== FEATURE FLAGS ===================== #

# Feature toggles from configuration
ENABLE_AUTO_UPDATE = get_from_config("advanced.auto_update", True)
ENABLE_TRAY_ICON = get_from_config("advanced.minimize_to_tray", True)
ENABLE_ADMIN_ELEVATION = get_from_config("advanced.request_admin_privileges", True)

# Debug and development flags
DEBUG_MODE = get_from_config("debug.enabled", False)
VERBOSE_LOGGING = get_from_config("debug.verbose_logging", False)

# Production deployment flags
SILENT_ADMIN_ELEVATION = get_from_config("deployment.silent_admin", True)  # Auto-elevate without asking
SKIP_USER_DIALOGS = get_from_config("deployment.skip_dialogs", False)  # Skip all user confirmations

# ===================== THREAT DETECTION (v4.0) ===================== #

# Enable/disable threat detection engine
ENABLE_THREAT_DETECTION = get_from_config("threat_detection.enabled", True)

# EventLog Watcher — refresh & watchdog intervals
EVENTLOG_WATCHDOG_INTERVAL = 60           # Check subscription health every 60s

# Threat Engine — scoring & correlation
THREAT_SCORE_DECAY_INTERVAL = 300         # Decay scores every 5 min
THREAT_CONTEXT_MAX_AGE = 86400            # Remove IP context after 24h inactivity
THREAT_ALERT_MIN_SCORE = 31              # Minimum score to generate an alert

# Alert Pipeline — batch & rate limiting
ALERT_BATCH_FLUSH_INTERVAL = 60           # Flush batch buffer every 60s
ALERT_BATCH_MAX_SIZE = 50                 # Force flush at 50 buffered events
ALERT_THREAT_LOG_FILE = "threats.log"     # Local threat log filename
ALERT_THREAT_LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
ALERT_THREAT_LOG_BACKUP_COUNT = 3

# Dashboard refresh for threat data
THREAT_DASHBOARD_REFRESH = 5000           # ms — refresh threat cards every 5s

# Auto-Response Engine — rate limits & safety
AUTO_RESPONSE_MAX_BLOCKS_PER_HOUR = 50    # Max firewall blocks per hour
AUTO_RESPONSE_MAX_BLOCKS_PER_DAY = 200    # Max firewall blocks per day
AUTO_RESPONSE_DEFAULT_BLOCK_HOURS = 24    # Default block duration (hours)

# Remote Command Executor — polling & security
REMOTE_CMD_POLL_INTERVAL = 5              # Poll API every 5 seconds
REMOTE_CMD_EXPIRY_SECONDS = 300           # Commands expire after 5 minutes
REMOTE_CMD_MAX_PER_MINUTE = 10            # Rate limit: max 10 commands/minute

# Silent Hours — defaults
SILENT_HOURS_ENABLED = get_from_config("silent_hours.enabled", True)
SILENT_HOURS_DEFAULT_MODE = "night_only"  # night_only | outside_working | always | custom
SILENT_HOURS_NIGHT_START = "00:00"
SILENT_HOURS_NIGHT_END = "07:00"
SILENT_HOURS_WORK_START = "08:00"
SILENT_HOURS_WORK_END = "18:00"
SILENT_HOURS_WEEKEND_SILENT = True        # All-day silent on weekends

# Config sync — pull threat/silent hours config from backend
THREAT_CONFIG_SYNC_INTERVAL = 120         # Re-fetch config every 2 minutes

# Ransomware Shield — canary & detection intervals
RANSOMWARE_CANARY_CHECK_INTERVAL = 10     # Check canary files every 10s
RANSOMWARE_PROCESS_CHECK_INTERVAL = 5     # Check suspicious processes every 5s
RANSOMWARE_VSS_CHECK_INTERVAL = 120       # Check VSS shadow copies every 2min
ENABLE_RANSOMWARE_SHIELD = get_from_config("ransomware_shield.enabled", True)

# System Health Monitor — collection & reporting
HEALTH_COLLECT_INTERVAL = 10              # Collect metrics every 10s
HEALTH_REPORT_INTERVAL = 300              # Report to API every 5 min
HEALTH_ANOMALY_Z_THRESHOLD = 3.0          # Z-score threshold for anomaly

# Self-Protection — last breath & DACL
ENABLE_SELF_PROTECTION = get_from_config("self_protection.enabled", True)
LAST_BREATH_THREAT_WINDOW = 60            # Consider threats within 60s
LAST_BREATH_MIN_SCORE = 70                # Min threat score to trigger block

# Performance Optimizer — adaptive throttling (v4.0 Faz 4)
PERF_ADAPTIVE_CHECK_INTERVAL = 30         # Re-evaluate resource usage every 30s
PERF_CPU_HIGH_THRESHOLD = 85              # Start throttling above 85% CPU
PERF_CPU_CRITICAL_THRESHOLD = 95          # Aggressive throttling above 95%
PERF_MAX_EVENTS_PER_SECOND = 50           # Event processing rate limit
ENABLE_PERFORMANCE_OPTIMIZER = get_from_config("performance_optimizer.enabled", True)

# False Positive Tuner — cooldown & whitelist learning (v4.0 Faz 4)
FP_AUTO_WHITELIST_MIN_EVENTS = 50         # Min events before auto-whitelist
FP_AUTO_WHITELIST_MAX_SCORE = 10          # Max score for auto-whitelist
FP_COOLDOWN_CLEANUP_INTERVAL = 3600       # Clean stale cooldowns every hour
ENABLE_FALSE_POSITIVE_TUNER = get_from_config("false_positive_tuner.enabled", True)

# Threat Summary — periodic fetch (v4.0 Faz 4)
THREAT_SUMMARY_FETCH_INTERVAL = 300       # Fetch threat summary every 5 min

# ===================== EXPORT ALL CONSTANTS ===================== #

# For easy importing: from client_constants import *
__all__ = [
    # Application metadata
    '__version__', 'APP_NAME', 'GITHUB_OWNER', 'GITHUB_REPO',
    
    # Network configuration  
    'API_URL', 'CONTROL_HOST', 'CONTROL_PORT', 'SERVER_NAME', 'CONNECT_TIMEOUT',
    
    # Honeypot service definitions
    'HONEYPOT_SERVICES', 'SSH_BANNER', 'FTP_BANNER', 'MYSQL_VERSION', 'MSSQL_VERSION', 'RDP_CERT_CN',
    'MAX_CREDENTIAL_LENGTH', 'MAX_ATTEMPTS_PER_IP_PER_MIN',
    'CREDENTIAL_BATCH_SIZE', 'CREDENTIAL_BATCH_INTERVAL',
    'HONEYPOT_AUTO_RESTART_MAX', 'HONEYPOT_RESTART_BACKOFF',
    
    # Service configuration (loaded from config)
    'DEFAULT_SERVICES', 'SERVICE_TABLE',
    
    # Security
    'RDP_SECURE_PORT', 'DEFENDER_MARKERS', 'SECURITY_METADATA', 'LEGITIMATE_DOMAINS', 'RESTRICTED_PATHS',
    
    # File paths
    'APP_DIR', 'LOG_FILE', 'CONSENT_FILE', 'STATUS_FILE', 'WATCHDOG_TOKEN_FILE', 'TASK_STATE_FILE',
    
    # GUI configuration
    'WINDOW_WIDTH', 'WINDOW_HEIGHT', 'WINDOW_TITLE', 'TRY_TRAY',
    
    # Windows integration
    'APP_STARTUP_KEY', 'REGISTRY_KEY_PATH',
    
    # Timing
    'API_RETRY_INTERVAL', 'API_HEARTBEAT_INTERVAL', 'FILE_HEARTBEAT_INTERVAL',
    'ATTACK_COUNT_REFRESH',
    'SERVICE_SYNC_INTERVAL', 'SERVICE_SYNC_CHECK', 'SERVICE_WATCHDOG_INTERVAL',
    'BLOCK_POLL_INTERVAL', 'PORT_REPORT_INTERVAL',
    'API_STARTUP_DELAY', 'RDP_TRANSITION_TIMEOUT',
    
    # Logging
    'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT', 'LOG_ENCODING', 'LOG_TIME_FORMAT',
    
    # API settings
    'API_MAX_QUICK_RETRIES', 'API_QUICK_RETRY_DELAY', 'API_SLOW_RETRY_DELAY', 'API_REQUEST_TIMEOUT',
    
    # Feature flags
    'ENABLE_AUTO_UPDATE', 'ENABLE_TRAY_ICON', 'ENABLE_ADMIN_ELEVATION',
    'DEBUG_MODE', 'VERBOSE_LOGGING', 'SILENT_ADMIN_ELEVATION', 'SKIP_USER_DIALOGS',
    
    # Threat detection (v4.0)
    'ENABLE_THREAT_DETECTION',
    'EVENTLOG_WATCHDOG_INTERVAL',
    'THREAT_SCORE_DECAY_INTERVAL', 'THREAT_CONTEXT_MAX_AGE', 'THREAT_ALERT_MIN_SCORE',
    'ALERT_BATCH_FLUSH_INTERVAL', 'ALERT_BATCH_MAX_SIZE',
    'ALERT_THREAT_LOG_FILE', 'ALERT_THREAT_LOG_MAX_BYTES', 'ALERT_THREAT_LOG_BACKUP_COUNT',
    'THREAT_DASHBOARD_REFRESH',

    # Auto-response & remote commands (v4.0 Faz 2)
    'AUTO_RESPONSE_MAX_BLOCKS_PER_HOUR', 'AUTO_RESPONSE_MAX_BLOCKS_PER_DAY',
    'AUTO_RESPONSE_DEFAULT_BLOCK_HOURS',
    'REMOTE_CMD_POLL_INTERVAL', 'REMOTE_CMD_EXPIRY_SECONDS', 'REMOTE_CMD_MAX_PER_MINUTE',
    'SILENT_HOURS_ENABLED', 'SILENT_HOURS_DEFAULT_MODE',
    'SILENT_HOURS_NIGHT_START', 'SILENT_HOURS_NIGHT_END',
    'SILENT_HOURS_WORK_START', 'SILENT_HOURS_WORK_END',
    'SILENT_HOURS_WEEKEND_SILENT',
    'THREAT_CONFIG_SYNC_INTERVAL',

    # Ransomware shield & system health & self-protection (v4.0 Faz 3)
    'RANSOMWARE_CANARY_CHECK_INTERVAL', 'RANSOMWARE_PROCESS_CHECK_INTERVAL',
    'RANSOMWARE_VSS_CHECK_INTERVAL', 'ENABLE_RANSOMWARE_SHIELD',
    'HEALTH_COLLECT_INTERVAL', 'HEALTH_REPORT_INTERVAL', 'HEALTH_ANOMALY_Z_THRESHOLD',
    'ENABLE_SELF_PROTECTION', 'LAST_BREATH_THREAT_WINDOW', 'LAST_BREATH_MIN_SCORE',

    # Performance optimizer & false positive tuner (v4.0 Faz 4)
    'PERF_ADAPTIVE_CHECK_INTERVAL', 'PERF_CPU_HIGH_THRESHOLD', 'PERF_CPU_CRITICAL_THRESHOLD',
    'PERF_MAX_EVENTS_PER_SECOND', 'ENABLE_PERFORMANCE_OPTIMIZER',
    'FP_AUTO_WHITELIST_MIN_EVENTS', 'FP_AUTO_WHITELIST_MAX_SCORE',
    'FP_COOLDOWN_CLEANUP_INTERVAL', 'ENABLE_FALSE_POSITIVE_TUNER',
    'THREAT_SUMMARY_FETCH_INTERVAL',
    
    # Helper functions
    'get_app_config', 'get_app_directory', 'get_window_dimensions',
    'get_default_services', 'get_service_table',
]
