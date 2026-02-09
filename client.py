#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud Honeypot Client — main application orchestrator.

Coordinates GUI/tray display, API communication, honeypot service management,
RDP operations, and background health monitoring. Runs in two modes:

  GUI mode  — Tkinter window + system tray, update watchdog thread (1 hr)
  Daemon    — Headless via Task Scheduler, auto-updates every 2 hrs

Modules:
  client_api                     — API layer
  client_honeypots               — Honeypot service implementations (FTP, SSH, MySQL, MSSQL, RDP)
  client_service_manager         — Central service lifecycle manager
  client_rdp / client_firewall   — RDP port mgmt, firewall rules
  client_monitoring / client_security — Health checks, Defender compat
  client_updater / client_tray   — Auto-update, system tray
  client_instance / client_logging — Singleton control, log setup
  client_tokens / client_task_scheduler — Auth tokens, scheduled tasks
  client_memory_restart          — Memory-threshold restart
  client_helpers / client_utils / client_constants — Shared utilities

Exit codes: 0 normal, 1 critical error, 2 another instance running, 3 health-check fail.
"""

# Standard library imports
import os, sys, socket, threading, time, json, subprocess, ctypes, argparse
import tkinter as tk
from tkinter import messagebox
from typing import Optional, Dict, Any, Union
import webbrowser, logging

import customtkinter as ctk

# Local module imports  
from client_firewall import FirewallAgent
from client_helpers import log, ClientHelpers, run_cmd
import client_helpers
from client_service_manager import ServiceManager
from client_api import HoneypotAPIClient, api_request_with_token
from client_helpers import is_port_in_use
from client_tokens import create_token_manager, get_token_file_paths
from client_task_scheduler import perform_comprehensive_task_management
from client_utils import (ServiceController, load_i18n, install_excepthook, 
                         load_config, get_config_value, set_config_value,
                         get_from_config, start_watchdog_if_needed, get_port_table,
                         update_language_config, watchdog_main, ensure_firewall_allow_for_port)

# Import constants from central configuration
from client_constants import (
    GUI_MODE, DAEMON_MODE, API_URL, APP_DIR, LOG_FILE,
    TRY_TRAY, RDP_SECURE_PORT,
    SERVER_NAME, HONEYPOT_SERVICES,
    API_STARTUP_DELAY, API_RETRY_INTERVAL, API_SLOW_RETRY_DELAY,
    API_HEARTBEAT_INTERVAL, ATTACK_COUNT_REFRESH,
    CONSENT_FILE, STATUS_FILE,
    WATCHDOG_TOKEN_FILE, __version__, GITHUB_OWNER, GITHUB_REPO,
    WINDOW_WIDTH, WINDOW_HEIGHT, CONTROL_HOST, CONTROL_PORT,
    ENABLE_THREAT_DETECTION
)

# Import RDP management module
from client_rdp import RDPManager, RDPPopupManager

# Import new modular components
from client_monitoring import MonitoringManager, perform_health_check
from client_instance import check_singleton
from client_logging import LoggingManager, setup_logging
from client_security import SecurityManager
from client_updater import UpdateManager
from client_tray import TrayManager
from client_gui import ModernGUI

# Import threat detection modules (v4.0)
from client_eventlog import EventLogWatcher
from client_threat_engine import ThreatEngine
from client_alerts import AlertPipeline

# Import Faz 2 modules (v4.0)
from client_auto_response import AutoResponse
from client_remote_commands import RemoteCommandExecutor
from client_silent_hours import SilentHoursGuard

# Import Faz 3 modules (v4.0)
from client_ransomware_shield import RansomwareShield
from client_system_health import SystemHealthMonitor
from client_self_protection import ProcessProtection

# Import Faz 4 modules (v4.0)
from client_performance import PerformanceOptimizer, FalsePositiveTuner

try:
    from client_memory_restart import enable_simple_memory_restart, get_current_memory_mb, check_previous_restart_state
    MEMORY_RESTART_AVAILABLE = True
except ImportError:
    MEMORY_RESTART_AVAILABLE = False
    # Define dummy functions to prevent errors
    def enable_simple_memory_restart(*args, **kwargs): pass
    def get_current_memory_mb(): return 0
    def check_previous_restart_state(): return None

def get_operation_mode(args) -> str:
    """Determine operation mode from arguments."""
    if getattr(args, 'mode', None) == "daemon" or getattr(args, 'daemon', False):
        return DAEMON_MODE
    elif getattr(args, 'mode', None) == "watchdog" or getattr(args, 'watchdog', False):
        return "watchdog"
    else:
        return GUI_MODE

# Global logger
LOGGER = None

# Initialize logging through modular system
logging_manager = LoggingManager()
if logging_manager.initialize():
    LOGGER = logging_manager.get_logger()

I18N = load_i18n()


class CloudHoneypotClient:
    # Port mappings loaded from configuration
    @property
    def PORT_TABLOSU(self):
        """Get port table from configuration file"""
        if not hasattr(self, '_port_table_cache'): self._port_table_cache = get_port_table()
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
        
        # Initialize security system
        try:
            log("Initializing security systems...")
            self.security_manager.initialize()
            log("Security systems initialized successfully")
        except Exception as e:
            log(f"Security initialization warning: {e}")
        
        # Load configuration directly - pure config-driven architecture
        self.config = load_config()
        
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
        
        if LOGGER: client_helpers.set_logger(LOGGER)
        self.reconciliation_lock = threading.Lock()
        self.rdp_transition_complete = threading.Event()
        
        # Initialize application state FIRST
        self.state = {
            "running": False, "token": None,
            "public_ip": None, "tray": None, "selected_rows": [],
            "selected_ports_map": None, "ctrl_sock": None,
        }
        
        # Initialize RDP Management modules
        self.rdp_manager = RDPManager(main_app=self)
        self.rdp_popup_manager = RDPPopupManager(main_app=self, translation_func=self.t)
        
        # Initialize Service Manager — central lifecycle manager for all honeypots
        self.service_manager = ServiceManager(api_client=self.api_client, rdp_manager=self.rdp_manager)
        
        # Initialize Threat Detection Pipeline (v4.0)
        self.alert_pipeline = None
        self.threat_engine = None
        self.event_watcher = None
        if ENABLE_THREAT_DETECTION:
            try:
                self.alert_pipeline = AlertPipeline(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    machine_name=SERVER_NAME,
                )
                self.threat_engine = ThreatEngine(
                    on_alert=self.alert_pipeline.handle_alert
                )
                self.event_watcher = EventLogWatcher(
                    on_event=self.threat_engine.process_event,
                )
                log("✅ Threat detection modules initialized (v4.0)")
            except Exception as e:
                log(f"⚠️ Threat detection init failed: {e}")
                self.alert_pipeline = None
                self.threat_engine = None
                self.event_watcher = None

        # Initialize Faz 2 modules (v4.0) — Auto-Response, Remote Commands, Silent Hours
        self.auto_response = None
        self.remote_commands = None
        self.silent_hours_guard = None
        if ENABLE_THREAT_DETECTION:
            try:
                self.auto_response = AutoResponse(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                )
                self.remote_commands = RemoteCommandExecutor(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    auto_response=self.auto_response,
                )
                self.silent_hours_guard = SilentHoursGuard(
                    auto_response=self.auto_response,
                    alert_pipeline=self.alert_pipeline,
                )
                # Wire silent hours guard into threat engine
                if self.threat_engine:
                    self.threat_engine.silent_hours_guard = self.silent_hours_guard
                log("✅ Faz 2 modules initialized (AutoResponse, RemoteCmd, SilentHours)")
            except Exception as e:
                log(f"⚠️ Faz 2 init failed: {e}")
                self.auto_response = None
                self.remote_commands = None
                self.silent_hours_guard = None

        # Initialize Faz 3 modules (v4.0) — Ransomware Shield, System Health, Self-Protection
        self.ransomware_shield = None
        self.health_monitor = None
        self.process_protection = None
        if ENABLE_THREAT_DETECTION:
            try:
                from client_constants import (
                    ENABLE_RANSOMWARE_SHIELD, ENABLE_SELF_PROTECTION,
                )
                if ENABLE_RANSOMWARE_SHIELD:
                    self.ransomware_shield = RansomwareShield(
                        on_alert=self.alert_pipeline.handle_alert if self.alert_pipeline else None,
                        threat_engine=self.threat_engine,
                    )
                self.health_monitor = SystemHealthMonitor(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    threat_engine=self.threat_engine,
                )
                if ENABLE_SELF_PROTECTION:
                    self.process_protection = ProcessProtection(
                        threat_engine=self.threat_engine,
                        alert_pipeline=self.alert_pipeline,
                        api_client=self.api_client,
                        token_getter=lambda: self.state.get("token", ""),
                    )
                log("✅ Faz 3 modules initialized (RansomwareShield, HealthMonitor, SelfProtection)")
            except Exception as e:
                log(f"⚠️ Faz 3 init failed: {e}")
                self.ransomware_shield = None
                self.health_monitor = None
                self.process_protection = None

        # Initialize Faz 4 modules (v4.0) — Performance Optimizer, False Positive Tuner
        self.perf_optimizer = None
        self.fp_tuner = None
        if ENABLE_THREAT_DETECTION:
            try:
                from client_constants import (
                    ENABLE_PERFORMANCE_OPTIMIZER, ENABLE_FALSE_POSITIVE_TUNER,
                )
                if ENABLE_PERFORMANCE_OPTIMIZER:
                    self.perf_optimizer = PerformanceOptimizer()
                if ENABLE_FALSE_POSITIVE_TUNER:
                    self.fp_tuner = FalsePositiveTuner(
                        threat_engine=self.threat_engine,
                        event_watcher=getattr(self, 'event_watcher', None),
                    )
                log("✅ Faz 4 modules initialized (PerfOptimizer, FPTuner)")
            except Exception as e:
                log(f"⚠️ Faz 4 init failed: {e}")
                self.perf_optimizer = None
                self.fp_tuner = None

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
        self.root = None
        self.gui = None
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
        
        # Comprehensive Task Scheduler management
        from client_task_scheduler import perform_comprehensive_task_management
        task_result = perform_comprehensive_task_management(log_func=log, app_state=self.state)
        
        # Memory management — restart every 8 hours if threshold exceeded
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
            
            # ServiceManager daemon thread'lerini başlat (sync, watchdog, batch reporter)
            self.service_manager.start()
            log("ServiceManager başlatıldı (sync + watchdog + batch reporter)")
            
            # Start Threat Detection Pipeline (v4.0)
            if ENABLE_THREAT_DETECTION and self.event_watcher:
                try:
                    self.alert_pipeline.start()
                    self.threat_engine.start()
                    self.event_watcher.start()
                    log("🛡️ Threat detection pipeline started (EventLog → Engine → Alerts)")
                except Exception as e:
                    log(f"⚠️ Threat detection start failed: {e}")

            # Start Faz 2 modules (v4.0)
            if ENABLE_THREAT_DETECTION:
                try:
                    if self.remote_commands:
                        self.remote_commands.start()
                    if self.auto_response:
                        self.auto_response.start()
                    # Fetch initial threat/silent-hours config from backend
                    self._sync_threat_config()
                    log("🛡️ Faz 2 started (AutoResponse + RemoteCommands + SilentHours)")
                except Exception as e:
                    log(f"⚠️ Faz 2 start failed: {e}")
                # Start periodic config sync
                threading.Thread(
                    target=self._threat_config_sync_loop,
                    name="ThreatConfigSync",
                    daemon=True,
                ).start()

            # Start Faz 3 modules (v4.0)
            if ENABLE_THREAT_DETECTION:
                try:
                    if self.ransomware_shield:
                        self.ransomware_shield.start()
                    if self.health_monitor:
                        self.health_monitor.start()
                    if self.process_protection:
                        self.process_protection.setup()
                    log("🛡️ Faz 3 started (RansomwareShield + HealthMonitor + SelfProtection)")
                except Exception as e:
                    log(f"⚠️ Faz 3 start failed: {e}")

            # Start Faz 4 modules (v4.0)
            if ENABLE_THREAT_DETECTION:
                try:
                    if self.perf_optimizer:
                        self.perf_optimizer.start()
                    log("⚙️ Faz 4 started (PerfOptimizer + FPTuner)")
                except Exception as e:
                    log(f"⚠️ Faz 4 start failed: {e}")

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
            if not isinstance(lang_dict, dict): lang_dict = I18N.get("tr", {})
            result = lang_dict.get(key, key)
            return result
        except Exception as e:
            log(f"Translation error for key '{key}': {e}")
            return key  # Return key itself as fallback

    # ---------- Helper Methods ---------- #
    def require_admin_for_operation(self, operation_name: str) -> bool:
        """Check and request admin privileges for critical operations"""
        if ctypes.windll.shell32.IsUserAnAdmin(): return True
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
            if os.name != "nt" or ctypes.windll.shell32.IsUserAnAdmin(): return True
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

    # ---------- Threat Config Sync (v4.0 Faz 2) ---------- #

    def _sync_threat_config(self):
        """Fetch threat detection + silent hours config from backend."""
        try:
            token = self.state.get("token", "")
            if not token or not self.api_client:
                return
            config = self.api_client.fetch_threat_config(token)
            if config and isinstance(config, dict):
                # Update silent hours config
                sh_cfg = config.get("silent_hours")
                if sh_cfg and self.silent_hours_guard:
                    self.silent_hours_guard.update_config(sh_cfg)
                log("[CONFIG-SYNC] Threat config refreshed from backend")
        except Exception as e:
            log(f"[CONFIG-SYNC] Error: {e}")

    def _threat_config_sync_loop(self):
        """Periodically re-fetch threat config from backend."""
        from client_constants import THREAT_CONFIG_SYNC_INTERVAL
        while getattr(self, '_running', True):
            time.sleep(THREAT_CONFIG_SYNC_INTERVAL)
            try:
                self._sync_threat_config()
            except Exception:
                pass

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
        """Determine intelligent status based on program and service state"""
        # Program açık olduğu kesin (çünkü bu kod çalışıyor)
        active_services = self.service_manager.running_services
        
        if active_services: return "online"  # en az bir servis aktif
        # Program açık ama servis yok → idle
        return "idle"

    def send_heartbeat_once(self, status_override: Optional[str] = None):
        """Send single heartbeat to API with intelligent status detection (session-based)"""
        token = self.state.get("token")
        if token:
            ip = self.state.get("public_ip") or ClientHelpers.get_public_ip()
            
            if status_override is None: status_override = self.get_intelligent_status()
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
                    if ip != last_gui_ip and self.gui:
                        last_gui_ip = ip
                        self._gui_safe(lambda i=ip: self._update_identity_ip(i))
                    
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
        if not self.root: return
        try:
            self.root.winfo_exists()
            self.gui_health['update_count'] += 1
            
            # Tray icon update — only if service state changed
            if hasattr(self, 'tray_manager'):
                current_state = len(self.service_manager.running_services) > 0
                if not hasattr(self, '_last_tray_state') or current_state != self._last_tray_state:
                    self._last_tray_state = current_state
                    self.update_tray_icon()
            
            # Windows Server session check — every 5th cycle (~5 min)
            if self.gui_health['update_count'] % 5 == 0:
                self.check_windows_session_state()
            
            if self.gui_health['update_count'] > 1000: self.gui_health['update_count'] = 0
                
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

    def _update_identity_ip(self, ip: str):
        """Identity bar IP label'ını güncelle (thread-safe çağrı için)."""
        try:
            if self.gui and hasattr(self.gui, '_identity_ip_lbl'):
                self.gui._identity_ip_lbl.configure(text=f"({ip})")
        except Exception:
            pass

    def refresh_attack_count(self, async_thread=True):
        """Dashboard kartındaki saldırı sayacını günceller"""
        token = self.state.get("token")
        if not token: return
        if not self.root: return

        def worker():
            try:
                cnt = self.fetch_attack_count_sync(token)
                if cnt is None:
                    self._last_api_ok = False
                    return
                self._last_api_ok = True
                if hasattr(self, '_last_attack_count') and self._last_attack_count == cnt: return
                self._last_attack_count = cnt
            except Exception:
                self._last_api_ok = False
                
        if async_thread:
            # PERFORMANCE: Reuse existing thread if already running
            if not hasattr(self, '_attack_count_thread') or not self._attack_count_thread.is_alive():
                self._attack_count_thread = threading.Thread(target=worker, daemon=True, name="AttackCountUpdater")
                self._attack_count_thread.start()
        else:
            worker()

    def poll_attack_count(self):
        """Poll attack count with single-chain scheduling guard"""
        if hasattr(self, '_poll_chain_active') and self._poll_chain_active: return
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
        self.state["selected_rows"] = [(str(a[0]), str(a[1])) for a in active_rows]
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
            # Normalize: support both legacy 3-tuple and new 2-tuple
            norm = []
            for r in rows:
                if len(r) >= 3:
                    norm.append((str(r[0]), str(r[2])))  # skip middle element
                elif len(r) == 2:
                    norm.append((str(r[0]), str(r[1])))
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
            self.service_manager.reconciliation_paused = True
            log("RDP işlemi için uzlaştırma döngüsü duraklatıldı.")
        
        def on_confirm_wrapped():
            """Wrapper for confirmation callback with additional handling"""
            try:
                log("✅ Kullanıcı RDP geçişini onayladı, işlem tamamlanıyor...")
                
                # Callback'i çağır (servisleri başlat vs.)
                on_confirm()
                
                # Update internal state
                self.state["running"] = True
                self.sync_gui_with_service_state()
                
                log("✅ RDP geçiş süreci kullanıcı onayı ile tamamlandı")
                    
            except Exception as e:
                log(f"❌ RDP geçiş callback hatası: {e}")
            finally:
                # Resume reconciliation
                with self.reconciliation_lock:
                    self.service_manager.reconciliation_paused = False
                log("RDP işlemi tamamlandı, uzlaştırma döngüsü devam ettiriliyor.")
        
        # Use RDP popup manager from module
        self.rdp_popup_manager.show_rdp_popup(mode, on_confirm_wrapped)

    # ---------- Application Control ---------- #
    def apply_services(self, selected_rows):
        """Apply selected service configurations via ServiceManager"""
        started = 0
        clean_rows = []
        for (listen_port, service) in selected_rows:
            port = int(listen_port)
            svc = str(service).upper()
            if self.service_manager.start_service(svc, port):
                clean_rows.append((str(listen_port), str(service)))
                self._update_row_ui(str(listen_port), str(service), True)
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
        self.sync_gui_with_service_state()
        return True

    def remove_services(self):
        """Stop all running honeypot services"""
        self.service_manager.shutdown()
        self.state["running"] = False
        
        # GUI'deki tüm satırları pasif olarak güncelle
        for (p1, svc) in self.PORT_TABLOSU:
            self._update_row_ui(str(p1), str(svc), False)
        
        self.update_tray_icon()
        try:
            self.write_status(self.state.get("selected_rows", []), running=False)
        except: pass
        self.send_heartbeat_once("offline")
        
        # GUI buton durumunu güncelle
        self.sync_gui_with_service_state()
    
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
                    self.sync_gui_with_service_state()
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
                    self.sync_gui_with_service_state()
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
            # Delegate to ModernGUI if available
            if hasattr(self, 'gui') and self.gui:
                self.gui.update_rdp_button()
                self.update_tray_icon()
                return
            # Fallback: legacy row_controls
            rdp_control = self.row_controls.get(("3389", "RDP"))
            if rdp_control and "rdp_button" in rdp_control:
                rdp_btn = rdp_control["rdp_button"]
                is_protected, current_port = self.rdp_manager.get_rdp_protection_status()
                target_port = 3389 if is_protected else RDP_SECURE_PORT
                new_text = f"RDP Taşı : {target_port}"
                if is_protected:
                    rdp_btn.config(text=new_text, bg="#FF9800", fg="white")
                else:
                    rdp_btn.config(text=new_text, bg="#2196F3", fg="white")
                self.update_tray_icon()
        except Exception as e:
            log(f"❌ RDP buton güncelleme hatası: {e}")

    def _restore_saved_services(self):
        """Önceki oturumda çalışan servisleri otomatik geri yükle."""
        try:
            cons = self.read_consent()
            if not cons.get("accepted"):
                log("[RESTORE] Kullanıcı onayı yok, servisler geri yüklenmeyecek.")
                self.state["running"] = False
                self.state["selected_rows"] = []
                return

            saved_rows, saved_running = self.read_status()
            if not saved_rows or not saved_running:
                log("[RESTORE] Kaydedilmiş aktif servis yok, temiz başlangıç.")
                self.state["running"] = False
                self.state["selected_rows"] = []
                return

            log(f"[RESTORE] Önceki oturumdan {len(saved_rows)} servis geri yükleniyor: {saved_rows}")

            def _restore_worker():
                """Servisleri arka plan thread'inde başlat (GUI donmasın)."""
                try:
                    started = 0
                    for (listen_port, service) in saved_rows:
                        port = int(listen_port)
                        svc = str(service).upper()
                        if self.service_manager.start_service(svc, port):
                            self._update_row_ui(str(listen_port), str(service), True)
                            started += 1
                            log(f"[RESTORE] ✅ {svc}:{port} başarıyla geri yüklendi")
                        else:
                            log(f"[RESTORE] ❌ {svc}:{port} başlatılamadı")

                    if started > 0:
                        self.state["running"] = True
                        self.state["selected_rows"] = [(str(a[0]), str(a[1])) for a in saved_rows]
                        self.write_status(saved_rows, running=True)
                        self.send_heartbeat_once("online")
                        log(f"[RESTORE] {started}/{len(saved_rows)} servis geri yüklendi")
                    else:
                        self.state["running"] = False
                        self.state["selected_rows"] = []
                        self.write_status([], running=False)
                        log("[RESTORE] Hiçbir servis başlatılamadı")

                    # GUI senkronizasyonu (thread-safe)
                    self._gui_safe(lambda: self.sync_gui_with_service_state())
                except Exception as e:
                    log(f"[RESTORE] Servis geri yükleme hatası: {e}")

            threading.Thread(target=_restore_worker, daemon=True, name="ServiceRestorer").start()

        except Exception as e:
            log(f"[RESTORE] Hata: {e}")
            self.state["running"] = False
            self.state["selected_rows"] = []

    def sync_gui_with_service_state(self):
        """GUI buton durumunu gerçek servis durumu ile senkronize et"""
        try:
            self.update_rdp_button()
            self.update_tray_icon()
            # Update header badge
            if hasattr(self, 'gui') and self.gui:
                any_active = len(self.service_manager.running_services) > 0
                self.gui.update_header_status(any_active)
        except Exception as e:
            log(f"[GUI_SYNC] Senkronizasyon hatası: {e}")
            import traceback
            log(f"[GUI_SYNC] Traceback: {traceback.format_exc()}")

    # ---------- Servis Durum Yönetimi ---------- #
    def get_service_state(self) -> Dict[str, Any]:
        """ServiceManager'dan güncel servis durumlarını al."""
        return self.service_manager.get_all_statuses()

    def get_active_services(self) -> list:
        """Get list of currently active services for tray status detection"""
        return self.service_manager.running_services

    # ---------- Per-row helpers ---------- #

    def _update_row_ui(self, listen_port: str, service_name: str, active: bool):
        # Delegate to ModernGUI if available
        if hasattr(self, 'gui') and self.gui:
            self.gui.update_row_ui(listen_port, service_name, active)
            return
        # Fallback for headless / legacy
        def apply():
            try:
                key = (str(listen_port), str(service_name).upper())
                rc = getattr(self, 'row_controls', {}).get(key)
                if rc:
                    btn = rc.get("button"); fr = rc.get("frame"); st = rc.get("status")
                    log(f"[UI] Updating row UI for {key}: {'Active' if active else 'Inactive'}")
                    if active:
                        if btn: btn.config(text=self.t('btn_row_stop'), bg="#E53935")
                        if fr: fr.configure(bg="#EEF7EE")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_running')}")
                    else:
                        if btn: btn.config(text=self.t('btn_row_start'), bg="#4CAF50")
                        if fr: fr.configure(bg="#ffffff")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_stopped')}")
            except Exception:
                pass
        self._gui_safe(apply)

    def _active_rows_from_services(self):
        """Build active rows list from ServiceManager's running services"""
        rows = []
        try:
            running = self.service_manager.running_services
            for (p1, svc) in self.PORT_TABLOSU:
                if str(svc).upper() in running:
                    rows.append((str(p1), str(svc)))
        except Exception as e:
            log(f"Exception: {e}")
        return rows

    def start_single_row(self, p1: str, service: str, manual_action: bool = False) -> bool:
        """Tek bir honeypot servisini ServiceManager üzerinden başlatır.
        
        Args:
            p1: Dinleme portu
            service: Servis adı
            manual_action: Kullanıcı tarafından tetiklenip tetiklenmediği
        """
        service_upper = str(service).upper()
        listen_port = int(p1)
        
        # RDP özel durumu — port 3389 honeypot başlatmadan önce RDP'nin güvenli porta taşınması gerekir
        if service_upper == 'RDP':
            listen_port = 3389  # RDP honeypot her zaman 3389 dinler
            
            # Reconciliation'ı duraklat
            self.service_manager.reconciliation_paused = True
            
            current_rdp_port = ServiceController.get_rdp_port()
            port_in_use = is_port_in_use(3389)
            
            log(f"🔍 RDP DURUM: current_port={current_rdp_port}, secure_port={RDP_SECURE_PORT}, 3389_in_use={port_in_use}, manual_action={manual_action}")
            
            if current_rdp_port == RDP_SECURE_PORT:
                # RDP güvenli portta — 3389 boşsa honeypot başlat
                if not port_in_use:
                    log(f"✅ RDP güvenli portta ({RDP_SECURE_PORT}), 3389 boş - honeypot başlatılıyor...")
                    if self.service_manager.start_service("RDP", 3389):
                        self._on_service_started("RDP", 3389)
                        self.service_manager.reconciliation_paused = False
                        return True
                    else:
                        log("❌ RDP honeypot başlatılamadı!")
                        self.service_manager.reconciliation_paused = False
                        return False
                else:
                    # Windows Terminal Services bug workaround
                    log("⚠️ RDP Registry'de güvenli portta ama 3389 hala dolu")
                    if manual_action:
                        self._show_rdp_port_conflict_warning()
                    self.service_manager.reconciliation_paused = False
                    return False
            
            elif current_rdp_port == 3389:
                # RDP standart portta — port taşıma gerekli
                if port_in_use:
                    log("⚠️ RDP standart portta (3389) ve port dolu - taşıma gerekli")
                    if manual_action:
                        self._show_rdp_move_prompt()
                    self.service_manager.reconciliation_paused = False
                    return False
                else:
                    log("⚠️ RDP 3389'da ama port boş - beklenmeyen durum")
                    self.service_manager.reconciliation_paused = False
                    return False
            else:
                log(f"⚠️ RDP beklenmeyen portta: {current_rdp_port}")
                self.service_manager.reconciliation_paused = False
                return False
        
        # Non-RDP honeypot başlatma
        if is_port_in_use(listen_port):
            try:
                if not messagebox.askyesno(self.t("warn"), self.t("port_in_use").format(port=listen_port)):
                    return False
            except Exception as e:
                log(f"Port-in-use dialog failed for port {listen_port}: {e}")
        
        # ServiceManager üzerinden honeypot başlat
        if self.service_manager.start_service(service_upper, listen_port):
            self._on_service_started(service_upper, listen_port)
            return True
        
        try: messagebox.showerror(self.t("error"), self.t("port_busy_error"))
        except: pass
        return False

    def stop_single_row(self, p1: str, service: str, manual_action: bool = False) -> bool:
        """Tek bir honeypot servisini ServiceManager üzerinden durdurur."""
        service_upper = str(service).upper()
        listen_port = 3389 if service_upper == 'RDP' else int(p1)

        if service_upper == 'RDP':
            # RDP durdurulduğunda rollback popup göster
            self.service_manager.stop_service("RDP")
            
            if manual_action:
                def on_rdp_confirm_rollback():
                    self._on_service_stopped("RDP", 3389)
                self.rdp_move_popup(mode="rollback", on_confirm=on_rdp_confirm_rollback)
            else:
                # API-driven RDP stop
                if not self.start_rdp_transition("rollback"):
                    log("❌ API akışı: RDP 3389'a geri alınamadı.")
                self._on_service_stopped("RDP", 3389)
            return True

        # Non-RDP stop
        self.service_manager.stop_service(service_upper)
        self._on_service_stopped(service_upper, listen_port)
        return True

    def _on_service_started(self, service_name: str, port: int):
        """Servis başarıyla başlatıldığında çağrılır — GUI ve state güncelleme."""
        self.write_status(self._active_rows_from_services(), running=True)
        self.state["running"] = True
        self.update_tray_icon()
        self.send_heartbeat_once("online")
        self._update_row_ui(str(port), service_name, True)
        self.sync_gui_with_service_state()

    def _on_service_stopped(self, service_name: str, port: int):
        """Servis durdurulduğunda çağrılır — GUI ve state güncelleme."""
        running_services = self.service_manager.running_services
        self.write_status(self._active_rows_from_services(), running=len(running_services) > 0)
        if not running_services:
            self.state["running"] = False
            self.send_heartbeat_once("offline")
        self.update_tray_icon()
        self._update_row_ui(str(port), service_name, False)
        self.sync_gui_with_service_state()

    def _show_rdp_port_conflict_warning(self):
        """RDP port çakışması uyarısı göster"""
        def show_warning():
            import tkinter as tk
            from tkinter import messagebox as mb
            root = tk.Tk()
            root.withdraw()
            message = (
                f"RDP portu güvenli porta ({RDP_SECURE_PORT}) taşınmış\n"
                "ancak 3389 portunda hala bir uygulama dinliyor.\n\n"
                "Çözüm: Cihazı yeniden başlatın."
            )
            result = mb.askyesno("Port Çakışması", message, icon='warning')
            root.destroy()
            if result:
                subprocess.run(['shutdown', '/r', '/t', '30', '/c', 'RDP port çakışması için yeniden başlatılıyor...'])
        threading.Thread(target=show_warning, daemon=True).start()

    def _show_rdp_move_prompt(self):
        """RDP port taşıma uyarısı göster"""
        def show_warning():
            import tkinter as tk
            from tkinter import messagebox as mb
            root = tk.Tk()
            root.withdraw()
            message = (
                "RDP honeypot başlatmak için 3389 portu boş olmalıdır.\n"
                "Şu anda RDP servisi 3389 portunda çalışıyor.\n\n"
                f"'RDP Taşı' butonu ile portu {RDP_SECURE_PORT}'a taşıyın.\n\n"
                "RDP portunu şimdi taşımak istiyor musunuz?"
            )
            result = mb.askyesno("RDP Port Uyarısı", message, icon='warning')
            root.destroy()
            if result:
                self.toggle_rdp_protection()
        threading.Thread(target=show_warning, daemon=True).start()

    def report_service_status_once(self):
        """Güncel servis durumlarını API'ye bildirir — ServiceManager'a delege eder."""
        try:
            self.service_manager._report_statuses()
        except Exception as e:
            log(f"Servis durumu raporlanırken hata: {e}")

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
        """Check if service is running — delegates to ServiceManager"""
        status = self.service_manager.get_status(service_name)
        return status == "started"

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
            if hasattr(self, 'monitoring_manager'): self.monitoring_manager.stop_heartbeat_system()
            # Stop threat detection pipeline (v4.0)
            if getattr(self, 'event_watcher', None):
                try: self.event_watcher.stop()
                except Exception: pass
            if getattr(self, 'threat_engine', None):
                try: self.threat_engine.stop()
                except Exception: pass
            if getattr(self, 'alert_pipeline', None):
                try: self.alert_pipeline.stop()
                except Exception: pass
            # Stop Faz 4 modules (v4.0)
            if getattr(self, 'perf_optimizer', None):
                try: self.perf_optimizer.stop()
                except Exception: pass
            # Stop Faz 3 modules (v4.0)
            if getattr(self, 'ransomware_shield', None):
                try: self.ransomware_shield.stop()
                except Exception: pass
            if getattr(self, 'health_monitor', None):
                try: self.health_monitor.stop()
                except Exception: pass
            # Stop Faz 2 modules (v4.0)
            if getattr(self, 'remote_commands', None):
                try: self.remote_commands.stop()
                except Exception: pass
            if getattr(self, 'auto_response', None):
                try: self.auto_response.stop()
                except Exception: pass
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
        
        # Session monitoring for daemon-to-tray handover
        threading.Thread(target=self.monitor_user_sessions, daemon=True).start()
        # Remote management: report open ports
        try:
            threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
        except Exception as e:
            log(f"open ports reporter start failed: {e}")
        # ServiceManager (sync + watchdog + batch reporter)
        try:
            self.service_manager.start()
            log("ServiceManager başlatıldı (daemon mode)")
        except Exception as e:
            log(f"ServiceManager start failed: {e}")
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
            log("Daemon: kullanıcı onayı yok, servis uygulanmayacak.")
            return

        saved_rows, saved_running = self.read_status()
        rows = saved_rows if saved_rows else [(p1, s) for (p1, s) in self.PORT_TABLOSU]
        self.state["selected_rows"] = [(str(a[0]), str(a[1])) for a in rows]

        if not rows:
            log("Daemon: aktif port yok, beklemede.")

        while True:
            try:
                if rows and not self.state.get("running"):
                    ok = self.apply_services(rows)
                    if ok:
                        log("Daemon: Servisler aktif (arka plan).")
                time.sleep(5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Daemon loop err: {e}")
        try:
            self.remove_services()
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
            
        # Ensure root window exists (CTk)
        if not self.root:
            self.root = ctk.CTk()
            self.root.withdraw()  # Start hidden — will be configured below

        self.start_single_instance_server()

        # Background services - skip if daemon is running (UI-only mode)
        if not getattr(self, 'daemon_is_active', False):
            threading.Thread(target=self.heartbeat_loop, daemon=True).start()
            try:
                threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
            except Exception as e:
                log(f"open ports reporter start failed: {e}")
            try:
                self.start_firewall_agent()
            except Exception as e:
                log(f"firewall agent start failed (gui): {e}")
        else:
            log("🔄 UI-only mode: Skipping background threads (heartbeat, open ports, services, firewall)")
        
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

        # Language from central config
        self.lang = get_config_value("language.selected", "tr")

        # Token'ı yükle
        token = self.token_manager.load_token(self.root, self.t)
        self.state["token"] = token
        self.state["public_ip"] = ClientHelpers.get_public_ip()

        # row_controls — ModernGUI populates this
        self.row_controls = {}

        # ── Modern GUI ── #
        self.gui = ModernGUI(self)

        # Consent dialog (modern)
        try:
            self.gui.show_consent_dialog()
        except Exception as e:
            log(f"consent ui error: {e}")

        # Build the full interface
        self.gui.build(self.root, startup_mode)

        # Wire threat detection GUI toast (v4.0)
        if self.alert_pipeline and self.gui:
            self.alert_pipeline.gui_toast_func = self.gui.show_toast

        # Attack count polling
        self.poll_attack_count()
        if token:
            self.refresh_attack_count(async_thread=True)

        # Optional silent auto-update on startup if configured and no active services
        try:
            if os.environ.get('AUTO_UPDATE_SILENT') == '1':
                if not self.service_manager.running_services:
                    self.check_updates_and_apply_silent()
        except Exception as e:
            log(f"auto-update silent error: {e}")

        # Initialize tray system
        if TRY_TRAY:
            self.initialize_tray_manager()
            # Wire tray notifications to alert pipeline (v4.0)
            if self.alert_pipeline and hasattr(self, 'tray_manager') and self.tray_manager:
                self.alert_pipeline.tray_notify_func = getattr(
                    self.tray_manager, 'notify', None
                )

        # Önceki oturumdan kalan servisleri geri yükle
        self._restore_saved_services()
        try:
            self.update_tray_icon()
        except Exception as e:
            log(f"Exception: {e}")

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
    parser.add_argument("--show-gui", action="store_true", help="Force show GUI window (used by installer launch)")
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
            # --show-gui overrides tray mode (used by installer finish page)
            tray_mode = getattr(args, 'mode', None) == 'tray' and not getattr(args, 'show_gui', False)
            
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
                app.sync_gui_with_service_state()
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


