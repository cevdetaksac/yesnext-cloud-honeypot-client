#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Helper Functions
Yardımcı fonksiyonlar ve genel amaçlı utilities

Version: See client_constants.VERSION

Features:
- Public IP caching with 5-minute TTL (reduces HTTP calls)
- Token obfuscation and security helpers
- GUI message utilities
- Hash and checksum functions

Performance Notes:
- get_public_ip() now caches results for 60 seconds
- Use force_refresh=True to bypass cache when needed
"""

import os
import sys
import time
import socket
import threading
import requests
import tkinter as tk
from typing import Dict, Optional
import logging

# Import required modules
from client_utils import SystemUtils

# Global logger reference - will be set by main application
LOGGER: Optional[logging.Logger] = None

# IP Cache for performance optimization
# Short TTL so laptop Wi‑Fi / network switches report WAN IP quickly via update-ip
_ip_cache = {
    'ip': None,
    'last_check': 0,
    'cache_duration': 60  # 1 minute (was 300s)
}

def get_windows_session_id() -> int:
    """Return current process Windows session id, or -1 on failure."""
    try:
        import ctypes
        from ctypes import wintypes
        sid = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(
            ctypes.windll.kernel32.GetCurrentProcessId(),
            ctypes.byref(sid),
        ):
            return int(sid.value)
    except Exception:
        pass
    return -1


def is_session_zero() -> bool:
    """True when running in Session 0 (services / SYSTEM) — GUI is invisible to users."""
    return get_windows_session_id() == 0


def has_interactive_user_session(query_stdout: Optional[str] = None) -> bool:
    """True if any Active console/RDP session with id > 0 exists (not services/Session 0)."""
    try:
        import subprocess
        stdout = query_stdout
        if stdout is None:
            result = subprocess.run(
                ["query", "session"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                return False
            stdout = result.stdout or ""
        for line in stdout.splitlines()[1:]:
            if "Active" not in line:
                continue
            low = line.lower()
            if "services" in low:
                continue
            parts = line.split()
            try:
                # SESSIONNAME USERNAME ID STATE … — ID sits immediately before Active
                idx = next(i for i, p in enumerate(parts) if p == "Active")
                sid = int(parts[idx - 1])
                if sid > 0:
                    return True
            except (StopIteration, ValueError, IndexError):
                if "console" in low or "rdp" in low:
                    return True
        return False
    except Exception:
        return False


def interactive_frontend_running() -> bool:
    """True if honeypot-client is already running in a user session (session id > 0)."""
    try:
        import ctypes
        import psutil
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if "honeypot-client" not in name and "client.py" not in cmdline:
                    continue
                if "--watchdog" in cmdline or "--silent-update" in cmdline:
                    continue
                sid = wintypes.DWORD()
                if kernel32.ProcessIdToSessionId(int(proc.info["pid"]), ctypes.byref(sid)):
                    if int(sid.value) > 0:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
                continue
        return False
    except Exception:
        return False


def launch_interactive_tray_gui() -> bool:
    """Start CloudHoneypot-Tray in the logged-on user session (visible desktop)."""
    try:
        import subprocess
        from client_task_scheduler import TASK_NAME_TRAY
        CREATE_NO_WINDOW = 0x08000000
        if interactive_frontend_running():
            log(f"[SESSION] Interactive frontend already running — skip {TASK_NAME_TRAY}")
            return True
        # Ensure task is enabled, then run (Authenticated Users → any interactive logon)
        subprocess.run(
            ["schtasks", "/change", "/tn", TASK_NAME_TRAY, "/enable"],
            capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW,
        )
        r = subprocess.run(
            ["schtasks", "/run", "/tn", TASK_NAME_TRAY],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = r.returncode == 0
        log(f"[SESSION] Trigger {TASK_NAME_TRAY}: rc={r.returncode} ok={ok}")
        return ok
    except Exception as e:
        log(f"[SESSION] launch_interactive_tray_gui failed: {e}")
        return False


def set_logger(logger: logging.Logger) -> None:
    """Set global logger for helper functions"""
    global LOGGER
    LOGGER = logger

# ===================== GLOBAL UTILITY FUNCTIONS ===================== #

def log(msg: str) -> None:
    """Centralized logging function with error handling"""
    try:
        if LOGGER:
            LOGGER.info(str(msg))
        else:
            print(f"[LOG] {msg}")  # Fallback to print if logger not set
    except Exception as e:
        if LOGGER:
            LOGGER.error(f"Log error: {e}")
        else:
            print(f"[LOG ERROR] {e}")

def run_cmd(cmd, timeout: int = 20, suppress_rc_log: bool = False):
    """Execute system commands using modular SystemUtils"""
    return SystemUtils.run_cmd(cmd, timeout, suppress_rc_log, log)

def is_port_in_use(port: int) -> bool:
    """Check if a TCP port is currently in use (native socket — no subprocess)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex(("127.0.0.1", int(port)))
            return result == 0  # 0 = connected = port in use
    except Exception:
        return False

# ===================== HELPER FUNCTIONS CLASS ===================== #

class ClientHelpers:
    """Container class for client helper functions"""
    
    @staticmethod
    def current_executable() -> str:
        """Get current executable path"""
        return sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])

    @staticmethod
    def get_public_ip(force_refresh: bool = False, *, allow_network: bool = True) -> str:
        """Get public IP address with caching for performance.

        allow_network=False: never block (GUI startup) — return cache or "".
        """
        global _ip_cache
        current_time = time.time()
        
        # Return cached IP if still valid and not forcing refresh
        if not force_refresh and _ip_cache['ip'] and \
           (current_time - _ip_cache['last_check']) < _ip_cache['cache_duration']:
            return _ip_cache['ip']

        if not allow_network:
            return _ip_cache['ip'] if _ip_cache['ip'] else ""
        
        # Fetch new IP
        try:
            ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
            _ip_cache['ip'] = ip
            _ip_cache['last_check'] = current_time
            return ip
        except Exception as e:
            log(f"get_public_ip error: {e}")
            # Return cached IP if available, otherwise fallback
            return _ip_cache['ip'] if _ip_cache['ip'] else "0.0.0.0"

    @staticmethod
    def safe_set_entry(entry, text: str):
        """Safely update entry widget text (supports both tk.Entry and CTkEntry)"""
        try:
            # CTkEntry requires configure to toggle state
            if hasattr(entry, 'configure'):
                try:
                    entry.configure(state="normal")
                except Exception:
                    pass
            entry.delete(0, "end")
            entry.insert(0, str(text) if text else "")
            if hasattr(entry, 'configure'):
                try:
                    entry.configure(state="disabled")
                except Exception:
                    pass
        except Exception as e:
            log(f"Entry update error: {e}")

    @staticmethod
    def set_primary_button(button: tk.Button, text: str, cmd, color: str):
        """Update primary button properties"""
        if button:
            try:
                button.config(text=text, command=cmd, bg=color)
            except Exception as e:
                log(f"Button update error: {e}")

    @staticmethod
    def is_app_running() -> bool:
        """Check if main app is currently running"""
        try:
            import psutil
            current_pid = os.getpid()
            
            # Check for other instances of this app
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['pid'] == current_pid:
                        continue  # Skip current process
                    
                    # Check if it's our executable
                    if proc.info['name'] and 'honeypot-client' in proc.info['name'].lower():
                        return True
                    
                    # Check command line for python script
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        if 'client.py' in cmdline and '--watchdog' not in cmdline:
                            return True
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return False
            
        except ImportError:
            log("psutil not available, checking via process name")
            # Fallback to simpler check
            try:
                import subprocess
                result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq honeypot-client.exe'], 
                                      capture_output=True, text=True, shell=True)
                return 'honeypot-client.exe' in result.stdout
            except Exception as e:
                log(f"Process check error: {e}")
                return False
        except Exception as e:
            log(f"is_app_running error: {e}")
            return False

    @staticmethod
    def is_daemon_running() -> bool:
        """Check if daemon mode is currently running"""
        try:
            import psutil
            current_pid = os.getpid()
            
            # Check for daemon instances of this app
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['pid'] == current_pid:
                        continue  # Skip current process
                    
                    # Check command line for daemon mode
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        if ('client.py' in cmdline or 'honeypot-client' in cmdline.lower()) and '--mode=daemon' in cmdline:
                            return True
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return False
            
        except ImportError:
            log("psutil not available, using mutex check for daemon")
            # Check if daemon mutex exists
            try:
                import tempfile
                daemon_mutex_file = os.path.join(tempfile.gettempdir(), "CloudHoneypotClient_daemon.lock")
                return os.path.exists(daemon_mutex_file)
            except Exception as e:
                log(f"Daemon check error: {e}")
                return False
        except Exception as e:
            log(f"is_daemon_running error: {e}")
            return False


# ===================== BOUNDED BACKGROUND TASKS ===================== #
# Prevents thread explosion from fire-and-forget API reports / retries.

_bg_pool = None
_bg_sem = None
_bg_lock = threading.Lock()
_BG_MAX_WORKERS = 8
_BG_MAX_PENDING = 64


def submit_background(fn, *args, **kwargs) -> bool:
    """Run fn in a bounded thread pool. Returns False if queue saturated (task dropped)."""
    import threading as _threading
    from concurrent.futures import ThreadPoolExecutor

    global _bg_pool, _bg_sem
    with _bg_lock:
        if _bg_pool is None:
            _bg_pool = ThreadPoolExecutor(
                max_workers=_BG_MAX_WORKERS, thread_name_prefix="HP-BG"
            )
            _bg_sem = _threading.Semaphore(_BG_MAX_PENDING)

    if not _bg_sem.acquire(blocking=False):
        try:
            log("[BG] background queue full — dropping task")
        except Exception:
            pass
        return False

    def _wrap():
        try:
            fn(*args, **kwargs)
        except Exception as e:
            try:
                log(f"[BG] background task error: {e}")
            except Exception:
                pass
        finally:
            _bg_sem.release()

    try:
        _bg_pool.submit(_wrap)
        return True
    except Exception:
        _bg_sem.release()
        return False
