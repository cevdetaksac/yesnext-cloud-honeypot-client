#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Helper Functions
Yardımcı fonksiyonlar ve genel amaçlı utilities

Version: 2.8.5 (Performance Optimized)

Features:
- Public IP caching with 5-minute TTL (reduces HTTP calls)
- Token obfuscation and security helpers
- GUI message utilities
- Hash and checksum functions

Performance Notes (v2.8.5):
- get_public_ip() now caches results for 300 seconds
- Use force_refresh=True to bypass cache when needed
"""

import os
import sys
import time
import requests
import tkinter as tk
from typing import Dict, Optional
import logging

# Import required modules
from client_utils import SystemUtils

# Global logger reference - will be set by main application
LOGGER: Optional[logging.Logger] = None

# IP Cache for performance optimization
_ip_cache = {
    'ip': None,
    'last_check': 0,
    'cache_duration': 300  # 5 minutes cache (was checking every 60s)
}

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

# ===================== HELPER FUNCTIONS CLASS ===================== #

class ClientHelpers:
    """Container class for client helper functions"""
    
    @staticmethod
    def current_executable() -> str:
        """Get current executable path"""
        return sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])

    @staticmethod
    def get_public_ip(force_refresh: bool = False) -> str:
        """Get public IP address with caching for performance
        
        Args:
            force_refresh: If True, bypass cache and fetch fresh IP
            
        Returns:
            Public IP address string
        """
        global _ip_cache
        current_time = time.time()
        
        # Return cached IP if still valid and not forcing refresh
        if not force_refresh and _ip_cache['ip'] and \
           (current_time - _ip_cache['last_check']) < _ip_cache['cache_duration']:
            return _ip_cache['ip']
        
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
    def safe_set_entry(entry: tk.Entry, text: str):
        """Safely update entry widget text"""
        try:
            entry.delete(0, tk.END)
            entry.insert(0, str(text) if text else "")
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
