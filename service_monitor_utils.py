#!/usr/bin/env python3
"""
Service Monitor Utilities
========================

Utilities for interacting with the Honeypot Monitor Service.
Main application can use these to communicate with the service.
"""

import os
import json
import time
import psutil
from pathlib import Path
from typing import Optional, Dict, Any

# Service configuration
SERVICE_DIR = Path(__file__).parent
STATUS_FILE = SERVICE_DIR / "monitor_status.json"
LOG_FILE = SERVICE_DIR / "monitor.log"

class MonitorUtils:
    """Utilities for monitor service interaction"""
    
    @staticmethod
    def is_monitor_running() -> bool:
        """Check if monitor service is running"""
        try:
            import win32serviceutil
            status = win32serviceutil.QueryServiceStatus("HoneypotClientMonitor")
            return status[1] == 4  # SERVICE_RUNNING
        except Exception:
            return False
    
    @staticmethod
    def get_monitor_status() -> Optional[Dict[str, Any]]:
        """Get current monitor status"""
        try:
            if STATUS_FILE.exists():
                with open(STATUS_FILE, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return None
    
    @staticmethod
    def register_pid(pid: Optional[int] = None):
        """Register current process PID with monitor"""
        if pid is None:
            pid = os.getpid()
            
        try:
            status = MonitorUtils.get_monitor_status() or {}
            status["pid"] = pid
            status["registered_at"] = time.time()
            
            with open(STATUS_FILE, 'w') as f:
                json.dump(status, f, indent=2)
                
        except Exception:
            pass  # Fail silently - monitor service handles detection
    
    @staticmethod
    def is_monitored() -> bool:
        """Check if current process is being monitored"""
        status = MonitorUtils.get_monitor_status()
        if not status:
            return False
            
        monitored_pid = status.get("pid")
        current_pid = os.getpid()
        
        return monitored_pid == current_pid
    
    @staticmethod
    def get_recent_logs(lines: int = 10) -> list:
        """Get recent monitor log lines"""
        try:
            if LOG_FILE.exists():
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    return f.readlines()[-lines:]
        except Exception:
            pass
        return []

# ===================== INTEGRATION HELPERS ===================== #

def notify_monitor_startup():
    """Call this when main application starts"""
    MonitorUtils.register_pid()

def check_monitor_health() -> Dict[str, Any]:
    """Get comprehensive monitor health info"""
    return {
        "monitor_service_running": MonitorUtils.is_monitor_running(),
        "current_process_monitored": MonitorUtils.is_monitored(),
        "monitor_status": MonitorUtils.get_monitor_status(),
        "recent_restarts": len([l for l in MonitorUtils.get_recent_logs(50) 
                               if "started successfully" in l])
    }

if __name__ == "__main__":
    # CLI tool for monitor status
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "health":
        health = check_monitor_health()
        print("Monitor Service Health Check:")
        print("=" * 40)
        for key, value in health.items():
            print(f"{key}: {value}")
    else:
        print("Usage: python service_monitor_utils.py health")