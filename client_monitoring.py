#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLIENT MONITORING MODULE
========================

SYSTEM HEALTH & HEARTBEAT MANAGEMENT
=====================================
Version: See client_constants.VERSION

Performance Notes:
- FILE_HEARTBEAT_INTERVAL increased to 60s (was 10s)
- Reduced file I/O by 83%
- Health checks now at 60s intervals

🔍 MODULE PURPOSE:
This module provides comprehensive system monitoring capabilities for the 
Cloud Honeypot Client, including real-time health checks, heartbeat monitoring,
and application lifecycle tracking.

📋 CORE RESPONSIBILITIES:
┌─────────────────────────────────────────────────────────────────┐
│                    MONITORING FUNCTIONS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  💓 HEARTBEAT SYSTEM                                            │
│  ├─ create_heartbeat_file()   → Initialize heartbeat tracking  │
│  ├─ update_heartbeat_file()   → Update system status           │
│  ├─ heartbeat_worker()        → Background monitoring thread   │
│  └─ cleanup_heartbeat_file()  → Graceful system shutdown       │
│                                                                 │
│  🔍 HEALTH MONITORING                                           │
│  ├─ perform_health_check()    → System health validation       │
│  └─ Health status reporting   → External monitoring support    │
│                                                                 │
│  🏗️ MANAGEMENT CLASS                                            │
│  └─ MonitoringManager         → Centralized monitoring control │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

🚀 KEY FEATURES:
├─ Real-time System Status: JSON-based heartbeat with timestamps
├─ Health Check Automation: Periodic health validation (exit codes)
├─ Process Lifecycle Tracking: PID, startup, shutdown monitoring
├─ Admin Privilege Detection: Security context awareness  
├─ API Connection Status: External service connectivity
├─ Active Tunnel Monitoring: Real-time tunnel count tracking
└─ External Monitoring Support: Standard exit codes for automation

📝 HEARTBEAT DATA STRUCTURE:
{
  "application": "Cloud Honeypot Client",
  "version": "2.x.x",
  "pid": 1234,
  "executable": "/path/to/executable",
  "started_at": "2025-09-27T16:00:00",
  "last_heartbeat": "2025-09-27T16:05:30",
  "status": "running|initializing|stopped",
  "admin_privileges": true|false,
  "active_tunnels": 3,
  "api_connected": true|false
}

🔧 USAGE PATTERNS:
# Initialize monitoring system
monitoring_manager = MonitoringManager(app_dir)
if monitoring_manager.start_heartbeat_system(app_instance):
    heartbeat_path = monitoring_manager.get_heartbeat_path()

# Perform health check (CLI usage)
perform_health_check()  # Exits with appropriate code

🚨 EXIT CODES:
├─ 0: Health check passed
├─ 3: Health check failed (stale heartbeat, system issues)
└─ Standard Python exit codes for other errors

🔄 INTEGRATION:
- Used by: Main application (client.py)
- Depends on: client_constants.py, client_helpers.py
- Thread-safe: Yes (background heartbeat worker)
- External monitoring: Compatible with standard monitoring tools

📈 PERFORMANCE:
- Heartbeat interval: 10 seconds (configurable)
- Health check timeout: 60 seconds for stale detection
- Memory footprint: Minimal (<1MB additional)
- I/O operations: Optimized JSON read/write
"""

import os
import sys
import json
import time
import threading
import datetime as dt
import ctypes
import tempfile
from typing import Optional, Dict, Any

from client_constants import HEARTBEAT_FILE, FILE_HEARTBEAT_INTERVAL, __version__
from client_helpers import log

# ===================== HEARTBEAT SYSTEM ===================== #

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

def _atomic_write_json(filepath: str, data: dict):
    """Atomik JSON yazma — temp dosyaya yaz, sonra rename et"""
    dir_name = os.path.dirname(filepath)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, filepath)  # atomic on same filesystem
    except Exception:
        try: os.unlink(tmp_path)
        except OSError: pass
        raise

def update_heartbeat_file(heartbeat_path: str, app_instance=None) -> bool:
    """Update heartbeat file with current timestamp and status (atomic write)"""
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
        
        # Atomic write — çökme anında dosya bozulmaz
        _atomic_write_json(heartbeat_path, heartbeat_data)
        
        return True
    except Exception as e:
        log(f"Heartbeat güncelleme hatası: {e}")
        return False

def heartbeat_worker(heartbeat_path: str, app_instance=None):
    """Background worker for heartbeat updates"""
    log(f"Heartbeat worker başlatıldı (her {FILE_HEARTBEAT_INTERVAL} saniye)")
    
    while True:
        try:
            if update_heartbeat_file(heartbeat_path, app_instance):
                pass  # Successful update, no logging needed to avoid spam
            else:
                log("Heartbeat güncellenemedi")
            
            time.sleep(FILE_HEARTBEAT_INTERVAL)
        except Exception as e:
            log(f"Heartbeat worker hatası: {e}")
            time.sleep(FILE_HEARTBEAT_INTERVAL)

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

# ===================== HEALTH CHECK SYSTEM ===================== #

def perform_health_check():
    """Perform health check and return status"""
    try:
        log("=== HEALTH CHECK STARTED ===")
        
        # Check if process is running
        pid = os.getpid()
        log(f"Current PID: {pid}")
        
        # Check heartbeat file if exists
        import sys
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

class MonitoringManager:
    """Central monitoring manager for heartbeat and health checks"""
    
    def __init__(self, app_dir: str):
        self.app_dir = app_dir
        self.heartbeat_path = None
        self.heartbeat_thread = None
        
    def start_heartbeat_system(self, app_instance=None):
        """Start heartbeat monitoring system"""
        try:
            self.heartbeat_path = create_heartbeat_file(self.app_dir)
            if self.heartbeat_path:
                # Start heartbeat worker thread
                self.heartbeat_thread = threading.Thread(
                    target=heartbeat_worker, 
                    args=(self.heartbeat_path, app_instance),
                    daemon=True,
                    name="HeartbeatWorker"
                )
                self.heartbeat_thread.start()
                log("Heartbeat monitoring başlatıldı")
                return True
        except Exception as e:
            log(f"Heartbeat sistem başlatma hatası: {e}")
        return False
    
    def stop_heartbeat_system(self):
        """Stop heartbeat monitoring system"""
        try:
            if self.heartbeat_path:
                cleanup_heartbeat_file(self.heartbeat_path)
            log("Heartbeat monitoring durduruldu")
        except Exception as e:
            log(f"Heartbeat sistem durdurma hatası: {e}")
    
    def get_heartbeat_path(self) -> str:
        """Get current heartbeat file path"""
        return self.heartbeat_path or ""