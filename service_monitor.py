#!/usr/bin/env python3
"""
Windows Service Monitor for Cloud Honeypot Client
=================================================

Simple, robust watchdog service that monitors main application health.
Runs as Windows Service independently from main application.

Features:
- Process monitoring with PID tracking
- Automatic restart on crashes/exits  
- Duplicate prevention (no multiple instances)
- Configurable check intervals
- Minimal resource usage
- Independent error handling
"""

import os
import sys
import time
import json
import psutil
import logging
import subprocess
import win32service
import win32serviceutil
import win32event
import servicemanager
from pathlib import Path
from typing import Optional, Dict, Any

# ===================== CONFIGURATION ===================== #

SERVICE_NAME = "HoneypotClientMonitor"
SERVICE_DISPLAY_NAME = "Cloud Honeypot Client Monitor"
SERVICE_DESCRIPTION = "Monitors and maintains Cloud Honeypot Client application"

# Monitoring settings
CHECK_INTERVAL = 30         # Check every 30 seconds
RESTART_DELAY = 5          # Wait 5 seconds before restart
MAX_RESTART_ATTEMPTS = 3   # Max restarts per hour
RESTART_WINDOW = 3600      # 1 hour window for restart counting

# File paths (relative to service directory)
CLIENT_EXE = "client.exe"
CLIENT_PYTHON = "client.py"
STATUS_FILE = "monitor_status.json"
LOG_FILE = "monitor.log"

# ===================== LOGGING SETUP ===================== #

def setup_logging():
    """Setup simple file logging"""
    log_path = Path(__file__).parent / LOG_FILE
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_path, encoding='utf-8'),
            logging.StreamHandler()  # Console for debug
        ]
    )
    return logging.getLogger(__name__)

# ===================== MONITOR CLASS ===================== #

class HoneypotMonitor:
    """Main application monitor"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.service_dir = Path(__file__).parent
        self.status_file = self.service_dir / STATUS_FILE
        self.restart_history = []
        
        # Find client executable
        self.client_path = self._find_client_executable()
        
    def _find_client_executable(self) -> Optional[Path]:
        """Find client executable (prefer .exe over .py)"""
        exe_path = self.service_dir / CLIENT_EXE
        py_path = self.service_dir / CLIENT_PYTHON
        
        if exe_path.exists():
            self.logger.info(f"Found client executable: {exe_path}")
            return exe_path
        elif py_path.exists():
            self.logger.info(f"Found client Python script: {py_path}")
            return py_path
        else:
            self.logger.error("No client executable found!")
            return None
    
    def _load_status(self) -> Dict[str, Any]:
        """Load monitor status from file"""
        try:
            if self.status_file.exists():
                with open(self.status_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load status: {e}")
        
        return {"pid": None, "last_check": 0, "restart_count": 0}
    
    def _save_status(self, status: Dict[str, Any]):
        """Save monitor status to file"""
        try:
            with open(self.status_file, 'w') as f:
                json.dump(status, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to save status: {e}")
    
    def _is_process_running(self, pid: Optional[int]) -> bool:
        """Check if process with given PID is running"""
        if not pid:
            return False
            
        try:
            process = psutil.Process(pid)
            return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _find_running_client(self) -> Optional[int]:
        """Find any running client process"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    name = proc_info['name'].lower()
                    cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                    
                    # Look for client.exe or python client.py
                    if ('client.exe' in name or 
                        ('python' in name and 'client.py' in cmdline)):
                        self.logger.info(f"Found running client: PID {proc_info['pid']}")
                        return proc_info['pid']
                        
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Error finding client process: {e}")
            
        return None
    
    def _can_restart(self) -> bool:
        """Check if we can restart (respect rate limits)"""
        now = time.time()
        
        # Clean old restart history
        self.restart_history = [t for t in self.restart_history 
                              if now - t < RESTART_WINDOW]
        
        # Check restart limit
        if len(self.restart_history) >= MAX_RESTART_ATTEMPTS:
            self.logger.warning(f"Restart limit exceeded: {len(self.restart_history)} restarts in last hour")
            return False
            
        return True
    
    def _start_client(self) -> Optional[int]:
        """Start client application"""
        if not self.client_path or not self.client_path.exists():
            self.logger.error("Client executable not found")
            return None
            
        if not self._can_restart():
            return None
            
        try:
            self.logger.info(f"Starting client: {self.client_path}")
            
            # Start process
            if self.client_path.suffix == '.py':
                # Python script
                process = subprocess.Popen([
                    sys.executable, str(self.client_path)
                ], cwd=str(self.service_dir))
            else:
                # Executable
                process = subprocess.Popen([
                    str(self.client_path)
                ], cwd=str(self.service_dir))
            
            # Record restart
            self.restart_history.append(time.time())
            
            # Wait a bit to ensure process started
            time.sleep(RESTART_DELAY)
            
            if process.poll() is None:  # Process still running
                self.logger.info(f"Client started successfully: PID {process.pid}")
                return process.pid
            else:
                self.logger.error("Client process exited immediately")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to start client: {e}")
            return None
    
    def check_and_maintain(self):
        """Main monitoring logic"""
        status = self._load_status()
        current_pid = status.get("pid")
        
        # Check if tracked process is still running
        if self._is_process_running(current_pid):
            self.logger.debug(f"Client running: PID {current_pid}")
            status["last_check"] = time.time()
            self._save_status(status)
            return
        
        # Process not running, try to find it
        found_pid = self._find_running_client()
        if found_pid:
            self.logger.info(f"Found existing client process: PID {found_pid}")
            status["pid"] = found_pid
            status["last_check"] = time.time()
            self._save_status(status)
            return
        
        # No client running, start it
        self.logger.warning("Client not running, attempting restart")
        new_pid = self._start_client()
        
        if new_pid:
            status["pid"] = new_pid
            status["restart_count"] = status.get("restart_count", 0) + 1
        else:
            status["pid"] = None
            
        status["last_check"] = time.time()
        self._save_status(status)

# ===================== WINDOWS SERVICE ===================== #

class HoneypotMonitorService(win32serviceutil.ServiceFramework):
    """Windows Service wrapper"""
    
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.logger = setup_logging()
        self.monitor = HoneypotMonitor(self.logger)
        self.running = False
    
    def SvcStop(self):
        """Service stop handler"""
        self.logger.info("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.hWaitStop)
    
    def SvcDoRun(self):
        """Main service execution"""
        self.logger.info("Honeypot Monitor Service starting")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        self.running = True
        
        try:
            # Main monitoring loop
            while self.running:
                try:
                    self.monitor.check_and_maintain()
                except Exception as e:
                    self.logger.error(f"Monitor error: {e}")
                
                # Wait for stop event or timeout
                if win32event.WaitForSingleObject(self.hWaitStop, CHECK_INTERVAL * 1000) == win32event.WAIT_OBJECT_0:
                    break
                    
        except Exception as e:
            self.logger.error(f"Service error: {e}")
        
        self.logger.info("Honeypot Monitor Service stopped")

# ===================== MAIN ENTRY POINT ===================== #

def main():
    """Main entry point for service management"""
    if len(sys.argv) == 1:
        # No arguments, run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(HoneypotMonitorService)
        servicemanager.StartServiceCtrlDispatcher()
    elif len(sys.argv) == 2 and sys.argv[1].lower() == 'debug':
        # Debug mode - run in console
        logger = setup_logging()
        monitor = HoneypotMonitor(logger)
        
        logger.info("Running in DEBUG mode (Ctrl+C to stop)")
        try:
            while True:
                monitor.check_and_maintain()
                time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Debug mode stopped by user")
    else:
        # Command line arguments for service management
        win32serviceutil.HandleCommandLine(HoneypotMonitorService)

if __name__ == "__main__":
    main()