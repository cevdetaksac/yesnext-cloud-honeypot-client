#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Instance Management — Singleton control & process management.

Ensures only one Cloud Honeypot Client instance runs at a time using
Windows named mutexes. Handles graceful shutdown of existing instances.

Key exports:
  check_singleton(mode)         — Acquire global mutex, shutdown conflicts
  shutdown_existing_instance()  — Find & terminate running instances
  InstanceManager               — OOP wrapper around singleton logic
"""

import os
import time
import win32event
import win32api
import winerror
import psutil

from client_constants import SINGLETON_MUTEX_NAME
from client_helpers import log

# ===================== SINGLETON SYSTEM ===================== #

def check_singleton(mode: str) -> bool:
    """Check if another instance is running and handle accordingly"""
    try:
        # Try to create mutex
        mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()
        
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            log(f"Another instance detected - attempting graceful shutdown")
            
            # Close the duplicate handle before retrying
            try:
                win32api.CloseHandle(mutex)
            except Exception:
                pass
            
            # Try to find and gracefully shutdown existing process
            if shutdown_existing_instance():
                log("Existing instance shutdown successfully - waiting before starting new instance")
                time.sleep(3)
                
                # Try mutex again after shutdown
                mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
                last_error = win32api.GetLastError()
                
                if last_error == winerror.ERROR_ALREADY_EXISTS:
                    log("ERROR: Could not acquire singleton mutex after shutdown attempt")
                    try:
                        win32api.CloseHandle(mutex)
                    except Exception:
                        pass
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

class InstanceManager:
    """Singleton instance management"""
    
    def __init__(self):
        self.mutex_handle = None
        
    def acquire_singleton(self, mode: str) -> bool:
        """Acquire singleton mutex for the application"""
        return check_singleton(mode)
        
    def release_singleton(self):
        """Release singleton mutex"""
        try:
            if self.mutex_handle:
                win32api.CloseHandle(self.mutex_handle)
                self.mutex_handle = None
                log("Singleton mutex released")
        except Exception as e:
            log(f"Error releasing singleton mutex: {e}")