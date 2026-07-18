#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Instance Management — Singleton control & process management.

Ensures only one Cloud Honeypot Client instance runs at a time using
Windows named mutexes. Handles graceful shutdown of existing instances.

Key exports:
  check_singleton(mode)         — Acquire global mutex, shutdown conflicts
  try_acquire_mutex_soft()      — Acquire without killing (tray must not steal GUI)
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

# Keep mutex handle alive for process lifetime
_MUTEX_HANDLE = None


def try_acquire_mutex_soft() -> bool:
    """Acquire singleton mutex without killing others. False if already taken."""
    global _MUTEX_HANDLE
    try:
        mutex = win32event.CreateMutex(None, False, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            try:
                win32api.CloseHandle(mutex)
            except Exception:
                pass
            return False
        _MUTEX_HANDLE = mutex
        return True
    except Exception as e:
        log(f"ERROR: Soft mutex acquire failed: {e}")
        return False


def mutex_already_held() -> bool:
    """True if another honeypot-client instance owns the singleton mutex."""
    try:
        mutex = win32event.CreateMutex(None, False, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()
        try:
            win32api.CloseHandle(mutex)
        except Exception:
            pass
        return last_error == winerror.ERROR_ALREADY_EXISTS
    except Exception:
        return False


# ===================== SINGLETON SYSTEM ===================== #

def check_singleton(mode: str, *, allow_steal: bool = True) -> bool:
    """Check if another instance is running and handle accordingly.

    allow_steal=False: if mutex taken, return False without killing (tray mode).
    allow_steal=True: try graceful shutdown of existing, then take mutex (GUI / --show-gui).
    """
    global _MUTEX_HANDLE
    try:
        mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()

        if last_error == winerror.ERROR_ALREADY_EXISTS:
            try:
                win32api.CloseHandle(mutex)
            except Exception:
                pass

            if not allow_steal:
                log(f"Singleton held — soft mode will not steal ({mode})")
                return False

            log("Another instance detected - attempting graceful shutdown")

            if shutdown_existing_instance():
                log("Existing instance shutdown successfully - waiting before starting new instance")
                time.sleep(3)

                mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
                last_error = win32api.GetLastError()

                if last_error == winerror.ERROR_ALREADY_EXISTS:
                    log("ERROR: Could not acquire singleton mutex after shutdown attempt")
                    try:
                        win32api.CloseHandle(mutex)
                    except Exception:
                        pass
                    return False
                _MUTEX_HANDLE = mutex
            else:
                log("ERROR: Failed to shutdown existing instance")
                return False
        else:
            _MUTEX_HANDLE = mutex

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

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if (proc.info['name'].lower() in ['honeypot-client.exe', 'client.exe'] and
                proc.info['pid'] != current_pid):
                processes_found.append(proc)

        if not processes_found:
            log("No existing instances found")
            return True

        log(f"Found {len(processes_found)} existing processes to shutdown")

        # Prefer QUIT via control socket (bypasses DACL)
        try:
            import socket
            with socket.create_connection(("127.0.0.1", 58632), timeout=0.8) as sock:
                sock.sendall(b"QUIT\n")
            time.sleep(1.5)
        except Exception:
            pass

        for proc in list(processes_found):
            try:
                if not proc.is_running():
                    continue
                log(f"Gracefully terminating PID {proc.info['pid']}")
                proc.terminate()
                proc.wait(timeout=5)
                log(f"Successfully terminated PID {proc.info['pid']}")
            except psutil.TimeoutExpired:
                try:
                    log(f"Force killing PID {proc.info['pid']}")
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            except Exception as e:
                log(f"Terminate PID {proc.info.get('pid')} failed: {e}")

        time.sleep(0.5)
        still = [
            p for p in psutil.process_iter(['pid', 'name'])
            if p.info['name'] and p.info['name'].lower() in ['honeypot-client.exe', 'client.exe']
            and p.info['pid'] != current_pid
        ]
        if still:
            log(f"WARNING: {len(still)} process(es) still running after shutdown")
            return False
        return True

    except Exception as e:
        log(f"ERROR: shutdown_existing_instance failed: {e}")
        return False


class InstanceManager:
    """OOP wrapper around singleton helpers."""

    def acquire(self, mode: str = "gui", allow_steal: bool = True) -> bool:
        return check_singleton(mode, allow_steal=allow_steal)
