# -*- coding: utf-8 -*-
"""
Daemon IPC — GUI frontend talks to Session-0 SYSTEM motor.

Protocol (newline-terminated, UTF-8):
  PING
  STATUS
  HONEYPOT START <SERVICE> <PORT>
  HONEYPOT STOP <SERVICE>
  HONEYPOT LIST
  SHOW / QUIT  (legacy; daemon replies NOGUI to SHOW)

JSON replies are a single line starting with '{' .
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from typing import Any, Dict, Optional

try:
    from client_constants import CONTROL_HOST, CONTROL_PORT
except Exception:
    CONTROL_HOST = "127.0.0.1"
    CONTROL_PORT = 58632


def _recv_line(sock: socket.socket, timeout: float = 3.0) -> str:
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf and len(buf) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n", 1)[0].decode("utf-8", "ignore").strip()


def request(cmd: str, timeout: float = 3.0) -> str:
    """Send one command line; return raw reply line (may be JSON)."""
    line = (cmd or "").strip()
    if not line.endswith("\n"):
        line += "\n"
    with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=timeout) as sock:
        sock.sendall(line.encode("utf-8"))
        return _recv_line(sock, timeout=timeout)


def request_json(cmd: str, timeout: float = 3.0) -> Dict[str, Any]:
    raw = request(cmd, timeout=timeout)
    if not raw:
        return {"ok": False, "error": "empty_reply"}
    if raw.startswith("{"):
        try:
            return json.loads(raw)
        except Exception as e:
            return {"ok": False, "error": f"bad_json: {e}", "raw": raw}
    # legacy text
    return {"ok": True, "reply": raw}


def ping(timeout: float = 1.5) -> bool:
    try:
        r = request("PING", timeout=timeout)
        return r.upper().startswith("PONG") or (
            r.startswith("{") and json.loads(r).get("ok") is True
        )
    except Exception:
        return False


def get_status(timeout: float = 3.0) -> Dict[str, Any]:
    try:
        return request_json("STATUS", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "daemon": False}


def honeypot_start(service: str, port: int, timeout: float = 8.0) -> Dict[str, Any]:
    svc = str(service).upper().strip()
    try:
        return request_json(f"HONEYPOT START {svc} {int(port)}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def honeypot_stop(service: str, timeout: float = 8.0) -> Dict[str, Any]:
    svc = str(service).upper().strip()
    try:
        return request_json(f"HONEYPOT STOP {svc}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def honeypot_list(timeout: float = 3.0) -> Dict[str, Any]:
    try:
        return request_json("HONEYPOT LIST", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "services": []}


def ensure_daemon_running(log_func=None, wait_sec: float = 20.0) -> bool:
    """If motor not answering, start --mode=daemon and wait for PING."""
    if log_func is None:
        log_func = print
    if ping():
        return True

    try:
        from client_helpers import ClientHelpers
        if ClientHelpers.is_daemon_running():
            log_func("[IPC] Daemon process present — waiting for control port...")
            deadline = time.time() + wait_sec
            while time.time() < deadline:
                if ping():
                    return True
                time.sleep(0.5)
    except Exception:
        pass

    log_func("[IPC] Starting SYSTEM daemon motor...")
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            args = [exe, "--mode=daemon", "--silent"]
        else:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.py")
            args = [sys.executable, script, "--mode=daemon", "--silent"]
        flags = 0
        if os.name == "nt":
            flags = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
        subprocess.Popen(args, creationflags=flags, close_fds=True)
    except Exception as e:
        log_func(f"[IPC] Failed to spawn daemon: {e}")
        return False

    deadline = time.time() + wait_sec
    while time.time() < deadline:
        if ping():
            log_func("[IPC] Daemon motor ready")
            return True
        time.sleep(0.5)
    log_func("[IPC] Daemon did not answer PING in time")
    return False
