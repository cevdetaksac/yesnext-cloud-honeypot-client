#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Remote Command Executor (v4.0)

Polls the backend API for pending commands issued from the dashboard
and executes them securely on the local machine.  This is the
generalised successor of the existing pending-blocks pattern in
client_firewall.py.

Flow:
  1. Poll GET /api/commands/pending?token=X  every 5 seconds
  2. Validate command (type, expiry, protected targets)
  3. Execute via AutoResponse / subprocess
  4. Report result POST /api/commands/result

Supported commands:
  block_ip, unblock_ip, logoff_user, disable_account, enable_account,
  reset_password, kill_process, stop_service, disable_service,
  emergency_lockdown, lift_lockdown, list_sessions, list_processes,
  snapshot, collect_diagnostics

Security layers:
  - Command whitelist (ALLOWED_COMMANDS)
  - 5-minute expiry window
  - Protected accounts / processes / services
  - Rate limiting (max 10 commands/minute)

Exports:
  RemoteCommandExecutor — main class (start / stop / get_stats)
"""

import os
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

from client_helpers import log
from client_security_utils import verify_command_signature, sign_command

# ── Constants ─────────────────────────────────────────────────────

try:
    from client_constants import REMOTE_CMD_POLL_INTERVAL as _POLL
    POLL_INTERVAL = int(_POLL)
except Exception:
    POLL_INTERVAL = 10  # V4 default
COMMAND_EXPIRY_SECONDS = 300  # 5 minutes
MAX_COMMANDS_PER_MINUTE = 10

CREATE_NO_WINDOW = 0x08000000

ALLOWED_COMMANDS: Set[str] = {
    "block_ip", "unblock_ip",
    "logoff_user", "disable_account", "enable_account", "reset_password",
    "kill_process", "block_process",
    "stop_service", "start_service", "restart_service", "disable_service",
    "emergency_lockdown", "lift_lockdown",
    "enable_lockdown", "disable_lockdown",  # aliases
    "list_sessions", "list_processes", "snapshot",
    "collect_diagnostics",
    "remote_stream_start", "remote_stream_stop", "remote_input",
}

# High-frequency IR commands — skip global cmd/min rate limit
_STREAM_COMMANDS = frozenset({
    "remote_stream_start", "remote_stream_stop", "remote_input",
})

PROTECTED_ACCOUNTS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "ADMINISTRATOR", "DEFAULTACCOUNT", "GUEST",
}

PROTECTED_PROCESSES: Set[str] = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe",
    "honeypot-client.exe",
}

PROTECTED_SERVICES: Set[str] = {
    "wuauserv", "windefend", "eventlog", "mpssvc",
}

# Commands that require dashboard-side confirmation before reaching here
REQUIRES_CONFIRMATION: Set[str] = {
    "emergency_lockdown", "reset_password", "disable_account",
}


# ── Remote Command Executor ──────────────────────────────────────

class RemoteCommandExecutor:
    """
    Polls for and executes dashboard-issued remote commands.

    Usage:
        executor = RemoteCommandExecutor(
            api_client=api_client,
            token_getter=lambda: state.get("token", ""),
            auto_response=auto_response,
        )
        executor.start()
    """

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        auto_response=None,
        health_monitor=None,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.auto_response = auto_response  # AutoResponse instance
        self.health_monitor = health_monitor  # SystemHealthMonitor (wired after init)

        self._running = False
        self._poll_thread: Optional[threading.Thread] = None

        # Remote desktop screen mirror (lazy init)
        self._remote_desktop = None

        # Rate limiting
        self._cmd_timestamps: deque = deque(maxlen=MAX_COMMANDS_PER_MINUTE * 2)

        # Stats
        self._stats = {
            "commands_received": 0,
            "commands_executed": 0,
            "commands_failed": 0,
            "commands_rejected": 0,
            "commands_expired": 0,
            "poll_errors": 0,
        }

        # Command history (last 50)
        self._history: deque = deque(maxlen=50)

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        """Start the polling thread."""
        if self._running:
            return
        self._running = True
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            name="RemoteCommands-Poll",
            daemon=True,
        )
        self._poll_thread.start()
        log("[REMOTE-CMD] 🚀 Remote command executor started (poll every 5s)")

    def stop(self):
        """Stop polling and remote desktop stream."""
        self._running = False
        try:
            if self._remote_desktop:
                self._remote_desktop.stop(reason="executor_stop")
        except Exception:
            pass
        log("[REMOTE-CMD] ✅ Stopped")

    def get_stats(self) -> dict:
        return dict(self._stats)

    def get_history(self) -> List[dict]:
        return list(self._history)

    # ── Polling Loop ──────────────────────────────────────────────

    def _poll_loop(self):
        """Main polling loop — fetches and executes pending commands."""
        while self._running:
            try:
                commands = self._fetch_pending()
                for cmd in commands:
                    self._stats["commands_received"] += 1

                    # Validate
                    rejection = self._validate(cmd)
                    if rejection:
                        log(f"[REMOTE-CMD] ❌ Rejected: {cmd.get('command_type', '?')} — {rejection}")
                        self._stats["commands_rejected"] += 1
                        self._report_result(cmd, {
                            "success": False,
                            "error": rejection,
                            "status": "rejected",
                        })
                        continue

                    # Rate limit (exempt remote desktop input/stream cmds)
                    cmd_type = cmd.get("command_type", "")
                    if cmd_type not in _STREAM_COMMANDS and not self._check_rate_limit():
                        log("[REMOTE-CMD] ⚠️ Rate limit — skipping command")
                        self._stats["commands_rejected"] += 1
                        continue

                    # Execute
                    result = self._execute(cmd)

                    # Track
                    if cmd_type not in _STREAM_COMMANDS:
                        self._cmd_timestamps.append(time.time())
                    entry = {
                        "command_type": cmd.get("command_type", ""),
                        "command_id": cmd.get("command_id", ""),
                        "parameters": cmd.get("parameters") or cmd.get("params") or {},
                        "result": result,
                        "executed_at": time.time(),
                    }
                    self._history.append(entry)

                    if result.get("success"):
                        self._stats["commands_executed"] += 1
                        if cmd_type != "remote_input":
                            log(f"[REMOTE-CMD] ✅ {cmd['command_type']} — {result.get('message', 'OK')}")
                    else:
                        self._stats["commands_failed"] += 1
                        log(f"[REMOTE-CMD] ❌ {cmd['command_type']} — {result.get('error', 'Failed')}")

                    # Report
                    self._report_result(cmd, result)

            except Exception as e:
                self._stats["poll_errors"] += 1
                log(f"[REMOTE-CMD] Poll error: {e}")

            time.sleep(POLL_INTERVAL)

    # ── API Communication ─────────────────────────────────────────

    def _fetch_pending(self) -> List[dict]:
        """GET /api/commands/pending"""
        if not self.api_client:
            return []
        token = self.token_getter()
        if not token:
            return []

        try:
            resp = self.api_client.api_request(
                "GET", "commands/pending",
                token=token,
                timeout=8,
            )
            if isinstance(resp, dict):
                return resp.get("commands", [])
        except Exception as e:
            self._stats["poll_errors"] += 1
        return []

    def _report_result(self, cmd: dict, result: dict):
        """POST /api/commands/result"""
        if not self.api_client:
            return
        token = self.token_getter()
        if not token:
            return

        def _send():
            try:
                cmd_id = cmd.get("command_id", "")
                cmd_type = cmd.get("command_type", "")
                executed_at = datetime.now(timezone.utc).isoformat()
                payload = {
                    "token": token,
                    "command_id": cmd_id,
                    "status": "completed" if result.get("success") else "failed",
                    "result": result,
                    "executed_at": executed_at,
                    "execution_time_ms": result.get("execution_time_ms", 0),
                    "signature": sign_command(token, cmd_id, cmd_type, executed_at),
                }
                self.api_client.api_request("POST", "commands/result", data=payload)
            except Exception as e:
                log(f"[REMOTE-CMD] Result report error: {e}")

        threading.Thread(target=_send, daemon=True).start()

    # ── Validation ────────────────────────────────────────────────

    def _validate(self, cmd: dict) -> Optional[str]:
        """
        Validate command. Returns rejection reason or None if valid.
        """
        # 0. HMAC signature (when server provides one)
        token = self.token_getter()
        if token and cmd.get("signature") and not verify_command_signature(token, cmd):
            return "Invalid command signature"

        cmd_type = cmd.get("command_type", "")

        # 1. Known command?
        if cmd_type not in ALLOWED_COMMANDS:
            return f"Unknown command: {cmd_type}"

        # 2. Expired?  API may send issued_at, requested_at, or created_at
        issued_at = cmd.get("issued_at") or cmd.get("requested_at") or cmd.get("created_at") or ""
        if issued_at:
            try:
                issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - issued).total_seconds()
                if age > COMMAND_EXPIRY_SECONDS:
                    self._stats["commands_expired"] += 1
                    return f"Command expired ({int(age)}s old, max {COMMAND_EXPIRY_SECONDS}s)"
            except (ValueError, TypeError):
                pass

        # 3. Protected target checks — accept both "parameters" and "params"
        params = cmd.get("parameters") or cmd.get("params") or {}

        if cmd_type in ("logoff_user", "disable_account", "enable_account", "reset_password"):
            username = params.get("username", "")
            if username.upper() in PROTECTED_ACCOUNTS:
                return f"Protected account: {username}"

        if cmd_type == "kill_process":
            pname = params.get("process_name", "").lower()
            if pname in PROTECTED_PROCESSES:
                return f"Protected process: {pname}"

        if cmd_type in ("stop_service", "disable_service"):
            sname = params.get("service_name", "").lower()
            if sname in PROTECTED_SERVICES:
                return f"Protected service: {sname}"

        return None

    # ── Rate Limiting ─────────────────────────────────────────────

    def _check_rate_limit(self) -> bool:
        now = time.time()
        minute_ago = now - 60
        recent = [t for t in self._cmd_timestamps if t >= minute_ago]
        return len(recent) < MAX_COMMANDS_PER_MINUTE

    # ── Command Execution ─────────────────────────────────────────

    def _execute(self, cmd: dict) -> dict:
        """Route to the appropriate handler."""
        cmd_type = cmd.get("command_type", "")
        # API may send "params" or "parameters" — accept both
        params = cmd.get("parameters") or cmd.get("params") or {}

        handler = getattr(self, f"_cmd_{cmd_type}", None)
        if handler:
            try:
                start_ms = time.monotonic()
                result = handler(params)
                elapsed_ms = int((time.monotonic() - start_ms) * 1000)
                result["execution_time_ms"] = elapsed_ms
                return result
            except Exception as e:
                return {"success": False, "error": str(e)}

        return {"success": False, "error": f"No handler for: {cmd_type}"}

    def get_remote_desktop_status(self) -> dict:
        """UI / diagnostics — lazy-init streamer status without starting stream."""
        try:
            rd = self._get_remote_desktop()
            st = rd.get_status()
            st["ready"] = True
            st["controlled_by"] = "dashboard"
            return st
        except Exception as e:
            return {
                "ready": False,
                "streaming": False,
                "error": str(e),
                "controlled_by": "dashboard",
            }

    def stop_remote_desktop_local(self, reason: str = "local_ui") -> dict:
        """Emergency stop from tray UI (if stream active)."""
        try:
            if not self._remote_desktop:
                return {"success": True, "message": "not streaming"}
            return self._remote_desktop.stop(reason=reason)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get_remote_desktop(self):
        if self._remote_desktop is None:
            from client_remote_desktop import RemoteDesktopStreamer
            self._remote_desktop = RemoteDesktopStreamer(
                api_client=self.api_client,
                token_getter=self.token_getter,
            )
        return self._remote_desktop

    def _cmd_remote_stream_start(self, params: dict) -> dict:
        rd = self._get_remote_desktop()
        result = rd.start(
            fps=float(params.get("fps", 6.0) or 6.0),
            quality=int(params.get("quality", 35) or 35),
            max_width=int(params.get("max_width", 1280) or 1280),
        )
        if result.get("success"):
            self._notify_remote_desktop_ui("started")
        else:
            log(f"[REMOTE-DESKTOP] start rejected: {result.get('error')} {result.get('message')}")
            self._notify_remote_desktop_ui("failed")
        return result

    def _cmd_remote_stream_stop(self, params: dict) -> dict:
        rd = self._get_remote_desktop()
        result = rd.stop(reason="command")
        self._notify_remote_desktop_ui("stopped")
        return result

    def _notify_remote_desktop_ui(self, event: str) -> None:
        """Best-effort tray toast + GUI refresh hook."""
        try:
            cb = getattr(self, "on_remote_desktop_event", None)
            if callable(cb):
                cb(event)
        except Exception:
            pass
        try:
            # Tray balloon if wired via alert pipeline later
            log(f"[REMOTE-DESKTOP] UI event: {event}")
        except Exception:
            pass

    def _cmd_remote_input(self, params: dict) -> dict:
        rd = self._get_remote_desktop()
        return rd.apply_input(params or {})

    # ── Command Handlers ──────────────────────────────────────────

    def _cmd_block_ip(self, params: dict) -> dict:
        ip = params.get("ip", "")
        if not ip:
            return {"success": False, "error": "No IP specified"}
        duration = params.get("duration_hours", 24)
        reason = params.get("reason", "Remote command")

        if self.auto_response:
            ok = self.auto_response.block_ip(ip, reason=reason, duration_hours=duration)
            return {"success": ok, "message": f"IP {ip} blocked for {duration}h"}

        # Fallback: direct netsh
        return self._netsh_block(ip, f"HONEYPOT_REMOTE_BLOCK_{ip.replace('.', '_')}")

    def _cmd_unblock_ip(self, params: dict) -> dict:
        ip = params.get("ip", "")
        if not ip:
            return {"success": False, "error": "No IP specified"}
        # Same delete path as pending-unblocks (all rule-name variants + ACK)
        if self.auto_response:
            ok = self.auto_response.unblock_ip(ip)
            return {"success": ok, "message": f"IP {ip} unblocked"}
        try:
            from client_firewall import WindowsFirewallBackend, make_logger
            backend = WindowsFirewallBackend(logger=make_logger())
            ok = backend.remove_block("", ip_or_cidr=ip)
            return {"success": ok, "message": f"IP {ip} unblocked (direct)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_logoff_user(self, params: dict) -> dict:
        username = params.get("username", "")
        session_id = params.get("session_id")
        if session_id is not None and str(session_id).isdigit():
            result = subprocess.run(
                ["logoff", str(session_id)],
                capture_output=True, text=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            ok = result.returncode == 0
            # Push fresh sessions to dashboard
            if self.health_monitor and hasattr(self.health_monitor, "force_report"):
                try:
                    self.health_monitor.force_report(refresh=True)
                except Exception:
                    pass
            return {
                "success": ok,
                "message": f"logged off session {session_id}" if ok else (result.stderr or result.stdout or "logoff failed"),
            }
        if not username:
            return {"success": False, "error": "No username or session_id specified"}
        if self.auto_response:
            ok = self.auto_response.logoff_user(username)
            if self.health_monitor and hasattr(self.health_monitor, "force_report"):
                try:
                    self.health_monitor.force_report(refresh=True)
                except Exception:
                    pass
            return {"success": ok, "message": f"Session for {username} terminated"}
        return self._logoff_direct(username)

    def _cmd_disable_account(self, params: dict) -> dict:
        username = params.get("username", "")
        if not username:
            return {"success": False, "error": "No username specified"}
        if self.auto_response:
            ok = self.auto_response.disable_account(username)
            return {"success": ok, "message": f"Account {username} disabled"}
        return self._run_net_user(username, "/active:no", "disabled")

    def _cmd_enable_account(self, params: dict) -> dict:
        username = params.get("username", "")
        if not username:
            return {"success": False, "error": "No username specified"}
        if self.auto_response:
            ok = self.auto_response.enable_account(username)
            return {"success": ok, "message": f"Account {username} enabled"}
        return self._run_net_user(username, "/active:yes", "enabled")

    def _cmd_reset_password(self, params: dict) -> dict:
        username = params.get("username", "")
        if not username:
            return {"success": False, "error": "No username specified"}

        # Import password generator from auto_response or inline
        if self.auto_response:
            new_pass = params.get("new_password") or self.auto_response.generate_strong_password()
        else:
            import secrets as _sec, string as _str
            chars = _str.ascii_letters + _str.digits + "!@#$%&*"
            new_pass = params.get("new_password") or ''.join(
                _sec.choice(chars) for _ in range(16)
            )

        result = subprocess.run(
            ["net", "user", username, new_pass],
            capture_output=True, text=True, timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            return {
                "success": True,
                "message": f"Password reset for {username}",
                "new_password": new_pass,
            }
        return {"success": False, "error": result.stderr.strip()}

    def _cmd_kill_process(self, params: dict) -> dict:
        pid = params.get("pid")
        process_name = params.get("process_name", "")

        # Protect critical PIDs by resolving name
        if pid is not None:
            try:
                import psutil
                p = psutil.Process(int(pid))
                pname = (p.name() or "").lower()
                if pname in PROTECTED_PROCESSES or int(pid) in (0, 4):
                    return {"success": False, "error": f"Protected process: {pname or pid}"}
            except Exception:
                pass
            cmd = ["taskkill", "/F", "/PID", str(pid)]
        elif process_name:
            if process_name.lower() in PROTECTED_PROCESSES:
                return {"success": False, "error": f"Protected process: {process_name}"}
            cmd = ["taskkill", "/F", "/IM", process_name]
        else:
            return {"success": False, "error": "No PID or process_name specified"}

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = result.returncode == 0
        if ok and self.health_monitor and hasattr(self.health_monitor, "force_report"):
            try:
                self.health_monitor.force_report(refresh=True)
            except Exception:
                pass
        return {
            "success": ok,
            "message": result.stdout.strip() or result.stderr.strip(),
        }

    def _cmd_block_process(self, params: dict) -> dict:
        """Persist a path/name firewall-style block via Software Restriction / netsh is limited.

        Practical approach: add inbound block is wrong for process — use AppLocker-like
        deny via Image File Execution Options debugger stub OR scheduled kill+watch.
        We create a Defender-style block by writing an IFEO null debugger for the image
        name (admin) when path/name_pattern given — reversible via unblock not in scope.
        """
        path = (params.get("path") or "").strip()
        pattern = (params.get("name_pattern") or params.get("name") or "").strip()
        image = ""
        if path:
            image = os.path.basename(path)
        elif pattern:
            image = pattern if pattern.lower().endswith(".exe") else f"{pattern}.exe"
        if not image:
            return {"success": False, "error": "path or name_pattern required"}
        if image.lower() in PROTECTED_PROCESSES:
            return {"success": False, "error": f"Protected process: {image}"}

        # IFEO Debugger = nul → process fails to start (common admin block technique)
        try:
            import winreg
            key_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\\" + image
            )
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, "nyan")
            log(f"[REMOTE-CMD] block_process IFEO set for {image}")
            return {
                "success": True,
                "message": f"Process block applied (IFEO): {image}",
                "data": {"image": image, "path": path or None},
            }
        except PermissionError:
            return {"success": False, "error": "Admin required for process block"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_list_sessions(self, params: dict) -> dict:
        # Push fresh active_sessions via health report (dashboard source of truth)
        reported = False
        sessions = []
        if self.health_monitor and hasattr(self.health_monitor, "force_report"):
            try:
                reported = bool(self.health_monitor.force_report(refresh=True))
                sessions = list(
                    (self.health_monitor.get_stats() or {}).get("active_sessions") or []
                )
            except Exception as e:
                return {"success": False, "error": str(e)}
        else:
            # Fallback local query
            try:
                result = subprocess.run(
                    ["query", "user"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=CREATE_NO_WINDOW,
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        sessions.append({
                            "username": parts[0].strip(">"),
                            "session_name": parts[1] if len(parts) > 1 else "",
                            "session_id": parts[2] if len(parts) > 2 else "",
                            "status": parts[3] if len(parts) > 3 else "",
                        })
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {
            "success": True,
            "message": f"{len(sessions)} session(s); health_report={'ok' if reported else 'skipped'}",
            "data": {"sessions": sessions, "active_sessions": sessions},
        }

    def _cmd_list_processes(self, params: dict) -> dict:
        reported = False
        procs = []
        if self.health_monitor and hasattr(self.health_monitor, "force_report"):
            try:
                reported = bool(self.health_monitor.force_report(refresh=True))
                procs = list(
                    (self.health_monitor.get_stats() or {}).get("top_processes") or []
                )
            except Exception as e:
                return {"success": False, "error": str(e)}
        else:
            try:
                import psutil
                for p in psutil.process_iter(
                    ["pid", "name", "cpu_percent", "memory_info", "username", "exe"]
                ):
                    try:
                        info = p.info
                        mem = info.get("memory_info")
                        procs.append({
                            "pid": info.get("pid", 0),
                            "name": info.get("name", ""),
                            "cpu_percent": info.get("cpu_percent", 0),
                            "memory_mb": round((mem.rss if mem else 0) / 1024 / 1024, 1),
                            "username": info.get("username", ""),
                            "path": info.get("exe") or "",
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                procs.sort(key=lambda p: p.get("cpu_percent", 0), reverse=True)
                procs = procs[:150]
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {
            "success": True,
            "message": f"{len(procs)} process(es); health_report={'ok' if reported else 'skipped'}",
            "data": {"processes": procs, "top_processes": procs},
        }

    def _cmd_stop_service(self, params: dict) -> dict:
        svc = params.get("service_name", "")
        if not svc:
            return {"success": False, "error": "No service_name specified"}
        result = subprocess.run(
            ["sc", "stop", svc],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "message": f"Service {svc} stop requested",
        }

    def _cmd_start_service(self, params: dict) -> dict:
        svc = params.get("service_name", "")
        if not svc:
            return {"success": False, "error": "No service_name specified"}
        result = subprocess.run(
            ["sc", "start", svc],
            capture_output=True, text=True, timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "message": f"Service {svc} start requested",
        }

    def _cmd_restart_service(self, params: dict) -> dict:
        svc = params.get("service_name", "")
        if not svc:
            return {"success": False, "error": "No service_name specified"}
        stop = self._cmd_stop_service(params)
        time.sleep(1.5)
        start = self._cmd_start_service(params)
        ok = bool(start.get("success"))
        return {
            "success": ok,
            "message": f"Service {svc} restarted",
            "data": {"stop": stop, "start": start},
        }

    def _cmd_disable_service(self, params: dict) -> dict:
        svc = params.get("service_name", "")
        if not svc:
            return {"success": False, "error": "No service_name specified"}
        result = subprocess.run(
            ["sc", "config", svc, "start=disabled"],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "message": f"Service {svc} disabled",
        }

    def _cmd_emergency_lockdown(self, params: dict) -> dict:
        mgmt_ip = params.get("management_ip", "")
        duration = params.get("duration_minutes", 60)
        if not mgmt_ip:
            return {"success": False, "error": "management_ip required"}
        if self.auto_response:
            ok = self.auto_response.emergency_lockdown(mgmt_ip, duration)
            return {"success": ok, "message": f"Lockdown active, management IP: {mgmt_ip}"}
        return {"success": False, "error": "AutoResponse not available"}

    def _cmd_enable_lockdown(self, params: dict) -> dict:
        """Alias for emergency_lockdown (V4 prompt naming)."""
        return self._cmd_emergency_lockdown(params)

    def _cmd_lift_lockdown(self, params: dict) -> dict:
        if self.auto_response:
            ok = self.auto_response.lift_lockdown()
            return {"success": ok, "message": "Lockdown lifted"}
        return {"success": False, "error": "AutoResponse not available"}

    def _cmd_disable_lockdown(self, params: dict) -> dict:
        """Alias for lift_lockdown (V4 prompt naming)."""
        return self._cmd_lift_lockdown(params)

    def _cmd_snapshot(self, params: dict) -> dict:
        try:
            import psutil
            return {
                "success": True,
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory": dict(psutil.virtual_memory()._asdict()),
                "disk": dict(psutil.disk_usage('C:\\')._asdict()),
                "top_processes": [
                    {"pid": p.pid, "name": p.name(),
                     "cpu": p.cpu_percent(),
                     "memory_mb": round(p.memory_info().rss / 1024 / 1024, 1)}
                    for p in sorted(
                        psutil.process_iter(['pid', 'name', 'cpu_percent']),
                        key=lambda p: p.cpu_percent(), reverse=True
                    )[:20]
                ],
                "connections": len(psutil.net_connections()),
                "boot_time": psutil.boot_time(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_collect_diagnostics(self, params: dict) -> dict:
        """Collect comprehensive system diagnostics."""
        try:
            import psutil
            import platform
            import socket

            diag: Dict = {}

            # OS info
            diag["os"] = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "hostname": socket.gethostname(),
            }

            # Agent info
            try:
                from client_constants import VERSION
                diag["agent"] = {
                    "version": VERSION,
                    "uptime_seconds": int(time.time() - psutil.boot_time()),
                    "pid": os.getpid() if hasattr(os, 'getpid') else None,
                }
            except Exception:
                diag["agent"] = {"version": "unknown"}

            # CPU
            diag["cpu"] = {
                "percent": psutil.cpu_percent(interval=1),
                "count_logical": psutil.cpu_count(logical=True),
                "count_physical": psutil.cpu_count(logical=False),
                "freq_mhz": round(psutil.cpu_freq().current, 0) if psutil.cpu_freq() else None,
            }

            # Memory
            mem = psutil.virtual_memory()
            diag["memory"] = {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "available_gb": round(mem.available / (1024 ** 3), 2),
                "percent": mem.percent,
            }

            # Disk
            diag["disk"] = {}
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    diag["disk"][part.mountpoint] = {
                        "total_gb": round(usage.total / (1024 ** 3), 2),
                        "used_gb": round(usage.used / (1024 ** 3), 2),
                        "free_gb": round(usage.free / (1024 ** 3), 2),
                        "percent": usage.percent,
                    }
                except (PermissionError, OSError):
                    continue

            # Network interfaces
            diag["network"] = {
                "interfaces": {},
                "active_connections": len(psutil.net_connections()),
            }
            for iface, addrs in psutil.net_if_addrs().items():
                diag["network"]["interfaces"][iface] = [
                    {"address": a.address, "family": str(a.family)}
                    for a in addrs
                ]

            # Firewall rules summary
            try:
                fw_result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule",
                     "name=HONEYPOT", "dir=in"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=CREATE_NO_WINDOW,
                )
                rule_count = fw_result.stdout.count("Rule Name:")
                diag["firewall"] = {
                    "honeypot_rules_count": rule_count,
                    "status": "active" if rule_count >= 0 else "unknown",
                }
            except Exception:
                diag["firewall"] = {"status": "query_failed"}

            # Services check
            diag["services"] = {}
            check_services = ["sshd", "W3SVC", "MSSQLSERVER", "MySQL", "TermService"]
            for svc_name in check_services:
                try:
                    svc = psutil.win_service_get(svc_name)
                    info = svc.as_dict()
                    diag["services"][svc_name] = {
                        "status": info.get("status", "unknown"),
                        "start_type": info.get("start_type", "unknown"),
                    }
                except Exception:
                    diag["services"][svc_name] = {"status": "not_found"}

            # Top processes (top 10 by CPU)
            diag["top_processes"] = []
            for p in sorted(
                psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']),
                key=lambda p: p.info.get('cpu_percent', 0) or 0,
                reverse=True,
            )[:10]:
                try:
                    info = p.info
                    diag["top_processes"].append({
                        "pid": info.get("pid"),
                        "name": info.get("name", ""),
                        "cpu_percent": info.get("cpu_percent", 0),
                        "memory_mb": round(
                            (info.get("memory_info") or type("", (), {"rss": 0})).rss / 1024 / 1024, 1
                        ),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            return {"success": True, "diagnostics": diag}

        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Fallback Helpers ──────────────────────────────────────────

    @staticmethod
    def _netsh_block(ip: str, rule_name: str) -> dict:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip}", "enable=yes"],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "message": f"IP {ip} blocked" if result.returncode == 0 else result.stderr.strip(),
        }

    @staticmethod
    def _logoff_direct(username: str) -> dict:
        try:
            query = subprocess.run(
                ["query", "session"],
                capture_output=True, text=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            for line in query.stdout.splitlines():
                if username.lower() in line.lower():
                    parts = line.split()
                    for p in parts:
                        if p.isdigit():
                            subprocess.run(
                                ["logoff", p],
                                capture_output=True, text=True, timeout=10,
                                creationflags=CREATE_NO_WINDOW,
                            )
                            return {"success": True, "message": f"Session {p} logoff sent"}
            return {"success": False, "error": f"No session for {username}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _run_net_user(username: str, flag: str, action: str) -> dict:
        result = subprocess.run(
            ["net", "user", username, flag],
            capture_output=True, text=True, timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "message": f"Account {username} {action}" if result.returncode == 0 else result.stderr.strip(),
        }
