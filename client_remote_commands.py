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
  snapshot

Security layers:
  - Command whitelist (ALLOWED_COMMANDS)
  - 5-minute expiry window
  - Protected accounts / processes / services
  - Rate limiting (max 10 commands/minute)

Exports:
  RemoteCommandExecutor — main class (start / stop / get_stats)
"""

import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

POLL_INTERVAL = 5  # seconds
COMMAND_EXPIRY_SECONDS = 300  # 5 minutes
MAX_COMMANDS_PER_MINUTE = 10

CREATE_NO_WINDOW = 0x08000000

ALLOWED_COMMANDS: Set[str] = {
    "block_ip", "unblock_ip",
    "logoff_user", "disable_account", "enable_account", "reset_password",
    "kill_process", "stop_service", "disable_service",
    "emergency_lockdown", "lift_lockdown",
    "list_sessions", "list_processes", "snapshot",
}

PROTECTED_ACCOUNTS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
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
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.auto_response = auto_response  # AutoResponse instance

        self._running = False
        self._poll_thread: Optional[threading.Thread] = None

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
        """Stop polling."""
        self._running = False
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

                    # Rate limit
                    if not self._check_rate_limit():
                        log("[REMOTE-CMD] ⚠️ Rate limit — skipping command")
                        self._stats["commands_rejected"] += 1
                        continue

                    # Execute
                    result = self._execute(cmd)

                    # Track
                    self._cmd_timestamps.append(time.time())
                    entry = {
                        "command_type": cmd.get("command_type", ""),
                        "command_id": cmd.get("command_id", ""),
                        "parameters": cmd.get("parameters", {}),
                        "result": result,
                        "executed_at": time.time(),
                    }
                    self._history.append(entry)

                    if result.get("success"):
                        self._stats["commands_executed"] += 1
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
                params={"token": token},
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
                self.api_client.api_request("POST", "commands/result", data={
                    "token": token,
                    "command_id": cmd.get("command_id", ""),
                    "status": "completed" if result.get("success") else "failed",
                    "result": result,
                    "executed_at": datetime.now(timezone.utc).isoformat(),
                })
            except Exception as e:
                log(f"[REMOTE-CMD] Result report error: {e}")

        threading.Thread(target=_send, daemon=True).start()

    # ── Validation ────────────────────────────────────────────────

    def _validate(self, cmd: dict) -> Optional[str]:
        """
        Validate command. Returns rejection reason or None if valid.
        """
        cmd_type = cmd.get("command_type", "")

        # 1. Known command?
        if cmd_type not in ALLOWED_COMMANDS:
            return f"Unknown command: {cmd_type}"

        # 2. Expired?
        issued_at = cmd.get("issued_at", "")
        if issued_at:
            try:
                issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - issued).total_seconds()
                if age > COMMAND_EXPIRY_SECONDS:
                    self._stats["commands_expired"] += 1
                    return f"Command expired ({int(age)}s old, max {COMMAND_EXPIRY_SECONDS}s)"
            except (ValueError, TypeError):
                pass

        # 3. Protected target checks
        params = cmd.get("parameters", {})

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
        params = cmd.get("parameters", {})

        handler = getattr(self, f"_cmd_{cmd_type}", None)
        if handler:
            try:
                return handler(params)
            except Exception as e:
                return {"success": False, "error": str(e)}

        return {"success": False, "error": f"No handler for: {cmd_type}"}

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
        if self.auto_response:
            ok = self.auto_response.unblock_ip(ip)
            return {"success": ok, "message": f"IP {ip} unblocked"}
        return {"success": False, "error": "AutoResponse not available"}

    def _cmd_logoff_user(self, params: dict) -> dict:
        username = params.get("username", "")
        if not username:
            return {"success": False, "error": "No username specified"}
        if self.auto_response:
            ok = self.auto_response.logoff_user(username)
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
        if "pid" in params:
            cmd = ["taskkill", "/F", "/PID", str(params["pid"])]
        elif "process_name" in params:
            cmd = ["taskkill", "/F", "/IM", params["process_name"]]
        else:
            return {"success": False, "error": "No PID or process_name specified"}

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "message": result.stdout.strip() or result.stderr.strip(),
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

    def _cmd_lift_lockdown(self, params: dict) -> dict:
        if self.auto_response:
            ok = self.auto_response.lift_lockdown()
            return {"success": ok, "message": "Lockdown lifted"}
        return {"success": False, "error": "AutoResponse not available"}

    def _cmd_list_sessions(self, params: dict) -> dict:
        try:
            result = subprocess.run(
                ["query", "session"],
                capture_output=True, text=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            sessions = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    sessions.append({
                        "username": parts[0].strip(">"),
                        "session": parts[1] if len(parts) > 1 else "",
                        "id": parts[2] if len(parts) > 2 else "",
                        "state": parts[3] if len(parts) > 3 else "",
                    })
            return {"success": True, "sessions": sessions}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_list_processes(self, params: dict) -> dict:
        try:
            import psutil
            filter_mode = params.get("filter", "")
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'username']):
                try:
                    info = p.info
                    procs.append({
                        "pid": info.get('pid', 0),
                        "name": info.get('name', ''),
                        "cpu_percent": info.get('cpu_percent', 0),
                        "memory_mb": round(
                            (info.get('memory_info') or type('', (), {'rss': 0})).rss / 1024 / 1024, 1
                        ),
                        "username": info.get('username', ''),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Sort by CPU usage descending
            procs.sort(key=lambda p: p.get("cpu_percent", 0), reverse=True)
            return {"success": True, "processes": procs[:50]}  # Top 50
        except Exception as e:
            return {"success": False, "error": str(e)}

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
