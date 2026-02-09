#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Auto-Response Engine (v4.0)

Executes automatic defensive actions when threat score thresholds
are exceeded. Integrates with Windows Firewall, user session management,
and the alert pipeline.

Actions:
  block_ip           — Add Windows Firewall inbound block rule
  unblock_ip         — Remove block rule (scheduled or manual)
  logoff_user        — Terminate active RDP/console session
  disable_account    — Disable Windows user account
  enable_account     — Re-enable Windows user account
  emergency_lockdown — Block all inbound except management IP
  lift_lockdown      — Remove lockdown rules

Safety guards:
  - Max blocks per hour/day
  - Whitelist IPs/subnets never blocked
  - Protected accounts (SYSTEM, LOCAL SERVICE, etc.)
  - Auto-unblock timer (default 24h)

Exports:
  AutoResponse — main class (block_ip / unblock_ip / logoff_user / ...)
"""

import ipaddress
import secrets
import string
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

FIREWALL_RULE_PREFIX = "HP-BLOCK"

# Safety limits
MAX_BLOCKS_PER_HOUR = 50
MAX_BLOCKS_PER_DAY = 200
AUTO_UNBLOCK_HOURS = 24

# Protected resources — never touch these
PROTECTED_ACCOUNTS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "DEFAULTACCOUNT", "GUEST", "WDAGUTILITYACCOUNT",
}

PROTECTED_PROCESSES: Set[str] = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe",
    "honeypot-client.exe",
}

PROTECTED_SERVICES: Set[str] = {
    "wuauserv", "windefend", "eventlog", "mpssvc",
    "w32time", "dnscache",
}

# Subprocess creation flags
CREATE_NO_WINDOW = 0x08000000


# ── Block Tracking ───────────────────────────────────────────────

@dataclass
class BlockRecord:
    """Tracks a firewall block for auto-unblock scheduling."""
    ip: str
    rule_name: str
    reason: str
    blocked_at: float
    unblock_at: float  # 0 = permanent until manual removal
    auto_unblock: bool = True


# ── Auto-Response Engine ─────────────────────────────────────────

class AutoResponse:
    """
    Automatic defensive action executor.

    Usage:
        ar = AutoResponse(
            api_client=api_client,
            token_getter=lambda: state.get("token", ""),
            whitelist_ips={"10.0.0.1"},
        )
        ar.start()
        ar.block_ip("1.2.3.4", reason="Brute force", duration_hours=24)
    """

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        whitelist_ips: Optional[Set[str]] = None,
        whitelist_subnets: Optional[List[str]] = None,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.whitelist_ips: Set[str] = whitelist_ips or set()
        self.whitelist_subnets: List[str] = whitelist_subnets or []

        # Active blocks
        self._blocks: Dict[str, BlockRecord] = {}
        self._lock = threading.Lock()

        # Rate limiting
        self._block_timestamps: deque = deque(maxlen=MAX_BLOCKS_PER_DAY)

        # Auto-unblock thread
        self._running = False
        self._unblock_thread: Optional[threading.Thread] = None

        # Lockdown state
        self._lockdown_active = False
        self._lockdown_management_ip: Optional[str] = None

        # Stats
        self._stats = {
            "blocks_applied": 0,
            "blocks_removed": 0,
            "logoffs_executed": 0,
            "accounts_disabled": 0,
            "rate_limited": 0,
            "whitelisted_skipped": 0,
            "errors": 0,
        }

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        """Start the auto-unblock scheduler thread."""
        if self._running:
            return
        self._running = True
        self._unblock_thread = threading.Thread(
            target=self._unblock_scheduler_loop,
            name="AutoResponse-Unblock",
            daemon=True,
        )
        self._unblock_thread.start()
        log("[AUTO-RESPONSE] 🚀 Auto-response engine started")

    def stop(self):
        """Stop the engine."""
        self._running = False
        log("[AUTO-RESPONSE] ✅ Stopped")

    def get_stats(self) -> dict:
        """Return action statistics."""
        stats = dict(self._stats)
        with self._lock:
            stats["active_blocks"] = len(self._blocks)
            stats["lockdown_active"] = self._lockdown_active
        return stats

    def get_blocked_ips(self) -> List[dict]:
        """Return list of currently blocked IPs."""
        with self._lock:
            return [
                {
                    "ip": b.ip,
                    "reason": b.reason,
                    "blocked_at": b.blocked_at,
                    "unblock_at": b.unblock_at,
                    "auto_unblock": b.auto_unblock,
                }
                for b in self._blocks.values()
            ]

    # ── IP Blocking ───────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str = "",
                 duration_hours: int = AUTO_UNBLOCK_HOURS) -> bool:
        """
        Block an IP via Windows Firewall.
        Returns True if successfully blocked.
        """
        # Safety: whitelist check
        if self._is_whitelisted(ip):
            log(f"[AUTO-RESPONSE] ⚪ Skipped whitelist IP: {ip}")
            self._stats["whitelisted_skipped"] += 1
            return False

        # Safety: already blocked?
        with self._lock:
            if ip in self._blocks:
                log(f"[AUTO-RESPONSE] Already blocked: {ip}")
                return True

        # Safety: rate limit check
        if not self._check_rate_limit():
            log(f"[AUTO-RESPONSE] ⚠️ Rate limit reached — skipping block for {ip}")
            self._stats["rate_limited"] += 1
            return False

        # Execute firewall command
        rule_name = f"{FIREWALL_RULE_PREFIX}-{ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes",
        ]

        success = self._run_system_cmd(cmd)
        if success:
            now = time.time()
            unblock_at = now + (duration_hours * 3600) if duration_hours > 0 else 0

            with self._lock:
                self._blocks[ip] = BlockRecord(
                    ip=ip,
                    rule_name=rule_name,
                    reason=reason,
                    blocked_at=now,
                    unblock_at=unblock_at,
                    auto_unblock=duration_hours > 0,
                )

            self._block_timestamps.append(now)
            self._stats["blocks_applied"] += 1
            log(f"[AUTO-RESPONSE] 🚫 Blocked: {ip} — {reason} "
                f"(auto-unblock: {duration_hours}h)")

            # Report to API
            self._report_block_to_api(ip, reason, duration_hours)
            return True
        else:
            self._stats["errors"] += 1
            log(f"[AUTO-RESPONSE] ❌ Failed to block: {ip}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove firewall block for an IP."""
        with self._lock:
            record = self._blocks.pop(ip, None)

        if record:
            rule_name = record.rule_name
        else:
            rule_name = f"{FIREWALL_RULE_PREFIX}-{ip}"

        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}", "dir=in",
        ]
        success = self._run_system_cmd(cmd)
        if success:
            self._stats["blocks_removed"] += 1
            log(f"[AUTO-RESPONSE] ✅ Unblocked: {ip}")
            self._report_unblock_to_api(ip)
        return success

    # ── Session Management ────────────────────────────────────────

    def logoff_user(self, username: str) -> bool:
        """Force logoff an active user session."""
        if username.upper() in PROTECTED_ACCOUNTS:
            log(f"[AUTO-RESPONSE] ⚪ Cannot logoff protected account: {username}")
            return False

        try:
            # Find session ID
            result = subprocess.run(
                ["query", "session"],
                capture_output=True, text=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            for line in result.stdout.splitlines()[1:]:
                if username.lower() in line.lower():
                    parts = line.split()
                    # Session ID is typically the 2nd or 3rd column
                    session_id = None
                    for p in parts:
                        if p.isdigit():
                            session_id = p
                            break
                    if session_id:
                        logoff_result = subprocess.run(
                            ["logoff", session_id],
                            capture_output=True, text=True, timeout=10,
                            creationflags=CREATE_NO_WINDOW,
                        )
                        if logoff_result.returncode == 0:
                            self._stats["logoffs_executed"] += 1
                            log(f"[AUTO-RESPONSE] 🚪 Logged off: {username} (session {session_id})")
                            return True

            log(f"[AUTO-RESPONSE] No active session found for: {username}")
            return False

        except Exception as e:
            self._stats["errors"] += 1
            log(f"[AUTO-RESPONSE] Logoff error for {username}: {e}")
            return False

    # ── Account Management ────────────────────────────────────────

    def disable_account(self, username: str) -> bool:
        """Disable a Windows user account."""
        if username.upper() in PROTECTED_ACCOUNTS:
            log(f"[AUTO-RESPONSE] ⚪ Cannot disable protected account: {username}")
            return False

        cmd = ["net", "user", username, "/active:no"]
        success = self._run_system_cmd(cmd)
        if success:
            self._stats["accounts_disabled"] += 1
            log(f"[AUTO-RESPONSE] 🔒 Account disabled: {username}")
        return success

    def enable_account(self, username: str) -> bool:
        """Re-enable a Windows user account."""
        cmd = ["net", "user", username, "/active:yes"]
        success = self._run_system_cmd(cmd)
        if success:
            log(f"[AUTO-RESPONSE] 🔓 Account enabled: {username}")
        return success

    # ── Emergency Lockdown ────────────────────────────────────────

    def emergency_lockdown(self, management_ip: str,
                           duration_minutes: int = 60) -> bool:
        """
        Block ALL inbound traffic except from management IP.
        Use with extreme caution — only for active ransomware/compromise.
        """
        if not management_ip:
            log("[AUTO-RESPONSE] ❌ Lockdown requires management_ip")
            return False

        if self._lockdown_active:
            log("[AUTO-RESPONSE] Lockdown already active")
            return True

        # Add rule: block all inbound
        cmd_block = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=HONEYPOT_LOCKDOWN_BLOCK", "dir=in", "action=block",
            "enable=yes",
        ]
        # Add rule: allow management IP
        cmd_allow = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=HONEYPOT_LOCKDOWN_ALLOW", "dir=in", "action=allow",
            f"remoteip={management_ip}", "enable=yes",
        ]

        if self._run_system_cmd(cmd_allow) and self._run_system_cmd(cmd_block):
            self._lockdown_active = True
            self._lockdown_management_ip = management_ip
            log(f"[AUTO-RESPONSE] 🛑 EMERGENCY LOCKDOWN — only {management_ip} can access")

            # Schedule auto-lift
            if duration_minutes > 0:
                threading.Timer(
                    duration_minutes * 60,
                    self.lift_lockdown,
                ).start()

            return True

        self._stats["errors"] += 1
        return False

    def lift_lockdown(self) -> bool:
        """Remove emergency lockdown rules."""
        if not self._lockdown_active:
            return True

        cmd1 = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name=HONEYPOT_LOCKDOWN_BLOCK", "dir=in",
        ]
        cmd2 = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name=HONEYPOT_LOCKDOWN_ALLOW", "dir=in",
        ]
        self._run_system_cmd(cmd1)
        self._run_system_cmd(cmd2)
        self._lockdown_active = False
        self._lockdown_management_ip = None
        log("[AUTO-RESPONSE] ✅ Lockdown lifted — normal traffic restored")
        return True

    # ── Whitelist Management ──────────────────────────────────────

    def update_whitelist(self, ips: Set[str], subnets: Optional[List[str]] = None):
        """Update whitelist IPs and subnets (thread-safe)."""
        self.whitelist_ips = set(ips)
        if subnets is not None:
            self.whitelist_subnets = list(subnets)

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted (exact match or subnet)."""
        if ip in self.whitelist_ips:
            return True
        if ip in ("127.0.0.1", "::1", ""):
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in self.whitelist_subnets:
                try:
                    if addr in ipaddress.ip_network(subnet_str, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    # ── Rate Limiting ─────────────────────────────────────────────

    def _check_rate_limit(self) -> bool:
        """Check hourly and daily block rate limits."""
        now = time.time()
        hour_ago = now - 3600
        day_ago = now - 86400

        recent = [t for t in self._block_timestamps if t >= day_ago]
        hourly = [t for t in recent if t >= hour_ago]

        if len(hourly) >= MAX_BLOCKS_PER_HOUR:
            return False
        if len(recent) >= MAX_BLOCKS_PER_DAY:
            return False
        return True

    # ── Auto-Unblock Scheduler ────────────────────────────────────

    def _unblock_scheduler_loop(self):
        """Check for expired blocks every 60 seconds."""
        while self._running:
            try:
                self._process_expired_blocks()
            except Exception as e:
                log(f"[AUTO-RESPONSE] Unblock scheduler error: {e}")
            time.sleep(60)

    def _process_expired_blocks(self):
        """Remove blocks that have exceeded their duration."""
        now = time.time()
        expired = []

        with self._lock:
            for ip, record in self._blocks.items():
                if record.auto_unblock and record.unblock_at > 0 and now >= record.unblock_at:
                    expired.append(ip)

        for ip in expired:
            log(f"[AUTO-RESPONSE] ⏰ Auto-unblocking expired: {ip}")
            self.unblock_ip(ip)

    # ── API Reporting ─────────────────────────────────────────────

    def _report_block_to_api(self, ip: str, reason: str, duration_hours: int):
        """Report block action to API (fire-and-forget).

        POST /api/alerts/auto-block
        Body: {token, blocked_ip, reason, duration_hours, blocked_at (ISO)}
        """
        if not self.api_client:
            return

        def _send():
            try:
                token = self.token_getter()
                if not token:
                    return

                from datetime import datetime, timezone
                blocked_at = datetime.now(timezone.utc).isoformat()

                payload = {
                    "token": token,
                    "blocked_ip": ip,
                    "reason": reason,
                    "duration_hours": duration_hours,
                    "blocked_at": blocked_at,
                }
                result = self.api_client.api_request(
                    "POST", "alerts/auto-block", data=payload
                )
                if result:
                    log(f"[AUTO-RESPONSE] ✅ Block reported to API: {ip}")
                else:
                    log(f"[AUTO-RESPONSE] ⚠️ Block report failed for: {ip}")
            except Exception as e:
                log(f"[AUTO-RESPONSE] API report error: {e}")

        threading.Thread(target=_send, daemon=True).start()

    def _report_unblock_to_api(self, ip: str):
        """Report unblock action to API (fire-and-forget).

        POST /api/alerts/auto-unblock
        Body: {token, blocked_ip, unblocked_at (ISO)}
        """
        if not self.api_client:
            return

        def _send():
            try:
                token = self.token_getter()
                if not token:
                    return

                from datetime import datetime, timezone
                payload = {
                    "token": token,
                    "blocked_ip": ip,
                    "unblocked_at": datetime.now(timezone.utc).isoformat(),
                }
                result = self.api_client.api_request(
                    "POST", "alerts/auto-unblock", data=payload
                )
                if result:
                    log(f"[AUTO-RESPONSE] ✅ Unblock reported to API: {ip}")
                else:
                    log(f"[AUTO-RESPONSE] ⚠️ Unblock report failed for: {ip}")
            except Exception as e:
                log(f"[AUTO-RESPONSE] API unblock report error: {e}")

        threading.Thread(target=_send, daemon=True).start()

    # ── System Command Runner ─────────────────────────────────────

    @staticmethod
    def _run_system_cmd(cmd: list, timeout: int = 15) -> bool:
        """Run a system command and return success status."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            log(f"[AUTO-RESPONSE] Command timed out: {' '.join(cmd[:3])}...")
            return False
        except Exception as e:
            log(f"[AUTO-RESPONSE] Command error: {e}")
            return False

    # ── Password Generation ───────────────────────────────────────

    @staticmethod
    def generate_strong_password(length: int = 16) -> str:
        """Generate a cryptographically strong random password."""
        chars = string.ascii_letters + string.digits + "!@#$%&*"
        while True:
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                    and any(c.isdigit() for c in pwd)
                    and any(c in "!@#$%&*" for c in pwd)):
                return pwd
