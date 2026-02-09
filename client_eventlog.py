#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Windows Event Log Watcher (v4.0)

Real-time monitoring of Windows Security, System, Application and RDP
event logs using win32evtlog push-based subscriptions (EvtSubscribe).

Watched events:
  Security   — 4624/4625/4648/4672/4688/4697/4720/4732/1102
  System     — 1074/6005/6006/7045/7040
  Application — 18453/18456/15457/17135 (MSSQL)
  RDP        — 1149/21/24/25

Each parsed event is forwarded to ThreatEngine.process_event().

Exports:
  EventLogWatcher  — main watcher class (start / stop / get_stats)
"""

import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set
from collections import defaultdict

from client_helpers import log

# ── win32evtlog import (graceful fallback) ────────────────────────
try:
    import win32evtlog
    import win32con
    EVTLOG_AVAILABLE = True
except ImportError:
    EVTLOG_AVAILABLE = False
    log("[EVENTLOG] pywin32 not available — event log monitoring disabled")


# ── Constants ─────────────────────────────────────────────────────

# Channels → Event IDs to watch
WATCHED_CHANNELS: Dict[str, List[int]] = {
    "Security": [4624, 4625, 4648, 4672, 4688, 4697, 4720, 4732, 4735, 1102],
    "System": [1074, 6005, 6006, 7045, 7040],
    "Application": [18453, 18456, 15457, 17135],
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": [1149],
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": [21, 24, 25],
}

# Accounts to ignore (machine accounts, system accounts)
IGNORED_ACCOUNTS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "ANONYMOUS LOGON", "Font Driver Host",
}

# Logon types we ignore (5=Service, 7=Unlock)
IGNORED_LOGON_TYPES: Set[int] = {5, 7}

# Prefixes for machine/DWM accounts to skip
IGNORED_ACCOUNT_PREFIXES = ("DWM-", "UMFD-", "IUSR")

# Map Event ID → human-readable event type for ThreatEngine
EVENT_TYPE_MAP: Dict[int, str] = {
    # Auth
    4624: "successful_logon",
    4625: "failed_logon",
    4648: "explicit_credential_logon",
    4672: "privilege_assigned",
    4688: "new_process",
    4697: "new_service_installed",
    4720: "new_user_created",
    4732: "user_added_to_admin_group",
    4735: "security_group_changed",
    1102: "audit_log_cleared",
    # System
    1074: "system_shutdown",
    6005: "eventlog_started",
    6006: "eventlog_stopped",
    7045: "new_service_installed",
    7040: "service_start_type_changed",
    # MSSQL
    18453: "sql_successful_logon",
    18456: "sql_failed_logon",
    15457: "xp_cmdshell_executed",
    17135: "sql_server_restarted",
    # RDP
    1149: "rdp_connection_succeeded",
    21:   "rdp_session_logon",
    24:   "rdp_session_disconnect",
    25:   "rdp_session_reconnect",
}

# Logon type descriptions (for Event 4624)
LOGON_TYPE_NAMES: Dict[int, str] = {
    2:  "Interactive",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


# ── XPath query builder ──────────────────────────────────────────

def _build_xpath(event_ids: List[int]) -> str:
    """Build XPath filter for specific Event IDs — efficient server-side filtering."""
    id_clauses = " or ".join(f"EventID={eid}" for eid in event_ids)
    return f"*[System[{id_clauses}]]"


# ── Main Watcher ─────────────────────────────────────────────────

class EventLogWatcher:
    """
    Real-time Windows Event Log watcher using EvtSubscribe (push-based).

    Usage:
        watcher = EventLogWatcher(on_event=threat_engine.process_event)
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(self, on_event: Callable[[dict], None],
                 whitelist_ips: Optional[Set[str]] = None):
        """
        Args:
            on_event:       Callback receiving parsed event dicts.
            whitelist_ips:  IPs to ignore completely (user-configured).
        """
        self.on_event = on_event
        self.whitelist_ips: Set[str] = whitelist_ips or set()
        self._subscriptions: list = []
        self._running = False
        self._lock = threading.Lock()

        # Stats
        self._stats = {
            "events_processed": 0,
            "events_filtered": 0,
            "errors": 0,
            "started_at": 0.0,
            "channels_active": 0,
        }

    # ── Public API ────────────────────────────────────────────────

    def start(self):
        """Subscribe to all configured event channels."""
        if not EVTLOG_AVAILABLE:
            log("[EVENTLOG] ⚠️ Cannot start — pywin32 not installed")
            return

        if self._running:
            log("[EVENTLOG] Already running")
            return

        log("[EVENTLOG] 🚀 Starting Windows Event Log monitoring...")
        self._running = True
        self._stats["started_at"] = time.time()

        active = 0
        for channel, event_ids in WATCHED_CHANNELS.items():
            try:
                xpath = _build_xpath(event_ids)
                handle = win32evtlog.EvtSubscribe(
                    channel,
                    win32evtlog.EvtSubscribeToFutureEvents,
                    Query=xpath,
                    Callback=self._on_event_callback,
                )
                self._subscriptions.append(handle)
                active += 1
                log(f"[EVENTLOG] ✅ Subscribed: {channel} ({len(event_ids)} event IDs)")
            except Exception as e:
                log(f"[EVENTLOG] ❌ Failed to subscribe to {channel}: {e}")
                self._stats["errors"] += 1

        self._stats["channels_active"] = active
        log(f"[EVENTLOG] Monitoring active — {active}/{len(WATCHED_CHANNELS)} channels")

    def stop(self):
        """Unsubscribe from all channels and clean up."""
        if not self._running:
            return

        log("[EVENTLOG] Stopping event log monitoring...")
        self._running = False

        for handle in self._subscriptions:
            try:
                win32evtlog.EvtClose(handle)
            except Exception:
                pass

        self._subscriptions.clear()
        self._stats["channels_active"] = 0
        log("[EVENTLOG] ✅ Stopped")

    def get_stats(self) -> dict:
        """Return monitoring statistics."""
        stats = dict(self._stats)
        if stats["started_at"]:
            stats["uptime_seconds"] = int(time.time() - stats["started_at"])
        return stats

    def update_whitelist(self, ips: Set[str]):
        """Update whitelisted IPs (thread-safe)."""
        with self._lock:
            self.whitelist_ips = set(ips)

    # ── Internal callback ─────────────────────────────────────────

    def _on_event_callback(self, reason, context, event_handle):
        """
        Called by EvtSubscribe for each matching event.
        Runs on a win32 thread — keep it fast.
        """
        if reason != win32evtlog.EvtSubscribeActionDeliver:
            return

        if not self._running:
            return

        try:
            event = self._parse_event(event_handle)
            if event is None:
                return  # filtered out

            # Apply whitelist filter
            src_ip = event.get("source_ip", "")
            if src_ip and src_ip in self.whitelist_ips:
                self._stats["events_filtered"] += 1
                return

            # Apply account filter
            username = event.get("username", "")
            if self._is_ignored_account(username):
                self._stats["events_filtered"] += 1
                return

            # Apply logon type filter (for Event 4624)
            logon_type = event.get("logon_type")
            if logon_type is not None and logon_type in IGNORED_LOGON_TYPES:
                self._stats["events_filtered"] += 1
                return

            self._stats["events_processed"] += 1

            # Forward to threat engine (non-blocking)
            try:
                self.on_event(event)
            except Exception as e:
                log(f"[EVENTLOG] on_event callback error: {e}")

        except Exception as e:
            self._stats["errors"] += 1
            log(f"[EVENTLOG] Event parse error: {e}")

    # ── Event Parsing ─────────────────────────────────────────────

    def _parse_event(self, handle) -> Optional[dict]:
        """
        Render event to XML and extract structured data.
        Returns None if event should be filtered.
        """
        try:
            xml_str = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)

            # XML namespaces
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            # System section
            system = root.find("e:System", ns)
            if system is None:
                return None

            event_id_el = system.find("e:EventID", ns)
            event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

            channel_el = system.find("e:Channel", ns)
            channel = channel_el.text if channel_el is not None else ""

            time_el = system.find("e:TimeCreated", ns)
            timestamp = time_el.get("SystemTime", "") if time_el is not None else ""

            computer_el = system.find("e:Computer", ns)
            computer = computer_el.text if computer_el is not None else ""

            provider_el = system.find("e:Provider", ns)
            provider = provider_el.get("Name", "") if provider_el is not None else ""

            # EventData section — varies per event
            event_data = {}
            data_section = root.find("e:EventData", ns)
            if data_section is not None:
                for data_el in data_section.findall("e:Data", ns):
                    name = data_el.get("Name", "")
                    value = data_el.text or ""
                    if name:
                        event_data[name] = value

            # Build structured result
            event_type = EVENT_TYPE_MAP.get(event_id, f"unknown_{event_id}")

            result = {
                "event_id": event_id,
                "event_type": event_type,
                "channel": channel,
                "timestamp": timestamp,
                "computer": computer,
                "provider": provider,
                # Extracted fields (may be empty depending on event type)
                "source_ip": self._extract_ip(event_data, event_id),
                "username": self._extract_username(event_data, event_id),
                "logon_type": self._extract_logon_type(event_data, event_id),
                "target_service": self._detect_service(event_id, channel, event_data),
                "target_port": self._detect_port(event_id, event_data),
                "process_name": event_data.get("NewProcessName", event_data.get("ProcessName", "")),
                "service_name": event_data.get("ServiceName", ""),
                "raw_data": event_data,
            }

            return result

        except Exception as e:
            log(f"[EVENTLOG] XML parse error: {e}")
            return None

    # ── Field Extractors ──────────────────────────────────────────

    @staticmethod
    def _extract_ip(data: dict, event_id: int) -> str:
        """Extract source IP from event data."""
        # Security log events
        ip = data.get("IpAddress", "")
        if ip and ip not in ("-", "::1", "127.0.0.1", ""):
            return ip

        # MSSQL events often have client info in message text
        if event_id in (18453, 18456):
            # Pattern: "CLIENT: 1.2.3.4"
            for key in ("Message", "EventMessage"):
                msg = data.get(key, "")
                if "CLIENT:" in msg.upper():
                    parts = msg.upper().split("CLIENT:")
                    if len(parts) > 1:
                        ip_part = parts[1].strip().strip("[]").split("]")[0].strip()
                        if ip_part and ip_part not in ("-", "::1", "127.0.0.1"):
                            return ip_part

        # RDP events
        if event_id == 1149:
            return data.get("Param3", data.get("IpAddress", ""))

        return ""

    @staticmethod
    def _extract_username(data: dict, event_id: int) -> str:
        """Extract target username from event data."""
        # Standard logon events
        username = data.get("TargetUserName", "")
        if not username:
            username = data.get("SubjectUserName", "")
        if not username:
            username = data.get("UserName", "")

        # MSSQL — login name from event data
        if event_id in (18453, 18456) and not username:
            username = data.get("Param1", "")

        # RDP 1149
        if event_id == 1149:
            username = data.get("Param1", username)

        return username

    @staticmethod
    def _extract_logon_type(data: dict, event_id: int) -> Optional[int]:
        """Extract logon type (only for Event 4624/4625)."""
        if event_id not in (4624, 4625):
            return None
        lt_str = data.get("LogonType", "")
        try:
            return int(lt_str) if lt_str else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _detect_service(event_id: int, channel: str, data: dict) -> str:
        """Infer which service is being targeted based on event source."""
        if event_id in (18453, 18456, 15457, 17135):
            return "MSSQL"
        if event_id in (1149, 21, 24, 25) or "TerminalServices" in channel:
            return "RDP"
        if event_id in (4624, 4625):
            logon_type = data.get("LogonType", "")
            try:
                lt = int(logon_type) if logon_type else 0
            except (ValueError, TypeError):
                lt = 0
            if lt == 10:
                return "RDP"
            if lt == 3:
                return "Network"
        return "System"

    @staticmethod
    def _detect_port(event_id: int, data: dict) -> int:
        """Infer target port if possible."""
        if event_id in (18453, 18456, 15457, 17135):
            return 1433
        if event_id in (1149, 21, 24, 25):
            return 3389
        if event_id in (4624, 4625):
            logon_type = data.get("LogonType", "")
            try:
                lt = int(logon_type) if logon_type else 0
            except (ValueError, TypeError):
                lt = 0
            if lt == 10:
                return 3389
        return 0

    @staticmethod
    def _is_ignored_account(username: str) -> bool:
        """Check if username is a system/machine account to ignore."""
        if not username:
            return True
        upper = username.upper()
        if upper in IGNORED_ACCOUNTS:
            return True
        if upper.endswith("$"):  # Machine accounts
            return True
        for prefix in IGNORED_ACCOUNT_PREFIXES:
            if upper.startswith(prefix.upper()):
                return True
        return False
