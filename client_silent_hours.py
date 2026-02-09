#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Silent Hours Guard (v4.0)

Mesai dışı saatlerde beyaz listede olmayan tüm başarılı girişleri
otomatik olarak engeller.

Akış:
  1. EventLogWatcher başarılı logon tespit eder
  2. SilentHoursGuard.check(event) çağrılır
  3. is_silent_now() → Evet ise ve IP whitelist'te değilse
  4. → block_ip + logoff_user + disable_account + send_alert

Modlar:
  DISABLED         — Kapalı
  NIGHT_ONLY       — Sadece gece saatleri (varsayılan 00:00-07:00)
  OUTSIDE_WORKING  — Mesai dışı tüm saatler (08:00-18:00 dışı)
  ALWAYS           — 7/24 (yalnızca whitelist erişebilir)
  CUSTOM           — Gün bazlı özel takvim

Güvenlik:
  - Whitelist IP + Subnet kontrolü
  - Gece-yarısını geçen saat aralıkları desteklenir
  - Hafta sonu tüm gün sessiz modu
  - Dashboard'dan config çekilir (GET /api/threats/config)
  - "Bu Benim" düğmesi ile hızlı whitelist ekleme

Exports:
  SilentHoursMode   — Enum
  SilentHoursConfig — Dataclass
  SilentHoursGuard  — Main class (check / is_silent_now / is_whitelisted)
"""

import datetime
import ipaddress
import threading
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from client_helpers import log


# ── Enums ─────────────────────────────────────────────────────────

class SilentHoursMode(Enum):
    DISABLED = "disabled"
    NIGHT_ONLY = "night_only"
    OUTSIDE_WORKING = "outside_working"
    ALWAYS = "always"
    CUSTOM = "custom"


# ── Configuration ─────────────────────────────────────────────────

@dataclass
class SilentHoursConfig:
    """Dashboard'dan ayarlanabilir Silent Hours konfigürasyonu."""

    enabled: bool = True
    mode: SilentHoursMode = SilentHoursMode.NIGHT_ONLY

    # Night mode bounds
    night_start: str = "00:00"   # default midnight
    night_end: str = "07:00"     # default 7 AM

    # Working hours (for OUTSIDE_WORKING mode)
    work_start: str = "08:00"
    work_end: str = "18:00"
    work_days: List[int] = field(default_factory=lambda: [0, 1, 2, 3, 4])  # Mon-Fri

    # Custom schedule  e.g. {"monday": [{"start": "00:00", "end": "08:00"}, ...]}
    custom_schedule: Dict[str, list] = field(default_factory=dict)

    # Weekend policy
    weekend_all_day_silent: bool = True

    # Auto-actions
    auto_block_ip: bool = True
    auto_logoff: bool = True
    auto_disable_account: bool = True
    block_duration_hours: int = 0  # 0 = permanent (until admin clears)

    # Whitelist (managed from dashboard)
    whitelist_ips: List[str] = field(default_factory=list)
    whitelist_subnets: List[str] = field(default_factory=list)

    # Alert settings
    alert_on_block: bool = True
    alert_severity: str = "critical"

    @classmethod
    def from_dict(cls, data: dict) -> "SilentHoursConfig":
        """Build config from API response dict."""
        cfg = cls()
        if not isinstance(data, dict):
            return cfg

        cfg.enabled = data.get("enabled", cfg.enabled)

        mode_str = data.get("mode", "")
        for m in SilentHoursMode:
            if m.value == mode_str:
                cfg.mode = m
                break

        cfg.night_start = data.get("night_start", cfg.night_start)
        cfg.night_end = data.get("night_end", cfg.night_end)
        cfg.work_start = data.get("work_start", cfg.work_start)
        cfg.work_end = data.get("work_end", cfg.work_end)
        cfg.work_days = data.get("work_days", cfg.work_days)
        cfg.custom_schedule = data.get("custom_schedule", cfg.custom_schedule)
        cfg.weekend_all_day_silent = data.get("weekend_all_day_silent", cfg.weekend_all_day_silent)
        cfg.auto_block_ip = data.get("auto_block_ip", cfg.auto_block_ip)
        cfg.auto_logoff = data.get("auto_logoff", cfg.auto_logoff)
        cfg.auto_disable_account = data.get("auto_disable_account", cfg.auto_disable_account)
        cfg.block_duration_hours = data.get("block_duration_hours", cfg.block_duration_hours)
        cfg.whitelist_ips = data.get("whitelist_ips", cfg.whitelist_ips)
        cfg.whitelist_subnets = data.get("whitelist_subnets", cfg.whitelist_subnets)
        cfg.alert_on_block = data.get("alert_on_block", cfg.alert_on_block)
        cfg.alert_severity = data.get("alert_severity", cfg.alert_severity)

        return cfg


# ── Day name mapping for custom schedule ──────────────────────────

_DAY_NAMES = {
    0: "monday", 1: "tuesday", 2: "wednesday", 3: "thursday",
    4: "friday", 5: "saturday", 6: "sunday",
}


# ── Silent Hours Guard ────────────────────────────────────────────

class SilentHoursGuard:
    """
    Sessiz saatlerde beyaz listede olmayan başarılı girişleri engeller.

    Usage:
        guard = SilentHoursGuard(auto_response=ar, alert_pipeline=ap)
        guard.update_config(config_dict_from_api)

        # Called by EventLogWatcher on successful logon:
        if guard.check(event):
            # Already blocked, no further action needed
    """

    def __init__(
        self,
        auto_response=None,
        alert_pipeline=None,
    ):
        self.auto_response = auto_response
        self.alert_pipeline = alert_pipeline
        self.config = SilentHoursConfig()

        # Stats
        self._stats = {
            "checks": 0,
            "blocks": 0,
            "whitelisted_passes": 0,
            "outside_silent_passes": 0,
        }

        # Recent blocks log (last 50)
        self._recent_blocks: deque = deque(maxlen=50)

        self._lock = threading.Lock()

    # ── Config Management ─────────────────────────────────────────

    def update_config(self, data: dict):
        """Update config from API response."""
        with self._lock:
            self.config = SilentHoursConfig.from_dict(data)
        log(f"[SILENT-HOURS] Config updated — mode={self.config.mode.value}, "
            f"enabled={self.config.enabled}")

    def add_whitelist_ip(self, ip: str):
        """Quick-add an IP to the whitelist ('Bu Benim' action)."""
        with self._lock:
            if ip not in self.config.whitelist_ips:
                self.config.whitelist_ips.append(ip)
                log(f"[SILENT-HOURS] ✅ IP whitelisted: {ip}")

    def remove_whitelist_ip(self, ip: str):
        """Remove an IP from the whitelist."""
        with self._lock:
            if ip in self.config.whitelist_ips:
                self.config.whitelist_ips.remove(ip)
                log(f"[SILENT-HOURS] 🗑️ IP removed from whitelist: {ip}")

    # ── Core Logic ────────────────────────────────────────────────

    def is_silent_now(self) -> bool:
        """Is the current moment within a silent hours window?"""
        now = datetime.datetime.now()

        if self.config.mode == SilentHoursMode.DISABLED:
            return False

        if self.config.mode == SilentHoursMode.ALWAYS:
            return True

        # Weekend override
        if self.config.weekend_all_day_silent and now.weekday() >= 5:
            return True

        if self.config.mode == SilentHoursMode.NIGHT_ONLY:
            return self._in_time_range(
                now.time(),
                self.config.night_start,
                self.config.night_end,
            )

        if self.config.mode == SilentHoursMode.OUTSIDE_WORKING:
            if now.weekday() not in self.config.work_days:
                return True
            return not self._in_time_range(
                now.time(),
                self.config.work_start,
                self.config.work_end,
            )

        if self.config.mode == SilentHoursMode.CUSTOM:
            return self._check_custom_schedule(now)

        return False

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is in the whitelist or a trusted subnet."""
        if ip in self.config.whitelist_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in self.config.whitelist_subnets:
                try:
                    if addr in ipaddress.ip_network(subnet_str, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def check(self, event: dict) -> bool:
        """
        Evaluate a successful logon event.

        If we are in silent hours and the source IP is NOT whitelisted,
        trigger automatic defensive actions (block + logoff + disable).

        Returns True if the logon was blocked, False if allowed.
        """
        self._stats["checks"] += 1

        if not self.config.enabled:
            return False

        if not self.is_silent_now():
            self._stats["outside_silent_passes"] += 1
            return False

        source_ip = event.get("source_ip", "")
        if not source_ip:
            return False

        if self.is_whitelisted(source_ip):
            self._stats["whitelisted_passes"] += 1
            return False

        # ⚡ SILENT HOURS VIOLATION — auto-block
        username = event.get("username", "unknown")
        service = event.get("target_service", "unknown")

        log(
            f"[SILENT-HOURS] 🔇 VIOLATION: {source_ip} → {service} "
            f"({username}) — BLOCKING"
        )

        actions_taken = []

        # 1. Block IP via firewall
        if self.config.auto_block_ip and self.auto_response:
            try:
                self.auto_response.block_ip(
                    source_ip,
                    reason=f"Silent hours violation: {service}",
                    duration_hours=self.config.block_duration_hours,
                )
                actions_taken.append("block_ip")
            except Exception as e:
                log(f"[SILENT-HOURS] block_ip error: {e}")

        # 2. Logoff active session
        if self.config.auto_logoff and self.auto_response:
            try:
                self.auto_response.logoff_user(username)
                actions_taken.append("logoff_user")
            except Exception as e:
                log(f"[SILENT-HOURS] logoff error: {e}")

        # 3. Disable account
        if self.config.auto_disable_account and self.auto_response:
            try:
                self.auto_response.disable_account(username)
                actions_taken.append("disable_account")
            except Exception as e:
                log(f"[SILENT-HOURS] disable_account error: {e}")

        # 4. Send critical alert
        if self.config.alert_on_block and self.alert_pipeline:
            try:
                alert_data = {
                    "severity": self.config.alert_severity,
                    "threat_type": "silent_hours_violation",
                    "title": (
                        f"🔇 Sessiz Saat İhlali — {service} girişi engellendi"
                    ),
                    "description": (
                        f"Sessiz saatlerde {source_ip} adresinden {service} "
                        f"servisine başarılı giriş tespit edildi. "
                        f"IP beyaz listede olmadığı için otomatik engelleme "
                        f"uygulandı.\n\n"
                        f"Kullanıcı: {username}\n"
                        f"Bu siz miydiniz? Dashboard'dan IP'nizi beyaz listeye ekleyin."
                    ),
                    "source_ip": source_ip,
                    "target_service": service,
                    "username": username,
                    "threat_score": 95,
                    "auto_response_taken": actions_taken,
                }
                self.alert_pipeline.send_urgent(alert_data)
            except Exception as e:
                log(f"[SILENT-HOURS] alert error: {e}")

        # Record
        self._stats["blocks"] += 1
        self._recent_blocks.append({
            "ip": source_ip,
            "username": username,
            "service": service,
            "actions": actions_taken,
            "timestamp": datetime.datetime.now().isoformat(),
        })

        return True

    # ── Stats / History ───────────────────────────────────────────

    def get_stats(self) -> dict:
        return dict(self._stats)

    def get_recent_blocks(self) -> list:
        return list(self._recent_blocks)

    def get_status(self) -> dict:
        """Dashboard-friendly status summary."""
        return {
            "enabled": self.config.enabled,
            "mode": self.config.mode.value,
            "is_silent_now": self.is_silent_now(),
            "whitelist_count": len(self.config.whitelist_ips) + len(self.config.whitelist_subnets),
            "total_blocks": self._stats["blocks"],
        }

    # ── Time Helpers ──────────────────────────────────────────────

    @staticmethod
    def _in_time_range(current: datetime.time, start_str: str, end_str: str) -> bool:
        """
        Check whether *current* falls within [start, end].
        Handles midnight-crossing ranges (e.g. 22:00 → 06:00).
        """
        start = datetime.time.fromisoformat(start_str)
        end = datetime.time.fromisoformat(end_str)

        if start <= end:
            # Normal range, e.g. 08:00 → 18:00
            return start <= current <= end
        else:
            # Crosses midnight, e.g. 22:00 → 06:00
            return current >= start or current <= end

    def _check_custom_schedule(self, now: datetime.datetime) -> bool:
        """Evaluate the custom per-day schedule."""
        day_name = _DAY_NAMES.get(now.weekday(), "")
        ranges = self.config.custom_schedule.get(day_name, [])

        for rng in ranges:
            start_str = rng.get("start", "")
            end_str = rng.get("end", "")
            if start_str and end_str:
                if self._in_time_range(now.time(), start_str, end_str):
                    return True
        return False
