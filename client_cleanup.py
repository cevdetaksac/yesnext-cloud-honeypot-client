#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Data Cleanup — yerel + firewall + sunucu/dashboard senkronu.

Scopes:
  local     — IP pool, session stats, dedup, threats.log
  firewall  — HP-BLOCK-* kuralları + auto_response + sync-rules([])
  server    — POST /api/agent/clear-data (attacks/blocks/alerts)
  all       — hepsi

Auto limits:
  enforce_firewall_limit(max_rules)
  enforce_ip_pool_limit(max_ips)
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from client_helpers import log
from client_utils import get_from_config

# Defaults (overridable via client_config.json → cleanup.*)
DEFAULT_MAX_FIREWALL_RULES = 500
DEFAULT_MAX_IP_POOL = 8000
DEFAULT_AUTO_ENFORCE_INTERVAL = 3600  # 1h


class DataCleanupManager:
    """Bakım / temizlik işlemleri — GUI ve otomatik limitler için."""

    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()
        self._auto_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._stats = {
            "local_runs": 0,
            "firewall_runs": 0,
            "server_runs": 0,
            "rules_removed": 0,
            "last_result": {},
        }

    # ── Public API ────────────────────────────────────────────────

    def clear_local(self) -> Dict[str, Any]:
        """Bellek + yerel log temizliği (API yok)."""
        result = {
            "ip_pool_cleared": 0,
            "session_reset": False,
            "dedup_cleared": False,
            "threats_log_cleared": False,
            "fp_tuner_cleared": False,
        }
        with self._lock:
            te = getattr(self.app, "threat_engine", None)
            if te and hasattr(te, "clear_contexts"):
                result["ip_pool_cleared"] = te.clear_contexts()
            elif te and hasattr(te, "_ip_pool"):
                with te._lock:
                    n = len(te._ip_pool)
                    te._ip_pool.clear()
                    if hasattr(te, "_rule_blocked_ips"):
                        te._rule_blocked_ips.clear()
                    if hasattr(te, "_rdp_grace"):
                        te._rdp_grace.clear()
                result["ip_pool_cleared"] = n
                log(f"[CLEANUP] Threat IP pool cleared ({n})")

            sm = getattr(self.app, "service_manager", None)
            if sm and hasattr(sm, "session_stats"):
                with sm._stats_lock:
                    sm.session_stats = {
                        "total_credentials": 0,
                        "per_service": {},
                        "last_attack_ts": None,
                        "last_attacker_ip": None,
                        "last_service": None,
                        "unique_ips": set(),
                    }
                result["session_reset"] = True

            ap = getattr(self.app, "alert_pipeline", None)
            if ap:
                if hasattr(ap, "_dedup"):
                    ap._dedup.clear()
                    result["dedup_cleared"] = True
                if hasattr(ap, "_batch_buffer"):
                    with getattr(ap, "_batch_lock", threading.Lock()):
                        ap._batch_buffer.clear()

            fp = getattr(self.app, "fp_tuner", None)
            if fp and hasattr(fp, "cleanup_stale"):
                try:
                    fp.cleanup_stale(0)
                    result["fp_tuner_cleared"] = True
                except Exception:
                    pass

            result["threats_log_cleared"] = self._truncate_threats_log()

            # GUI counters
            if hasattr(self.app, "_last_attack_count"):
                # Keep server count until refresh; session card will show 0
                pass

            self._stats["local_runs"] += 1
            self._stats["last_result"] = result
            log(f"[CLEANUP] Local cleanup done: {result}")
            return result

    def clear_firewall(self, sync_dashboard: bool = True) -> Dict[str, Any]:
        """Tüm HP-BLOCK-* kurallarını sil + dashboard sync (boş liste)."""
        result = {
            "rules_removed": 0,
            "auto_blocks_cleared": 0,
            "api_synced": False,
            "server_cleared": False,
        }
        with self._lock:
            # Auto-response memory
            ar = getattr(self.app, "auto_response", None)
            if ar and hasattr(ar, "clear_all_blocks"):
                result["auto_blocks_cleared"] = ar.clear_all_blocks()
            elif ar and hasattr(ar, "_blocks"):
                with ar._lock:
                    n = len(ar._blocks)
                    # Remove firewall rules for each
                    ips = list(ar._blocks.keys())
                    ar._blocks.clear()
                for ip in ips:
                    try:
                        ar.unblock_ip(ip)
                    except Exception:
                        pass
                result["auto_blocks_cleared"] = n

            # Scan & delete all HP-BLOCK / legacy rules
            removed = self._delete_all_hp_block_rules()
            result["rules_removed"] = removed
            self._stats["rules_removed"] += removed

            if sync_dashboard:
                token = self._token()
                api = getattr(self.app, "api_client", None)
                if token and api:
                    # Empty sync = dashboard blok listesi sıfır
                    ok = api.sync_firewall_rules(token, [])
                    result["api_synced"] = bool(ok)
                    # Also clear server-side block records
                    cleared = api.clear_client_data(
                        token, scopes=["blocks"], reason="firewall_cleanup",
                    )
                    result["server_cleared"] = cleared is not None
                    result["server_response"] = cleared

            self._stats["firewall_runs"] += 1
            self._stats["last_result"] = result
            log(f"[CLEANUP] Firewall cleanup done: {result}")
            return result

    def clear_server(self, scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Sunucu/dashboard saldırı + alert + blok kayıtlarını temizle."""
        scopes = scopes or ["attacks", "blocks", "alerts", "threat_summary"]
        result = {"ok": False, "scopes": scopes, "response": None, "error": None}
        token = self._token()
        api = getattr(self.app, "api_client", None)
        if not token or not api:
            result["error"] = "no_token_or_api"
            return result
        try:
            resp = api.clear_client_data(token, scopes=scopes, reason="user_requested_cleanup")
            result["response"] = resp
            result["ok"] = resp is not None
            if result["ok"]:
                self._stats["server_runs"] += 1
                # Refresh attack count card
                try:
                    self.app.refresh_attack_count(async_thread=True)
                except Exception:
                    pass
            else:
                result["error"] = "api_rejected_or_missing_endpoint"
            log(f"[CLEANUP] Server clear: {result}")
        except Exception as e:
            result["error"] = str(e)
            log(f"[CLEANUP] Server clear error: {e}")
        self._stats["last_result"] = result
        return result

    def clear_all(self) -> Dict[str, Any]:
        """Yerel + firewall + sunucu — tam bakım."""
        out = {
            "local": self.clear_local(),
            "firewall": self.clear_firewall(sync_dashboard=True),
            "server": self.clear_server(
                scopes=["attacks", "blocks", "alerts", "threat_summary", "all"]
            ),
        }
        log(f"[CLEANUP] Full cleanup finished")
        return out

    def enforce_limits(self) -> Dict[str, Any]:
        """Otomatik limit: max firewall kuralı + IP pool boyutu."""
        max_rules = int(get_from_config(
            "cleanup.max_firewall_rules", DEFAULT_MAX_FIREWALL_RULES))
        max_ips = int(get_from_config(
            "cleanup.max_ip_pool", DEFAULT_MAX_IP_POOL))
        out = {
            "firewall_trimmed": 0,
            "ip_pool_trimmed": 0,
        }
        out["firewall_trimmed"] = self._trim_firewall_rules(max_rules)
        te = getattr(self.app, "threat_engine", None)
        if te and hasattr(te, "_cleanup_stale_contexts"):
            before = 0
            try:
                with te._lock:
                    before = len(te._ip_pool)
            except Exception:
                pass
            te._cleanup_stale_contexts()
            # Extra hard cap
            try:
                with te._lock:
                    if len(te._ip_pool) > max_ips:
                        items = sorted(
                            te._ip_pool.items(),
                            key=lambda x: x[1].last_seen,
                        )
                        drop = len(te._ip_pool) - max_ips
                        for ip, ctx in items[:drop]:
                            if ip != "local" and not getattr(ctx, "is_blocked", False):
                                del te._ip_pool[ip]
                                out["ip_pool_trimmed"] += 1
            except Exception as e:
                log(f"[CLEANUP] IP pool trim error: {e}")
        if out["firewall_trimmed"] or out["ip_pool_trimmed"]:
            log(f"[CLEANUP] Auto limits enforced: {out}")
        return out

    def start_auto_enforcer(self):
        """Periyodik limit enforcer (daemon)."""
        if not get_from_config("cleanup.auto_enforce", True):
            return
        if self._auto_thread and self._auto_thread.is_alive():
            return
        self._stop.clear()
        interval = int(get_from_config(
            "cleanup.auto_enforce_interval_seconds", DEFAULT_AUTO_ENFORCE_INTERVAL))

        def _loop():
            # İlk çalıştırma biraz gecikmeli (startup yükü olmasın)
            for _ in range(min(60, interval)):
                if self._stop.is_set():
                    return
                time.sleep(1)
            while not self._stop.is_set():
                try:
                    self.enforce_limits()
                except Exception as e:
                    log(f"[CLEANUP] Auto enforce error: {e}")
                for _ in range(interval):
                    if self._stop.is_set():
                        return
                    time.sleep(1)

        self._auto_thread = threading.Thread(
            target=_loop, daemon=True, name="CleanupEnforcer",
        )
        self._auto_thread.start()
        log(f"[CLEANUP] Auto enforcer started (every {interval}s)")

    def stop(self):
        self._stop.set()

    def get_stats(self) -> dict:
        return dict(self._stats)

    # ── Internals ─────────────────────────────────────────────────

    def _token(self) -> str:
        try:
            return self.app.state.get("token") or ""
        except Exception:
            return ""

    def _truncate_threats_log(self) -> bool:
        try:
            from client_constants import APP_DIR, ALERT_THREAT_LOG_FILE
            path = os.path.join(APP_DIR, ALERT_THREAT_LOG_FILE)
            if os.path.isfile(path):
                open(path, "w", encoding="utf-8").close()
                return True
            # Also try threats.log next to exe / cwd
            for alt in (
                os.path.join(os.getcwd(), "threats.log"),
                os.path.join(APP_DIR, "threats.log"),
            ):
                if os.path.isfile(alt):
                    open(alt, "w", encoding="utf-8").close()
                    return True
        except Exception as e:
            log(f"[CLEANUP] threats.log truncate error: {e}")
        return False

    def _delete_all_hp_block_rules(self) -> int:
        """netsh ile tüm HP-BLOCK / legacy kuralları sil."""
        removed = 0
        try:
            from client_firewall import WindowsFirewallBackend, is_windows, run_cmd
            if not is_windows():
                return 0
            backend = WindowsFirewallBackend(logger=_CleanupLogger())
            rules = backend.scan_existing_rules()
            for r in rules:
                name = r.get("name") or ""
                if not name:
                    continue
                rc, out, err = run_cmd([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}", "dir=in",
                ])
                if rc == 0 and "0 rule" not in (out or "").lower():
                    removed += 1
            log(f"[CLEANUP] Removed {removed}/{len(rules)} firewall rules")
        except Exception as e:
            log(f"[CLEANUP] Firewall rule purge error: {e}")
        return removed

    def _trim_firewall_rules(self, max_rules: int) -> int:
        """Max üstü en eski HP-BLOCK kurallarını sil (FIFO by name scan order)."""
        trimmed = 0
        try:
            from client_firewall import WindowsFirewallBackend, is_windows, run_cmd
            if not is_windows():
                return 0
            backend = WindowsFirewallBackend(logger=_CleanupLogger())
            rules = backend.scan_existing_rules()
            if len(rules) <= max_rules:
                return 0
            # Prefer auto_response IP-named rules for trim; keep numeric dashboard IDs longer
            def _priority(r):
                name = r.get("name", "")
                suffix = name.replace("HP-BLOCK-", "").replace("HONEYPOT_THREAT_BLOCK_", "")
                return (0 if any(c.isalpha() for c in suffix.replace(".", "").replace("_", "")) else 1, name)

            ordered = sorted(rules, key=_priority)
            excess = len(rules) - max_rules
            for r in ordered[:excess]:
                name = r.get("name") or ""
                rc, out, _ = run_cmd([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}", "dir=in",
                ])
                if rc == 0 and "0 rule" not in (out or "").lower():
                    trimmed += 1
                    # Drop from auto_response memory if IP rule
                    ip = r.get("ip") or r.get("remoteip", "").split("/")[0]
                    ar = getattr(self.app, "auto_response", None)
                    if ar and ip and hasattr(ar, "_blocks"):
                        with ar._lock:
                            ar._blocks.pop(ip, None)
            if trimmed:
                token = self._token()
                api = getattr(self.app, "api_client", None)
                if token and api:
                    # Re-sync remaining
                    remaining = backend.scan_existing_rules()
                    blocks = []
                    for r in remaining:
                        ip = r.get("ip") or (r.get("remoteip") or "").split("/")[0]
                        if ip:
                            blocks.append({
                                "ip": ip,
                                "rule_name": r.get("name", ""),
                                "source": "auto_response",
                                "reason": "trim_sync",
                            })
                    api.sync_firewall_rules(token, blocks)
                log(f"[CLEANUP] Trimmed {trimmed} firewall rules (max={max_rules})")
        except Exception as e:
            log(f"[CLEANUP] Firewall trim error: {e}")
        return trimmed


class _CleanupLogger:
    def info(self, msg): log(f"[CLEANUP] {msg}")
    def warning(self, msg): log(f"[CLEANUP] ⚠ {msg}")
    def error(self, msg): log(f"[CLEANUP] ❌ {msg}")
    def exception(self, msg): log(f"[CLEANUP] ❌ {msg}")
