#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Alert Pipeline (v4.0)

Receives alerts from ThreatEngine and routes them through appropriate
notification channels based on severity:

  info     (0-30)  → local log + dashboard update (batch 5min)
  warning  (31-60) → API batch + GUI toast (batch 1min)
  high     (61-80) → API instant + GUI popup (< 5s)
  critical (81-100)→ API instant + GUI popup (< 2s)

Channels:
  1. API Urgent    — immediate POST to /api/alerts/urgent
  2. API Batch     — buffered POST to /api/events/batch
  3. GUI Toast     — desktop notification via CustomTkinter
  4. Tray Popup    — Windows balloon via pystray
  5. Local Log     — threats.log (RotatingFileHandler)

Includes deduplication and rate limiting per IP+threat_type.

Exports:
  AlertPipeline — main pipeline class (handle_alert / start / stop)
"""

import json
import logging
import os
import socket
import threading
import time
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Dict, List, Optional, Set

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

# Rate limiting: same threat_type + source_ip → max 1 urgent / 5 min (V4)
ALERT_COOLDOWN = {
    "critical": 300,     # 5 min
    "high":     300,     # 5 min
    "warning":  900,     # 15 min
    "info":     3600,    # 1 hour
}

# Batch buffer flush intervals (seconds)
BATCH_INTERVALS = {
    "info":    120,       # 2 min
    "warning": 120,       # 2 min
}

# Max alerts to buffer before force-flush (V4)
BATCH_MAX_SIZE = 500
BATCH_FLUSH_SECONDS = 120
URGENT_RETRY_DELAY = 30
URGENT_MAX_RETRIES = 3

# Map threat_type → events/batch category
_THREAT_CATEGORY = {
    "failed_logon": "failed_logon",
    "brute_force": "failed_logon",
    "brute_force_detected": "failed_logon",
    "successful_logon": "successful_logon",
    "rdp_logon": "successful_logon",
    "account_created": "account_created",
    "new_admin_account": "account_created",
    "account_modified": "account_modified",
    "audit_log_cleared": "log_cleared",
    "log_cleared": "log_cleared",
    "service_installed": "service_state_change",
    "service_state_change": "service_state_change",
    "firewall_change": "firewall_change",
    "suspicious_process": "suspicious_process",
    "honeypot_connection": "honeypot_connection",
    "ransomware_canary_triggered": "suspicious_process",
    "vss_shadow_deleted": "suspicious_process",
}

# Local threat log config
THREAT_LOG_FILE = "threats.log"
THREAT_LOG_MAX_BYTES = 5 * 1024 * 1024   # 5 MB
THREAT_LOG_BACKUP_COUNT = 3


# ── Alert Pipeline ────────────────────────────────────────────────

class AlertPipeline:
    """
    Routes threat alerts to appropriate notification channels.

    Usage:
        pipeline = AlertPipeline(
            api_client=api_client,
            token_getter=lambda: state.get("token", ""),
            gui_toast_func=gui.show_toast,
            tray_notify_func=tray.notify,
        )
        pipeline.start()
        # ... alerts fed via handle_alert() from ThreatEngine ...
        pipeline.stop()
    """

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        gui_toast_func: Optional[Callable] = None,
        tray_notify_func: Optional[Callable] = None,
        machine_name: Optional[str] = None,
        auto_response=None,
    ):
        """
        Args:
            api_client:       HoneypotAPIClient instance for API calls.
            token_getter:     Callable returning current auth token.
            gui_toast_func:   Callable(title, message, severity) for GUI toast.
            tray_notify_func: Callable(title, message) for tray balloon.
            machine_name:     This machine's hostname.
            auto_response:    AutoResponse instance for executing block/logoff/disable.
        """
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.gui_toast_func = gui_toast_func
        self.tray_notify_func = tray_notify_func
        self.machine_name = machine_name or socket.gethostname()
        self.auto_response = auto_response

        # Batch buffers
        self._batch_buffer: List[dict] = []
        self._batch_lock = threading.Lock()

        # Dedup tracker: key=(ip, threat_type) → last_alert_time
        self._dedup: Dict[str, float] = {}

        # Local threat logger
        self._threat_logger = self._setup_threat_logger()

        # Running state
        self._running = False
        self._batch_thread: Optional[threading.Thread] = None

        # Stats
        self._stats = {
            "alerts_received": 0,
            "alerts_sent_urgent": 0,
            "alerts_sent_batch": 0,
            "alerts_deduplicated": 0,
            "alerts_gui": 0,
            "alerts_tray": 0,
            "errors": 0,
        }

    # ── Public API ────────────────────────────────────────────────

    def start(self):
        """Start the batch flush thread."""
        if self._running:
            return
        self._running = True
        self._batch_thread = threading.Thread(
            target=self._batch_flush_loop,
            name="AlertPipeline-BatchFlush",
            daemon=True,
        )
        self._batch_thread.start()
        log("[ALERTS] 🚀 Alert pipeline started")

    def stop(self):
        """Stop pipeline and flush remaining batch."""
        if not self._running:
            return
        self._running = False
        # Final flush
        self._flush_batch()
        log("[ALERTS] ✅ Alert pipeline stopped")

    def handle_alert(self, alert: dict):
        """
        Main entry point — routes alert based on severity.
        Called by ThreatEngine when threshold is exceeded.
        """
        self._stats["alerts_received"] += 1
        severity = alert.get("severity", "info")

        # Deduplication check
        dedup_key = f"{alert.get('source_ip', '')}:{alert.get('threat_type', '')}"
        now = time.time()
        cooldown = ALERT_COOLDOWN.get(severity, 300)
        last_time = self._dedup.get(dedup_key, 0)
        if now - last_time < cooldown:
            self._stats["alerts_deduplicated"] += 1
            return
        self._dedup[dedup_key] = now

        # Enrich alert with machine info
        alert["machine_name"] = self.machine_name
        alert["client_token"] = self.token_getter()

        # Always log locally
        self._log_threat(alert)

        # Execute auto-response actions (block_ip, logoff, disable_account)
        actions = alert.get("auto_response", [])
        if actions and self.auto_response:
            self._execute_auto_response(actions, alert)

        # Route based on severity
        if severity in ("critical", "high"):
            self._send_urgent(alert)
            self._notify_gui(alert)
            self._notify_tray(alert)
        elif severity == "warning":
            self._buffer_for_batch(alert)
            self._notify_gui(alert)
        else:  # info
            self._buffer_for_batch(alert)

    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        stats = dict(self._stats)
        stats["dedup_table_size"] = len(self._dedup)
        return stats

    def get_dedup_size(self) -> int:
        """Return current dedup table size for memory monitoring."""
        return len(self._dedup)

    def send_urgent(self, alert_data: dict):
        """Public method to send an urgent alert directly (used by RansomwareShield etc)."""
        self._send_urgent(alert_data)

    def get_recent_alerts(self, count: int = 20) -> List[dict]:
        """Get recent alerts from the batch buffer for dashboard display."""
        with self._batch_lock:
            return list(self._batch_buffer[-count:])

    # ── Auto-Response Execution ────────────────────────────────

    def _execute_auto_response(self, actions: List[str], alert: dict):
        """Execute auto-response actions from threat correlation rules.

        Supported actions:
          - block_ip:        Block source IP via Windows Firewall
          - logoff_user:     Force logoff the attacker session
          - disable_account: Disable the targeted user account
          - notify_urgent:   (handled separately in routing)
        """
        source_ip = alert.get("source_ip", "")
        username = alert.get("username", "")
        reason = (f"{alert.get('correlation_rule', '')} — "
                  f"{alert.get('title', 'Threat detected')}")

        for action in actions:
            try:
                if action == "block_ip" and source_ip:
                    ok = self.auto_response.block_ip(
                        source_ip, reason=reason, duration_hours=24
                    )
                    if ok:
                        self._stats.setdefault("auto_blocks", 0)
                        self._stats["auto_blocks"] += 1
                        log(f"[ALERTS] 🚫 Auto-blocked IP: {source_ip} — {reason}")

                elif action == "logoff_user" and username:
                    self.auto_response.logoff_user(username)
                    log(f"[ALERTS] 🚪 Auto-logoff: {username}")

                elif action == "disable_account" and username:
                    self.auto_response.disable_account(username)
                    log(f"[ALERTS] 🔒 Auto-disabled: {username}")

                elif action == "notify_urgent":
                    pass  # Handled in severity routing below

            except Exception as e:
                self._stats["errors"] += 1
                log(f"[ALERTS] ❌ Auto-response '{action}' failed: {e}")

    # ── Urgent Channel (instant API) ──────────────────────────────

    def _send_urgent(self, alert: dict):
        """Send alert immediately to API /api/alerts/urgent (canonical flat payload)."""
        try:
            token = self.token_getter()
            if not token or not self.api_client:
                log("[ALERTS] Cannot send urgent — no token or API client")
                return

            from datetime import datetime, timezone
            import uuid as _uuid

            # Canonical: auto_response_taken must be string[]
            actions = alert.get("auto_response_taken")
            if actions is None:
                actions = alert.get("auto_response", [])
            if isinstance(actions, str):
                actions = [actions] if actions else []
            elif not isinstance(actions, list):
                actions = list(actions) if actions else []
            actions = [str(a) for a in actions if a]

            ts = alert.get("timestamp", time.time())
            if isinstance(ts, (int, float)):
                ts_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            else:
                ts_iso = str(ts)

            try:
                threat_score = int(float(alert.get("threat_score", 0) or 0))
            except (TypeError, ValueError):
                threat_score = 0

            try:
                target_port = int(alert.get("target_port", 0) or 0)
            except (TypeError, ValueError):
                target_port = 0

            payload = {
                "token": token,
                "alert_id": alert.get("alert_id") or str(_uuid.uuid4()),
                "timestamp": ts_iso,
                "severity": alert.get("severity", "warning"),
                "threat_type": alert.get("threat_type", ""),
                "title": alert.get("title", ""),
                "description": alert.get("description", ""),
                "source_ip": alert.get("source_ip", ""),
                "source_country": alert.get("source_country", ""),
                "target_service": alert.get("target_service", ""),
                "target_port": target_port,
                "username": alert.get("username", ""),
                "password": alert.get("password", ""),
                "threat_score": threat_score,
                "event_ids": alert.get("event_ids", []) or [0],
                "correlation_rule": alert.get("correlation_rule", ""),
                "recommended_action": alert.get("recommended_action", ""),
                "auto_response_taken": actions,
                "raw_events": alert.get("raw_events", []) or [],
                "system_context": alert.get("system_context", {}) or {},
            }

            # Retry queue: up to 3 attempts, 30s apart; handle actions_requested
            threading.Thread(
                target=self._send_urgent_with_retry,
                args=(payload,),
                daemon=True,
                name="UrgentAlertRetry",
            ).start()
            self._send_webhook(alert)

        except Exception as e:
            self._stats["errors"] += 1
            log(f"[ALERTS] Urgent send error: {e}")

    def _send_urgent_with_retry(self, payload: dict):
        """POST alerts/urgent with retries; execute actions_requested from response."""
        last_err = None
        for attempt in range(1, URGENT_MAX_RETRIES + 1):
            try:
                response = self.api_client.api_request(
                    "POST", "alerts/urgent", data=payload, timeout=15
                )
                ok = isinstance(response, dict) and response.get("status") in (
                    "ok", "success", "created", "received",
                )
                if ok or response is not None:
                    self._stats["alerts_sent_urgent"] += 1
                    log(f"[ALERTS] ✅ urgent alert sent (attempt {attempt})")
                    self._handle_actions_requested(response if isinstance(response, dict) else {})
                    return
                last_err = f"unexpected response: {response}"
            except Exception as e:
                last_err = str(e)
                self._stats["errors"] += 1
            if attempt < URGENT_MAX_RETRIES:
                log(f"[ALERTS] Urgent retry {attempt}/{URGENT_MAX_RETRIES} in {URGENT_RETRY_DELAY}s — {last_err}")
                time.sleep(URGENT_RETRY_DELAY)
        log(f"[ALERTS] ❌ Urgent alert failed after {URGENT_MAX_RETRIES} attempts: {last_err}")

    def _handle_actions_requested(self, response: dict):
        """Execute server-requested follow-up actions from urgent response."""
        actions = response.get("actions_requested") or []
        if not actions or not self.auto_response:
            return
        # Minimal context for action executor
        alert = {
            "source_ip": "",
            "username": "",
            "threat_type": "server_requested",
        }
        try:
            self._execute_auto_response(list(actions), alert)
            log(f"[ALERTS] Executed actions_requested: {actions}")
        except Exception as e:
            log(f"[ALERTS] actions_requested error: {e}")

    # ── Batch Channel (buffered API) ──────────────────────────────

    def _buffer_for_batch(self, alert: dict):
        """Add alert to batch buffer for periodic sending."""
        with self._batch_lock:
            self._batch_buffer.append(alert)
            # Force flush if buffer is full
            if len(self._batch_buffer) >= BATCH_MAX_SIZE:
                self._flush_batch_locked()

    def _batch_flush_loop(self):
        """Periodically flush the batch buffer and cleanup stale dedup entries."""
        flush_count = 0
        while self._running:
            try:
                time.sleep(BATCH_FLUSH_SECONDS)
                self._flush_batch()
                flush_count += 1
                if flush_count % 15 == 0:  # ~30 min at 120s
                    self._cleanup_dedup()
            except Exception as e:
                log(f"[ALERTS] Batch flush error: {e}")

    def _cleanup_dedup(self):
        """Remove stale dedup entries to prevent unbounded memory growth."""
        now = time.time()
        max_cooldown = max(ALERT_COOLDOWN.values())  # 3600s
        stale_keys = [
            k for k, ts in self._dedup.items()
            if now - ts > max_cooldown * 2
        ]
        if stale_keys:
            for k in stale_keys:
                del self._dedup[k]
            log(f"[ALERTS] 🧹 Cleaned {len(stale_keys)} stale dedup entries "
                f"(remaining: {len(self._dedup)})")

    def _flush_batch(self):
        """Flush batch buffer to API."""
        with self._batch_lock:
            self._flush_batch_locked()

    def _flush_batch_locked(self):
        """Flush batch buffer (must hold _batch_lock) — canonical /api/events/batch.

        On failure, events stay in buffer for the next cycle.
        """
        if not self._batch_buffer:
            return

        events_to_send = list(self._batch_buffer)
        token = self.token_getter()
        if not token or not self.api_client:
            log(f"[ALERTS] Cannot flush batch ({len(events_to_send)} events) — no token/API")
            return

        from datetime import datetime, timezone
        import uuid as _uuid

        def _iso(ts):
            if isinstance(ts, (int, float)):
                return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            return str(ts or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

        events = []
        by_severity: Dict[str, int] = {}
        unique_ips: set = set()
        period_start = None
        period_end = None
        for e in events_to_send:
            event_ids = e.get("event_ids") or [0]
            try:
                win_eid = int(event_ids[0]) if event_ids else 0
            except (TypeError, ValueError, IndexError):
                win_eid = 0
            threat_type = e.get("threat_type", "") or ""
            category = e.get("category") or _THREAT_CATEGORY.get(threat_type, threat_type or "honeypot_connection")
            sev = e.get("severity", "info") or "info"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            sip = e.get("source_ip", "") or ""
            if sip:
                unique_ips.add(sip)
            ts_iso = _iso(e.get("timestamp"))
            if period_start is None or ts_iso < period_start:
                period_start = ts_iso
            if period_end is None or ts_iso > period_end:
                period_end = ts_iso
            events.append({
                "event_id": str(_uuid.uuid4()),
                "timestamp": ts_iso,
                "category": category,
                "severity": sev,
                "channel": e.get("channel", "Security"),
                "source_ip": sip,
                "source_country": e.get("source_country", ""),
                "username": e.get("username", ""),
                "threat_type": threat_type,
                "title": e.get("title", ""),
                "target_service": e.get("target_service", ""),
                "target_port": int(e.get("target_port", 0) or 0),
                "windows_event_id": win_eid,
                "logon_type": e.get("logon_type"),
                "threat_score": int(float(e.get("threat_score", 0) or 0)),
            })

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = {
            "token": token,
            "batch_id": str(_uuid.uuid4()),
            "events": events,
            "summary": {
                "period_start": period_start or now_iso,
                "period_end": period_end or now_iso,
                "total_events": len(events),
                "by_severity": by_severity,
                "unique_source_ips": len(unique_ips),
            },
        }

        # Synchronous send so we can keep buffer on failure
        try:
            response = self.api_client.api_request(
                "POST", "events/batch", data=payload, timeout=20
            )
            ok = isinstance(response, dict) and response.get("status") in (
                "ok", "success", "created", "received",
            )
            if ok or response is not None:
                self._batch_buffer.clear()
                self._stats["alerts_sent_batch"] += len(events)
                log(f"[ALERTS] ✅ batch flushed ({len(events)} events)")
            else:
                log(f"[ALERTS] ⚠️ batch flush kept buffer — response: {response}")
        except Exception as e:
            self._stats["errors"] += 1
            log(f"[ALERTS] ❌ batch flush failed, buffer retained ({len(events_to_send)}): {e}")

    # ── Webhook (Slack / Teams / custom) ───────────────────────────

    def _send_webhook(self, alert: dict):
        """POST alert JSON to configured webhook URL."""
        try:
            from client_utils import get_from_config
            if not get_from_config("notifications.webhook_enabled", False):
                return
            url = str(get_from_config("notifications.webhook_url", "") or "").strip()
            if not url:
                return
            import requests
            from client_security_utils import resolve_tls_verify, redact_sensitive

            body = {
                "event": "honeypot_alert",
                "machine": self.machine_name,
                "severity": alert.get("severity"),
                "title": alert.get("title"),
                "source_ip": alert.get("source_ip"),
                "threat_score": alert.get("threat_score"),
                "threat_type": alert.get("threat_type"),
            }

            def _post():
                try:
                    requests.post(url, json=body, timeout=8, verify=resolve_tls_verify())
                    log(f"[ALERTS] Webhook sent: {redact_sensitive(body)}")
                except Exception as ex:
                    log(f"[ALERTS] Webhook error: {ex}")

            threading.Thread(target=_post, daemon=True).start()
        except Exception as e:
            log(f"[ALERTS] Webhook setup error: {e}")

    # ── API Call Helper ───────────────────────────────────────────

    def _do_api_call(self, endpoint: str, payload: dict, channel: str):
        """Execute API call (runs in daemon thread). Legacy helper for non-batch paths."""
        try:
            response = self.api_client.api_request(
                "POST", endpoint, data=payload, timeout=15
            )
            if isinstance(response, dict) and response.get("status") in (
                "ok", "success", "created", "received",
            ):
                if channel == "urgent":
                    self._stats["alerts_sent_urgent"] += 1
                    self._handle_actions_requested(response)
                else:
                    self._stats["alerts_sent_batch"] += len(payload.get("events", []))
                log(f"[ALERTS] ✅ {channel} alert sent to API: {endpoint}")
            else:
                log(f"[ALERTS] ⚠️ API response for {endpoint}: {response}")
        except Exception as e:
            self._stats["errors"] += 1
            log(f"[ALERTS] ❌ API call failed ({endpoint}): {e}")

    # ── GUI Toast ─────────────────────────────────────────────────

    def _notify_gui(self, alert: dict):
        """Show toast notification in GUI."""
        if not self.gui_toast_func:
            return
        try:
            title = alert.get("title", "Threat Detected")
            severity = alert.get("severity", "info")
            ip = alert.get("source_ip", "")
            score = alert.get("threat_score", 0)
            message = f"IP: {ip} | Score: {score}"
            self.gui_toast_func(title, message, severity)
            self._stats["alerts_gui"] += 1
        except Exception as e:
            log(f"[ALERTS] GUI toast error: {e}")

    # ── Tray Balloon ──────────────────────────────────────────────

    def _notify_tray(self, alert: dict):
        """Show Windows tray balloon notification."""
        if not self.tray_notify_func:
            return
        try:
            title = f"🚨 {alert.get('severity', 'alert').upper()}: {alert.get('title', '')}"
            ip = alert.get("source_ip", "")
            score = alert.get("threat_score", 0)
            message = f"IP: {ip} — Score: {score}\n{alert.get('recommended_action', '')}"
            self.tray_notify_func(title, message)
            self._stats["alerts_tray"] += 1
        except Exception as e:
            log(f"[ALERTS] Tray notify error: {e}")

    # ── Local Threat Log ──────────────────────────────────────────

    def _setup_threat_logger(self) -> logging.Logger:
        """Set up a dedicated rotating log file for threats."""
        logger = logging.getLogger("threats")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            try:
                handler = RotatingFileHandler(
                    THREAT_LOG_FILE,
                    maxBytes=THREAT_LOG_MAX_BYTES,
                    backupCount=THREAT_LOG_BACKUP_COUNT,
                    encoding="utf-8",
                )
                formatter = logging.Formatter(
                    "%(asctime)s | %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
                handler.setFormatter(formatter)
                logger.addHandler(handler)
            except Exception as e:
                log(f"[ALERTS] Failed to set up threat logger: {e}")

        return logger

    def _log_threat(self, alert: dict):
        """Write alert to local threats.log."""
        try:
            severity = alert.get("severity", "info").upper()
            ip = alert.get("source_ip", "")
            title = alert.get("title", "")
            score = alert.get("threat_score", 0)
            service = alert.get("target_service", "")
            user = alert.get("username", "")
            rule = alert.get("correlation_rule", "")

            line = (
                f"[{severity}] {title} | "
                f"IP={ip} Score={score} Service={service} "
                f"User={user} Rule={rule}"
            )
            self._threat_logger.info(line)
        except Exception as e:
            log(f"[ALERTS] Threat log write error: {e}")
