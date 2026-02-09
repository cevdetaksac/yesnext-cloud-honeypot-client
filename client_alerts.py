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

# Rate limiting per severity (seconds between alerts for same IP+type)
ALERT_COOLDOWN = {
    "critical": 60,      # 1 min
    "high":     300,      # 5 min
    "warning":  900,      # 15 min
    "info":     3600,     # 1 hour
}

# Batch buffer flush intervals (seconds)
BATCH_INTERVALS = {
    "info":    300,       # 5 min
    "warning": 60,        # 1 min
}

# Max alerts to buffer before force-flush
BATCH_MAX_SIZE = 50

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
    ):
        """
        Args:
            api_client:       HoneypotAPIClient instance for API calls.
            token_getter:     Callable returning current auth token.
            gui_toast_func:   Callable(title, message, severity) for GUI toast.
            tray_notify_func: Callable(title, message) for tray balloon.
            machine_name:     This machine's hostname.
        """
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.gui_toast_func = gui_toast_func
        self.tray_notify_func = tray_notify_func
        self.machine_name = machine_name or socket.gethostname()

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
        return dict(self._stats)

    def get_recent_alerts(self, count: int = 20) -> List[dict]:
        """Get recent alerts from the batch buffer for dashboard display."""
        with self._batch_lock:
            return list(self._batch_buffer[-count:])

    # ── Urgent Channel (instant API) ──────────────────────────────

    def _send_urgent(self, alert: dict):
        """Send alert immediately to API /api/alerts/urgent."""
        try:
            token = self.token_getter()
            if not token or not self.api_client:
                log("[ALERTS] Cannot send urgent — no token or API client")
                return

            payload = {
                "token": token,
                "alert_id": alert.get("alert_id", ""),
                "severity": alert.get("severity", ""),
                "threat_type": alert.get("threat_type", ""),
                "title": alert.get("title", ""),
                "description": alert.get("description", ""),
                "source_ip": alert.get("source_ip", ""),
                "target_service": alert.get("target_service", ""),
                "target_port": alert.get("target_port", 0),
                "username": alert.get("username", ""),
                "threat_score": alert.get("threat_score", 0),
                "event_ids": alert.get("event_ids", []),
                "correlation_rule": alert.get("correlation_rule", ""),
                "recommended_action": alert.get("recommended_action", ""),
                "auto_response": alert.get("auto_response", []),
                "machine_name": alert.get("machine_name", ""),
                "timestamp": alert.get("timestamp", time.time()),
                "ip_context": alert.get("ip_context", {}),
            }

            # Fire-and-forget in thread to avoid blocking event processing
            threading.Thread(
                target=self._do_api_call,
                args=("alerts/urgent", payload, "urgent"),
                daemon=True,
            ).start()

        except Exception as e:
            self._stats["errors"] += 1
            log(f"[ALERTS] Urgent send error: {e}")

    # ── Batch Channel (buffered API) ──────────────────────────────

    def _buffer_for_batch(self, alert: dict):
        """Add alert to batch buffer for periodic sending."""
        with self._batch_lock:
            self._batch_buffer.append(alert)
            # Force flush if buffer is full
            if len(self._batch_buffer) >= BATCH_MAX_SIZE:
                self._flush_batch_locked()

    def _batch_flush_loop(self):
        """Periodically flush the batch buffer."""
        while self._running:
            try:
                time.sleep(60)  # Check every minute
                self._flush_batch()
            except Exception as e:
                log(f"[ALERTS] Batch flush error: {e}")

    def _flush_batch(self):
        """Flush batch buffer to API."""
        with self._batch_lock:
            self._flush_batch_locked()

    def _flush_batch_locked(self):
        """Flush batch buffer (must hold _batch_lock)."""
        if not self._batch_buffer:
            return

        events_to_send = list(self._batch_buffer)
        self._batch_buffer.clear()

        token = self.token_getter()
        if not token or not self.api_client:
            log(f"[ALERTS] Cannot flush batch ({len(events_to_send)} events) — no token/API")
            return

        payload = {
            "token": token,
            "events": [
                {
                    "alert_id": e.get("alert_id", ""),
                    "severity": e.get("severity", ""),
                    "threat_type": e.get("threat_type", ""),
                    "title": e.get("title", ""),
                    "source_ip": e.get("source_ip", ""),
                    "target_service": e.get("target_service", ""),
                    "threat_score": e.get("threat_score", 0),
                    "timestamp": e.get("timestamp", 0),
                    "username": e.get("username", ""),
                    "event_ids": e.get("event_ids", []),
                }
                for e in events_to_send
            ],
            "machine_name": self.machine_name,
            "batch_timestamp": time.time(),
        }

        threading.Thread(
            target=self._do_api_call,
            args=("events/batch", payload, "batch"),
            daemon=True,
        ).start()

    # ── API Call Helper ───────────────────────────────────────────

    def _do_api_call(self, endpoint: str, payload: dict, channel: str):
        """Execute API call (runs in daemon thread)."""
        try:
            response = self.api_client.api_request(
                "POST", endpoint, data=payload, timeout=15
            )
            if isinstance(response, dict) and response.get("status") in ("ok", "success", "created"):
                if channel == "urgent":
                    self._stats["alerts_sent_urgent"] += 1
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
