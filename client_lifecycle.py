# -*- coding: utf-8 -*-
"""
Client lifecycle logger — crash / watchdog / memory-restart events.

Writes to:
  %ProgramData%\\YesNext\\CloudHoneypotClient\\lifecycle-YYYY-MM-DD.log
  %ProgramData%\\YesNext\\CloudHoneypotClient\\lifecycle_queue.jsonl  (pending API)

Best-effort POST /api/alerts/lifecycle when token + API available.
Never blocks restart paths on network failure.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from client_log_retention import cleanup_daily_logs, current_local_date, daily_log_path

_MACHINE_DIR = os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"),
    "YesNext",
    "CloudHoneypotClient",
)
LIFECYCLE_LOG = os.path.join(_MACHINE_DIR, "lifecycle.log")
LIFECYCLE_QUEUE = os.path.join(_MACHINE_DIR, "lifecycle_queue.jsonl")
_LOG_RETENTION_DAYS = 7
_MAX_QUEUE_LINES = 200
_lock = threading.Lock()
_last_cleanup_day = None


def _ensure_dir() -> None:
    try:
        os.makedirs(_MACHINE_DIR, exist_ok=True)
    except OSError:
        pass


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def _version() -> str:
    try:
        from client_constants import VERSION
        return str(VERSION)
    except Exception:
        return ""


def _current_lifecycle_log() -> str:
    global _last_cleanup_day
    day = current_local_date()
    if day != _last_cleanup_day:
        cleanup_daily_logs(
            LIFECYCLE_LOG,
            _LOG_RETENTION_DAYS,
            today=day,
        )
        _last_cleanup_day = day
    return daily_log_path(LIFECYCLE_LOG, day)


def _append_queue(event: dict) -> None:
    try:
        with open(LIFECYCLE_QUEUE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        # Trim if huge
        try:
            with open(LIFECYCLE_QUEUE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > _MAX_QUEUE_LINES:
                with open(LIFECYCLE_QUEUE, "w", encoding="utf-8") as f:
                    f.writelines(lines[-_MAX_QUEUE_LINES:])
        except OSError:
            pass
    except OSError:
        pass


def emit(
    event_type: str,
    reason: str = "",
    details: Optional[Dict[str, Any]] = None,
    *,
    severity: str = "info",
    queue_for_api: bool = True,
    log_func: Optional[Callable[[str], None]] = None,
) -> dict:
    """Record a lifecycle event locally (+ queue for API flush)."""
    _ensure_dir()
    event = {
        "ts": _utc_iso(),
        "event_type": str(event_type or "unknown"),
        "reason": str(reason or ""),
        "severity": str(severity or "info"),
        "hostname": _hostname(),
        "version": _version(),
        "pid": os.getpid(),
        "details": details or {},
    }
    line = (
        f"{event['ts']} [{event['severity'].upper()}] "
        f"{event['event_type']}: {event['reason']}"
    )
    if details:
        try:
            line += " | " + json.dumps(details, ensure_ascii=False)
        except Exception:
            pass

    with _lock:
        try:
            with open(_current_lifecycle_log(), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
        if queue_for_api:
            _append_queue(event)

    if log_func:
        try:
            log_func(f"[LIFECYCLE] {event['event_type']}: {event['reason']}")
        except Exception:
            pass
    return event


def load_token() -> str:
    """Load machine token (DPAPI) for headless watchdog / flush."""
    try:
        from client_constants import TOKEN_FILE
        from client_utils import TokenStore
        return (TokenStore.load(TOKEN_FILE) or "").strip()
    except Exception:
        return ""


def flush_queue_to_api(
    api_client=None,
    token: Optional[str] = None,
    log_func: Optional[Callable[[str], None]] = None,
) -> int:
    """Send queued lifecycle events to API. Returns number sent."""
    token = (token or load_token() or "").strip()
    if not token:
        return 0

    if api_client is None:
        try:
            from client_constants import API_URL
            from client_api import HoneypotAPIClient
            api_client = HoneypotAPIClient(API_URL, log_func=log_func or (lambda m: None))
        except Exception:
            return 0

    if not os.path.isfile(LIFECYCLE_QUEUE):
        return 0

    with _lock:
        try:
            with open(LIFECYCLE_QUEUE, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return 0
        if not lines:
            return 0

    sent = 0
    remaining = []
    for ln in lines:
        try:
            event = json.loads(ln)
        except Exception:
            continue
        try:
            ok = False
            if hasattr(api_client, "report_lifecycle_event"):
                ok = bool(api_client.report_lifecycle_event(token, event))
            if ok:
                sent += 1
            else:
                remaining.append(ln)
        except Exception:
            remaining.append(ln)

    with _lock:
        try:
            with open(LIFECYCLE_QUEUE, "w", encoding="utf-8") as f:
                for ln in remaining:
                    f.write(ln + "\n")
        except OSError:
            pass

    if log_func and sent:
        try:
            log_func(f"[LIFECYCLE] Flushed {sent} event(s) to API "
                     f"({len(remaining)} pending)")
        except Exception:
            pass
    return sent


def report_now(
    event_type: str,
    reason: str = "",
    details: Optional[Dict[str, Any]] = None,
    *,
    severity: str = "info",
    api_client=None,
    token: Optional[str] = None,
    log_func: Optional[Callable[[str], None]] = None,
) -> bool:
    """Emit locally and try immediate API post (still queues on failure)."""
    event = emit(
        event_type, reason, details,
        severity=severity, queue_for_api=True, log_func=log_func,
    )
    token = (token or load_token() or "").strip()
    if not token:
        return False
    try:
        if api_client is None:
            from client_constants import API_URL
            from client_api import HoneypotAPIClient
            api_client = HoneypotAPIClient(API_URL, log_func=log_func or (lambda m: None))
        if hasattr(api_client, "report_lifecycle_event"):
            if api_client.report_lifecycle_event(token, event):
                # Drop matching last queue line best-effort
                flush_queue_to_api(api_client, token, log_func=log_func)
                return True
    except Exception as e:
        if log_func:
            try:
                log_func(f"[LIFECYCLE] API report failed: {e}")
            except Exception:
                pass
    return False
