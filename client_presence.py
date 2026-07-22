#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Realtime agent presence (contract api/11-presence-realtime.md ≥1.4.12).

SYSTEM daemon owns signals. GUI quit alone must NOT mark host offline.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(*_a, **_k):
        pass

_lock = threading.Lock()
_control_ws = None
_api_client = None
_token_getter: Optional[Callable[[], str]] = None
_goodbye_sent = False
_pending_online_on_connect = False
_last_state = ""
_last_reason = ""
_reconnect_cb: Optional[Callable[[], None]] = None


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def configure(
    *,
    control_ws=None,
    api_client=None,
    token_getter: Optional[Callable[[], str]] = None,
    reconnect_cb: Optional[Callable[[], None]] = None,
) -> None:
    global _control_ws, _api_client, _token_getter, _reconnect_cb
    with _lock:
        if control_ws is not None:
            _control_ws = control_ws
        if api_client is not None:
            _api_client = api_client
        if token_getter is not None:
            _token_getter = token_getter
        if reconnect_cb is not None:
            _reconnect_cb = reconnect_cb


def request_ws_reconnect() -> None:
    cb = None
    ws = None
    with _lock:
        cb = _reconnect_cb
        ws = _control_ws
    try:
        if callable(cb):
            cb()
            return
    except Exception:
        pass
    try:
        if ws is not None and hasattr(ws, "request_reconnect"):
            ws.request_reconnect()
    except Exception:
        pass


def reset_goodbye_flag() -> None:
    global _goodbye_sent
    with _lock:
        _goodbye_sent = False


def mark_online_on_next_connect() -> None:
    global _pending_online_on_connect
    with _lock:
        _pending_online_on_connect = True


def on_control_ws_connected() -> None:
    """After hello: clear suspend with presence online when waking."""
    global _pending_online_on_connect
    send = False
    with _lock:
        if _pending_online_on_connect:
            _pending_online_on_connect = False
            send = True
    if send:
        signal_presence("online", "resume", http_fallback=True)


def http_presence(state: str, reason: str = "", *, timeout: float = 2.0) -> bool:
    """POST /api/presence — best-effort, never block longer than timeout."""
    token = ""
    try:
        if _token_getter:
            token = (_token_getter() or "").strip()
    except Exception:
        token = ""
    if not token:
        try:
            from client_lifecycle import load_token
            token = (load_token() or "").strip()
        except Exception:
            token = ""
    if not token:
        return False

    api_base = ""
    try:
        if _api_client is not None:
            api_base = getattr(_api_client, "base_url", "") or ""
    except Exception:
        api_base = ""
    if not api_base:
        try:
            from client_constants import API_URL
            api_base = API_URL
        except Exception:
            return False
    url = str(api_base).rstrip("/") + "/presence"
    body = {
        "token": token,
        "state": state,
        "reason": reason or "",
        "ts": _utc_iso(),
    }
    try:
        import requests
        from client_security_utils import resolve_tls_verify
        r = requests.post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {token}"},
            timeout=max(0.3, min(2.0, float(timeout))),
            verify=resolve_tls_verify(),
        )
        ok = int(getattr(r, "status_code", 0) or 0) < 300
        if ok:
            log(f"[PRESENCE] HTTP ok state={state} reason={reason}")
        else:
            log(f"[PRESENCE] HTTP {r.status_code} state={state}")
        return ok
    except Exception as e:
        log(f"[PRESENCE] HTTP failed: {e}")
        return False


def signal_presence(
    state: str,
    reason: str = "",
    *,
    http_fallback: bool = True,
    timeout: float = 2.0,
) -> bool:
    """WS presence first; optional HTTP fallback (≤2s)."""
    global _last_state, _last_reason
    state = str(state or "").strip().lower()
    reason = str(reason or "").strip().lower()
    if not state:
        return False

    with _lock:
        _last_state = state
        _last_reason = reason
        ws = _control_ws

    ws_ok = False
    try:
        if ws is not None and hasattr(ws, "send_presence"):
            ws_ok = bool(ws.send_presence(state, reason))
    except Exception as e:
        log(f"[PRESENCE] WS send failed: {e}")
        ws_ok = False

    if ws_ok:
        return True
    if http_fallback:
        return http_presence(state, reason, timeout=timeout)
    return False


def signal_goodbye(
    reason: str = "shutdown",
    *,
    http_fallback: bool = True,
    close_after: bool = False,
) -> bool:
    """Planned stop — immediate offline on cloud. Idempotent per process."""
    global _goodbye_sent
    reason = str(reason or "shutdown").strip().lower() or "shutdown"
    with _lock:
        if _goodbye_sent:
            return True
        _goodbye_sent = True
        ws = _control_ws

    ws_ok = False
    try:
        if ws is not None and hasattr(ws, "send_goodbye"):
            ws_ok = bool(ws.send_goodbye(reason))
    except Exception as e:
        log(f"[PRESENCE] goodbye WS failed: {e}")

    http_ok = False
    if not ws_ok and http_fallback:
        http_ok = http_presence("offline", reason, timeout=2.0)

    if close_after and ws is not None:
        try:
            if hasattr(ws, "stop"):
                ws.stop()
        except Exception:
            pass

    log(f"[PRESENCE] goodbye reason={reason} ws={ws_ok} http={http_ok}")
    return bool(ws_ok or http_ok)


def emit_lifecycle_mirror(event_type: str, reason: str = "") -> None:
    """Optional audit trail — presence is primary (faster)."""
    try:
        from client_lifecycle import report_now
        report_now(event_type, reason or event_type, {}, severity="warning")
    except Exception:
        pass


def status_snapshot() -> dict:
    with _lock:
        return {
            "last_state": _last_state,
            "last_reason": _last_reason,
            "goodbye_sent": _goodbye_sent,
            "pending_online": _pending_online_on_connect,
        }
