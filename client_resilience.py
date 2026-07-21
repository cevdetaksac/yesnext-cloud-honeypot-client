#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local resilience SLO, storm breaker and recovery helpers (SR-001/002/003).

Additive status only. Cloud/dashboard may ignore unknown fields until the
`resilience{}` draft in SECURITY_RESILIENCE_VNEXT is promoted.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

try:
    from client_constants import MACHINE_DATA_DIR, VERSION
except Exception:  # pragma: no cover
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext", "CloudHoneypotClient",
    )
    VERSION = "0.0.0"

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(*_a, **_k):
        pass

STATE_FILE = os.path.join(MACHINE_DATA_DIR, "resilience_state.json")
CREATE_NO_WINDOW = 0x08000000

# Bounded exponential backoff (seconds) for motor/guardian recovery attempts.
RECOVERY_BACKOFF_SEC = [5, 15, 60, 180, 600]
STORM_WINDOW_SEC = 600
STORM_THRESHOLD = 5
COUNTER_RETENTION_SEC = 24 * 3600

_lock = threading.RLock()
_state: dict = {
    "version": VERSION,
    "daemon_restarts": [],       # monotonic wall epoch timestamps
    "guardian_restarts": [],
    "last_recovery_ms": 0,
    "last_recovery_leg": "",
    "last_recovery_ok": False,
    "restart_storm": False,
    "stand_down_reason": "",
    "binary_integrity": "unknown",
    "guardian_exit_code": None,
}


def _now() -> float:
    return time.time()


def _iso(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(
        ts if ts is not None else _now(), timezone.utc
    ).isoformat().replace("+00:00", "Z")


def _load_state() -> None:
    global _state
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            merged = dict(_state)
            merged.update(data)
            _state = merged
    except Exception:
        pass


def _save_state() -> None:
    try:
        os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_state, fh)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def _prune_list(values: List[float], now: float) -> List[float]:
    cutoff = now - COUNTER_RETENTION_SEC
    return [float(v) for v in values if float(v) >= cutoff]


_load_state()


def note_stand_down(reason: str) -> None:
    """Record a legitimate update/PIN/uninstall stand-down (not a storm)."""
    with _lock:
        _state["stand_down_reason"] = str(reason or "")[:120]
        _state["restart_storm"] = False
        _save_state()


def clear_stand_down() -> None:
    with _lock:
        if _state.get("stand_down_reason"):
            _state["stand_down_reason"] = ""
            _save_state()


def set_binary_integrity(value: str) -> None:
    allowed = {"valid", "invalid", "unknown"}
    with _lock:
        _state["binary_integrity"] = value if value in allowed else "unknown"
        _save_state()


def query_guardian_exit_code(service_name: str = "CloudHoneypotGuardian") -> Optional[int]:
    """Best-effort WIN32_EXIT_CODE from `sc queryex` (None if unavailable)."""
    try:
        import subprocess
        r = subprocess.run(
            ["sc", "queryex", service_name],
            capture_output=True, text=True, timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        if r.returncode != 0:
            return None
        for line in (r.stdout or "").splitlines():
            if "WIN32_EXIT_CODE" in line.upper():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    code = parts[1].strip().split()[0]
                    return int(code)
    except Exception:
        return None
    return None


def _storm_active(timestamps: List[float], now: float) -> bool:
    recent = [t for t in timestamps if now - t <= STORM_WINDOW_SEC]
    return len(recent) >= STORM_THRESHOLD


def _backoff_for_count(count: int) -> int:
    if count <= 0:
        return 0
    idx = min(count - 1, len(RECOVERY_BACKOFF_SEC) - 1)
    return int(RECOVERY_BACKOFF_SEC[idx])


def should_attempt_recovery(leg: str) -> Tuple[bool, int]:
    """Return (allowed, backoff_sec). Never abandons recovery permanently."""
    key = "daemon_restarts" if leg == "daemon" else "guardian_restarts"
    with _lock:
        now = _now()
        stamps = _prune_list(list(_state.get(key) or []), now)
        _state[key] = stamps
        storm = _storm_active(stamps, now)
        _state["restart_storm"] = storm or bool(_state.get("restart_storm"))
        if not stamps:
            _save_state()
            return True, 0
        backoff = _backoff_for_count(len([
            t for t in stamps if now - t <= STORM_WINDOW_SEC
        ]))
        last = max(stamps)
        wait = max(0, int(backoff - (now - last)))
        if wait > 0:
            _save_state()
            return False, wait
        _save_state()
        return True, backoff


def record_recovery_attempt(
    leg: str,
    *,
    ok: bool,
    duration_ms: int = 0,
    stand_down: bool = False,
) -> None:
    if stand_down:
        note_stand_down(leg)
        return
    key = "daemon_restarts" if leg == "daemon" else "guardian_restarts"
    with _lock:
        now = _now()
        stamps = _prune_list(list(_state.get(key) or []), now)
        stamps.append(now)
        _state[key] = stamps
        _state["last_recovery_ms"] = int(duration_ms)
        _state["last_recovery_leg"] = str(leg)
        _state["last_recovery_ok"] = bool(ok)
        _state["restart_storm"] = _storm_active(stamps, now)
        if _state["stand_down_reason"]:
            _state["stand_down_reason"] = ""
        _save_state()
        if _state["restart_storm"]:
            log(
                f"[RESILIENCE] restart storm leg={leg} "
                f"count_24h={len(stamps)} window={STORM_WINDOW_SEC}s"
            )


def snapshot(
    *,
    guardian_installed: Optional[bool] = None,
    guardian_running: Optional[bool] = None,
) -> dict:
    """Additive resilience block for IPC/status/health."""
    with _lock:
        now = _now()
        daemon = _prune_list(list(_state.get("daemon_restarts") or []), now)
        guardian = _prune_list(list(_state.get("guardian_restarts") or []), now)
        _state["daemon_restarts"] = daemon
        _state["guardian_restarts"] = guardian
        storm = _storm_active(daemon, now) or _storm_active(guardian, now)
        _state["restart_storm"] = storm
        recent_daemon = [t for t in daemon if now - t <= STORM_WINDOW_SEC]
        backoff = _backoff_for_count(len(recent_daemon))
        exit_code = _state.get("guardian_exit_code")
        out = {
            "guardian_installed": (
                bool(guardian_installed)
                if guardian_installed is not None
                else None
            ),
            "guardian_running": (
                bool(guardian_running)
                if guardian_running is not None
                else None
            ),
            "guardian_exit_code": exit_code,
            "daemon_restarts_24h": len(daemon),
            "guardian_restarts_24h": len(guardian),
            "last_recovery_ms": int(_state.get("last_recovery_ms") or 0),
            "last_recovery_leg": str(_state.get("last_recovery_leg") or ""),
            "last_recovery_ok": bool(_state.get("last_recovery_ok")),
            "restart_backoff_sec": int(backoff if storm or recent_daemon else 0),
            "restart_storm": bool(storm),
            "stand_down_reason": str(_state.get("stand_down_reason") or ""),
            "binary_integrity": str(_state.get("binary_integrity") or "unknown"),
            "observed_at": _iso(now),
        }
        _save_state()
        return out


def refresh_guardian_exit_code(service_name: str = "CloudHoneypotGuardian") -> Optional[int]:
    code = query_guardian_exit_code(service_name)
    with _lock:
        _state["guardian_exit_code"] = code
        _save_state()
    return code


def _legitimate_stand_down() -> bool:
    try:
        from client_utils import is_update_in_progress
        if is_update_in_progress():
            return True
    except Exception:
        pass
    try:
        from client_operator_stop import is_operator_stop_active
        if is_operator_stop_active():
            return True
    except Exception:
        pass
    return False


def ensure_guardian_with_backoff(exe_path: str = None) -> bool:
    """SR-003: heal installed-but-not-running Guardian with storm breaker."""
    from client_guardian_service import (
        ensure_guardian_service_running,
        is_guardian_service_installed,
        is_guardian_service_running,
    )

    if _legitimate_stand_down():
        note_stand_down("update_or_operator_stop")
        return True
    clear_stand_down()
    if is_guardian_service_running():
        refresh_guardian_exit_code()
        return True

    allowed, wait = should_attempt_recovery("guardian")
    if not allowed:
        log(f"[RESILIENCE] guardian start deferred backoff={wait}s")
        return False

    t0 = time.monotonic()
    installed_before = is_guardian_service_installed()
    ok = ensure_guardian_service_running(exe_path)
    ms = int((time.monotonic() - t0) * 1000)
    # Count recoveries for start/heal attempts (install-or-start).
    record_recovery_attempt("guardian", ok=ok, duration_ms=ms)
    refresh_guardian_exit_code()
    if installed_before and not ok:
        log("[RESILIENCE] guardian installed but not running — start failed")
    return bool(ok)
