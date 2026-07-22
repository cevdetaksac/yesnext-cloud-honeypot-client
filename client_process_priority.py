#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Session-0 motor process priority (RES-101 / RES-102).

Default: ABOVE_NORMAL so command poll / IPC / heartbeat stay responsive when
the host is CPU-saturated. Process-wide REALTIME is never applied.
"""

from __future__ import annotations

import ctypes
import threading
import time
from typing import Any, Dict, Optional

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(*_a, **_k):
        pass

# Win32 priority classes
IDLE_PRIORITY_CLASS = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100  # forbidden

_LEVEL_MAP = {
    "idle": IDLE_PRIORITY_CLASS,
    "below_normal": BELOW_NORMAL_PRIORITY_CLASS,
    "normal": NORMAL_PRIORITY_CLASS,
    "above_normal": ABOVE_NORMAL_PRIORITY_CLASS,
    "high": HIGH_PRIORITY_CLASS,
}

_state_lock = threading.Lock()
_state: Dict[str, Any] = {
    "requested": "above_normal",
    "applied": "normal",
    "class": NORMAL_PRIORITY_CLASS,
    "ok": False,
    "error": "",
    "guard_active": False,
}


def _resolve_level(name: Optional[str]) -> str:
    key = str(name or "above_normal").strip().lower().replace("-", "_")
    if key in ("realtime", "real_time", "time_critical"):
        return "above_normal"
    if key not in _LEVEL_MAP:
        return "above_normal"
    return key


def _configured_level() -> str:
    try:
        from client_utils import get_from_config
        raw = get_from_config("security.motor_priority", "above_normal")
        return _resolve_level(raw)
    except Exception:
        return "above_normal"


def apply_motor_priority(level: Optional[str] = None) -> Dict[str, Any]:
    """Raise current process priority. Never applies REALTIME.

    Default / recommended: ``above_normal``. Optional ``high`` via config
    ``security.motor_priority`` (still not realtime).
    """
    wanted = _resolve_level(level) if level is not None else _configured_level()
    pclass = _LEVEL_MAP[wanted]
    err = ""
    ok = False
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetCurrentProcess()
        ok = bool(kernel32.SetPriorityClass(handle, int(pclass)))
        if not ok:
            err = f"SetPriorityClass failed winerr={ctypes.GetLastError()}"
    except Exception as e:
        err = str(e)
        ok = False

    with _state_lock:
        _state["requested"] = wanted
        _state["applied"] = wanted if ok else _state.get("applied") or "normal"
        _state["class"] = pclass if ok else _state.get("class")
        _state["ok"] = ok
        _state["error"] = err
        snap = dict(_state)

    if ok:
        log(f"[PRIORITY] motor process -> {wanted} (class=0x{pclass:X})")
    else:
        log(f"[PRIORITY] apply failed ({wanted}): {err}")
    return snap


def restore_normal_priority(reason: str = "") -> Dict[str, Any]:
    """Drop back to NORMAL (RES-102 safety)."""
    err = ""
    ok = False
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetCurrentProcess()
        ok = bool(kernel32.SetPriorityClass(handle, NORMAL_PRIORITY_CLASS))
        if not ok:
            err = f"SetPriorityClass failed winerr={ctypes.GetLastError()}"
    except Exception as e:
        err = str(e)

    with _state_lock:
        _state["applied"] = "normal" if ok else _state.get("applied")
        _state["class"] = NORMAL_PRIORITY_CLASS if ok else _state.get("class")
        _state["ok"] = ok
        _state["error"] = err
        _state["guard_active"] = True
        snap = dict(_state)

    log(f"[PRIORITY] restored NORMAL ({reason or 'guard'})")
    return snap


def get_priority_status() -> Dict[str, Any]:
    with _state_lock:
        return dict(_state)


def start_priority_guard(
    *,
    cpu_threshold: float = 55.0,
    sustain_sec: float = 45.0,
    poll_sec: float = 5.0,
) -> None:
    """If motor CPU stays high, drop to NORMAL once (RES-102 lite)."""
    if getattr(start_priority_guard, "_started", False):
        return
    start_priority_guard._started = True  # type: ignore[attr-defined]

    def _loop():
        proc = None
        high_since = 0.0
        try:
            import psutil
            proc = psutil.Process()
            proc.cpu_percent(interval=None)
        except Exception:
            return
        while True:
            try:
                time.sleep(poll_sec)
                with _state_lock:
                    applied = _state.get("applied")
                    guard = _state.get("guard_active")
                if guard or applied in ("normal", "below_normal", "idle"):
                    continue
                cpu = float(proc.cpu_percent(interval=None) or 0.0)
                now = time.time()
                if cpu >= cpu_threshold:
                    if high_since <= 0:
                        high_since = now
                    elif (now - high_since) >= sustain_sec:
                        restore_normal_priority(
                            reason=f"cpu {cpu:.0f}% ≥ {cpu_threshold:.0f}% for {sustain_sec:.0f}s"
                        )
                        high_since = 0.0
                else:
                    high_since = 0.0
            except Exception:
                time.sleep(poll_sec)

    threading.Thread(target=_loop, name="PriorityGuard", daemon=True).start()
