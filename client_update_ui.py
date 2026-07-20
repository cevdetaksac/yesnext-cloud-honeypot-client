#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-process update status for GUI banner.

SYSTEM daemon handles dashboard self_update; interactive GUI is a separate
process. Status is written to ProgramData so the GUI can poll and show a
top banner ("Güncelleme talimatı alındı…", download %, installing, done).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

_VALID_PHASES = frozenset({
    "accepted",
    "downloading",
    "staging",
    "installing",
    "done",
    "failed",
})

# Active phases must not stick forever when helper dies silently.
_PHASE_STALE_SEC = {
    "accepted": 600,       # 10 min
    "downloading": 1800,   # 30 min
    "staging": 600,
    "installing": 600,     # 10 min — helper/NSIS stall or never started
    "done": 86400,
    "failed": 86400,
}


def _status_path() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext",
        "CloudHoneypotClient",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "update_ui_status.json")


def set_update_ui_status(
    phase: str,
    *,
    from_version: str = "",
    to_version: str = "",
    detail: str = "",
    progress: Optional[int] = None,
    error: str = "",
) -> None:
    """Write update UI status (best-effort; never raises to callers)."""
    try:
        phase = (phase or "").strip().lower()
        if phase not in _VALID_PHASES:
            return
        prev = _read_raw() or {}
        payload: Dict[str, Any] = {
            "phase": phase,
            "from_version": (from_version or prev.get("from_version") or "").strip(),
            "to_version": (to_version or prev.get("to_version") or "").strip(),
            "detail": (detail or "").strip(),
            "error": (error or "").strip(),
            "updated_at": time.time(),
        }
        if progress is not None:
            try:
                payload["progress"] = max(0, min(100, int(progress)))
            except (TypeError, ValueError):
                pass
        elif "progress" in prev and phase == "downloading":
            payload["progress"] = prev.get("progress")

        path = _status_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass


def _read_raw() -> Optional[Dict[str, Any]]:
    try:
        path = _status_path()
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        phase = (data.get("phase") or "").strip().lower()
        if phase not in _VALID_PHASES:
            return None
        data["phase"] = phase
        return data
    except Exception:
        return None


def _release_stale_lock() -> None:
    try:
        from client_utils import release_update_lock
        release_update_lock(resume_updaters=True)
    except Exception:
        pass


def _mark_stalled(st: Dict[str, Any], reason: str = "update_stalled") -> Dict[str, Any]:
    set_update_ui_status(
        "failed",
        from_version=str(st.get("from_version") or ""),
        to_version=str(st.get("to_version") or ""),
        detail=reason,
        error=reason,
    )
    _release_stale_lock()
    return _read_raw() or {
        "phase": "failed",
        "error": reason,
        "from_version": st.get("from_version") or "",
        "to_version": st.get("to_version") or "",
        "updated_at": time.time(),
    }


def get_update_ui_status(max_age_sec: float = 7200.0) -> Optional[Dict[str, Any]]:
    """Read status file; expire stuck active phases to failed."""
    data = _read_raw()
    if not data:
        return None
    phase = data.get("phase") or ""
    updated = float(data.get("updated_at") or 0)
    age = (time.time() - updated) if updated else 0.0

    stale_limit = float(_PHASE_STALE_SEC.get(phase, max_age_sec))
    if updated and age > stale_limit and phase in (
        "accepted", "downloading", "staging", "installing",
    ):
        return _mark_stalled(data, "update_stalled")

    if updated and max_age_sec > 0 and age > max_age_sec and phase in ("done", "failed"):
        return None

    return data


def clear_update_ui_status() -> None:
    try:
        path = _status_path()
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass


def _norm_ver(v: str) -> str:
    return (v or "").strip().lstrip("vV")


def maybe_mark_done_on_startup(current_version: str) -> None:
    """
    After install, new process starts: if status targeted this version,
    mark done so GUI can show success briefly.

    If still on old version while phase=installing and status is old → failed
    (helper died after setting 'installing' without finishing).
    """
    try:
        st = _read_raw()
        if not st:
            return
        phase = st.get("phase") or ""
        target = _norm_ver(str(st.get("to_version") or ""))
        cur = _norm_ver(current_version)
        updated = float(st.get("updated_at") or 0)
        age = (time.time() - updated) if updated else 0.0

        if target and cur and cur == target and phase in (
            "accepted", "downloading", "staging", "installing", "done",
        ):
            set_update_ui_status(
                "done",
                from_version=str(st.get("from_version") or ""),
                to_version=target,
                detail="install_complete",
            )
            return

        # Still old build but banner says installing → helper never finished
        if (
            phase in ("installing", "staging", "accepted", "downloading")
            and target
            and cur
            and cur != target
            and age > 120  # give helper 2 min after relaunch
        ):
            # If age already past phase stale, mark stalled
            limit = float(_PHASE_STALE_SEC.get(phase, 900))
            if age > min(300.0, limit):  # 5 min soft fail on boot
                _mark_stalled(st, "install_did_not_complete")
    except Exception:
        pass
