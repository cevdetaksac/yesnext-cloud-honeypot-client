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
        prev = get_update_ui_status() or {}
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


def get_update_ui_status(max_age_sec: float = 7200.0) -> Optional[Dict[str, Any]]:
    """Read status file; None if missing/stale/invalid."""
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
        updated = float(data.get("updated_at") or 0)
        if updated and max_age_sec > 0 and (time.time() - updated) > max_age_sec:
            # Stale failed/done can linger; still return recent active phases only
            if phase in ("done", "failed"):
                return None
            if (time.time() - updated) > max_age_sec:
                return None
        data["phase"] = phase
        return data
    except Exception:
        return None


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
    """
    try:
        st = get_update_ui_status(max_age_sec=86400.0)
        if not st:
            return
        phase = st.get("phase") or ""
        target = _norm_ver(str(st.get("to_version") or ""))
        cur = _norm_ver(current_version)
        if not target or not cur:
            return
        if cur == target and phase in (
            "accepted", "downloading", "staging", "installing", "done",
        ):
            set_update_ui_status(
                "done",
                from_version=str(st.get("from_version") or ""),
                to_version=target,
                detail="install_complete",
            )
        elif phase == "failed":
            pass  # leave for GUI to show
        elif target and cur != target and phase in ("installing", "staging"):
            # Still mid-flight or failed silently — keep installing signal briefly
            pass
    except Exception:
        pass
