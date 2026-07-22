#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Server Management inventory helpers (contract 1.4.8 — agent/server-management.md)."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional

from client_helpers import log

CREATE_NO_WINDOW = 0x08000000
MAX_SERVICES = 500

_START_MODE_MAP = {
    "auto": "Automatic",
    "automatic": "Automatic",
    "manual": "Manual",
    "disabled": "Disabled",
    "boot": "Boot",
    "system": "System",
}

_STATE_MAP = {
    "running": "Running",
    "stopped": "Stopped",
    "start pending": "StartPending",
    "stop pending": "StopPending",
    "continue pending": "ContinuePending",
    "pause pending": "PausePending",
    "paused": "Paused",
}


def normalize_service_name(params: Optional[dict]) -> str:
    """Accept dashboard ``name`` or legacy ``service_name``."""
    params = params or {}
    raw = params.get("name")
    if raw is None or str(raw).strip() == "":
        raw = params.get("service_name")
    return str(raw or "").strip()


def list_windows_services(
    *,
    include_drivers: bool = False,
    include_stopped: bool = True,
) -> List[Dict[str, Any]]:
    """Enumerate Win32 services for Server Management → Services.

    Prefer CIM (Name, DisplayName, State, StartMode, ProcessId). Cap ≤500.
    """
    ps = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-CimInstance Win32_Service | "
        "Select-Object Name, DisplayName, State, StartMode, ProcessId, "
        "ServiceType | ConvertTo-Json -Compress -Depth 3"
    )
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", ps,
            ],
            capture_output=True,
            text=True,
            timeout=45,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as exc:
        log(f"[SERVER-MGMT] list_services PS failed: {exc}")
        return []

    if result.returncode != 0 or not (result.stdout or "").strip():
        # Fallback: Get-Service (no pid / start mode as rich)
        return _list_services_fallback(
            include_drivers=include_drivers,
            include_stopped=include_stopped,
        )

    try:
        raw = json.loads(result.stdout.strip())
    except Exception as exc:
        log(f"[SERVER-MGMT] list_services JSON parse: {exc}")
        return _list_services_fallback(
            include_drivers=include_drivers,
            include_stopped=include_stopped,
        )

    if isinstance(raw, dict):
        raw = [raw]
    services: List[Dict[str, Any]] = []
    for row in raw or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or "").strip()
        if not name:
            continue
        svc_type = str(row.get("ServiceType") or "")
        if not include_drivers and "Driver" in svc_type:
            continue
        state_raw = str(row.get("State") or "").strip()
        status = _STATE_MAP.get(state_raw.lower(), state_raw or "Unknown")
        if not include_stopped and status.lower() == "stopped":
            continue
        start_raw = str(row.get("StartMode") or "").strip()
        start_type = _START_MODE_MAP.get(start_raw.lower(), start_raw or "Unknown")
        pid = row.get("ProcessId")
        try:
            pid_i = int(pid) if pid is not None else 0
        except (TypeError, ValueError):
            pid_i = 0
        entry: Dict[str, Any] = {
            "name": name,
            "display_name": str(row.get("DisplayName") or name),
            "status": status,
            "start_type": start_type,
        }
        if pid_i > 0:
            entry["pid"] = pid_i
        services.append(entry)
        if len(services) >= MAX_SERVICES:
            break

    services.sort(key=lambda s: (s.get("name") or "").lower())
    return services


def _list_services_fallback(
    *,
    include_drivers: bool,
    include_stopped: bool,
) -> List[Dict[str, Any]]:
    ps = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-Service | Select-Object Name, DisplayName, Status, StartType | "
        "ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", ps,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode != 0 or not (result.stdout or "").strip():
            return []
        raw = json.loads(result.stdout.strip())
    except Exception:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    out: List[Dict[str, Any]] = []
    for row in raw or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or "").strip()
        if not name:
            continue
        status = str(row.get("Status") or "")
        if not include_stopped and status.lower() == "stopped":
            continue
        # Get-Service has no driver filter — skip when drivers requested off is N/A
        _ = include_drivers
        start = str(row.get("StartType") or "")
        out.append({
            "name": name,
            "display_name": str(row.get("DisplayName") or name),
            "status": _STATE_MAP.get(status.lower(), status or "Unknown"),
            "start_type": _START_MODE_MAP.get(start.lower(), start or "Unknown"),
        })
        if len(out) >= MAX_SERVICES:
            break
    out.sort(key=lambda s: (s.get("name") or "").lower())
    return out
