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

# win32service.SERVICE_* start-type codes → contract labels
_WIN32_START_TYPE = {
    0: "Boot",       # SERVICE_BOOT_START
    1: "System",     # SERVICE_SYSTEM_START
    2: "Automatic",  # SERVICE_AUTO_START
    3: "Manual",     # SERVICE_DEMAND_START
    4: "Disabled",   # SERVICE_DISABLED
}

# win32service current-state codes
_WIN32_STATE = {
    1: "Stopped",
    2: "StartPending",
    3: "StopPending",
    4: "Running",
    5: "ContinuePending",
    6: "PausePending",
    7: "Paused",
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

    Primary: pywin32 SCM (no PowerShell encoding issues under SYSTEM).
    Fallback: PowerShell with UTF-8. Cap ≤500.
    """
    try:
        services = _list_services_win32(
            include_drivers=include_drivers,
            include_stopped=include_stopped,
        )
        if services:
            return services
    except Exception as exc:
        log(f"[SERVER-MGMT] list_services win32 path: {exc}")

    return _list_services_powershell(
        include_drivers=include_drivers,
        include_stopped=include_stopped,
    )


def _list_services_win32(
    *,
    include_drivers: bool,
    include_stopped: bool,
) -> List[Dict[str, Any]]:
    import win32service  # type: ignore

    # SERVICE_WIN32 = own+share process; optionally OR drivers
    svc_type = win32service.SERVICE_WIN32
    if include_drivers:
        svc_type |= getattr(
            win32service, "SERVICE_DRIVER", 0x0000000B
        )

    hscm = win32service.OpenSCManager(
        None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
    )
    try:
        # (name, display_name, status)
        # status: (ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
        #          ServiceSpecificExitCode, CheckPoint, WaitHint)
        raw = win32service.EnumServicesStatus(
            hscm, svc_type, win32service.SERVICE_STATE_ALL
        )
    finally:
        try:
            win32service.CloseServiceHandle(hscm)
        except Exception:
            pass

    # Re-open for QueryServiceConfig / StatusEx (need QUERY access)
    hscm = win32service.OpenSCManager(
        None, None, win32service.SC_MANAGER_CONNECT
    )
    services: List[Dict[str, Any]] = []
    try:
        for name, display_name, status in raw or []:
            name = str(name or "").strip()
            if not name:
                continue
            state_code = int(status[1]) if status and len(status) > 1 else 0
            state = _WIN32_STATE.get(state_code, f"Unknown({state_code})")
            if not include_stopped and state == "Stopped":
                continue

            start_type = "Unknown"
            pid = 0
            hs = None
            try:
                hs = win32service.OpenService(
                    hscm,
                    name,
                    win32service.SERVICE_QUERY_CONFIG
                    | win32service.SERVICE_QUERY_STATUS,
                )
                cfg = win32service.QueryServiceConfig(hs)
                # cfg: (ServiceType, StartType, ErrorControl, BinaryPathName,
                #       LoadOrderGroup, TagId, Dependencies, ServiceStartName,
                #       DisplayName)
                start_type = _WIN32_START_TYPE.get(int(cfg[1]), "Unknown")
                try:
                    st_ex = win32service.QueryServiceStatusEx(hs)
                    # dict with ProcessId on modern pywin32
                    if isinstance(st_ex, dict):
                        pid = int(st_ex.get("ProcessId") or 0)
                    elif isinstance(st_ex, (tuple, list)) and len(st_ex) > 7:
                        pid = int(st_ex[7] or 0)
                except Exception:
                    pid = 0
            except Exception:
                pass
            finally:
                if hs is not None:
                    try:
                        win32service.CloseServiceHandle(hs)
                    except Exception:
                        pass

            entry: Dict[str, Any] = {
                "name": name,
                "display_name": str(display_name or name),
                "status": state,
                "start_type": start_type,
            }
            if pid > 0:
                entry["pid"] = pid
            services.append(entry)
            if len(services) >= MAX_SERVICES:
                break
    finally:
        try:
            win32service.CloseServiceHandle(hscm)
        except Exception:
            pass

    services.sort(key=lambda s: (s.get("name") or "").lower())
    return services


def _run_ps_utf8(script: str, *, timeout: int = 45) -> subprocess.CompletedProcess:
    """Run PowerShell forcing UTF-8 stdout (avoids cp1254 decode failures)."""
    wrapped = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$OutputEncoding = [System.Text.Encoding]::UTF8; "
        + script
    )
    return subprocess.run(
        [
            "powershell", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", wrapped,
        ],
        capture_output=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
        encoding="utf-8",
        errors="replace",
    )


def _list_services_powershell(
    *,
    include_drivers: bool,
    include_stopped: bool,
) -> List[Dict[str, Any]]:
    ps = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-CimInstance Win32_Service | "
        "Select-Object Name, DisplayName, State, StartMode, ProcessId, "
        "ServiceType | ConvertTo-Json -Compress -Depth 3"
    )
    try:
        result = _run_ps_utf8(ps, timeout=60)
    except Exception as exc:
        log(f"[SERVER-MGMT] list_services PS failed: {exc}")
        return _list_services_get_service_fallback(
            include_stopped=include_stopped
        )

    stdout = (result.stdout or "").strip()
    if result.returncode != 0 or not stdout:
        log(
            f"[SERVER-MGMT] list_services CIM empty rc={result.returncode} "
            f"err={(result.stderr or '')[:160]}"
        )
        return _list_services_get_service_fallback(
            include_stopped=include_stopped
        )

    try:
        raw = json.loads(stdout)
    except Exception as exc:
        log(f"[SERVER-MGMT] list_services JSON parse: {exc}")
        return _list_services_get_service_fallback(
            include_stopped=include_stopped
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


def _list_services_get_service_fallback(
    *,
    include_stopped: bool,
) -> List[Dict[str, Any]]:
    ps = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-Service | Select-Object Name, DisplayName, Status, StartType | "
        "ConvertTo-Json -Compress"
    )
    try:
        result = _run_ps_utf8(ps, timeout=45)
        stdout = (result.stdout or "").strip()
        if result.returncode != 0 or not stdout:
            return []
        raw = json.loads(stdout)
    except Exception as exc:
        log(f"[SERVER-MGMT] Get-Service fallback failed: {exc}")
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
