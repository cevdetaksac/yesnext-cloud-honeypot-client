#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight process + host resource snapshot for STATUS / GUI badge."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

_proc = None
_prev_io = None
_prev_io_t = 0.0
_prev_net = None
_prev_net_t = 0.0


def _proc_handle():
    global _proc
    if _proc is None:
        import psutil
        _proc = psutil.Process(os.getpid())
        try:
            _proc.cpu_percent(interval=None)
        except Exception:
            pass
    return _proc


def format_bps(bps: Optional[float]) -> str:
    if bps is None:
        return "—"
    try:
        v = float(bps)
    except Exception:
        return "—"
    if v < 0:
        v = 0.0
    if v < 1024:
        return f"{v:.0f}B/s"
    if v < 1024 * 1024:
        return f"{v / 1024:.0f}KB/s"
    return f"{v / (1024 * 1024):.1f}MB/s"


def collect_resources(health_monitor=None) -> Dict[str, Any]:
    """Compact dict safe for STATUS (no process lists)."""
    out: Dict[str, Any] = {
        "host_cpu_percent": None,
        "host_memory_percent": None,
        "net_recv_bps": None,
        "net_sent_bps": None,
        "process_cpu_percent": None,
        "process_rss_mb": None,
        "process_io_read_bps": None,
        "process_io_write_bps": None,
        "priority": {},
    }

    # Host snapshot from health monitor when available (already sampled)
    try:
        if health_monitor is not None and hasattr(health_monitor, "get_snapshot"):
            snap = health_monitor.get_snapshot() or {}
            out["host_cpu_percent"] = round(float(snap.get("cpu_percent") or 0.0), 1)
            out["host_memory_percent"] = round(float(snap.get("memory_percent") or 0.0), 1)
            if snap.get("net_recv_bps") is not None:
                out["net_recv_bps"] = float(snap.get("net_recv_bps") or 0.0)
            if snap.get("net_sent_bps") is not None:
                out["net_sent_bps"] = float(snap.get("net_sent_bps") or 0.0)
    except Exception:
        pass

    try:
        import psutil
        if out["host_cpu_percent"] is None:
            out["host_cpu_percent"] = round(float(psutil.cpu_percent(interval=0) or 0.0), 1)
        if out["host_memory_percent"] is None:
            out["host_memory_percent"] = round(float(psutil.virtual_memory().percent or 0.0), 1)

        global _prev_net, _prev_net_t
        if out["net_recv_bps"] is None or out["net_sent_bps"] is None:
            net = psutil.net_io_counters()
            now = time.time()
            if _prev_net is not None and _prev_net_t > 0 and now > _prev_net_t:
                dt = now - _prev_net_t
                if dt > 0:
                    out["net_recv_bps"] = max(0.0, (net.bytes_recv - _prev_net.bytes_recv) / dt)
                    out["net_sent_bps"] = max(0.0, (net.bytes_sent - _prev_net.bytes_sent) / dt)
            _prev_net = net
            _prev_net_t = now

        p = _proc_handle()
        out["process_cpu_percent"] = round(float(p.cpu_percent(interval=None) or 0.0), 1)
        out["process_rss_mb"] = round(float(p.memory_info().rss) / (1024 * 1024), 1)

        global _prev_io, _prev_io_t
        try:
            io = p.io_counters()
            now = time.time()
            if _prev_io is not None and _prev_io_t > 0 and now > _prev_io_t:
                dt = now - _prev_io_t
                if dt > 0:
                    out["process_io_read_bps"] = max(
                        0.0, (io.read_bytes - _prev_io.read_bytes) / dt
                    )
                    out["process_io_write_bps"] = max(
                        0.0, (io.write_bytes - _prev_io.write_bytes) / dt
                    )
            _prev_io = io
            _prev_io_t = now
        except Exception:
            pass
    except Exception:
        pass

    try:
        from client_process_priority import get_priority_status
        out["priority"] = get_priority_status()
    except Exception:
        out["priority"] = {}

    return out
