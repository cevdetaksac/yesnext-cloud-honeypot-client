#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RANS-301 — read-only ETW file-I/O shadow sensor (PoC).

Hard invariants:
- Never suspend/kill/restore network.
- Shadow mode only: aggregate locally, optional callback for telemetry.
- Safe without elevated privileges / without pywintrace: reports unavailable.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, Optional


class EtwShadowSensor:
    """In-process shadow counters. Real ETW attach is opt-in later."""

    def __init__(
        self,
        on_sample: Optional[Callable[[dict], None]] = None,
        window_sec: float = 60.0,
    ):
        self.on_sample = on_sample
        self.window_sec = float(window_sec)
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._events: Deque[tuple] = deque(maxlen=5000)
        self._dropped = 0
        self._provider_restarts = 0
        self._available = False
        self._error = ""
        self._mode = "shadow"

    def capabilities(self) -> dict:
        return {
            "etw_file_io": False,  # truthful until a real consumer is wired
            "mode": self._mode,
            "auto_containment": False,
        }

    def start(self) -> bool:
        if self._running:
            return True
        # PoC: do not attach kernel providers yet — inventory + API surface only.
        self._available = False
        self._error = "etw consumer not attached (shadow stub)"
        self._running = True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="EtwShadow", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        self._stop.set()

    def ingest_test_event(
        self,
        *,
        op: str,
        pid: int,
        path: str = "",
        image: str = "",
        process_start_time: float = 0.0,
    ) -> None:
        """Unit-test / future provider hook — never used for containment."""
        with self._lock:
            if len(self._events) >= self._events.maxlen:
                self._dropped += 1
            self._events.append((
                time.time(),
                str(op),
                int(pid),
                str(path)[:260],
                str(image)[:260],
                float(process_start_time or 0.0),
            ))

    def mark_provider_restart(self) -> None:
        with self._lock:
            self._provider_restarts += 1

    def _loop(self) -> None:
        while self._running and not self._stop.is_set():
            sample = self.sample()
            if self.on_sample:
                try:
                    self.on_sample(sample)
                except Exception:
                    pass
            self._stop.wait(self.window_sec)

    def sample(self) -> dict:
        now = time.time()
        with self._lock:
            cutoff = now - self.window_sec
            recent = [e for e in self._events if e[0] >= cutoff]
            by_op: Dict[str, int] = {}
            by_pid: Dict[int, int] = {}
            for _ts, op, pid, _path, _image, _start in recent:
                by_op[op] = by_op.get(op, 0) + 1
                by_pid[pid] = by_pid.get(pid, 0) + 1
            return {
                "available": bool(self._available),
                "mode": self._mode,
                "auto_containment": False,
                "window_sec": self.window_sec,
                "events_in_window": len(recent),
                "ops": by_op,
                "top_pids": sorted(
                    by_pid.items(), key=lambda item: item[1], reverse=True
                )[:8],
                "dropped_events": int(self._dropped),
                "provider_restarts": int(self._provider_restarts),
                "buffer_pressure": bool(
                    self._dropped > 0 or len(self._events) > 4000
                ),
                "error": self._error,
            }

    def status(self) -> dict:
        return self.sample()
