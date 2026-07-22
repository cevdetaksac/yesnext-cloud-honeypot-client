#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RANS-301/302 — read-only ETW file-I/O shadow sensor (PoC).

Hard invariants:
- Never suspend/kill/restore network.
- Shadow mode only: aggregate locally, optional callback for telemetry.
- Safe without elevated privileges / without pywintrace: reports unavailable.
- Optional psutil disk-IO fallback is named honestly and never claims ETW.
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
        *,
        enable_psutil_fallback: bool = False,
    ):
        self.on_sample = on_sample
        self.window_sec = float(window_sec)
        self.enable_psutil_fallback = bool(enable_psutil_fallback)
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
        self._source = "stub"
        self._fallback = "none"
        self._disk_io_prev: Optional[tuple] = None  # (write_count, write_bytes, ts)

    def capabilities(self) -> dict:
        return {
            "etw_file_io": False,  # truthful until a real consumer is wired
            "mode": self._mode,
            "auto_containment": False,
            "psutil_fallback": bool(self.enable_psutil_fallback),
        }

    def start(self) -> bool:
        if self._running:
            return True
        # PoC: do not attach kernel providers yet — inventory + API surface only.
        self._available = False
        self._error = "etw consumer not attached (shadow stub)"
        self._source = "stub"
        self._fallback = "none"
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

    def _sample_psutil_fallback(self) -> None:
        """Host disk write deltas as soft observe signal (no paths, no ETW claim)."""
        if not self.enable_psutil_fallback:
            return
        try:
            import psutil
        except Exception:
            with self._lock:
                self._fallback = "none"
                self._error = "etw consumer not attached; psutil unavailable"
            return
        try:
            io = psutil.disk_io_counters()
            if io is None:
                with self._lock:
                    self._fallback = "none"
                    self._error = "etw consumer not attached; disk_io unavailable"
                return
            now = time.time()
            cur = (int(io.write_count or 0), int(io.write_bytes or 0), now)
            prev = self._disk_io_prev
            self._disk_io_prev = cur
            with self._lock:
                self._fallback = "psutil"
                self._source = "psutil_io"
                self._error = "etw consumer not attached; using psutil disk_io fallback"
            if not prev:
                return
            dt = max(now - prev[2], 0.5)
            write_delta = max(0, cur[0] - prev[0])
            # Bound synthetic events so fallback cannot flood the deque.
            synthetic = min(write_delta, 32)
            if synthetic <= 0:
                # Still mark activity when bytes moved without count change.
                if cur[1] > prev[1]:
                    self.ingest_test_event(
                        op="write",
                        pid=0,
                        path="",
                        image="psutil_disk_io",
                    )
                return
            for _ in range(int(synthetic)):
                self.ingest_test_event(
                    op="write",
                    pid=0,
                    path="",
                    image="psutil_disk_io",
                )
        except Exception as exc:
            with self._lock:
                self._fallback = "none"
                self._error = f"etw consumer not attached; psutil fallback error: {exc}"

    def _loop(self) -> None:
        while self._running and not self._stop.is_set():
            self._sample_psutil_fallback()
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
            unique_paths: Dict[int, set] = {}
            identities: Dict[int, set] = {}
            for _ts, op, pid, path, image, start in recent:
                normalized_op = str(op).strip().lower()
                by_op[normalized_op] = by_op.get(normalized_op, 0) + 1
                by_pid[pid] = by_pid.get(pid, 0) + 1
                if path:
                    unique_paths.setdefault(pid, set()).add(path.lower())
                identities.setdefault(pid, set()).add((image.lower(), start))

            # RANS-303 shadow correlation: bounded, explainable signals only.
            # This is telemetry, not a ransomware verdict or containment input.
            correlated = []
            write_ops = {"write", "fileio/write", "rename", "fileio/rename"}
            for pid, count in by_pid.items():
                path_count = len(unique_paths.get(pid, set()))
                identity_count = len(identities.get(pid, set()))
                pid_events = [
                    e for e in recent
                    if e[2] == pid and str(e[1]).strip().lower() in write_ops
                ]
                rename_count = sum(
                    1 for e in pid_events
                    if "rename" in str(e[1]).strip().lower()
                )
                write_count = len(pid_events) - rename_count
                score = 0
                signals = []
                if path_count >= 25:
                    score += 35
                    signals.append("file_fanout")
                if rename_count >= 20:
                    score += 30
                    signals.append("rename_burst")
                if write_count >= 30:
                    score += 25
                    signals.append("write_burst")
                if identity_count > 1:
                    score += 10
                    signals.append("pid_identity_changed")
                if score:
                    correlated.append({
                        "pid": pid,
                        "score": min(score, 100),
                        "signals": signals,
                        "events": count,
                        "unique_paths": path_count,
                    })
            correlated.sort(key=lambda item: item["score"], reverse=True)
            return {
                "available": bool(self._available),
                "provider_attached": False,
                "mode": self._mode,
                "source": self._source,
                "fallback": self._fallback,
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
                "correlation": {
                    "mode": "shadow",
                    "auto_containment": False,
                    "candidates": correlated[:8],
                    "candidate_count": len(correlated),
                    "thresholds": {
                        "file_fanout": 25,
                        "rename_burst": 20,
                        "write_burst": 30,
                    },
                },
                "error": self._error,
            }

    def status(self) -> dict:
        return self.sample()
