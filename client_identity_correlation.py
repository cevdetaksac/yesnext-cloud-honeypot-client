#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ID-402/403 password-change burst correlation (observe only).

Consumes redacted 4723/4724 events, maintains a bounded in-memory window and
reports aggregate candidates. It never locks/disables accounts and never
retains passwords or raw event payloads.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque


class PasswordBurstCorrelator:
    def __init__(self, window_sec: int = 300, threshold: int = 5):
        self.window_sec = max(30, int(window_sec))
        self.threshold = max(2, int(threshold))
        self._events: Deque[dict] = deque(maxlen=1000)
        self._lock = threading.Lock()

    def record(self, event: dict) -> None:
        if event.get("event_type") not in (
            "password_change_attempt", "password_reset_attempt"
        ):
            return
        with self._lock:
            self._events.append({
                "ts": time.time(),
                "actor": str(event.get("actor_username") or "").lower()[:128],
                "target": str(event.get("username") or "").lower()[:128],
                "result": str(event.get("result") or "unknown")[:32],
                "event_id": int(event.get("event_id") or 0),
            })

    def status(self) -> dict:
        now = time.time()
        with self._lock:
            cutoff = now - self.window_sec
            while self._events and self._events[0]["ts"] < cutoff:
                self._events.popleft()
            events = list(self._events)
        by_actor = {}
        targets = set()
        failures = 0
        for event in events:
            actor = event["actor"] or "<unknown>"
            by_actor[actor] = by_actor.get(actor, 0) + 1
            if event["target"]:
                targets.add(event["target"])
            if event["result"].lower() not in ("success", "succeeded"):
                failures += 1
        peak = max(by_actor.values()) if by_actor else 0
        burst = len(events) >= self.threshold or peak >= self.threshold
        return {
            "mode": "observe",
            "auto_lockout": False,
            "window_sec": self.window_sec,
            "threshold": self.threshold,
            "events": len(events),
            "unique_targets": len(targets),
            "unique_actors": len(by_actor),
            "failed_or_unknown": failures,
            "peak_actor_events": peak,
            "burst_detected": burst,
        }

    @classmethod
    def idle_status(cls, window_sec: int = 300, threshold: int = 5) -> dict:
        """Contract-shaped empty aggregate when correlator is unavailable."""
        return cls(window_sec=window_sec, threshold=threshold).status()
