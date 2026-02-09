#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Performance Optimizer & False Positive Tuning (v4.0 Faz 4)

1. PerformanceOptimizer   — adaptive throttling, resource-aware scheduling, metric collection
2. FalsePositiveTuner     — whitelist learning, cooldown management, score decay tuning

Together they ensure the v4.0 threat detection pipeline runs efficiently on
production servers without impacting legitimate workloads.

Exports:
  PerformanceOptimizer  — singleton, adjusts module intervals based on system load
  FalsePositiveTuner    — learns from user feedback, applies whitelist/cooldown rules
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from client_helpers import log

# ═══════════════════════════════════════════════════════════════════
#  PERFORMANCE OPTIMIZER
# ═══════════════════════════════════════════════════════════════════

# Adaptive thresholds
CPU_HIGH_THRESHOLD = 85          # % — start throttling
CPU_CRITICAL_THRESHOLD = 95      # % — aggressive throttling
MEMORY_HIGH_THRESHOLD = 85       # %
ADAPTIVE_CHECK_INTERVAL = 30     # seconds — how often to re-evaluate
THROTTLE_FACTOR_NORMAL = 1.0
THROTTLE_FACTOR_HIGH = 2.0       # double all intervals
THROTTLE_FACTOR_CRITICAL = 4.0   # quadruple all intervals

# Event processing budget
MAX_EVENTS_PER_SECOND = 50       # throttle EventLog processing
EVENT_BATCH_SIZE = 20            # process in batches
EVENT_QUEUE_MAX = 5000           # drop oldest if queue full


@dataclass
class PerformanceSnapshot:
    """Point-in-time performance reading."""
    timestamp: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    thread_count: int = 0
    event_queue_size: int = 0
    throttle_factor: float = 1.0
    events_per_second: float = 0.0
    dropped_events: int = 0


class PerformanceOptimizer:
    """
    Monitors system resource usage and adjusts threat detection pipeline
    intervals dynamically to prevent impacting server performance.
    
    Features:
      - Adaptive throttling based on CPU/RAM
      - Event rate limiting with queue management
      - Performance metrics collection for dashboard
      - Module interval adjustment recommendations
    """

    def __init__(self):
        self._running = False
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

        # State
        self._throttle_factor: float = THROTTLE_FACTOR_NORMAL
        self._snapshots: deque = deque(maxlen=360)  # ~3 hours @ 30s intervals
        self._event_counter = 0
        self._event_counter_ts = time.time()
        self._dropped_events = 0
        self._events_per_second: float = 0.0

        # Callbacks — modules register their interval adjusters
        self._interval_adjusters: Dict[str, Callable] = {}

        # Event rate limiter
        self._event_times: deque = deque(maxlen=200)

    def start(self):
        """Begin adaptive monitoring loop."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="PerfOptimizer",
            daemon=True,
        )
        self._thread.start()
        log("⚙️ PerformanceOptimizer started (adaptive throttling)")

    def stop(self):
        self._running = False

    def register_adjuster(self, name: str, callback: Callable):
        """Register a module's interval adjuster callback.
        
        callback(factor: float) — called when throttle factor changes.
        Module should multiply its base interval by factor.
        """
        with self._lock:
            self._interval_adjusters[name] = callback

    def should_process_event(self) -> bool:
        """Rate limiter — returns True if event should be processed, False to drop."""
        now = time.time()
        self._event_times.append(now)

        # Calculate current rate
        cutoff = now - 1.0
        recent = sum(1 for t in self._event_times if t >= cutoff)

        effective_limit = MAX_EVENTS_PER_SECOND / self._throttle_factor
        if recent > effective_limit:
            self._dropped_events += 1
            return False
        return True

    def record_event_processed(self):
        """Track event processing for rate calculation."""
        self._event_counter += 1

    @property
    def throttle_factor(self) -> float:
        return self._throttle_factor

    def get_stats(self) -> dict:
        """Current performance stats for dashboard."""
        with self._lock:
            return {
                "throttle_factor": self._throttle_factor,
                "events_per_second": round(self._events_per_second, 1),
                "dropped_events": self._dropped_events,
                "cpu_percent": self._snapshots[-1].cpu_percent if self._snapshots else 0,
                "memory_percent": self._snapshots[-1].memory_percent if self._snapshots else 0,
                "thread_count": threading.active_count(),
                "snapshots_count": len(self._snapshots),
                "throttle_mode": self._get_mode_label(),
            }

    def get_trend_data(self, points: int = 30) -> List[dict]:
        """Return recent snapshots for trend mini-chart."""
        with self._lock:
            recent = list(self._snapshots)[-points:]
        return [
            {
                "ts": s.timestamp,
                "cpu": s.cpu_percent,
                "mem": s.memory_percent,
                "eps": s.events_per_second,
                "tf": s.throttle_factor,
            }
            for s in recent
        ]

    # ─── Internal ──────────────────────────────────────────────

    def _monitor_loop(self):
        """Periodic resource check and throttle adjustment."""
        while self._running:
            try:
                snap = self._take_snapshot()
                with self._lock:
                    self._snapshots.append(snap)

                new_factor = self._calculate_throttle(snap)
                if new_factor != self._throttle_factor:
                    old = self._throttle_factor
                    self._throttle_factor = new_factor
                    self._notify_adjusters(new_factor)
                    log(f"⚙️ Throttle adjusted: {old:.1f}x → {new_factor:.1f}x "
                        f"(CPU={snap.cpu_percent:.0f}%, RAM={snap.memory_percent:.0f}%)")

            except Exception as e:
                log(f"[PerfOptimizer] monitor error: {e}")
            time.sleep(ADAPTIVE_CHECK_INTERVAL)

    def _take_snapshot(self) -> PerformanceSnapshot:
        now = time.time()
        cpu = 0.0
        mem = 0.0
        if PSUTIL_AVAILABLE:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent

        # Calculate events/sec
        elapsed = now - self._event_counter_ts
        if elapsed > 0:
            self._events_per_second = self._event_counter / elapsed
        self._event_counter = 0
        self._event_counter_ts = now

        return PerformanceSnapshot(
            timestamp=now,
            cpu_percent=cpu,
            memory_percent=mem,
            thread_count=threading.active_count(),
            throttle_factor=self._throttle_factor,
            events_per_second=self._events_per_second,
            dropped_events=self._dropped_events,
        )

    def _calculate_throttle(self, snap: PerformanceSnapshot) -> float:
        """Determine throttle factor based on resource usage."""
        if snap.cpu_percent >= CPU_CRITICAL_THRESHOLD or snap.memory_percent >= 95:
            return THROTTLE_FACTOR_CRITICAL
        if snap.cpu_percent >= CPU_HIGH_THRESHOLD or snap.memory_percent >= MEMORY_HIGH_THRESHOLD:
            return THROTTLE_FACTOR_HIGH
        return THROTTLE_FACTOR_NORMAL

    def _notify_adjusters(self, factor: float):
        with self._lock:
            adjusters = dict(self._interval_adjusters)
        for name, cb in adjusters.items():
            try:
                cb(factor)
            except Exception as e:
                log(f"[PerfOptimizer] adjuster '{name}' error: {e}")

    def _get_mode_label(self) -> str:
        if self._throttle_factor >= THROTTLE_FACTOR_CRITICAL:
            return "CRITICAL"
        if self._throttle_factor >= THROTTLE_FACTOR_HIGH:
            return "THROTTLED"
        return "NORMAL"


# ═══════════════════════════════════════════════════════════════════
#  FALSE POSITIVE TUNER
# ═══════════════════════════════════════════════════════════════════

# Default cooldowns (seconds) — prevent repeated alerts for same source
DEFAULT_COOLDOWNS: Dict[str, int] = {
    "failed_logon_single": 60,       # 1 single fail per minute per IP
    "failed_logon_burst": 300,       # burst alert every 5 min
    "successful_logon_rdp": 120,     # RDP login alert every 2 min
    "successful_logon_network": 120,
    "rdp_session_reconnect": 300,    # reconnect is often normal
    "service_start_type_changed": 600,
}

# Score adjustments for frequently false-positive events
FP_SCORE_ADJUSTMENTS: Dict[str, float] = {
    "rdp_session_reconnect": 0.5,    # halve score for reconnects
    "service_start_type_changed": 0.6,
    "unexpected_restart": 0.7,
}

# Max auto-learned whitelist size
MAX_AUTO_WHITELIST = 200
# Min events to consider auto-whitelisting an IP
AUTO_WHITELIST_MIN_EVENTS = 50
# Max threat score for auto-whitelist consideration
AUTO_WHITELIST_MAX_SCORE = 10


@dataclass
class AlertCooldownEntry:
    """Tracks last alert time per (ip, event_type) pair."""
    last_alert_ts: float = 0.0
    count_suppressed: int = 0
    count_total: int = 0


class FalsePositiveTuner:
    """
    Learns from event patterns and reduces false positive alerts.
    
    Features:
      - Per-event-type cooldowns (prevent alert flooding)
      - Score multiplier adjustments for FP-prone events
      - Auto-whitelist learning for trusted IPs
      - User-configurable whitelist overlays
      - Statistics for dashboard display
    """

    def __init__(self,
                 threat_engine=None,
                 event_watcher=None,
                 user_whitelist_ips: Optional[Set[str]] = None):
        self._lock = threading.Lock()
        self._threat_engine = threat_engine
        self._event_watcher = event_watcher

        # Cooldown tracking: key = (ip, event_type)
        self._cooldowns: Dict[tuple, AlertCooldownEntry] = {}
        self._cooldown_config = dict(DEFAULT_COOLDOWNS)

        # Score multipliers
        self._score_adjustments = dict(FP_SCORE_ADJUSTMENTS)

        # Whitelists
        self._user_whitelist: Set[str] = user_whitelist_ips or set()
        self._auto_whitelist: Set[str] = set()

        # IP reputation tracking for auto-learn
        self._ip_event_counts: Dict[str, int] = defaultdict(int)
        self._ip_max_scores: Dict[str, float] = defaultdict(float)

        # Stats
        self._stats = {
            "events_suppressed": 0,
            "events_adjusted": 0,
            "auto_whitelist_count": 0,
            "user_whitelist_count": len(self._user_whitelist),
        }

    def should_alert(self, ip: str, event_type: str) -> bool:
        """Check if an alert should be emitted or suppressed (cooldown check)."""
        # Always allow if no cooldown defined
        cooldown = self._cooldown_config.get(event_type)
        if cooldown is None:
            return True

        key = (ip, event_type)
        now = time.time()

        with self._lock:
            entry = self._cooldowns.get(key)
            if entry is None:
                self._cooldowns[key] = AlertCooldownEntry(last_alert_ts=now, count_total=1)
                return True

            entry.count_total += 1
            if now - entry.last_alert_ts < cooldown:
                entry.count_suppressed += 1
                self._stats["events_suppressed"] += 1
                return False

            entry.last_alert_ts = now
            return True

    def adjust_score(self, event_type: str, base_score: float) -> float:
        """Apply FP score adjustment multiplier."""
        multiplier = self._score_adjustments.get(event_type, 1.0)
        if multiplier != 1.0:
            with self._lock:
                self._stats["events_adjusted"] += 1
        return base_score * multiplier

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted (user or auto-learned)."""
        return ip in self._user_whitelist or ip in self._auto_whitelist

    def record_ip_event(self, ip: str, score: float):
        """Track IP events for auto-whitelist learning."""
        with self._lock:
            self._ip_event_counts[ip] += 1
            self._ip_max_scores[ip] = max(self._ip_max_scores[ip], score)

            # Auto-whitelist: high event count + consistently low score
            if (self._ip_event_counts[ip] >= AUTO_WHITELIST_MIN_EVENTS
                    and self._ip_max_scores[ip] <= AUTO_WHITELIST_MAX_SCORE
                    and len(self._auto_whitelist) < MAX_AUTO_WHITELIST
                    and ip not in self._user_whitelist):
                self._auto_whitelist.add(ip)
                self._stats["auto_whitelist_count"] = len(self._auto_whitelist)
                log(f"🔰 Auto-whitelisted IP {ip} "
                    f"(events={self._ip_event_counts[ip]}, max_score={self._ip_max_scores[ip]})")

    def update_user_whitelist(self, ips: Set[str]):
        """Update user-configured whitelist."""
        with self._lock:
            self._user_whitelist = set(ips)
            self._stats["user_whitelist_count"] = len(self._user_whitelist)
            # Remove auto-whitelisted entries that are now user-whitelisted
            self._auto_whitelist -= self._user_whitelist

        # Push to EventLogWatcher if available
        if self._event_watcher and hasattr(self._event_watcher, 'update_whitelist'):
            self._event_watcher.update_whitelist(ips)

    def update_cooldown(self, event_type: str, seconds: int):
        """Update cooldown for a specific event type."""
        with self._lock:
            self._cooldown_config[event_type] = seconds

    def update_score_adjustment(self, event_type: str, multiplier: float):
        """Update score multiplier for a specific event type."""
        with self._lock:
            self._score_adjustments[event_type] = max(0.0, min(2.0, multiplier))

    def get_stats(self) -> dict:
        """Stats for dashboard display."""
        with self._lock:
            stats = dict(self._stats)
            stats["cooldown_rules"] = len(self._cooldown_config)
            stats["score_adjustments"] = len(self._score_adjustments)
            stats["tracked_ips"] = len(self._ip_event_counts)
            stats["auto_whitelist"] = sorted(self._auto_whitelist)[:20]  # sample
            return stats

    def get_cooldown_config(self) -> Dict[str, int]:
        """Return current cooldown config for settings display."""
        with self._lock:
            return dict(self._cooldown_config)

    def cleanup_stale(self, max_age: int = 3600):
        """Remove stale cooldown entries older than max_age seconds."""
        cutoff = time.time() - max_age
        with self._lock:
            stale = [k for k, v in self._cooldowns.items() if v.last_alert_ts < cutoff]
            for k in stale:
                del self._cooldowns[k]
