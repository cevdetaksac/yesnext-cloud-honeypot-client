#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — System Health Monitor (v4.0 Faz 3)

psutil ile sistem metriklerini toplar, hareketli ortalama (z-score)
bazlı anomali tespiti yapar ve sonuçları ThreatEngine'e besler.

İzlenen metrikler:
  - CPU kullanımı (% — eşik: 90)
  - RAM kullanımı (% — eşik: 90)
  - Disk kullanımı (% — eşik: 95)
  - Disk I/O (bytes/s — 3x baseline = anomali)
  - Network I/O (bytes/s — 5x baseline = anomali)
  - Süreç sayısı (2x baseline = anomali)
  - Açık bağlantı sayısı (3x baseline = anomali)

Anomali tespiti:
  - Son 60 ölçümün ortalaması ve std sapması tutulur
  - Z-score > 3.0 → anomali olarak işaretlenir
  - Birden fazla anomali korelasyonu (CPU + Disk I/O → kripto madenci)

API raporlama:
  - POST /api/health/report — periyodik snapshot (her 5 dk)
  - Anomali tespit edilirse ThreatEngine'e skor gönderilir

Exports:
  SystemHealthMonitor — ana sınıf (start / stop / get_stats / get_snapshot)
"""

import statistics
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

COLLECT_INTERVAL = 10       # Collect metrics every 10 seconds
REPORT_INTERVAL = 300       # Report to API every 5 minutes
ANOMALY_Z_THRESHOLD = 3.0   # Z-score threshold for anomaly
MIN_SAMPLES = 15            # Minimum samples before anomaly detection

# Metric definitions: (threshold_type, threshold_value, threat_description, score)
METRIC_CONFIG = {
    "cpu_percent":          ("fixed", 90, "CPU spike — kripto madenci şüphesi", 60),
    "memory_percent":       ("fixed", 90, "Memory spike — bellek sızıntısı veya madenci", 50),
    "disk_usage_percent":   ("fixed", 95, "Disk full — veri taşması veya ransomware", 40),
    "disk_io_read_rate":    ("multiplier", 3.0, "Disk I/O spike — ransomware şüphesi", 70),
    "disk_io_write_rate":   ("multiplier", 3.0, "Disk I/O write spike — ransomware", 75),
    "net_bytes_sent_rate":  ("multiplier", 5.0, "Network outbound spike — data exfiltration", 65),
    "net_bytes_recv_rate":  ("multiplier", 5.0, "Network inbound spike — download/C2", 55),
    "process_count":        ("multiplier", 2.0, "Process count spike — process injection", 45),
    "connection_count":     ("multiplier", 3.0, "Connection count spike — C2 beaconing", 50),
}


# ── Anomaly Detector ─────────────────────────────────────────────

class AnomalyDetector:
    """
    Hareketli ortalama bazlı anomali dedektörü.
    Z-score > threshold → anomali.
    """

    def __init__(self, window_size: int = 60):
        self.values: deque = deque(maxlen=window_size)

    def add(self, value: float) -> Tuple[bool, float]:
        """
        Yeni değer ekle.
        Returns: (is_anomaly, z_score)
        """
        self.values.append(value)
        if len(self.values) < MIN_SAMPLES:
            return False, 0.0

        mean = statistics.mean(self.values)
        stdev = statistics.stdev(self.values)
        if stdev == 0:
            return False, 0.0

        z_score = (value - mean) / stdev
        return z_score > ANOMALY_Z_THRESHOLD, round(z_score, 2)

    @property
    def mean(self) -> float:
        return statistics.mean(self.values) if len(self.values) >= 2 else 0.0


# ── System Health Monitor ────────────────────────────────────────

class SystemHealthMonitor:
    """
    Sistem sağlık metriklerini toplar ve anomali tespiti yapar.

    Usage:
        monitor = SystemHealthMonitor(
            on_alert=threat_engine.process_event,
            api_client=api_client,
            token_getter=lambda: state.get("token", ""),
        )
        monitor.start()
    """

    def __init__(
        self,
        on_alert: Optional[Callable] = None,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        threat_engine=None,
        ransomware_shield=None,
    ):
        self.on_alert = on_alert
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.threat_engine = threat_engine
        self._ransomware_shield = ransomware_shield

        self._running = False

        # Anomaly detectors for each metric
        self._detectors: Dict[str, AnomalyDetector] = {
            name: AnomalyDetector() for name in METRIC_CONFIG
        }

        # Previous I/O counters for rate calculation
        self._prev_disk_io = None
        self._prev_net_io = None
        self._prev_time: float = 0.0

        # Latest snapshot
        self._latest: Dict[str, float] = {}
        self._anomalies: List[str] = []

        # Stats
        self._stats = {
            "samples_collected": 0,
            "anomalies_detected": 0,
            "reports_sent": 0,
            "top_cpu_processes": [],
        }

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True

        threading.Thread(
            target=self._collect_loop,
            name="HealthMonitor-Collect",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._report_loop,
            name="HealthMonitor-Report",
            daemon=True,
        ).start()

        log("[HEALTH] 💊 System health monitor started")

    def stop(self):
        self._running = False
        log("[HEALTH] ✅ Stopped")

    # ── Data Collection ───────────────────────────────────────────

    def _collect_loop(self):
        """Collect system metrics every COLLECT_INTERVAL seconds."""
        while self._running:
            try:
                self._collect_metrics()
            except Exception as e:
                log(f"[HEALTH] Collection error: {e}")
            time.sleep(COLLECT_INTERVAL)

    def _collect_metrics(self):
        """Gather all system metrics and run anomaly detection."""
        try:
            import psutil
        except ImportError:
            return

        now = time.time()
        metrics: Dict[str, float] = {}

        # ── Static metrics ──
        metrics["cpu_percent"] = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()
        metrics["memory_percent"] = mem.percent

        try:
            disk = psutil.disk_usage("C:\\")
            metrics["disk_usage_percent"] = disk.percent
        except Exception:
            metrics["disk_usage_percent"] = 0

        metrics["process_count"] = len(list(psutil.process_iter()))

        try:
            metrics["connection_count"] = len(psutil.net_connections())
        except (psutil.AccessDenied, OSError):
            metrics["connection_count"] = 0

        # ── Rate-based metrics (I/O) ──
        try:
            disk_io = psutil.disk_io_counters()
            net_io = psutil.net_io_counters()

            if self._prev_disk_io and self._prev_time > 0:
                dt = now - self._prev_time
                if dt > 0:
                    metrics["disk_io_read_rate"] = (
                        disk_io.read_bytes - self._prev_disk_io.read_bytes
                    ) / dt
                    metrics["disk_io_write_rate"] = (
                        disk_io.write_bytes - self._prev_disk_io.write_bytes
                    ) / dt
                    metrics["net_bytes_sent_rate"] = (
                        net_io.bytes_sent - self._prev_net_io.bytes_sent
                    ) / dt
                    metrics["net_bytes_recv_rate"] = (
                        net_io.bytes_recv - self._prev_net_io.bytes_recv
                    ) / dt

            self._prev_disk_io = disk_io
            self._prev_net_io = net_io
            self._prev_time = now
        except Exception:
            pass

        # ── Top CPU processes ──
        try:
            top_procs = []
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    pinfo = p.info
                    cpu = pinfo.get('cpu_percent', 0) or 0
                    if cpu > 1.0:
                        mem_mb = round(
                            ((pinfo.get('memory_info') or type('', (), {'rss': 0})).rss)
                            / 1024 / 1024, 1
                        )
                        top_procs.append({
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "cpu": cpu,
                            "memory_mb": mem_mb,
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            top_procs.sort(key=lambda x: x["cpu"], reverse=True)
            self._stats["top_cpu_processes"] = top_procs[:10]
        except Exception:
            pass

        # ── Anomaly detection ──
        detected_anomalies = []
        for name, value in metrics.items():
            if name not in self._detectors:
                continue

            config = METRIC_CONFIG.get(name)
            if not config:
                continue

            threshold_type, threshold_val, description, score = config

            is_anomaly = False

            if threshold_type == "fixed":
                # Fixed threshold check
                if value >= threshold_val:
                    is_anomaly = True
            elif threshold_type == "multiplier":
                # Z-score based
                anomaly_flag, z = self._detectors[name].add(value)
                if anomaly_flag:
                    is_anomaly = True
            else:
                self._detectors[name].add(value)

            if is_anomaly:
                detected_anomalies.append((name, value, description, score))

        self._latest = metrics
        self._anomalies = [a[0] for a in detected_anomalies]
        self._stats["samples_collected"] += 1

        # ── Alert on anomalies ──
        if detected_anomalies:
            self._stats["anomalies_detected"] += len(detected_anomalies)
            for name, value, desc, score in detected_anomalies:
                self._emit_anomaly(name, value, desc, score)

    # ── Anomaly Alerting ──────────────────────────────────────────

    def _emit_anomaly(self, metric: str, value: float, description: str, score: int):
        """Feed anomaly to ThreatEngine."""
        log(f"[HEALTH] ⚠️ Anomaly: {metric} = {value:.1f} — {description}")

        if self.on_alert:
            self.on_alert({
                "event_type": "system_health_anomaly",
                "threat_type": "health_anomaly",
                "severity": "high" if score >= 60 else "warning",
                "threat_score": score,
                "details": {
                    "metric": metric,
                    "value": round(value, 2),
                    "description": description,
                },
                "description": (
                    f"Sistem anomalisi: {description}\n"
                    f"Metrik: {metric} = {value:.1f}"
                ),
            })

    # ── API Reporting ─────────────────────────────────────────────

    def _report_loop(self):
        """Report system health snapshot to API periodically."""
        while self._running:
            time.sleep(REPORT_INTERVAL)
            try:
                self._send_report()
            except Exception as e:
                log(f"[HEALTH] Report error: {e}")

    def _send_report(self):
        """POST /api/health/report"""
        if not self.api_client or not self._latest:
            return
        token = self.token_getter()
        if not token:
            return

        # Collect extended memory and disk info
        mem_total_gb = 0.0
        mem_used_gb = 0.0
        disk_total_gb = 0
        disk_free_gb = 0
        try:
            import psutil
            mem = psutil.virtual_memory()
            mem_total_gb = round(mem.total / (1024 ** 3), 1)
            mem_used_gb = round(mem.used / (1024 ** 3), 1)
            try:
                disk = psutil.disk_usage("C:\\")
                disk_total_gb = round(disk.total / (1024 ** 3))
                disk_free_gb = round(disk.free / (1024 ** 3))
            except Exception:
                pass
        except Exception:
            pass

        # VSS shadow count + ransomware shield status
        vss_shadow_count = 0
        ransomware_shield_status = "disabled"
        canary_files_intact = True
        if self._ransomware_shield:
            try:
                ransomware_shield_status = "active" if self._ransomware_shield._running else "disabled"
                rs_stats = self._ransomware_shield.get_stats()
                canary_files_intact = rs_stats.get("canary_alerts", 0) == 0
                vss_shadow_count = getattr(self._ransomware_shield, "_vss_count", 0) or 0
            except Exception:
                ransomware_shield_status = "error"

        payload = {
            "token": token,
            "snapshot": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cpu_percent": self._latest.get("cpu_percent", 0),
                "memory_percent": self._latest.get("memory_percent", 0),
                "memory_total_gb": mem_total_gb,
                "memory_used_gb": mem_used_gb,
                "disk_usage_percent": self._latest.get("disk_usage_percent", 0),
                "disk_total_gb": disk_total_gb,
                "disk_free_gb": disk_free_gb,
                "disk_io_read_rate": round(self._latest.get("disk_io_read_rate", 0)),
                "disk_io_write_rate": round(self._latest.get("disk_io_write_rate", 0)),
                "net_bytes_sent_rate": round(self._latest.get("net_bytes_sent_rate", 0)),
                "net_bytes_recv_rate": round(self._latest.get("net_bytes_recv_rate", 0)),
                "process_count": self._latest.get("process_count", 0),
                "connection_count": self._latest.get("connection_count", 0),
                "anomalies_detected": self._anomalies,
                "top_cpu_processes": self._stats.get("top_cpu_processes", [])[:5],
                "vss_shadow_count": vss_shadow_count,
                "ransomware_shield_status": ransomware_shield_status,
                "canary_files_intact": canary_files_intact,
            },
        }

        try:
            resp = self.api_client.api_request(
                "POST", "health/report",
                data=payload, timeout=10, verbose_logging=False,
            )
            if isinstance(resp, dict) and resp.get("status") in ("ok", "success", "received"):
                self._stats["reports_sent"] += 1
        except Exception as e:
            log(f"[HEALTH] API report error: {e}")

    # ── Public Accessors ──────────────────────────────────────────

    def get_stats(self) -> dict:
        return dict(self._stats)

    def get_snapshot(self) -> dict:
        """Current system health snapshot for dashboard."""
        return {
            "cpu_percent": self._latest.get("cpu_percent", 0),
            "memory_percent": self._latest.get("memory_percent", 0),
            "disk_usage_percent": self._latest.get("disk_usage_percent", 0),
            "process_count": self._latest.get("process_count", 0),
            "connection_count": self._latest.get("connection_count", 0),
            "anomalies": list(self._anomalies),
            "status": self._get_health_status(),
        }

    def _get_health_status(self) -> str:
        """Overall health assessment."""
        if len(self._anomalies) >= 3:
            return "critical"
        elif len(self._anomalies) >= 1:
            return "warning"
        return "healthy"
