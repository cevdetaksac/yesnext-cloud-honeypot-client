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
REPORT_INTERVAL = 60        # Health report to API every 60s (sessions/processes for dashboard)
ANOMALY_Z_THRESHOLD = 3.0   # Z-score threshold for anomaly
MIN_SAMPLES = 15            # Minimum samples before anomaly detection
MAX_TOP_PROCESSES = 120     # Cap process list for health report

# Suspicious process heuristics
_SUSPICIOUS_NAMES = (
    "mimikatz", "procdump", "psexec", "psexesvc", "nc.exe", "ncat",
    "cobalt", "beacon", "ransom", "lazagne", "sharpdump", "nanodump",
)
_SUSPICIOUS_PATH_MARKERS = (
    "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\public\\",
)
_LOLBIN_HINTS = (
    ("powershell", ("-enc", "-encodedcommand", "-e ", "downloadstring", "iex ")),
    ("pwsh", ("-enc", "-encodedcommand", "downloadstring")),
    ("wscript", (".vbs", ".js", "http")),
    ("cscript", (".vbs", ".js")),
    ("mshta", ("http", ".hta", "javascript:")),
    ("rundll32", ("http", "javascript:", ".dll,")),
    ("certutil", ("-urlcache", "-decode", "-f ")),
)
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
            "top_processes": [],
            "active_sessions": [],
        }
        self._mem_total_bytes = 0
        self._rdp_ports = {3389}
        try:
            from client_constants import RDP_SECURE_PORT
            if RDP_SECURE_PORT:
                self._rdp_ports.add(int(RDP_SECURE_PORT))
        except Exception:
            pass

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

        # ── Top / rich processes + active sessions ──
        try:
            mem_total = mem.total or 1
            self._mem_total_bytes = mem_total
            rich = self._collect_rich_processes(psutil, mem_total)
            self._stats["top_processes"] = rich
            self._stats["top_cpu_processes"] = rich[:10]
        except Exception as e:
            log(f"[HEALTH] Process collect error: {e}")

        try:
            self._stats["active_sessions"] = self._collect_active_sessions()
        except Exception as e:
            log(f"[HEALTH] Session collect error: {e}")

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

    # ── Sessions & Processes ──────────────────────────────────────

    def _collect_active_sessions(self) -> List[dict]:
        """Enumerate interactive / RDP sessions (canonical active_sessions schema)."""
        import subprocess
        CREATE_NO_WINDOW = 0x08000000
        sessions: List[dict] = []
        now = time.time()
        remote_ips = self._guess_rdp_client_ips()

        # query user — richest text source
        try:
            r = subprocess.run(
                ["query", "user"],
                capture_output=True, text=True, timeout=8,
                creationflags=CREATE_NO_WINDOW,
            )
            for line in (r.stdout or "").splitlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                if parts[0].startswith(">"):
                    parts[0] = parts[0][1:]
                username = parts[0]
                # Typical: USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME
                # Disconnected may omit SESSIONNAME
                session_name = ""
                session_id = None
                status = "Unknown"
                idle_sec = None
                login_time = None

                # Find numeric session id
                id_idx = None
                for i, p in enumerate(parts[1:], 1):
                    if p.isdigit():
                        id_idx = i
                        break
                if id_idx is None:
                    continue
                if id_idx > 1:
                    session_name = parts[1]
                session_id = int(parts[id_idx])
                status_raw = parts[id_idx + 1] if len(parts) > id_idx + 1 else ""
                status = {
                    "active": "Active",
                    "disc": "Disconnected",
                    "listen": "Listen",
                }.get(status_raw.lower(), status_raw or "Unknown")

                # Idle column often "none" or ".:" or "1+00:12"
                rest = parts[id_idx + 2:]
                if rest:
                    idle_tok = rest[0]
                    idle_sec = self._parse_idle_to_sec(idle_tok)
                    logon_parts = rest[1:] if idle_tok.lower() != "none" or len(rest) > 1 else rest
                    if idle_tok.lower() in ("none", ".") or ":" in idle_tok or idle_tok.isdigit() or "+" in idle_tok:
                        logon_parts = rest[1:]
                    else:
                        logon_parts = rest
                    login_time = self._parse_logon_to_iso(" ".join(logon_parts)) if logon_parts else None

                protocol = "Console"
                sn = (session_name or "").lower()
                if sn.startswith("rdp") or "tcp#" in sn:
                    protocol = "RDP"
                elif not session_name or sn in ("console", "services"):
                    protocol = "Console" if sn != "services" else "Services"

                client_ip = ""
                if protocol == "RDP" and status == "Active":
                    if len(remote_ips) == 1:
                        client_ip = remote_ips[0]
                    elif remote_ips:
                        client_ip = remote_ips[0]  # best-effort

                duration_sec = None
                if login_time:
                    try:
                        lt = datetime.fromisoformat(login_time.replace("Z", "+00:00"))
                        duration_sec = max(0, int(now - lt.timestamp()))
                    except Exception:
                        pass

                sessions.append({
                    "username": username,
                    "session_id": session_id,
                    "session_name": session_name or ("Console" if protocol == "Console" else ""),
                    "status": status,
                    "client_ip": client_ip,
                    "protocol": protocol,
                    "logon_type": 10 if protocol == "RDP" else (2 if protocol == "Console" else None),
                    "login_time": login_time,
                    "duration_sec": duration_sec,
                    "idle_sec": idle_sec,
                    "client_name": "",
                })
        except Exception as e:
            log(f"[HEALTH] query user failed: {e}")

        # Fallback: at least console from query session
        if not sessions:
            try:
                r = subprocess.run(
                    ["query", "session"],
                    capture_output=True, text=True, timeout=8,
                    creationflags=CREATE_NO_WINDOW,
                )
                for line in (r.stdout or "").splitlines()[1:]:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    name = parts[0].lstrip(">")
                    # SESSIONNAME USERNAME ID STATE
                    if len(parts) >= 4 and not parts[1].isdigit():
                        username, sid, state = parts[1], parts[2], parts[3]
                    elif parts[1].isdigit():
                        username, sid, state = "", parts[1], parts[2] if len(parts) > 2 else ""
                    else:
                        continue
                    if not sid.isdigit():
                        continue
                    proto = "RDP" if name.lower().startswith("rdp") else "Console"
                    sessions.append({
                        "username": username or "SYSTEM",
                        "session_id": int(sid),
                        "session_name": name,
                        "status": state or "Unknown",
                        "client_ip": remote_ips[0] if proto == "RDP" and remote_ips else "",
                        "protocol": proto,
                        "logon_type": 10 if proto == "RDP" else 2,
                        "login_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "duration_sec": None,
                        "idle_sec": None,
                        "client_name": "",
                    })
            except Exception as e:
                log(f"[HEALTH] query session fallback failed: {e}")

        return sessions

    def _guess_rdp_client_ips(self) -> List[str]:
        """Best-effort remote IPs connected to RDP listen ports."""
        ips: List[str] = []
        try:
            import psutil
            for c in psutil.net_connections(kind="inet"):
                try:
                    if c.status != "ESTABLISHED":
                        continue
                    lport = c.laddr.port if c.laddr else None
                    if lport not in self._rdp_ports:
                        continue
                    rip = c.raddr.ip if c.raddr else ""
                    if rip and rip not in ("127.0.0.1", "::1") and rip not in ips:
                        ips.append(rip)
                except Exception:
                    continue
        except Exception:
            pass
        return ips

    @staticmethod
    def _parse_idle_to_sec(tok: str) -> Optional[int]:
        t = (tok or "").strip().lower()
        if not t or t in (".", "none", "hiçbir"):
            return 0
        try:
            # formats: 1:23, 1+02:15, 12
            days = 0
            if "+" in t:
                d, t = t.split("+", 1)
                days = int(d)
            if ":" in t:
                parts = [int(x) for x in t.split(":")]
                if len(parts) == 2:
                    return days * 86400 + parts[0] * 3600 + parts[1] * 60
                if len(parts) == 3:
                    return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]
            return int(t) * 60
        except Exception:
            return None

    @staticmethod
    def _parse_logon_to_iso(text: str) -> Optional[str]:
        text = (text or "").strip()
        if not text:
            return None
        # Try common local formats then emit UTC ISO
        from datetime import datetime as _dt
        for fmt in (
            "%d.%m.%Y %H:%M",
            "%d/%m/%Y %H:%M",
            "%m/%d/%Y %I:%M %p",
            "%m/%d/%Y %H:%M",
            "%Y-%m-%d %H:%M",
            "%d.%m.%Y %H:%M:%S",
        ):
            try:
                local = _dt.strptime(text, fmt)
                # Assume local timezone wall clock
                ts = time.mktime(local.timetuple())
                return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                continue
        return None

    def _collect_rich_processes(self, psutil, mem_total: int) -> List[dict]:
        """Build canonical top_processes list (≤ MAX_TOP_PROCESSES)."""
        now = time.time()
        # Prime CPU counters
        for p in psutil.process_iter(["pid"]):
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass
        time.sleep(0.15)

        collected: Dict[int, dict] = {}
        for p in psutil.process_iter([
            "pid", "name", "cpu_percent", "memory_info", "username",
            "exe", "create_time", "cmdline", "status",
        ]):
            try:
                info = p.info
                pid = info.get("pid")
                if not pid:
                    continue
                mem_info = info.get("memory_info")
                rss = getattr(mem_info, "rss", 0) if mem_info else 0
                mem_mb = round(rss / (1024 * 1024), 1)
                mem_pct = round((rss / mem_total) * 100, 2) if mem_total else 0.0
                cpu = float(info.get("cpu_percent") or 0.0)
                path = info.get("exe") or ""
                name = info.get("name") or ""
                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list or "")
                create_time = info.get("create_time") or 0
                started_at = None
                runtime_sec = None
                if create_time:
                    started_at = datetime.fromtimestamp(
                        create_time, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    runtime_sec = max(0, int(now - create_time))

                suspicious, reasons = self._process_suspicion(name, path, cmdline)
                entry = {
                    "pid": pid,
                    "name": name,
                    "path": path[:260] if path else "",
                    "username": info.get("username") or "",
                    "cpu_percent": round(cpu, 1),
                    "cpu": round(cpu, 1),  # alias
                    "memory_mb": mem_mb,
                    "memory_percent": mem_pct,
                    "status": info.get("status") or "running",
                    "started_at": started_at,
                    "runtime_sec": runtime_sec,
                    "cmdline": (cmdline[:500] if cmdline else ""),
                    "suspicious": suspicious,
                    "suspicion_reasons": reasons,
                }
                collected[pid] = entry
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        procs = list(collected.values())
        by_cpu = sorted(procs, key=lambda x: x.get("cpu_percent", 0), reverse=True)[:80]
        by_mem = sorted(procs, key=lambda x: x.get("memory_mb", 0), reverse=True)[:40]
        suspicious = [p for p in procs if p.get("suspicious")]

        merged: Dict[int, dict] = {}
        for group in (by_cpu, by_mem, suspicious):
            for p in group:
                merged[p["pid"]] = p

        out = list(merged.values())
        out.sort(
            key=lambda x: (not x.get("suspicious"), -(x.get("cpu_percent") or 0)),
        )
        return out[:MAX_TOP_PROCESSES]

    @staticmethod
    def _process_suspicion(name: str, path: str, cmdline: str) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        nlow = (name or "").lower()
        plow = (path or "").lower().replace("/", "\\")
        clow = (cmdline or "").lower()

        for marker in _SUSPICIOUS_PATH_MARKERS:
            if marker in plow:
                reasons.append("temp_path")
                break
        for bad in _SUSPICIOUS_NAMES:
            if bad in nlow or bad in plow:
                reasons.append("name_match")
                break
        for bin_name, hints in _LOLBIN_HINTS:
            if bin_name in nlow or bin_name in plow:
                if any(h in clow for h in hints):
                    reasons.append("lolbin")
                    break
        return (len(reasons) > 0), reasons

    # ── Anomaly Alerting ──────────────────────────────────────────

    def _get_top_disk_io_processes(self, top_n: int = 5) -> List[dict]:
        """Disk I/O anomalisi sırasında en çok disk yazan/okuyan süreçleri tespit et."""
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'io_counters', 'exe', 'create_time']):
                try:
                    info = p.info
                    io = info.get('io_counters')
                    if io is None:
                        continue
                    procs.append({
                        "pid": info['pid'],
                        "name": info.get('name', 'unknown'),
                        "exe": (info.get('exe') or 'N/A')[:120],
                        "read_bytes": io.read_bytes,
                        "write_bytes": io.write_bytes,
                        "read_mb": round(io.read_bytes / 1024 / 1024, 1),
                        "write_mb": round(io.write_bytes / 1024 / 1024, 1),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            procs.sort(key=lambda x: x["write_bytes"], reverse=True)
            return procs[:top_n]
        except Exception:
            return []

    def _get_top_network_processes(self, top_n: int = 5) -> List[dict]:
        """Network anomalisi sırasında en çok ağ trafiği oluşturan süreçleri tespit et."""
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'io_counters', 'exe']):
                try:
                    info = p.info
                    io = info.get('io_counters')
                    if io is None:
                        continue
                    # psutil io_counters doesn't distinguish network from disk
                    # but we can use net connections per process instead
                    try:
                        conns = p.net_connections()
                        conn_count = len(conns)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        conn_count = 0
                    if conn_count > 0:
                        procs.append({
                            "pid": info['pid'],
                            "name": info.get('name', 'unknown'),
                            "exe": (info.get('exe') or 'N/A')[:120],
                            "connections": conn_count,
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            procs.sort(key=lambda x: x["connections"], reverse=True)
            return procs[:top_n]
        except Exception:
            return []

    def _emit_anomaly(self, metric: str, value: float, description: str, score: int):
        """Feed anomaly to ThreatEngine with detailed process information."""
        # Metriğe göre detaylı bilgi topla
        process_details = []
        if "disk_io" in metric:
            process_details = self._get_top_disk_io_processes()
            if process_details:
                proc_lines = "; ".join(
                    f"{p['name']}(PID:{p['pid']}) W:{p['write_mb']}MB R:{p['read_mb']}MB [{p['exe']}]"
                    for p in process_details[:3]
                )
                log(f"[HEALTH] ⚠️ Anomaly: {metric} = {value:.1f} — {description}")
                log(f"[HEALTH] 📋 Top disk I/O processes: {proc_lines}")
            else:
                log(f"[HEALTH] ⚠️ Anomaly: {metric} = {value:.1f} — {description}")
        elif "net_bytes" in metric:
            process_details = self._get_top_network_processes()
            if process_details:
                proc_lines = "; ".join(
                    f"{p['name']}(PID:{p['pid']}) conns:{p['connections']} [{p['exe']}]"
                    for p in process_details[:3]
                )
                log(f"[HEALTH] ⚠️ Anomaly: {metric} = {value:.1f} — {description}")
                log(f"[HEALTH] 📋 Top network processes: {proc_lines}")
            else:
                log(f"[HEALTH] ⚠️ Anomaly: {metric} = {value:.1f} — {description}")
        else:
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
                    "suspect_processes": process_details[:5],
                },
                "description": (
                    f"Sistem anomalisi: {description}\n"
                    f"Metrik: {metric} = {value:.1f}\n"
                    + (f"Şüpheli süreçler: {', '.join(p['name'] + '(PID:' + str(p['pid']) + ')' for p in process_details[:3])}"
                       if process_details else "")
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
        self_memory_mb = 0.0
        try:
            import psutil
            mem = psutil.virtual_memory()
            mem_total_gb = round(mem.total / (1024 ** 3), 1)
            mem_used_gb = round(mem.used / (1024 ** 3), 1)
            # Self-process memory usage
            self_memory_mb = round(
                psutil.Process().memory_info().rss / 1024 / 1024, 1
            )
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
                # Canonical field names (server also accepts legacy aliases)
                "disk_io_read_bytes_sec": round(self._latest.get("disk_io_read_rate", 0)),
                "disk_io_write_bytes_sec": round(self._latest.get("disk_io_write_rate", 0)),
                "network_bytes_sent_sec": round(self._latest.get("net_bytes_sent_rate", 0)),
                "network_bytes_recv_sec": round(self._latest.get("net_bytes_recv_rate", 0)),
                "process_count": self._latest.get("process_count", 0),
                "open_connections": self._latest.get("connection_count", 0),
                "connection_count": self._latest.get("connection_count", 0),
                "anomalies_detected": self._anomalies,
                "top_processes": list(self._stats.get("top_processes") or []),
                "top_cpu_processes": [
                    {
                        "pid": p.get("pid"),
                        "name": p.get("name"),
                        "cpu_percent": p.get("cpu_percent", p.get("cpu", 0)),
                        "cpu": p.get("cpu_percent", p.get("cpu", 0)),
                        "memory_mb": p.get("memory_mb", 0),
                        "memory_percent": p.get("memory_percent", 0),
                        "path": p.get("path", ""),
                        "username": p.get("username", ""),
                        "suspicious": p.get("suspicious", False),
                    }
                    for p in (self._stats.get("top_cpu_processes") or self._stats.get("top_processes") or [])[:15]
                ],
                "active_sessions": list(self._stats.get("active_sessions") or []),
                "sessions": list(self._stats.get("active_sessions") or []),
                "vss_shadow_count": vss_shadow_count,
                "ransomware_shield_status": ransomware_shield_status,
                "canary_files_intact": canary_files_intact,
                "client_memory_mb": self_memory_mb,
            },
        }

        try:
            resp = self.api_client.api_request(
                "POST", "health/report",
                data=payload, timeout=15, verbose_logging=False,
            )
            if isinstance(resp, dict) and resp.get("status") in ("ok", "success", "received"):
                self._stats["reports_sent"] += 1
                return True
            # Accept any 2xx-style non-null response
            if resp is not None:
                self._stats["reports_sent"] += 1
                return True
        except Exception as e:
            log(f"[HEALTH] API report error: {e}")
        return False

    def force_report(self, refresh: bool = True) -> bool:
        """Immediate health report (dashboard refresh / remote list_* cmds)."""
        try:
            if refresh:
                self._collect_metrics()
            return bool(self._send_report())
        except Exception as e:
            log(f"[HEALTH] force_report error: {e}")
            return False

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
            "active_sessions": list(self._stats.get("active_sessions") or []),
            "top_processes": list(self._stats.get("top_processes") or [])[:30],
            "status": self._get_health_status(),
        }

    def _get_health_status(self) -> str:
        """Overall health assessment."""
        if len(self._anomalies) >= 3:
            return "critical"
        elif len(self._anomalies) >= 1:
            return "warning"
        return "healthy"
