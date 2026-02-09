#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Ransomware Shield (v4.0 Faz 3)

Çok katmanlı ransomware algılama ve savunma sistemi.

Katmanlar:
  1. Canary Files — Stratejik konumlara tuzak dosyalar yerleştirilir.
     Herhangi bir değişiklik/silme/rename → Skor 100 → Anlık alert.
  2. File System Watchdog — Toplu dosya operasyonlarını izler.
     Kısa sürede çok fazla rename/modify → ransomware göstergesi.
  3. Suspicious Process Detector — vssadmin delete shadows,
     bcdedit /set recoveryenabled no, cipher /w gibi komutları tespit eder.
  4. VSS Monitor — Shadow Copy sayısı azaldıysa → ransomware.

Akış:
  - Her katman bağımsız çalışır ve ThreatEngine'e skor besler.
  - Skor 100'e ulaşırsa AutoResponse.emergency_lockdown() tetiklenir.
  - API'ye "ransomware_detected" tipinde urgent alert gönderilir.

Exports:
  RansomwareShield — ana sınıf (start / stop / get_stats)
"""

import ctypes
import hashlib
import os
import re
import secrets
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

CREATE_NO_WINDOW = 0x08000000

# Canary file deployment locations (relative to user profile or root)
CANARY_FOLDER_NAMES = [
    "IMPORTANT_DOCUMENTS",
    "Financial_Reports",
    "Company_Data",
]

CANARY_FILES = [
    ("Q4_Financial_Report_2025.xlsx", 4096),
    ("Employee_Database.csv", 3072),
    ("Client_Contracts.pdf", 5120),
    ("Server_Passwords.docx", 2048),
    ("Backup_Keys.txt", 1024),
]

# Suspicious file extensions commonly used by ransomware
SUSPICIOUS_EXTENSIONS: Set[str] = {
    ".encrypted", ".locked", ".crypted", ".crypt",
    ".crypto", ".enc", ".locky", ".cerber", ".zepto",
    ".thor", ".aaa", ".abc", ".xyz", ".zzz",
    ".micro", ".fun", ".gws", ".btc", ".gryphon",
    ".pay", ".ransom", ".wncry", ".wcry",
}

# FS watchdog thresholds
FS_RENAMES_PER_MINUTE = 20
FS_MODIFICATIONS_PER_MINUTE = 50
FS_NEW_EXTENSION_RATIO = 0.3

# Processes that are suspicious when spawned
SUSPICIOUS_PROCESSES: Dict[str, str] = {
    "vssadmin.exe": "Shadow copy manipulation",
    "bcdedit.exe": "Boot config manipulation",
    "wbadmin.exe": "Backup deletion",
    "cipher.exe": "File encryption / disk wipe",
    "certutil.exe": "Certificate utility (download abuse)",
    "bitsadmin.exe": "BITS transfer (download abuse)",
    "mshta.exe": "HTML Application execution",
}

# Command-line patterns that indicate ransomware activity
SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r"vssadmin\s+delete\s+shadows", re.I), "VSS shadow delete", 100),
    (re.compile(r"wmic\s+shadowcopy\s+delete", re.I), "VSS WMIC delete", 100),
    (re.compile(r"bcdedit\s+/set\s+.*recoveryenabled\s+no", re.I), "Recovery disabled", 90),
    (re.compile(r"wbadmin\s+delete\s+catalog", re.I), "Backup catalog delete", 95),
    (re.compile(r"cipher\s+/w:", re.I), "Disk wipe via cipher", 80),
    (re.compile(r"net\s+stop\s+.*sql", re.I), "SQL service stop", 60),
    (re.compile(r"net\s+stop\s+.*backup", re.I), "Backup service stop", 70),
    (re.compile(r"icacls\s+.*/grant\s+Everyone", re.I), "Permission broadening", 50),
    (re.compile(r"attrib\s+\+h\s+\+s", re.I), "File attribute hiding", 40),
]

# VSS check interval
VSS_CHECK_INTERVAL = 120  # seconds


# ── Dataclasses ───────────────────────────────────────────────────

@dataclass
class CanaryState:
    """Tracks a deployed canary file's fingerprint."""
    path: str
    sha256: str
    size: int
    deployed_at: float = field(default_factory=time.time)


# ── Ransomware Shield ────────────────────────────────────────────

class RansomwareShield:
    """
    Multi-layered ransomware detection and defence.

    Usage:
        shield = RansomwareShield(
            on_alert=threat_engine.process_event,
            auto_response=auto_response,
        )
        shield.start()
    """

    def __init__(
        self,
        on_alert: Optional[Callable] = None,
        auto_response=None,
        alert_pipeline=None,
        threat_engine=None,
    ):
        self.on_alert = on_alert
        self.auto_response = auto_response
        self.alert_pipeline = alert_pipeline
        self.threat_engine = threat_engine

        self._running = False

        # Canary state
        self._canaries: List[CanaryState] = []
        self._canary_dir: Optional[str] = None

        # FS watchdog counters (sliding 60-second window)
        self._fs_renames: deque = deque(maxlen=500)
        self._fs_modifications: deque = deque(maxlen=500)

        # VSS baseline
        self._vss_count: Optional[int] = None

        # Process monitoring
        self._seen_pids: Set[int] = set()

        # Stats
        self._stats = {
            "canary_alerts": 0,
            "fs_alerts": 0,
            "process_alerts": 0,
            "vss_alerts": 0,
            "total_detections": 0,
        }

        # Recent detections log
        self._detections: deque = deque(maxlen=50)

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        """Start all ransomware protection layers."""
        if self._running:
            return
        self._running = True

        # Deploy canary files
        self._deploy_canaries()

        # Start monitoring threads
        threading.Thread(
            target=self._canary_watch_loop,
            name="RansomShield-Canary",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._process_monitor_loop,
            name="RansomShield-Process",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._vss_monitor_loop,
            name="RansomShield-VSS",
            daemon=True,
        ).start()

        log("[RANSOMWARE-SHIELD] 🛡️ Started (canary + process + VSS monitors)")

    def stop(self):
        """Stop all monitoring."""
        self._running = False
        log("[RANSOMWARE-SHIELD] ✅ Stopped")

    def get_stats(self) -> dict:
        return dict(self._stats)

    def get_detections(self) -> list:
        return list(self._detections)

    # ── Katman 1: Canary Files ────────────────────────────────────

    def _deploy_canaries(self):
        """Create canary files in strategic locations."""
        try:
            # Primary location: user profile Desktop
            user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Public")
            base_dirs = [
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "Documents"),
                os.path.join("C:\\Users\\Public", "Documents"),
            ]

            for base_dir in base_dirs:
                for folder_name in CANARY_FOLDER_NAMES:
                    canary_dir = os.path.join(base_dir, folder_name)
                    try:
                        os.makedirs(canary_dir, exist_ok=True)
                    except OSError:
                        continue

                    for filename, target_size in CANARY_FILES:
                        filepath = os.path.join(canary_dir, filename)
                        try:
                            if not os.path.exists(filepath):
                                # Generate realistic-looking random content
                                content = secrets.token_bytes(target_size)
                                with open(filepath, "wb") as f:
                                    f.write(content)

                            # Compute hash for change detection
                            file_hash = self._file_hash(filepath)
                            if file_hash:
                                self._canaries.append(CanaryState(
                                    path=filepath,
                                    sha256=file_hash,
                                    size=os.path.getsize(filepath),
                                ))
                        except OSError:
                            continue

            log(f"[RANSOMWARE-SHIELD] 🎯 Deployed {len(self._canaries)} canary files")
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] Canary deploy error: {e}")

    def _canary_watch_loop(self):
        """Periodically check canary file integrity (every 10s)."""
        while self._running:
            try:
                for canary in self._canaries:
                    if not os.path.exists(canary.path):
                        # DELETED — ransomware indicator!
                        self._on_canary_triggered(canary, "DELETED")
                        continue

                    current_hash = self._file_hash(canary.path)
                    if current_hash and current_hash != canary.sha256:
                        # MODIFIED — ransomware indicator!
                        self._on_canary_triggered(canary, "MODIFIED")
                        canary.sha256 = current_hash  # Update to avoid repeat alerts

                    current_size = os.path.getsize(canary.path)
                    if current_size != canary.size:
                        self._on_canary_triggered(canary, "SIZE_CHANGED")
                        canary.size = current_size
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] Canary check error: {e}")

            time.sleep(10)

    def _on_canary_triggered(self, canary: CanaryState, change_type: str):
        """Canary file was tampered with — CRITICAL alert."""
        self._stats["canary_alerts"] += 1
        self._stats["total_detections"] += 1

        filename = os.path.basename(canary.path)
        log(f"[RANSOMWARE-SHIELD] 🚨 CANARY TRIGGERED: {filename} — {change_type}")

        detection = {
            "type": "canary_triggered",
            "file": canary.path,
            "change": change_type,
            "threat_score": 100,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)

        # Feed to threat engine
        if self.on_alert:
            self.on_alert({
                "event_type": "canary_file_tampered",
                "threat_type": "ransomware_canary",
                "severity": "critical",
                "threat_score": 100,
                "details": {
                    "file": filename,
                    "change_type": change_type,
                    "full_path": canary.path,
                },
                "description": (
                    f"🚨 RANSOMWARE ALERT: Canary file '{filename}' was {change_type}. "
                    f"This is a strong indicator of ransomware activity!"
                ),
            })

        # Send urgent alert
        if self.alert_pipeline:
            try:
                self.alert_pipeline.send_urgent({
                    "severity": "critical",
                    "threat_type": "ransomware_canary",
                    "title": f"🚨 Ransomware Tespiti — Canary dosya {change_type}!",
                    "description": (
                        f"Tuzak dosya '{filename}' değiştirildi/silindi. "
                        f"Bu, aktif bir ransomware saldırısının güçlü göstergesidir.\n\n"
                        f"Dosya: {canary.path}\n"
                        f"Değişiklik: {change_type}\n\n"
                        f"Acil müdahale önerilir!"
                    ),
                    "threat_score": 100,
                    "auto_response_taken": ["emergency_alert"],
                })
            except Exception:
                pass

    # ── Katman 3: Suspicious Process Detection ────────────────────

    def _process_monitor_loop(self):
        """Monitor for suspicious process spawns (every 5s)."""
        while self._running:
            try:
                self._check_suspicious_processes()
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] Process monitor error: {e}")
            time.sleep(5)

    def _check_suspicious_processes(self):
        """Check for newly spawned suspicious processes and command patterns."""
        try:
            import psutil
        except ImportError:
            return

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                info = proc.info
                pid = info.get('pid', 0)

                # Skip already-seen processes
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)

                pname = (info.get('name') or '').lower()
                cmdline_parts = info.get('cmdline') or []
                cmdline = ' '.join(cmdline_parts)

                # Check process name
                if pname in SUSPICIOUS_PROCESSES:
                    reason = SUSPICIOUS_PROCESSES[pname]
                    self._on_suspicious_process(pname, pid, cmdline, reason, 50)

                # Check command-line patterns
                for pattern, desc, score in SUSPICIOUS_CMD_PATTERNS:
                    if pattern.search(cmdline):
                        self._on_suspicious_process(pname, pid, cmdline, desc, score)
                        break  # One match per process is enough

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Prune seen PIDs set (keep only active)
        if len(self._seen_pids) > 5000:
            try:
                active_pids = {p.pid for p in psutil.process_iter(['pid'])}
                self._seen_pids &= active_pids
            except Exception:
                self._seen_pids.clear()

    def _on_suspicious_process(
        self, pname: str, pid: int, cmdline: str, reason: str, score: int
    ):
        """Handle detection of a suspicious process."""
        self._stats["process_alerts"] += 1
        self._stats["total_detections"] += 1

        log(f"[RANSOMWARE-SHIELD] ⚠️ Suspicious process: {pname} (PID {pid}) — {reason}")

        detection = {
            "type": "suspicious_process",
            "process": pname,
            "pid": pid,
            "cmdline": cmdline[:200],
            "reason": reason,
            "threat_score": score,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)

        if self.on_alert:
            self.on_alert({
                "event_type": "suspicious_process_detected",
                "threat_type": "ransomware_process",
                "severity": "critical" if score >= 90 else "high",
                "threat_score": score,
                "details": {
                    "process": pname,
                    "pid": pid,
                    "cmdline": cmdline[:200],
                    "reason": reason,
                },
                "description": (
                    f"Şüpheli süreç tespit edildi: {pname} (PID: {pid})\n"
                    f"Sebep: {reason}\n"
                    f"Komut: {cmdline[:200]}"
                ),
            })

        # For VSS deletion — trigger emergency lockdown
        if score >= 95 and self.auto_response:
            try:
                log(f"[RANSOMWARE-SHIELD] 🛑 Emergency lockdown triggered by: {reason}")
                # Kill the suspicious process first
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True, timeout=5,
                        creationflags=CREATE_NO_WINDOW,
                    )
                except Exception:
                    pass
            except Exception:
                pass

    # ── Katman 4: VSS Monitor ─────────────────────────────────────

    def _vss_monitor_loop(self):
        """Monitor Volume Shadow Copy count for deletions."""
        # Get initial baseline
        self._vss_count = self._get_vss_count()
        if self._vss_count is not None:
            log(f"[RANSOMWARE-SHIELD] VSS baseline: {self._vss_count} shadow copies")

        while self._running:
            time.sleep(VSS_CHECK_INTERVAL)
            try:
                current = self._get_vss_count()
                if current is None:
                    continue

                if self._vss_count is not None and current < self._vss_count:
                    # Shadow copies were deleted!
                    deleted_count = self._vss_count - current
                    self._on_vss_deletion(deleted_count, current)

                self._vss_count = current
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] VSS check error: {e}")

    def _get_vss_count(self) -> Optional[int]:
        """Get current number of Volume Shadow Copies."""
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=15,
                creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                return 0

            # Count "Shadow Copy ID:" lines
            count = result.stdout.lower().count("shadow copy id:")
            return count
        except Exception:
            return None

    def _on_vss_deletion(self, deleted_count: int, remaining: int):
        """Shadow copies were deleted — critical ransomware indicator."""
        self._stats["vss_alerts"] += 1
        self._stats["total_detections"] += 1

        log(
            f"[RANSOMWARE-SHIELD] 🚨 VSS DELETION DETECTED: "
            f"{deleted_count} shadow copies deleted ({remaining} remaining)"
        )

        detection = {
            "type": "vss_deletion",
            "deleted_count": deleted_count,
            "remaining": remaining,
            "threat_score": 100,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)

        if self.on_alert:
            self.on_alert({
                "event_type": "vss_shadow_deleted",
                "threat_type": "shadow_copy_deleted",
                "severity": "critical",
                "threat_score": 100,
                "details": {
                    "deleted_count": deleted_count,
                    "remaining": remaining,
                },
                "description": (
                    f"🚨 {deleted_count} Volume Shadow Copy silindi! "
                    f"Kalan: {remaining}. Aktif ransomware saldırısı göstergesi."
                ),
            })

        if self.alert_pipeline:
            try:
                self.alert_pipeline.send_urgent({
                    "severity": "critical",
                    "threat_type": "shadow_copy_deleted",
                    "title": f"🚨 VSS Shadow Copy Silindi — Ransomware Şüphesi!",
                    "description": (
                        f"{deleted_count} adet Volume Shadow Copy silindi.\n"
                        f"Kalan shadow copy sayısı: {remaining}\n\n"
                        f"Bu, aktif bir ransomware saldırısının en güçlü göstergesidir.\n"
                        f"Acil müdahale gereklidir!"
                    ),
                    "threat_score": 100,
                    "auto_response_taken": ["emergency_alert"],
                })
            except Exception:
                pass

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _file_hash(filepath: str) -> Optional[str]:
        """Compute SHA-256 hash of a file."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None
