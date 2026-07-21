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
  - Canary/VSS hit → süreç öldür + IFEO karantina (dashboard/app unlock).
  - Skor 100'e ulaşırsa AutoResponse.emergency_lockdown() tetiklenebilir.
  - API'ye "ransomware_detected" tipinde urgent alert gönderilir.

Gizleme dengesi: ADS / aşırı obscure path ransomware enum'undan kaçar
→ canary işe yaramaz. Hidden+System + erken sort (!000_) doğru denge.

NOT: System Health "disk full" / IDE disk I/O kapasite veya performans
uyarılarıdır — ransomware DEĞİLDİR. Gerçek ransomware sinyalleri:
canary, VSS silme, toplu rename, şüpheli process (vssadmin/bcdedit).

Exports:
  RansomwareShield — ana sınıf (start / stop / get_stats / unlock_quarantine)
"""

import ctypes
import hashlib
import json
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

# Hidden+System + sort-bait names (early in ransomware FindFirstFile walk).
# Admin notice → ProgramData only (not inside bait tree).
CANARY_ROOT_FOLDER = ".cloud-honeypot-canary"

CANARY_SUBFOLDER_NAMES = [
    "!000_reports",
    "!000_finance",
    "!000_archive",
]

_LEGACY_CANARY_SUBFOLDERS = ["reports", "finance", "archive"]

CANARY_FILES = [
    ("!000_quarterly_report.xlsx", 4096),
    ("!000_employee_list.csv", 3072),
    ("!000_contract_draft.pdf", 5120),
    ("!000_credentials_backup.docx", 2048),
    ("!000_recovery_keys.txt", 1024),
]

_LEGACY_CANARY_FILES = [
    ("quarterly_report.xlsx", 4096),
    ("employee_list.csv", 3072),
    ("contract_draft.pdf", 5120),
    ("credentials_backup.docx", 2048),
    ("recovery_keys.txt", 1024),
]

CANARY_README_CONTENT = """Cloud Honeypot Client — koruma dosyalari (yonetici)

Bu dosyalar arka planda ransomware erken tespiti icindir.
Explorer'da gizli + sistem ozelliklidir; normal kullanicida gorunmez.

Silmeyin. Destek: destek@yesnext.com.tr
"""

_QUARANTINE_FILE = "ransomware_quarantine.json"
_PROTECTED_IMAGES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "honeypot-client.exe", "winlogon.exe", "dwm.exe",
    # Benign scanners / sync / indexers — never IFEO-kill (UX + false positive)
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "securityhealthservice.exe",
    "onedrive.exe", "onedriveupdater.exe", "filecoauth.exe",
    "backup.exe", "sdclt.exe", "dllhost.exe", "runtimebroker.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe",
}

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
    (re.compile(r"Get-WmiObject\s+Win32_ShadowCopy", re.I), "VSS WMI PowerShell", 95),
    (re.compile(r"Win32_ShadowCopy.*Delete\(\)", re.I), "VSS WMI delete", 100),
    (re.compile(r"bcdedit\s+/set\s+.*recoveryenabled\s+no", re.I), "Recovery disabled", 90),
    (re.compile(r"wbadmin\s+delete\s+catalog", re.I), "Backup catalog delete", 95),
    (re.compile(r"wbadmin\s+delete\s+systemstatebackup", re.I), "System state backup delete", 95),
    (re.compile(r"cipher\s+/w:", re.I), "Disk wipe via cipher", 80),
    (re.compile(r"fsutil\s+usn\s+deletejournal", re.I), "USN journal wipe", 90),
    (re.compile(r"wevtutil\s+cl\s+", re.I), "Event log clear", 70),
    (re.compile(r"net\s+stop\s+.*sql", re.I), "SQL service stop", 60),
    (re.compile(r"net\s+stop\s+.*backup", re.I), "Backup service stop", 70),
    (re.compile(r"net\s+stop\s+.*vss", re.I), "VSS service stop", 85),
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
        self.canary_enabled = True

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

        # Cloud threat-intel merges (docs/CLOUD_THREAT_INTEL_API.md)
        self._cloud_extensions: Set[str] = set()
        self._cloud_processes: Dict[str, str] = {}
        self._cloud_cmdline_patterns: List = []

        # Quarantine / lockdown after canary or VSS hit
        self._quarantine_lock = threading.RLock()
        self._quarantine: Dict = {
            "active": False,
            "locked_at": "",
            "trigger": "",
            "entries": [],
        }
        self._quarantine_images: Set[str] = set()
        self._load_quarantine()
        self._stats["quarantine_active"] = bool(self._quarantine.get("active"))
        self._stats["quarantine_entries"] = len(self._quarantine.get("entries") or [])
        self._stats["quarantine_kills"] = 0

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

        threading.Thread(
            target=self._quarantine_enforce_loop,
            name="RansomShield-Quarantine",
            daemon=True,
        ).start()

        log("[RANSOMWARE-SHIELD] Started (canary + process + VSS + quarantine)")
        if self._quarantine.get("active"):
            log(
                f"[RANSOMWARE-SHIELD] Quarantine STILL ACTIVE "
                f"({len(self._quarantine_images)} image(s)) — unlock via dashboard/app"
            )

    def stop(self):
        """Stop all monitoring."""
        self._running = False
        log("[RANSOMWARE-SHIELD] ✅ Stopped")

    def get_stats(self) -> dict:
        s = dict(self._stats)
        s["running"] = self._running
        s["canary_files"] = len(self._canaries)
        s["alerts_total"] = (
            s.get("canary_alerts", 0)
            + s.get("fs_alerts", 0)
            + s.get("process_alerts", 0)
            + s.get("vss_alerts", 0)
        )
        with self._quarantine_lock:
            s["quarantine_active"] = bool(self._quarantine.get("active"))
            s["quarantine_entries"] = len(self._quarantine.get("entries") or [])
            s["quarantine_trigger"] = self._quarantine.get("trigger") or ""
            s["quarantine_locked_at"] = self._quarantine.get("locked_at") or ""
        return s

    def get_detections(self) -> list:
        return list(self._detections)

    def get_quarantine(self) -> dict:
        with self._quarantine_lock:
            return dict(self._quarantine)

    def unlock_quarantine(self, reason: str = "manual") -> dict:
        """Clear IFEO blocks + quarantine flag (dashboard / GUI / IPC)."""
        removed = []
        with self._quarantine_lock:
            for entry in list(self._quarantine.get("entries") or []):
                image = (entry.get("image") or "").strip()
                if image and self._clear_ifeo(image):
                    removed.append(image)
            self._quarantine = {
                "active": False,
                "locked_at": "",
                "trigger": "",
                "entries": [],
                "unlocked_at": datetime.now().isoformat(),
                "unlock_reason": reason,
            }
            self._quarantine_images.clear()
            self._stats["quarantine_active"] = False
            self._stats["quarantine_entries"] = 0
            self._persist_quarantine()
        log(f"[RANSOMWARE-SHIELD] Quarantine unlocked ({reason}); cleared={removed}")
        return {"ok": True, "cleared": removed, "reason": reason}

    # ── Katman 1: Canary Files ────────────────────────────────────

    def _deploy_canaries(self):
        """Create sort-bait canaries (Hidden+System) in non-Desktop locations.

        Strategy:
        - NEVER use Desktop
        - Root: .cloud-honeypot-canary (H+S)
        - Subfolders/files prefixed !000_ so ransomware enum hits them early
        - Admin README only in ProgramData (not inside bait tree)
        - Still fingerprint legacy plain-named canaries if present
        """
        try:
            self._write_admin_canary_notice()

            user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Public")
            base_dirs = [
                os.path.join("C:\\Users\\Public", "Documents"),
                os.path.join(os.environ.get("ProgramData", "C:\\ProgramData")),
            ]
            # SYSTEM profile Documents only if not a confusing path
            sys_docs = os.path.join(user_profile, "Documents")
            if not self._is_onedrive_path(sys_docs):
                base_dirs.insert(0, sys_docs)

            # Interactive users' Documents — skip OneDrive-backed (sync scare + quota)
            for up in self._interactive_user_profiles():
                docs = os.path.join(up, "Documents")
                if self._is_onedrive_path(docs):
                    log(f"[RANSOMWARE-SHIELD] skip OneDrive Documents canary: {docs}")
                    continue
                if docs not in base_dirs:
                    base_dirs.append(docs)

            self._canaries = []
            for base_dir in base_dirs:
                canary_root = os.path.join(base_dir, CANARY_ROOT_FOLDER)
                try:
                    os.makedirs(canary_root, exist_ok=True)
                except OSError:
                    continue

                # Remove bait-tree README if older builds left one (sorts early as R*)
                for noise in ("README.txt", "README.md"):
                    try:
                        noise_path = os.path.join(canary_root, noise)
                        if os.path.isfile(noise_path):
                            os.remove(noise_path)
                    except OSError:
                        pass

                self._set_hidden_attribute(canary_root)

                for subfolder in CANARY_SUBFOLDER_NAMES:
                    canary_dir = os.path.join(canary_root, subfolder)
                    try:
                        os.makedirs(canary_dir, exist_ok=True)
                    except OSError:
                        continue
                    self._set_hidden_attribute(canary_dir)

                    for filename, target_size in CANARY_FILES:
                        filepath = os.path.join(canary_dir, filename)
                        try:
                            if not os.path.exists(filepath):
                                content = secrets.token_bytes(target_size)
                                with open(filepath, "wb") as f:
                                    f.write(content)
                            self._set_hidden_attribute(filepath)
                            file_hash = self._file_hash(filepath)
                            if file_hash:
                                self._canaries.append(CanaryState(
                                    path=filepath,
                                    sha256=file_hash,
                                    size=os.path.getsize(filepath),
                                ))
                        except OSError:
                            continue

                # Keep watching legacy names if still on disk (pre-4.5.62)
                for subfolder in _LEGACY_CANARY_SUBFOLDERS:
                    canary_dir = os.path.join(canary_root, subfolder)
                    if not os.path.isdir(canary_dir):
                        continue
                    self._set_hidden_attribute(canary_dir)
                    for filename, _sz in _LEGACY_CANARY_FILES:
                        filepath = os.path.join(canary_dir, filename)
                        if not os.path.isfile(filepath):
                            continue
                        self._set_hidden_attribute(filepath)
                        file_hash = self._file_hash(filepath)
                        if file_hash:
                            self._canaries.append(CanaryState(
                                path=filepath,
                                sha256=file_hash,
                                size=os.path.getsize(filepath),
                            ))

            self._cleanup_legacy_canaries()
            self._register_existing_canary_trees()

            log(
                f"[RANSOMWARE-SHIELD] Deployed {len(self._canaries)} canary files "
                f"(sort-bait + Hidden+System)"
            )

            try:
                from client_utils import get_from_config
                extra = get_from_config("threat_detection.canary_file_paths", None)
                if not extra:
                    extra = get_from_config("canary_file_paths", [])
                for filepath in (extra or []):
                    try:
                        d = os.path.dirname(filepath)
                        if d:
                            os.makedirs(d, exist_ok=True)
                        if not os.path.exists(filepath):
                            with open(filepath, "wb") as f:
                                f.write(secrets.token_bytes(4096))
                        self._set_hidden_attribute(filepath)
                        file_hash = self._file_hash(filepath)
                        if file_hash:
                            self._canaries.append(CanaryState(
                                path=filepath,
                                sha256=file_hash,
                                size=os.path.getsize(filepath),
                            ))
                    except OSError:
                        continue
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] Config canary paths error: {e}")
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] Canary deploy error: {e}")

    def _write_admin_canary_notice(self):
        """Admin-facing notice outside bait tree (ProgramData)."""
        try:
            from client_utils import _programdata_client_dir
            base = _programdata_client_dir()
        except Exception:
            base = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "YesNext",
                "CloudHoneypotClient",
            )
        try:
            os.makedirs(base, exist_ok=True)
            path = os.path.join(base, "CANARY_README.txt")
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(CANARY_README_CONTENT)
        except OSError:
            pass

    @staticmethod
    def _interactive_user_profiles() -> List[str]:
        """Return interactive user profile dirs (exclude Default/Public/system)."""
        out: List[str] = []
        skip = {
            "public", "default", "default user", "all users",
            "defaultuser0", "wdagutilityaccount", "systemprofile",
        }
        # Preferred: ProfileList (works under SYSTEM)
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(root, i)
                        i += 1
                    except OSError:
                        break
                    if not sid.startswith("S-1-5-21-"):
                        continue
                    try:
                        with winreg.OpenKey(root, sid) as sk:
                            profile, _ = winreg.QueryValueEx(sk, "ProfileImagePath")
                    except OSError:
                        continue
                    profile = os.path.expandvars(str(profile or "")).strip()
                    if not profile or not os.path.isdir(profile):
                        continue
                    name = os.path.basename(profile).lower()
                    if name in skip:
                        continue
                    out.append(profile)
        except Exception:
            pass

        # Fallback: C:\Users\*
        if not out:
            users_root = os.path.join(os.environ.get("SystemDrive", "C:"), "Users")
            try:
                for name in os.listdir(users_root):
                    if name.lower() in skip:
                        continue
                    path = os.path.join(users_root, name)
                    if os.path.isdir(path):
                        out.append(path)
            except OSError:
                pass
        return out

    def _register_existing_canary_trees(self) -> None:
        """Watch any .cloud-honeypot-canary trees under Users (even if deploy skipped)."""
        users_root = os.path.join(os.environ.get("SystemDrive", "C:"), "Users")
        known = {c.path.lower() for c in self._canaries}
        try:
            names = os.listdir(users_root)
        except OSError:
            return
        for name in names:
            root = os.path.join(users_root, name, "Documents", CANARY_ROOT_FOLDER)
            if not os.path.isdir(root):
                continue
            if self._is_onedrive_path(root):
                continue
            self._set_hidden_attribute(root)
            for dirpath, _dns, fns in os.walk(root):
                for fn in fns:
                    if not (fn.startswith("!000_") or fn in {x[0] for x in _LEGACY_CANARY_FILES}):
                        continue
                    filepath = os.path.join(dirpath, fn)
                    key = filepath.lower()
                    if key in known:
                        continue
                    try:
                        self._set_hidden_attribute(filepath)
                        file_hash = self._file_hash(filepath)
                        if not file_hash:
                            continue
                        self._canaries.append(CanaryState(
                            path=filepath,
                            sha256=file_hash,
                            size=os.path.getsize(filepath),
                        ))
                        known.add(key)
                    except OSError:
                        continue

    @staticmethod
    def _is_onedrive_path(path: str) -> bool:
        """True if path is under OneDrive (sync would expose bait to user cloud UI)."""
        p = (path or "").lower().replace("/", "\\")
        if "onedrive" in p:
            return True
        try:
            # Resolve junctions (Documents → OneDrive\Documents)
            real = os.path.realpath(path).lower().replace("/", "\\")
            if "onedrive" in real:
                return True
        except OSError:
            pass
        return False

    @staticmethod
    def _set_hidden_attribute(folder_path: str):
        """Hidden + System + NotContentIndexed — invisible in normal Explorer, skip Search."""
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
            ctypes.windll.kernel32.SetFileAttributesW(
                str(folder_path),
                FILE_ATTRIBUTE_HIDDEN
                | FILE_ATTRIBUTE_SYSTEM
                | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            )
        except Exception:
            pass  # Non-Windows or permission issue, silently skip

    def _cleanup_legacy_canaries(self):
        """Remove old-style canary folders from Desktop (pre-v4.0.2).

        Previous versions placed highly visible folders on the Desktop
        which alarmed administrators.  Clean them up silently.
        """
        import shutil

        legacy_folder_names = ["IMPORTANT_DOCUMENTS", "Financial_Reports", "Company_Data"]
        user_profile = os.environ.get("USERPROFILE", "")
        if not user_profile:
            return

        legacy_bases = [
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Documents"),
            os.path.join("C:\\Users\\Public", "Documents"),
        ]

        for base in legacy_bases:
            for folder_name in legacy_folder_names:
                legacy_path = os.path.join(base, folder_name)
                if os.path.isdir(legacy_path):
                    try:
                        shutil.rmtree(legacy_path)
                        log(f"[RANSOMWARE-SHIELD] 🧹 Cleaned legacy canary: {legacy_path}")
                    except OSError:
                        pass

    def _canary_watch_loop(self):
        """Periodically check canary file integrity (default 30s)."""
        while self._running:
            try:
                if getattr(self, "canary_enabled", True):
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

            try:
                from client_constants import RANSOMWARE_CANARY_CHECK_INTERVAL
                interval = int(RANSOMWARE_CANARY_CHECK_INTERVAL)
            except Exception:
                interval = 30
            time.sleep(interval)

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

        # Arm quarantine and attribute the writer before publishing the urgent
        # alert. The scan is bounded to <=4s; empty suspects are still valid.
        containment = {
            "trigger": f"canary {change_type}: {canary.path}",
            "suspects": [],
            "actions": [],
            "quarantine": {"active": True, "entries": 0, "kills": 0},
        }
        try:
            containment = self._contain_after_hit(
                trigger=containment["trigger"],
                focus_path=canary.path,
            )
        except Exception as e:
            # Alert delivery must survive a containment implementation failure.
            log(f"[RANSOMWARE-SHIELD] containment error before urgent: {e}")
        ransomware_context = {
            "trigger": containment.get("trigger") or (
                f"canary {change_type}: {canary.path}"
            ),
            "file": canary.path,
            "change_type": change_type,
            "suspects": list(containment.get("suspects") or []),
            "quarantine": dict(containment.get("quarantine") or {}),
        }
        raw_events = [{
            "event_type": "canary_file_tampered",
            "file": canary.path,
            "full_path": canary.path,
            "change_type": change_type,
            "timestamp": detection["timestamp"],
        }]
        raw_events.extend(
            {
                "event_type": "ransomware_suspect_process",
                "process_name": suspect.get("image") or "",
                "image": suspect.get("image") or "",
                "process_path": suspect.get("path") or "",
                "path": suspect.get("path") or "",
                "pid": suspect.get("pid") or 0,
                "cmdline": suspect.get("cmdline") or "",
                "command_line": suspect.get("cmdline") or "",
                "sha256": suspect.get("sha256") or "",
            }
            for suspect in ransomware_context["suspects"]
            if isinstance(suspect, dict)
        )

        # Feed to threat engine
        if self.on_alert:
            self.on_alert({
                "event_type": "canary_file_tampered",
                "threat_type": "ransomware_canary_triggered",
                "severity": "critical",
                "threat_score": 100,
                # Dashboard/API yes — local tray/toast no (do not scare end users)
                "suppress_local_notify": True,
                "details": {
                    "file": filename,
                    "change_type": change_type,
                    "full_path": canary.path,
                },
                "description": (
                    f"RANSOMWARE ALERT: Canary file '{filename}' was {change_type}. "
                    f"Strong indicator of ransomware activity."
                ),
                "title": "Ransomware koruması — canary tetiklendi",
            })

        # Send urgent alert
        if self.alert_pipeline:
            try:
                self.alert_pipeline.send_urgent({
                    "severity": "critical",
                    "threat_type": "ransomware_canary_triggered",
                    "title": f"🚨 Ransomware Tespiti — Canary dosya {change_type}!",
                    "description": (
                        f"Tuzak dosya '{filename}' değiştirildi/silindi. "
                        f"Bu, aktif bir ransomware saldırısının güçlü göstergesidir.\n\n"
                        f"Dosya: {canary.path}\n"
                        f"Değişiklik: {change_type}\n\n"
                        f"Acil müdahale önerilir!"
                    ),
                    "threat_score": 100,
                    "target_service": "SYSTEM",
                    "recommended_action": "isolate_host",
                    "auto_response_taken": (
                        ["emergency_alert"]
                        + list(containment.get("actions") or [])
                    ),
                    "raw_events": raw_events,
                    "system_context": {
                        "ransomware": ransomware_context,
                    },
                })
            except Exception:
                pass

        # Ransomware tespit — aktif şüpheli IP'leri engelle
        self._block_suspicious_ips(f"canary {change_type}: {filename}")

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

                # Check process name (builtin + cloud intel)
                if pname in SUSPICIOUS_PROCESSES:
                    reason = SUSPICIOUS_PROCESSES[pname]
                    self._on_suspicious_process(pname, pid, cmdline, reason, 50)
                elif pname in self._cloud_processes:
                    reason = self._cloud_processes[pname]
                    self._on_suspicious_process(pname, pid, cmdline, reason, 55)

                # Check command-line patterns (builtin + cloud)
                matched = False
                for pattern, desc, score in SUSPICIOUS_CMD_PATTERNS:
                    if pattern.search(cmdline):
                        self._on_suspicious_process(pname, pid, cmdline, desc, score)
                        matched = True
                        break
                if not matched:
                    for pattern, desc, score in self._cloud_cmdline_patterns:
                        try:
                            if pattern.search(cmdline):
                                self._on_suspicious_process(pname, pid, cmdline, desc, score)
                                break
                        except Exception:
                            continue

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Prune seen PIDs set (keep only active)
        if len(self._seen_pids) > 5000:
            try:
                active_pids = {p.pid for p in psutil.process_iter(['pid'])}
                self._seen_pids &= active_pids
            except Exception:
                self._seen_pids.clear()

    def merge_cloud_intel(self, ransomware_layer: dict) -> int:
        """Merge cloud threat-intel ransomware layer (extensions / processes / cmdline).

        Does NOT trigger lockdown by itself — local canary/VSS remain authoritative.
        """
        if not isinstance(ransomware_layer, dict):
            return 0
        n = 0
        exts = ransomware_layer.get("extensions") or []
        if isinstance(exts, list):
            for x in exts:
                s = str(x or "").strip().lower()
                if not s:
                    continue
                if not s.startswith("."):
                    s = "." + s
                self._cloud_extensions.add(s)
                n += 1

        procs = ransomware_layer.get("process_names") or []
        if isinstance(procs, list):
            for p in procs:
                name = str(p or "").strip().lower()
                if not name:
                    continue
                if not name.endswith(".exe"):
                    name = name + ".exe"
                self._cloud_processes[name] = "cloud_threat_intel"
                n += 1

        patterns = ransomware_layer.get("cmdline_patterns") or []
        compiled = []
        if isinstance(patterns, list):
            for item in patterns:
                if not isinstance(item, dict):
                    continue
                pat = str(item.get("pattern") or "").strip()
                if not pat:
                    continue
                flags = re.I if "i" in str(item.get("flags") or "i").lower() else 0
                try:
                    rx = re.compile(pat, flags)
                except re.error:
                    continue
                desc = str(item.get("id") or item.get("description") or "cloud_cmdline")
                score = 90 if str(item.get("severity") or "").lower() == "critical" else 70
                compiled.append((rx, desc, score))
                n += 1
        if compiled:
            self._cloud_cmdline_patterns = compiled

        if n:
            log(f"[RANSOMWARE-SHIELD] merged cloud intel rules={n}")
        return n

    def get_cloud_extensions(self) -> Set[str]:
        return set(self._cloud_extensions) | set(SUSPICIOUS_EXTENSIONS)

    def _on_suspicious_process(
        self, pname: str, pid: int, cmdline: str, reason: str, score: int
    ):
        """Handle detection of a suspicious process."""
        self._stats["process_alerts"] += 1
        self._stats["total_detections"] += 1

        log(f"[RANSOMWARE-SHIELD] Suspicious process: {pname} (PID {pid}) — {reason}")

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
                log(f"[RANSOMWARE-SHIELD] Emergency lockdown triggered by: {reason}")
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

        # Yüksek skorlu tespit — aktif şüpheli IP'leri engelle
        if score >= 90:
            self._block_suspicious_ips(f"suspicious process: {pname} — {reason}")

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

        # VSS silme — aktif şüpheli IP'leri engelle
        self._block_suspicious_ips(f"VSS deletion: {deleted_count} shadows deleted")

        self._contain_after_hit(
            trigger=f"vss_deletion:{deleted_count}",
            focus_path="",
        )

    # ── Helpers ────────────────────────────────────────────────────

    def _block_suspicious_ips(self, trigger_reason: str):
        """Ransomware tespit edildiğinde ThreatEngine'deki aktif şüpheli IP'leri engelle.

        Mantık:
          - ThreatEngine'deki tüm IP bağlamlarını al
          - Whitelist'te olanları atla
          - Threat score'u >= 30 olanları auto_response ile engelle
          - Bu sayede ransomware'i deploy etmiş olabilecek ağ saldırganları kesilir
        """
        if not self.auto_response or not self.threat_engine:
            return

        try:
            whitelist = getattr(self.threat_engine, '_whitelist_ips', set())
            contexts = self.threat_engine.get_all_contexts()
            blocked_count = 0

            for ip, ctx in contexts.items():
                if ip in whitelist:
                    continue
                # Sadece gerçekten şüpheli olanları engelle
                if ctx.threat_score < 30:
                    continue
                try:
                    self.auto_response.block_ip(
                        ip,
                        reason=f"Ransomware alert — {trigger_reason}",
                        duration_hours=24,
                    )
                    blocked_count += 1
                except Exception:
                    pass

            if blocked_count:
                log(
                    f"[RANSOMWARE-SHIELD] 🔒 Blocked {blocked_count} suspicious IP(s) "
                    f"after ransomware detection ({trigger_reason})"
                )
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] IP block error: {e}")

    # ── Quarantine / containment ─────────────────────────────────

    def _quarantine_path(self) -> str:
        try:
            from client_utils import _programdata_client_dir
            base = _programdata_client_dir()
        except Exception:
            base = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "YesNext",
                "CloudHoneypotClient",
            )
        return os.path.join(base, _QUARANTINE_FILE)

    def _load_quarantine(self) -> None:
        path = self._quarantine_path()
        try:
            if not os.path.isfile(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return
            self._quarantine = data
            images = set()
            for e in data.get("entries") or []:
                img = (e.get("image") or "").strip().lower()
                if img:
                    images.add(img)
            self._quarantine_images = images
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] quarantine load error: {e}")

    def _persist_quarantine(self) -> None:
        path = self._quarantine_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._quarantine, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] quarantine persist error: {e}")

    def _contain_after_hit(self, trigger: str, focus_path: str = "") -> dict:
        """Kill writers of canary path + IFEO-block their images until unlock.

        Arms quarantine immediately (STATUS/GUI), then best-effort attribution.
        Full open_files() scans can take tens of seconds on busy hosts — must not
        delay the lockdown flag.
        """
        # 1) Arm lock immediately
        with self._quarantine_lock:
            entries = list(self._quarantine.get("entries") or [])
            self._quarantine = {
                "active": True,
                "locked_at": self._quarantine.get("locked_at")
                or datetime.now().isoformat(),
                "trigger": trigger,
                "entries": entries,
            }
            self._stats["quarantine_active"] = True
            self._stats["quarantine_entries"] = len(entries)
            self._persist_quarantine()
        log(f"[RANSOMWARE-SHIELD] Quarantine ARMED trigger={trigger}")

        # 2) Attribute writers (time-boxed)
        suspects: List[dict] = []
        try:
            holder: List[List[dict]] = [[]]

            def _scan():
                try:
                    holder[0] = self._find_suspect_processes(focus_path)
                except Exception as e:
                    log(f"[RANSOMWARE-SHIELD] suspect scan error: {e}")

            th = threading.Thread(target=_scan, name="RS-SuspectScan", daemon=True)
            th.start()
            th.join(timeout=4.0)
            if th.is_alive():
                log("[RANSOMWARE-SHIELD] suspect scan timeout — quarantine stays armed")
            else:
                suspects = holder[0] or []
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] suspect scan setup error: {e}")

        actions = []
        with self._quarantine_lock:
            if not self._quarantine.get("active"):
                # Operator unlocked while we scanned
                log("[RANSOMWARE-SHIELD] Containment skipped — already unlocked")
                return {
                    "trigger": trigger,
                    "suspects": suspects,
                    "actions": [],
                    "quarantine": {
                        "active": False,
                        "entries": 0,
                        "kills": int(
                            self._stats.get("quarantine_kills") or 0
                        ),
                    },
                }
            entries = list(self._quarantine.get("entries") or [])
            known = {
                (e.get("image") or "").lower()
                for e in entries
                if e.get("image")
            }
            for s in suspects:
                image = (s.get("image") or "").lower()
                if not image or image in _PROTECTED_IMAGES:
                    continue
                pid = s.get("pid")
                if pid:
                    if self._kill_pid(int(pid)):
                        actions.append(f"kill:{pid}:{image}")
                        self._stats["quarantine_kills"] = (
                            int(self._stats.get("quarantine_kills") or 0) + 1
                        )
                if image not in known:
                    ifeo_ok = self._apply_ifeo(image)
                    entries.append({
                        "image": image,
                        "path": s.get("path") or "",
                        "pid": pid,
                        "cmdline": s.get("cmdline") or "",
                        "sha256": s.get("sha256") or "",
                        "ifeo": bool(ifeo_ok),
                        "at": datetime.now().isoformat(),
                        "trigger": trigger,
                    })
                    known.add(image)
                    self._quarantine_images.add(image)
                    actions.append(f"ifeo:{image}")
            self._quarantine["entries"] = entries
            self._quarantine["trigger"] = trigger
            self._stats["quarantine_entries"] = len(entries)
            self._persist_quarantine()

        if actions:
            log(f"[RANSOMWARE-SHIELD] Containment: {', '.join(actions[:12])}")
        else:
            log(
                f"[RANSOMWARE-SHIELD] Containment armed (no live writer found) "
                f"trigger={trigger}"
            )

        detection = {
            "type": "quarantine_lock",
            "trigger": trigger,
            "actions": actions[:20],
            "threat_score": 100,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)
        return {
            "trigger": trigger,
            "suspects": suspects,
            "actions": actions[:20],
            "quarantine": {
                "active": True,
                "entries": len(entries),
                "kills": int(self._stats.get("quarantine_kills") or 0),
            },
        }

    def _find_suspect_processes(self, focus_path: str) -> List[dict]:
        """Best-effort: processes with open handles under canary root / file.

        Bounded: skip protected images, cap process count, ignore AccessDenied fast.
        """
        out: List[dict] = []
        try:
            import psutil
        except ImportError:
            return out

        focus = (focus_path or "").lower().replace("/", "\\")
        roots = set()
        if focus:
            roots.add(focus)
            parent = os.path.dirname(focus)
            if parent:
                roots.add(parent.lower())
            parts = focus.split("\\")
            for i, p in enumerate(parts):
                if p == CANARY_ROOT_FOLDER.lower() and i > 0:
                    roots.add("\\".join(parts[: i + 1]))
                    break

        my_pid = os.getpid()
        checked = 0
        deadline = time.time() + 3.5
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            if time.time() > deadline:
                break
            try:
                info = proc.info
                pid = int(info.get("pid") or 0)
                if pid in (0, 4, my_pid):
                    continue
                pname = (info.get("name") or "").lower()
                if pname in _PROTECTED_IMAGES:
                    continue
                checked += 1
                if checked > 250:
                    break
                exe = info.get("exe") or ""
                cmdline_raw = info.get("cmdline") or []
                cmdline = (
                    " ".join(str(part) for part in cmdline_raw)
                    if isinstance(cmdline_raw, (list, tuple))
                    else str(cmdline_raw)
                )
                matched = False
                try:
                    for of in proc.open_files() or []:
                        pth = (of.path or "").lower().replace("/", "\\")
                        if not pth:
                            continue
                        if focus and (pth == focus or focus in pth):
                            matched = True
                            break
                        for root in roots:
                            if root and (pth.startswith(root) or root in pth):
                                matched = True
                                break
                        if matched:
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                if not matched:
                    continue
                sha = ""
                if exe and os.path.isfile(exe):
                    sha = self._file_hash(exe) or ""
                out.append({
                    "pid": pid,
                    "image": pname,
                    "path": exe,
                    "cmdline": cmdline,
                    "sha256": sha,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return out

    def _quarantine_enforce_loop(self) -> None:
        """While quarantine active, kill matching image names if they respawn."""
        while self._running:
            try:
                with self._quarantine_lock:
                    active = bool(self._quarantine.get("active"))
                    images = set(self._quarantine_images)
                if active and images:
                    self._kill_quarantined_images(images)
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] quarantine enforce error: {e}")
            time.sleep(3)

    def _kill_quarantined_images(self, images: Set[str]) -> None:
        try:
            import psutil
        except ImportError:
            return
        my_pid = os.getpid()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = int(proc.info.get("pid") or 0)
                if pid in (0, 4, my_pid):
                    continue
                name = (proc.info.get("name") or "").lower()
                if name in images and name not in _PROTECTED_IMAGES:
                    if self._kill_pid(pid):
                        self._stats["quarantine_kills"] = (
                            int(self._stats.get("quarantine_kills") or 0) + 1
                        )
                        log(f"[RANSOMWARE-SHIELD] Quarantine re-kill {name} PID {pid}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    @staticmethod
    def _kill_pid(pid: int) -> bool:
        try:
            r = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _apply_ifeo(image: str) -> bool:
        """IFEO Debugger stub — process fails to start (reversible on unlock)."""
        image = (image or "").strip()
        if not image or image.lower() in _PROTECTED_IMAGES:
            return False
        try:
            import winreg
            key_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\\" + image
            )
            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
            ) as k:
                winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, "nyan")
            return True
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] IFEO apply failed for {image}: {e}")
            return False

    @staticmethod
    def _clear_ifeo(image: str) -> bool:
        image = (image or "").strip()
        if not image:
            return False
        try:
            import winreg
            key_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\\" + image
            )
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
                ) as k:
                    try:
                        winreg.DeleteValue(k, "Debugger")
                    except FileNotFoundError:
                        pass
            except FileNotFoundError:
                return True
            # Remove empty IFEO key if possible
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            except OSError:
                pass
            return True
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] IFEO clear failed for {image}: {e}")
            return False

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
