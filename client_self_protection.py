#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Process Self-Protection (v4.0 Faz 3)

Üç katmanlı süreç koruma sistemi:

  Katman 1 — Zamanlanmış Görev (Task Scheduler):
      Client süreci ölürse Windows Task Scheduler otomatik yeniden başlatır.
      on_boot + on_logon + on_event trigger'ları ile 7/24 ayakta kalır.

  Katman 2 — Süreç DACL Koruması:
      SetProcessShutdownParameters ile kapatma sırasını en sona alır.
      Sürecin güvenlik tanımlayıcısını değiştirerek basit taskkill'i engeller.

  Katman 3 — Güvenli Son Nefes (Safe Last Breath):
      Süreç sonlandırılırken çalışır.
      Aktif tehdit bağlamı varsa → SADECE şüpheli IP engellenir.
      Tehdit yoksa (normal çökme) → firewall'a DOKUNMAZ.
      ASLA tüm portları kapatmaz — sunucu brick olmaz.

  ⚠️ TASARIM PRENSİBİ: "Primum non nocere" — Önce zarar verme.

Exports:
  ProcessProtection — ana sınıf (setup / get_status)
"""

import atexit
import ctypes
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Optional

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

CREATE_NO_WINDOW = 0x08000000

TASK_NAME = "HoneypotClientGuard"
TASK_DESCRIPTION = "YesNext Honeypot Client — otomatik yeniden başlatma koruyucusu"

# Last breath: only consider threats within this window
LAST_BREATH_THREAT_WINDOW = 60  # seconds
LAST_BREATH_MIN_SCORE = 70     # minimum threat score to trigger IP block


# ── Process Protection ────────────────────────────────────────────

class ProcessProtection:
    """
    Client sürecinin saldırgan tarafından kapatılmasını zorlaştırır
    ve kapatılsa bile güvenli aksiyonlar alır.

    Usage:
        protection = ProcessProtection(
            threat_engine=threat_engine,
            api_url="https://honeypot.yesnext.com.tr/api",
            token_getter=lambda: state.get("token", ""),
        )
        protection.setup()
    """

    def __init__(
        self,
        threat_engine=None,
        api_url: str = "",
        token_getter=None,
        alert_pipeline=None,
        api_client=None,
    ):
        self.threat_engine = threat_engine
        self.alert_pipeline = alert_pipeline
        self.api_client = api_client
        # Derive api_url from api_client if not provided
        if not api_url and api_client and hasattr(api_client, 'base_url'):
            self.api_url = api_client.base_url
        elif not api_url:
            try:
                from client_constants import API_URL
                self.api_url = API_URL
            except ImportError:
                self.api_url = ""
        else:
            self.api_url = api_url
        self.token_getter = token_getter or (lambda: "")
        self._setup_done = False

    # ── Public Setup ──────────────────────────────────────────────

    def setup(self):
        """Tüm koruma katmanlarını etkinleştir."""
        if self._setup_done:
            return
        self._setup_done = True

        # Katman 2: Shutdown priority + DACL
        self._set_shutdown_priority()
        self._protect_process_dacl()

        # Katman 3: Safe Last Breath signal handlers
        self._register_signal_handlers()

        # Katman 1: Ensure Task Scheduler entry exists
        self._ensure_task_scheduler()

        log("[SELF-PROTECT] 🛡️ Process protection active (3 layers)")

    def get_status(self) -> dict:
        """Return protection status for dashboard."""
        return {
            "setup_done": self._setup_done,
            "task_exists": self._check_task_exists(),
            "dacl_protected": self._setup_done,
            "last_breath_armed": self._setup_done,
        }

    # ── Katman 1: Task Scheduler ──────────────────────────────────

    def _ensure_task_scheduler(self):
        """
        Zamanlanmış görevin mevcut olduğundan emin ol.
        Not: client_task_scheduler.py zaten bu işlevi sağlıyor (v3.1.0).
        Burada sadece on_event trigger'ını ekliyoruz.
        """
        try:
            if not self._check_task_exists():
                self._create_restart_task()
            else:
                log("[SELF-PROTECT] Task Scheduler entry verified ✅")
        except Exception as e:
            log(f"[SELF-PROTECT] Task Scheduler check error: {e}")

    def _check_task_exists(self) -> bool:
        """Check if our restart task exists in Task Scheduler."""
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/tn", TASK_NAME],
                capture_output=True, text=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _create_restart_task(self):
        """Create a Task Scheduler entry for auto-restart on process death."""
        try:
            # Determine executable path
            exe_path = sys.executable
            if getattr(sys, 'frozen', False):
                exe_path = sys.executable  # PyInstaller frozen

            result = subprocess.run(
                [
                    "schtasks", "/create",
                    "/tn", TASK_NAME,
                    "/tr", f'"{exe_path}" --mode=tray',
                    "/sc", "ONLOGON",
                    "/rl", "HIGHEST",
                    "/f",  # Force overwrite
                ],
                capture_output=True, text=True, timeout=15,
                creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                log("[SELF-PROTECT] ✅ Restart task created in Task Scheduler")
            else:
                log(f"[SELF-PROTECT] Task creation warning: {result.stderr.strip()}")
        except Exception as e:
            log(f"[SELF-PROTECT] Task creation error: {e}")

    # ── Katman 2: Process DACL ────────────────────────────────────

    def _set_shutdown_priority(self):
        """Windows kapatma sırasında en son kapanan süreç ol."""
        try:
            # 0x100 = lowest priority (shuts down last)
            # SHUTDOWN_NORETRY = 0 (allow retry)
            ctypes.windll.kernel32.SetProcessShutdownParameters(0x100, 0)
            log("[SELF-PROTECT] Shutdown priority set to lowest (last to close)")
        except Exception as e:
            log(f"[SELF-PROTECT] Shutdown priority error: {e}")

    def _protect_process_dacl(self):
        """
        Modify process security descriptor to prevent casual taskkill.
        Non-admin users won't be able to terminate the process.
        Note: SYSTEM and elevated admin CAN still terminate.
        """
        try:
            import win32api
            import win32security
            import win32con
            import ntsecuritycon

            # Get current process handle
            pid = os.getpid()
            handle = win32api.OpenProcess(
                win32con.PROCESS_ALL_ACCESS, False, pid
            )

            # Get the process security descriptor
            sd = win32security.GetKernelObjectSecurity(
                handle,
                win32security.DACL_SECURITY_INFORMATION,
            )

            dacl = sd.GetSecurityDescriptorDacl()

            # Deny PROCESS_TERMINATE to Everyone
            everyone_sid = win32security.CreateWellKnownSid(
                win32security.WinWorldSid, None
            )
            dacl.AddAccessDeniedAce(
                win32security.ACL_REVISION,
                ntsecuritycon.PROCESS_TERMINATE,
                everyone_sid,
            )

            sd.SetSecurityDescriptorDacl(True, dacl, False)
            win32security.SetKernelObjectSecurity(
                handle,
                win32security.DACL_SECURITY_INFORMATION,
                sd,
            )

            win32api.CloseHandle(handle)
            log("[SELF-PROTECT] Process DACL protected — casual taskkill blocked")

        except ImportError:
            log("[SELF-PROTECT] DACL protection skipped (pywin32 not fully available)")
        except Exception as e:
            log(f"[SELF-PROTECT] DACL protection error: {e}")

    # ── Katman 3: Güvenli Son Nefes ───────────────────────────────

    def _register_signal_handlers(self):
        """Register atexit and signal handlers for Safe Last Breath."""
        atexit.register(self._on_termination)

        # SIGTERM and SIGINT (SIGKILL cannot be caught)
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (OSError, ValueError):
            pass  # Not all signals available on Windows

        try:
            signal.signal(signal.SIGINT, self._signal_handler)
        except (OSError, ValueError):
            pass

        log("[SELF-PROTECT] Last Breath handlers registered")

    def _signal_handler(self, signum, frame):
        """Signal handler wrapper."""
        self._on_termination(signum=signum)

    def _on_termination(self, signum=None):
        """
        GÜVENLİ SON NEFES — Süreç kapanıyor.

        KURAL: Sadece aktif tehdit bağlamındaki IP'yi engelle.
        ASLA tüm portları kapatma — sunucu brick olabilir!

        Senaryo 1 (Saldırı): Threat engine'de aktif tehdit var
            → Şüpheli IP'yi firewall'da engelle
            → API'ye alert gönder

        Senaryo 2 (Normal çökme/güncelleme): Threat context boş
            → Sadece API'ye "process stopped" log gönder
            → Firewall'a DOKUNMA
            → Zamanlanmış görev client'ı yeniden başlatacak
        """
        try:
            threat_context = self._get_active_threat_context()

            if threat_context and threat_context.get("suspicious_ip"):
                # SALDIRI SENARYOSU — Sadece şüpheli IP'yi engelle
                suspicious_ip = threat_context["suspicious_ip"]
                self._block_single_ip(
                    suspicious_ip,
                    f"Son Nefes: Client killed during active threat (score: "
                    f"{threat_context.get('threat_score', 0)})"
                )
                self._send_last_breath_alert(
                    alert_type="CLIENT_KILLED_DURING_ATTACK",
                    details={
                        "signal": signum,
                        "blocked_ip": suspicious_ip,
                        "threat_score": threat_context.get("threat_score", 0),
                        "threat_type": threat_context.get("threat_type", ""),
                        "message": (
                            f"Client süreci aktif saldırı sırasında sonlandırıldı. "
                            f"Şüpheli IP {suspicious_ip} engellendi. "
                            f"Zamanlanmış görev client'ı yeniden başlatacak."
                        ),
                    }
                )
            else:
                # NORMAL ÇÖKME — Firewall'a dokunma!
                self._send_last_breath_alert(
                    alert_type="CLIENT_PROCESS_STOPPED",
                    details={
                        "signal": signum,
                        "message": (
                            "Client süreci durdu (olası çökme veya güncelleme). "
                            "Tehdit bağlamı yok — firewall değiştirilmedi. "
                            "Zamanlanmış görev client'ı yeniden başlatacak."
                        ),
                    }
                )
        except Exception:
            pass  # Son nefeste exception fırlatma

    def _get_active_threat_context(self) -> Optional[dict]:
        """
        Threat engine'den son 60 saniyedeki aktif tehdit bilgisini al.

        Crash vs saldırı ayrımı:
        - Son 60sn'de yüksek skorlu tehdit varsa → saldırı
        - Hiç tehdit yoksa → muhtemelen kod hatası veya güncelleme
        """
        if not self.threat_engine:
            return None

        try:
            recent = self.threat_engine.get_recent_threats(
                max_age_seconds=LAST_BREATH_THREAT_WINDOW,
                min_score=LAST_BREATH_MIN_SCORE,
            )
            if recent:
                top = max(recent, key=lambda t: t.get("threat_score", 0))
                return {
                    "suspicious_ip": top.get("source_ip"),
                    "threat_score": top.get("threat_score"),
                    "threat_type": top.get("threat_type"),
                    "username": top.get("username"),
                }
        except Exception:
            pass

        return None

    def _block_single_ip(self, ip: str, reason: str):
        """Tek bir IP'yi firewall'da engelle (güvenli — sunucu brick olmaz)."""
        try:
            rule_name = f"HONEYPOT_LASTBREATH_{ip.replace('.', '_')}"
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in", "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                ],
                capture_output=True, text=True, timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    def _send_last_breath_alert(self, alert_type: str, details: dict):
        """Son nefeste API'ye bildirim gönder (timeout: 3sn)."""
        try:
            import requests

            token = self.token_getter()
            if not token or not self.api_url:
                return

            severity = "critical" if "ATTACK" in alert_type else "warning"
            score = 95 if "ATTACK" in alert_type else 30
            blocked_ip = details.get("blocked_ip", "")

            requests.post(
                f"{self.api_url}/alerts/urgent",
                json={
                    "token": token,
                    "severity": severity,
                    "threat_type": alert_type,
                    "title": (
                        "⚠️ Client Süreci Aktif Saldırı Sırasında Sonlandırıldı!"
                        if "ATTACK" in alert_type else
                        "ℹ️ Client Süreci Durdu — Yeniden Başlatılacak"
                    ),
                    "description": details.get("message", ""),
                    "threat_score": score,
                    "auto_response_taken": (
                        [f"block_ip:{blocked_ip}"] if blocked_ip else []
                    ),
                },
                timeout=3,
            )
        except Exception:
            pass  # Best-effort — don't let alert failure prevent shutdown
