"""Network Guard — offline ransomware bomb defense + network-drive backup/recovery.

Contract: agent/network-guard.md (>= 4.7.0).

Five parts:
  A) Signed network baseline snapshot (mapped drives, shares, adapters, DNS,
     routes, firewall, connectivity) with version rotation.
  B) Offline behavioural detection (no internet needed): network-cut delta vs
     baseline + per-process file-write storm (psutil io_counters) + suspicious
     origin scoring. Net-cut + FS-storm => trigger without waiting for canary.
  C) Aggressive containment, suspend-first (freeze suspects, best-effort
     emergency VSS snapshot, register into quarantine; operator confirms
     kill/release).
  D) Network / connectivity recovery from baseline (re-enable adapter, restore
     DNS/firewall/routes/mapped-drives/shares) so the daemon can reconnect.
  E) ransomware_offline_bomb urgent alert (system_context.network_guard).

Honest limit: this is not a full EDR/AV. Behavioural mass-encryption detection
can false-positive; defaults are safe (suspend-first) and thresholds tunable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

try:
    from client_constants import MACHINE_DATA_DIR, TOKEN_FILE
except Exception:  # pragma: no cover - test/deploy fallback
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", os.path.expanduser("~")),
        "YesNext", "CloudHoneypotClient",
    )
    TOKEN_FILE = os.path.join(MACHINE_DATA_DIR, "token.dat")

try:
    from client_utils import log
except Exception:  # pragma: no cover
    def log(msg: str) -> None:
        print(msg)


BASELINE_FILE = os.path.join(MACHINE_DATA_DIR, "network_baseline.json")
BASELINE_HISTORY_DIR = os.path.join(MACHINE_DATA_DIR, "network_baseline_history")
BASELINE_KEEP = 10

# Windows CREATE_NO_WINDOW for subprocess (no console flash)
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# Images never suspended/killed (OS + our own stack + common backup/AV)
_PROTECTED_IMAGES = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "dwm.exe", "fontdrvhost.exe", "spoolsv.exe", "taskhostw.exe",
    "honeypot-client.exe", "python.exe", "pythonw.exe",
    "msmpeng.exe", "mssense.exe", "sense.exe",  # Defender
    "vssvc.exe", "wbengine.exe", "veeam.exe", "backup.exe",  # backup/VSS
    "onedrive.exe", "searchindexer.exe", "searchprotocolhost.exe",
}

_SUSPICIOUS_ORIGIN = re.compile(
    r"(\\temp\\|\\tmp\\|\\downloads\\|\\appdata\\local\\temp\\|"
    r"\\users\\public\\|\\programdata\\(?!yesnext)|^[a-z]:\\\$recycle|"
    r"^\\\\)",  # UNC / network share
    re.I,
)


# ── Config ─────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "enabled": True,
    "baseline_interval_sec": 1800,          # 30 min
    "detect_interval_sec": 4.0,
    "fs_write_bytes_per_sec": 40 * 1024 * 1024,   # 40 MB/s sustained
    "fs_write_count_per_sec": 150,          # 150 file writes/s
    "score_threshold": 70,
    "auto_restore": True,
    "auto_kill": False,                     # default suspend-first
}


def load_config(client_config: Optional[dict] = None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        ng = ((client_config or {}).get("protection") or {}).get("network_guard")
        if isinstance(ng, dict):
            cfg.update({k: v for k, v in ng.items() if k in cfg})
    except Exception:
        pass
    return cfg


# ── Signing ────────────────────────────────────────────────────────

def _read_token() -> str:
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return (f.read() or "").strip()
    except Exception:
        return ""


def _signing_secret(token: str) -> bytes:
    machine = os.environ.get("COMPUTERNAME", "unknown")
    material = f"{token}|{machine}|yesnext-chp-v1"
    return hashlib.sha256(material.encode("utf-8")).digest()


def _sign_baseline(payload: dict, token: str = None) -> str:
    token = _read_token() if token is None else token
    body = json.dumps(_strip_sig(payload), sort_keys=True, ensure_ascii=False)
    return hmac.new(_signing_secret(token), body.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _strip_sig(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if k != "sig"}


def verify_baseline(payload: dict) -> bool:
    sig = payload.get("sig") or ""
    if not sig:
        return False
    try:
        return hmac.compare_digest(sig, _sign_baseline(payload))
    except Exception:
        return False


# ── Collectors (Windows, best-effort) ───────────────────────────────

def _run(cmd: List[str], timeout: float = 8.0) -> str:
    """Run a command and decode output defensively.

    Windows console tools (netsh / net / powershell) emit OEM/locale-encoded
    bytes that break the default locale text decoder (e.g. cp1254 on TR hosts).
    Capture raw bytes and decode utf-8 first, then cp1254, always errors=replace.
    """
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        raw = (r.stdout or b"") + (r.stderr or b"")
        for enc in ("utf-8", "cp1254", "cp850", "latin-1"):
            try:
                return raw.decode(enc)
            except Exception:
                continue
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def collect_mapped_drives() -> List[dict]:
    """Parse `net use` for mapped network drives."""
    out = _run(["net", "use"])
    drives: List[dict] = []
    for line in out.splitlines():
        m = re.search(r"([A-Z]:)\s+(\\\\[^\s]+)", line)
        if m:
            drives.append({"letter": m.group(1), "unc": m.group(2),
                           "persistent": "OK" in line or "Yes" in line})
    return drives


def collect_shares() -> List[dict]:
    """Parse `net share` for shares this host serves (skip default admin$)."""
    out = _run(["net", "share"])
    shares: List[dict] = []
    for line in out.splitlines():
        m = re.match(r"^(\S+)\s+([A-Za-z]:\\\S.*?)\s*$", line)
        if m:
            name = m.group(1)
            if name.endswith("$"):  # ADMIN$, C$, IPC$
                continue
            shares.append({"name": name, "path": m.group(2).strip()})
    return shares


def collect_adapters() -> List[dict]:
    """Adapter up/down + IPv4/DNS/gateway via PowerShell Get-NetIPConfiguration."""
    ps = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "Get-NetIPConfiguration | ForEach-Object { "
        "[pscustomobject]@{ name=$_.InterfaceAlias; "
        "state=$_.NetAdapter.Status; "
        "ipv4=($_.IPv4Address.IPAddress -join ','); "
        "gateway=($_.IPv4DefaultGateway.NextHop -join ','); "
        "dns=($_.DNSServer | Where-Object {$_.AddressFamily -eq 2} | "
        "ForEach-Object {$_.ServerAddresses} ) -join ',' } } | ConvertTo-Json -Compress"
    )
    out = _run(["powershell", "-NoProfile", "-Command", ps], timeout=15.0)
    adapters: List[dict] = []
    try:
        data = json.loads(out.strip()) if out.strip() else []
        if isinstance(data, dict):
            data = [data]
        for a in data:
            adapters.append({
                "name": a.get("name", ""),
                "state": str(a.get("state", "")).lower(),
                "ipv4": a.get("ipv4", ""),
                "gateway": a.get("gateway", ""),
                "dns": [d for d in str(a.get("dns", "")).split(",") if d],
            })
    except Exception:
        pass
    return adapters


def collect_firewall() -> dict:
    out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    fw = {"domain": "unknown", "private": "unknown", "public": "unknown"}
    cur = None
    for line in out.splitlines():
        low = line.lower()
        if "domain profile" in low:
            cur = "domain"
        elif "private profile" in low:
            cur = "private"
        elif "public profile" in low:
            cur = "public"
        elif cur and "state" in low:
            fw[cur] = "on" if "on" in low else ("off" if "off" in low else "unknown")
    return fw


def check_connectivity(dns_host: str = "8.8.8.8", port: int = 53,
                       timeout: float = 2.5) -> dict:
    internet_ok = False
    try:
        s = socket.create_connection((dns_host, port), timeout=timeout)
        s.close()
        internet_ok = True
    except Exception:
        internet_ok = False
    dns_ok = False
    try:
        socket.gethostbyname("cloudflare.com")
        dns_ok = True
    except Exception:
        dns_ok = False
    return {"internet_ok": internet_ok, "dns_ok": dns_ok,
            "gateway_ok": internet_ok}


def capture_baseline() -> dict:
    payload = {
        "version": 0,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mapped_drives": collect_mapped_drives(),
        "shares": collect_shares(),
        "adapters": collect_adapters(),
        "firewall": collect_firewall(),
        "connectivity": check_connectivity(),
    }
    return payload


# ── Baseline persistence + diff (pure, testable) ─────────────────────

def load_baseline() -> Optional[dict]:
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return None


def _baseline_meaningful_change(old: Optional[dict], new: dict) -> bool:
    if not old:
        return True
    keys = ("mapped_drives", "shares", "adapters", "firewall")
    for k in keys:
        if json.dumps(old.get(k), sort_keys=True) != json.dumps(new.get(k), sort_keys=True):
            return True
    return False


def save_baseline(payload: dict) -> dict:
    """Persist baseline with version bump + rotation. Returns saved payload."""
    prev = load_baseline()
    if not _baseline_meaningful_change(prev, payload) and prev:
        # connectivity may change often; refresh connectivity in place only
        prev["connectivity"] = payload.get("connectivity", prev.get("connectivity"))
        prev["captured_at"] = payload.get("captured_at")
        prev["sig"] = _sign_baseline(prev)
        _atomic_write(BASELINE_FILE, prev)
        return prev
    payload["version"] = int((prev or {}).get("version", 0)) + 1
    payload["sig"] = _sign_baseline(payload)
    os.makedirs(MACHINE_DATA_DIR, exist_ok=True)
    _atomic_write(BASELINE_FILE, payload)
    _rotate_history(payload)
    return payload


def _atomic_write(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _rotate_history(payload: dict) -> None:
    try:
        os.makedirs(BASELINE_HISTORY_DIR, exist_ok=True)
        hp = os.path.join(BASELINE_HISTORY_DIR,
                          f"network_baseline.{payload['version']}.json")
        _atomic_write(hp, payload)
        files = sorted(
            (os.path.join(BASELINE_HISTORY_DIR, f)
             for f in os.listdir(BASELINE_HISTORY_DIR)
             if f.endswith(".json")),
            key=os.path.getmtime,
        )
        for old in files[:-BASELINE_KEEP]:
            try:
                os.remove(old)
            except Exception:
                pass
    except Exception:
        pass


# ── Detection scoring (pure, testable) ───────────────────────────────

def score_signals(net_cut: bool, fs_storm: bool, suspicious_origin: bool,
                  vss_deleted: bool = False, canary: bool = False) -> int:
    if canary:
        return 100
    score = 0
    if net_cut:
        score += 45
    if fs_storm:
        score += 45
    if suspicious_origin:
        score += 20
    if vss_deleted:
        score += 45
    return min(score, 100)


def diff_connectivity(baseline: Optional[dict], current: dict) -> dict:
    """Return network-cut signal vs baseline."""
    base_conn = (baseline or {}).get("connectivity") or {}
    base_adapters = (baseline or {}).get("adapters") or []
    base_up = [a for a in base_adapters if str(a.get("state")).lower() == "up"]
    internet_lost = bool(base_conn.get("internet_ok")) and not current.get("internet_ok")
    cur_adapters = current.get("_adapters") or []
    adapters_down = []
    if base_up and cur_adapters is not None:
        cur_up_names = {a.get("name") for a in cur_adapters
                        if str(a.get("state")).lower() == "up"}
        adapters_down = [a.get("name") for a in base_up
                         if a.get("name") not in cur_up_names]
    return {
        "internet_lost": internet_lost,
        "adapters_down": adapters_down,
        "net_cut": bool(internet_lost or adapters_down),
    }


# ── NetworkGuard ─────────────────────────────────────────────────────

class NetworkGuard:
    def __init__(self, alert_pipeline=None, ransomware_shield=None,
                 config: Optional[dict] = None):
        self.alert_pipeline = alert_pipeline
        self.ransomware_shield = ransomware_shield
        self.cfg = config or dict(DEFAULT_CONFIG)
        self._running = False
        self._io_prev: Dict[int, tuple] = {}
        self._suspended: Dict[int, dict] = {}
        self._lock = threading.RLock()
        self._last_trigger_ts: Optional[str] = None
        self._last_baseline: Optional[dict] = None

    # -- lifecycle --

    def start(self):
        if self._running or not self.cfg.get("enabled", True):
            return
        self._running = True
        threading.Thread(target=self._baseline_loop,
                         name="NetGuard-Baseline", daemon=True).start()
        threading.Thread(target=self._detect_loop,
                         name="NetGuard-Detect", daemon=True).start()
        log("[NET-GUARD] Started (baseline + offline detection)")

    def stop(self):
        self._running = False

    # -- A: baseline loop --

    def _baseline_loop(self):
        try:
            self._last_baseline = save_baseline(capture_baseline())
            log(f"[NET-GUARD] baseline v{self._last_baseline.get('version')} captured")
        except Exception as e:
            log(f"[NET-GUARD] baseline capture error: {e}")
        interval = float(self.cfg.get("baseline_interval_sec", 1800))
        while self._running:
            time.sleep(min(interval, 60))
            if not self._running:
                break
            # Only re-capture on the full interval boundary
            if int(time.time()) % max(int(interval), 60) < 60:
                try:
                    self._last_baseline = save_baseline(capture_baseline())
                except Exception as e:
                    log(f"[NET-GUARD] baseline refresh error: {e}")

    # -- B: detection loop --

    def _detect_loop(self):
        interval = float(self.cfg.get("detect_interval_sec", 4.0))
        while self._running:
            time.sleep(interval)
            try:
                self._evaluate(interval)
            except Exception as e:
                log(f"[NET-GUARD] detect error: {e}")

    def _evaluate(self, interval: float):
        baseline = self._last_baseline or load_baseline()
        conn = check_connectivity()
        conn["_adapters"] = collect_adapters() if self._maybe_net_change(baseline, conn) else None
        netdiff = diff_connectivity(baseline, conn)

        storm_suspects = self._fs_storm_suspects(interval)
        fs_storm = bool(storm_suspects)
        suspicious_origin = any(s.get("suspicious_origin") for s in storm_suspects)

        score = score_signals(
            net_cut=netdiff["net_cut"],
            fs_storm=fs_storm,
            suspicious_origin=suspicious_origin,
        )
        if score >= int(self.cfg.get("score_threshold", 70)):
            trigger = "+".join(
                t for t, on in (("network_cut", netdiff["net_cut"]),
                                ("fs_storm", fs_storm)) if on
            ) or "fs_storm"
            self._trigger(trigger, score, netdiff, storm_suspects, baseline)

    def _maybe_net_change(self, baseline, conn) -> bool:
        base_conn = (baseline or {}).get("connectivity") or {}
        return bool(base_conn.get("internet_ok")) and not conn.get("internet_ok")

    def _fs_storm_suspects(self, interval: float) -> List[dict]:
        """Per-process write-rate storm via psutil io_counters."""
        if psutil is None:
            return []
        suspects: List[dict] = []
        bps_thr = float(self.cfg.get("fs_write_bytes_per_sec", 40 * 1024 * 1024))
        cnt_thr = float(self.cfg.get("fs_write_count_per_sec", 150))
        now = time.time()
        cur: Dict[int, tuple] = {}
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                pid = p.info["pid"]
                name = (p.info.get("name") or "").lower()
                if name in _PROTECTED_IMAGES:
                    continue
                io = p.io_counters()
                cur[pid] = (io.write_bytes, io.write_count, now)
                prev = self._io_prev.get(pid)
                if not prev:
                    continue
                dt = max(now - prev[2], 0.5)
                bps = (io.write_bytes - prev[0]) / dt
                cps = (io.write_count - prev[1]) / dt
                if bps >= bps_thr or cps >= cnt_thr:
                    exe = p.info.get("exe") or ""
                    suspects.append({
                        "pid": pid,
                        "image": name,
                        "path": exe,
                        "cmdline": " ".join(p.info.get("cmdline") or []),
                        "write_bytes_sec": int(bps),
                        "write_count_sec": int(cps),
                        "suspicious_origin": bool(_SUSPICIOUS_ORIGIN.search(exe or "")),
                    })
            except Exception:
                continue
        self._io_prev = cur
        return suspects

    # -- C: containment (suspend-first) --

    def _trigger(self, trigger: str, score: int, netdiff: dict,
                 suspects: List[dict], baseline: Optional[dict]):
        self._last_trigger_ts = datetime.now(timezone.utc).isoformat()
        log(f"[NET-GUARD] TRIGGER {trigger} score={score} suspects={len(suspects)}")

        suspended = []
        for s in suspects:
            if self._suspend_pid(s["pid"]):
                s["state"] = "suspended"
                with self._lock:
                    self._suspended[s["pid"]] = s
                suspended.append(s)
            elif self.cfg.get("auto_kill"):
                self._kill_pid(s["pid"])
                s["state"] = "killed"
                suspended.append(s)

        # Register suspects into ransomware quarantine (best-effort)
        try:
            if self.ransomware_shield and hasattr(self.ransomware_shield, "_contain_after_hit"):
                self.ransomware_shield._contain_after_hit(
                    trigger=f"network_guard:{trigger}", focus_path="")
        except Exception:
            pass

        vss_ok = self._emergency_vss()

        restored = {}
        if self.cfg.get("auto_restore", True) and netdiff.get("net_cut"):
            restored = self.restore_network(baseline)

        self._send_alert(trigger, score, netdiff, suspended, vss_ok, restored)

    def _suspend_pid(self, pid: int) -> bool:
        if psutil is None:
            return False
        try:
            psutil.Process(pid).suspend()
            log(f"[NET-GUARD] suspended pid={pid}")
            return True
        except Exception as e:
            log(f"[NET-GUARD] suspend pid={pid} failed: {e}")
            return False

    def _kill_pid(self, pid: int) -> bool:
        if psutil is None:
            return False
        try:
            psutil.Process(pid).kill()
            return True
        except Exception:
            return False

    def release_suspended(self, pid: int) -> bool:
        if psutil is None:
            return False
        try:
            psutil.Process(pid).resume()
            with self._lock:
                self._suspended.pop(pid, None)
            return True
        except Exception:
            return False

    def kill_suspended(self, pid: int) -> bool:
        ok = self._kill_pid(pid)
        with self._lock:
            self._suspended.pop(pid, None)
        return ok

    def _emergency_vss(self) -> bool:
        """Best-effort shadow copy of system drive before encryption spreads."""
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        out = _run(["wmic", "shadowcopy", "call", "create",
                    f"Volume={drive}"], timeout=30.0)
        ok = "ReturnValue = 0" in out or "successful" in out.lower()
        log(f"[NET-GUARD] emergency VSS snapshot ok={ok}")
        return ok

    # -- D: recovery --

    def restore_network(self, baseline: Optional[dict] = None,
                        targets: Optional[List[str]] = None) -> dict:
        baseline = baseline or self._last_baseline or load_baseline()
        if not baseline:
            return {"error": "no_baseline"}
        do = lambda t: (targets is None or t in targets)
        actions: List[str] = []

        if do("adapter"):
            for a in baseline.get("adapters", []):
                if str(a.get("state")).lower() == "up" and a.get("name"):
                    _run(["netsh", "interface", "set", "interface",
                          f'name={a["name"]}', "admin=enable"])
                    actions.append(f"adapter_enable:{a['name']}")
        if do("dns"):
            for a in baseline.get("adapters", []):
                dns = a.get("dns") or []
                if dns and a.get("name"):
                    _run(["netsh", "interface", "ip", "set", "dns",
                          f'name={a["name"]}', "static", dns[0]])
                    for extra in dns[1:]:
                        _run(["netsh", "interface", "ip", "add", "dns",
                              f'name={a["name"]}', extra, "index=2"])
                    actions.append(f"dns_restore:{a['name']}")
        if do("firewall"):
            fw = baseline.get("firewall") or {}
            for prof in ("domain", "private", "public"):
                if fw.get(prof) == "on":
                    _run(["netsh", "advfirewall", "set", f"{prof}profile",
                          "state", "on"])
            actions.append("firewall_restore")
        if do("mapped_drive"):
            for d in baseline.get("mapped_drives", []):
                if d.get("persistent") and d.get("letter") and d.get("unc"):
                    _run(["net", "use", d["letter"], d["unc"], "/persistent:yes"])
                    actions.append(f"netuse:{d['letter']}")

        # verify connectivity after restore
        conn = check_connectivity()
        log(f"[NET-GUARD] restore actions={actions} internet_ok={conn['internet_ok']}")
        return {"restore_actions": actions, "connectivity": conn}

    # -- E: alert --

    def _send_alert(self, trigger, score, netdiff, suspects, vss_ok, restored):
        if not self.alert_pipeline or not hasattr(self.alert_pipeline, "send_urgent"):
            return
        ng = {
            "trigger": trigger,
            "score": score,
            "network": {
                "internet_lost": netdiff.get("internet_lost"),
                "adapters_down": netdiff.get("adapters_down") or [],
                "restored": bool(restored.get("restore_actions")),
                "restore_actions": restored.get("restore_actions") or [],
            },
            "suspects": [
                {k: s.get(k) for k in ("pid", "image", "path", "cmdline",
                                       "state", "write_bytes_sec",
                                       "write_count_sec", "suspicious_origin")}
                for s in suspects
            ],
            "vss_emergency_snapshot": bool(vss_ok),
            "ts": self._last_trigger_ts,
        }
        try:
            self.alert_pipeline.send_urgent({
                "severity": "critical",
                "threat_type": "ransomware_offline_bomb",
                "title": "🔴 OFFLINE FİDYE BOMBASI — ağ kesildi + kütle şifreleme",
                "description": (
                    f"Şüpheli offline şifreleme tespit edildi (trigger={trigger}, "
                    f"skor={score}). {len(suspects)} süreç donduruldu; "
                    f"ağ {'geri yüklendi' if ng['network']['restored'] else 'incelendi'}."
                ),
                "threat_score": score,
                "target_service": "SYSTEM",
                "recommended_action": "isolate_host",
                "system_context": {"network_guard": ng},
                "raw_events": [{
                    "kind": "network_guard",
                    "trigger": trigger,
                    "suspect_pid": (suspects[0]["pid"] if suspects else None),
                    "image": (suspects[0]["image"] if suspects else None),
                    "state": (suspects[0].get("state") if suspects else None),
                }],
                "auto_response_taken": ["suspend", "emergency_vss"]
                + (["network_restore"] if ng["network"]["restored"] else []),
            })
        except Exception as e:
            log(f"[NET-GUARD] send_urgent failed: {e}")

    # -- status --

    def status(self) -> dict:
        base = self._last_baseline or load_baseline() or {}
        age = None
        try:
            if base.get("captured_at"):
                dt = datetime.fromisoformat(base["captured_at"].replace("Z", "+00:00"))
                age = int((datetime.now(timezone.utc) - dt).total_seconds())
        except Exception:
            pass
        conn = (base.get("connectivity") or {})
        with self._lock:
            suspended = len(self._suspended)
        return {
            "enabled": bool(self.cfg.get("enabled", True)),
            "baseline_version": base.get("version"),
            "baseline_age_sec": age,
            "internet_ok": conn.get("internet_ok"),
            "mapped_drives": len(base.get("mapped_drives") or []),
            "suspended_processes": suspended,
            "last_trigger_ts": self._last_trigger_ts,
            "auto_restore": bool(self.cfg.get("auto_restore", True)),
            "auto_kill": bool(self.cfg.get("auto_kill", False)),
        }

    def list_baseline(self) -> dict:
        base = self._last_baseline or load_baseline() or {}
        return {
            "version": base.get("version"),
            "captured_at": base.get("captured_at"),
            "mapped_drives": base.get("mapped_drives") or [],
            "shares": base.get("shares") or [],
            "adapters": [{"name": a.get("name"), "state": a.get("state"),
                          "dns": a.get("dns")} for a in (base.get("adapters") or [])],
            "firewall": base.get("firewall") or {},
            "verified": verify_baseline(base) if base else False,
        }
