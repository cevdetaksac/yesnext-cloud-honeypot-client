#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Honeypot Agent – Firewall Block/Unblock

Features (per spec):
- Polls backend for pending blocks/unblocks and applies them to OS firewall
- Windows: netsh advfirewall rules (chunked remoteip lists, same rule name per id)
- Linux: prefer ipset + iptables set match; fallback to iptables with comment
- Country blocks: fetch CIDR list per country daily and cache locally
- HTTPS with 5s timeout, retries with backoff; logs successes and failures

Config via environment or CLI args:
- API_BASE (e.g., https://HONEYPOT_HOST)
- TOKEN
- CIDR_FEED_BASE (default: https://example.com/cidr)
- REFRESH_INTERVAL_SEC (default: 10)

Endpoints:
- GET  {API_BASE}/api/agent/pending-blocks?token=TOKEN
- GET  {API_BASE}/api/agent/pending-unblocks?token=TOKEN
- POST {API_BASE}/api/agent/block-applied   body: {token, block_ids:[...]}
- POST {API_BASE}/api/agent/block-removed   body: {token, block_ids:[...]}

Requires admin/root privileges for firewall commands.
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from client_security_utils import auth_headers, resolve_tls_verify, use_legacy_token_query
from urllib3.util.retry import Retry


# ---------------------------- Logging ---------------------------- #

def make_logger(log_path: Optional[Path] = None) -> logging.Logger:
    logger = logging.getLogger("firewall-agent")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    try:
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                str(log_path), maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
            fh.setLevel(logging.INFO)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
    except Exception:
        # Best-effort file logging
        pass

    return logger


# ---------------------------- Utils ---------------------------- #

def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_admin() -> bool:
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False


def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    # Run command with timeout. Returns (rc, stdout, stderr).
    try:
        p = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout if timeout and timeout > 0 else None,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", f"{e}"


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------- HTTP client ---------------------------- #

def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


# ---------------------------- Country CIDR cache ---------------------------- #

class CountryCIDRCache:
    def __init__(self, base_url: str, cache_dir: Path, logger: logging.Logger) -> None:
        self.base_url = base_url.rstrip("/")
        self.cache_dir = cache_dir
        self.logger = logger
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, country_code: str, session: requests.Session, timeout: int = 5) -> List[str]:
        cc = country_code.upper()
        path = self.cache_dir / f"{cc}.txt"
        need_fetch = True
        if path.exists():
            try:
                mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
                if now_utc() - mtime < dt.timedelta(days=1):
                    need_fetch = False
            except Exception:
                need_fetch = True
        if need_fetch:
            # Try multiple provider filename styles; ipdeny.com uses lowercase and .zone
            candidates = [
                f"{self.base_url}/{cc}.txt",
                f"{self.base_url}/{cc.lower()}.txt",
                f"{self.base_url}/{cc.lower()}.zone",
            ]
            fetched = False
            for url in candidates:
                self.logger.info(f"Fetching country CIDRs for {cc} from {url}")
                try:
                    r = session.get(url, timeout=timeout)
                    if r.status_code == 200 and r.text:
                        text = r.text
                        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
                        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        fetched = True
                        break
                    else:
                        self.logger.warning(f"CIDR feed HTTP {r.status_code} for {cc} at {url}")
                except Exception as e:
                    self.logger.warning(f"CIDR fetch error for {cc} at {url}: {e}")
            if not fetched:
                self.logger.error(f"CIDR fetch failed for {cc} from all sources")
        # Read whatever we have
        try:
            return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except Exception:
            return []


# ---------------------------- Firewall backends ---------------------------- #

class FirewallBackend:
    def apply_block(self, block_id: str, cidrs: List[str]) -> bool:
        raise NotImplementedError

    def remove_block(self, block_id: str, ip_or_cidr: str = "",
                     extra_names: Optional[List[str]] = None) -> bool:
        raise NotImplementedError


class WindowsFirewallBackend(FirewallBackend):
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    @staticmethod
    def rule_name_candidates(block_id: str = "", ip_or_cidr: str = "") -> List[str]:
        """All historical / current honeypot block rule names for an IP or id."""
        names: List[str] = []
        bid = (block_id or "").strip()
        ip = (ip_or_cidr or "").strip().split("/")[0]
        if bid:
            names.append(f"HP-BLOCK-{bid}")
        if ip:
            for n in (
                f"HP-BLOCK-{ip}",
                f"HONEYPOT_THREAT_BLOCK_{ip.replace('.', '_')}",
                f"HONEYPOT_BLOCK_REMOTE_{ip}",
                f"HONEYPOT_BLOCK_REMOTE_{ip.replace('.', '_')}",
                f"HONEYPOT_REMOTE_BLOCK_{ip}",
                f"HONEYPOT_REMOTE_BLOCK_{ip.replace('.', '_')}",
            ):
                if n not in names:
                    names.append(n)
        return names

    def _delete_rule_by_name(self, name: str) -> Tuple[str, int, str, str]:
        """Delete rule by name. Returns (status, rc, out, err).

        status: 'removed' | 'missing' | 'failed'
        """
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}", "dir=in",
        ])
        combined = f"{out}\n{err}".lower()
        if rc == 0:
            if "0 rule" in combined:
                return "missing", rc, out, err
            return "removed", rc, out, err
        if any(x in combined for x in (
            "no rules match", "not found", "bulunamad", "eşleşen kural yok",
        )):
            return "missing", rc, out, err
        return "failed", rc, out, err

    def _add_rule(self, name: str, remoteip_csv: str) -> bool:
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}", "dir=in", "action=block", f"remoteip={remoteip_csv}",
        ])
        if rc == 0:
            if out.strip():
                self.logger.info(out.strip())
            return True
        self.logger.error(err.strip() or f"netsh add rule failed rc={rc}")
        return False

    def apply_block(self, block_id: str, cidrs: List[str]) -> bool:
        name = f"HP-BLOCK-{block_id}"
        # Replace any existing rules for id to be idempotent
        self._delete_rule_by_name(name)

        # netsh has command length limits; chunk remote IPs
        # Conservative chunking by count (e.g., 200 per rule)
        CHUNK = 200
        if not cidrs:
            self.logger.warning(f"No CIDRs to apply for {name}")
            return False
        ok_all = True
        for i in range(0, len(cidrs), CHUNK):
            chunk = cidrs[i : i + CHUNK]
            csv = ",".join(chunk)
            ok = self._add_rule(name, csv)
            ok_all = ok_all and ok
        return ok_all

    def _lookup_rule_remoteip(self, rule_name: str) -> str:
        """Query netsh for a rule's remoteip before deleting it."""
        try:
            rc, out, _ = run_cmd([
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={rule_name}", "dir=in",
            ], timeout=10)
            if rc != 0:
                return ""
            for line in out.splitlines():
                low = line.strip().lower()
                if any(k in low for k in ("remoteip", "uzak ip", "remote ip")):
                    _, _, val = line.partition(":")
                    val = val.strip()
                    if val and val.lower() not in ("any", "herhangi"):
                        return val.split(",")[0].strip().split("/")[0]
        except Exception:
            pass
        return ""

    def remove_block(self, block_id: str, ip_or_cidr: str = "",
                     extra_names: Optional[List[str]] = None) -> bool:
        """Remove firewall block rules (idempotent).

        Returns True if removed OR already absent (ACK safe).
        Returns False on hard failure (access denied) — do NOT ACK.
        """
        if not ip_or_cidr and block_id:
            ip_or_cidr = self._lookup_rule_remoteip(f"HP-BLOCK-{block_id}")
            if ip_or_cidr:
                self.logger.info(f"Resolved IP from rule HP-BLOCK-{block_id}: {ip_or_cidr}")

        names_to_try = self.rule_name_candidates(block_id, ip_or_cidr)
        if extra_names:
            for n in extra_names:
                if n and n not in names_to_try:
                    names_to_try.append(n)

        removed_any = False
        hard_fail = False
        for name in names_to_try:
            status, rc, out, err = self._delete_rule_by_name(name)
            if status == "removed":
                msg = (out or "").strip()
                self.logger.info(f"Removed rule: {name}" + (f" ({msg})" if msg else ""))
                removed_any = True
            elif status == "failed":
                combined = f"{out}\n{err}".lower()
                self.logger.error(err.strip() or f"Failed to delete {name} rc={rc}")
                if any(x in combined for x in ("access", "denied", "privilege", "izin")):
                    hard_fail = True
                elif not removed_any:
                    hard_fail = True

        if hard_fail and not removed_any:
            return False

        if not removed_any:
            self.logger.info(
                f"No firewall rules found for block {block_id} / {ip_or_cidr} (idempotent OK)"
            )
        return True
    def scan_existing_rules(self) -> List[dict]:
        """Scan all HP-BLOCK- and legacy HONEYPOT_THREAT_BLOCK_ firewall rules.

        Returns list of dicts: {name, remoteip, prefix, ip, legacy}
        """
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "show", "rule",
            "dir=in", "status=enabled", "type=static",
        ], timeout=30)
        if rc != 0:
            self.logger.error(f"Failed to enumerate firewall rules: {err}")
            return []

        rules: List[dict] = []
        current: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                if current:
                    rules.append(current)
                    current = {}
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if "rule name" in key or "kural ad" in key:
                    current["name"] = val
                elif "remoteip" in key or "uzak ip" in key or "remote ip" in key:
                    current["remoteip"] = val
        if current:
            rules.append(current)

        # Filter only our rules
        result = []
        for r in rules:
            name = r.get("name", "")
            remoteip = r.get("remoteip", "")
            if name.startswith("HP-BLOCK-"):
                suffix = name[len("HP-BLOCK-"):]
                result.append({
                    "name": name,
                    "remoteip": remoteip,
                    "suffix": suffix,
                    "legacy": False,
                })
            elif name.startswith("HONEYPOT_THREAT_BLOCK_"):
                suffix = name[len("HONEYPOT_THREAT_BLOCK_"):]
                # Convert underscored IP back to dotted
                ip = suffix.replace("_", ".")
                result.append({
                    "name": name,
                    "remoteip": remoteip,
                    "suffix": suffix,
                    "ip": ip,
                    "legacy": True,
                })
        return result

    def migrate_legacy_rule(self, old_name: str, ip: str, remoteip: str) -> bool:
        """Rename a legacy HONEYPOT_THREAT_BLOCK_ rule to HP-BLOCK-{ip}.

        netsh doesn't support rename, so delete old + create new.
        """
        new_name = f"HP-BLOCK-{ip}"
        # Delete old rule
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={old_name}", "dir=in",
        ])
        if rc != 0:
            msg = (out + err).lower()
            if "no rules match" not in msg:
                self.logger.error(f"Failed to delete legacy rule {old_name}: {err}")
                return False

        # Create new rule with same remoteip
        remote = remoteip if remoteip and remoteip.lower() not in ("any", "herhangi") else ip
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={new_name}", "dir=in", "action=block",
            f"remoteip={remote}", "enable=yes",
        ])
        if rc == 0:
            self.logger.info(f"Migrated: {old_name} → {new_name}")
            return True
        self.logger.error(f"Failed to create migrated rule {new_name}: {err}")
        return False


class LinuxFirewallBackend(FirewallBackend):
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        self.has_ipset = bool(shutil.which("ipset"))

    def _iptables_has_set_rule(self, set_name: str) -> bool:
        rc, _, _ = run_cmd([
            "iptables", "-C", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP",
        ])
        return rc == 0

    def _iptables_add_set_rule(self, set_name: str) -> bool:
        if self._iptables_has_set_rule(set_name):
            return True
        rc, _, err = run_cmd([
            "iptables", "-I", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP",
        ])
        if rc == 0:
            return True
        self.logger.error(err.strip() or f"iptables add rule for set {set_name} failed")
        return False

    def _iptables_del_set_rule(self, set_name: str) -> None:
        run_cmd(["iptables", "-D", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP"])  # best-effort

    def _apply_with_ipset(self, block_id: str, cidrs: List[str]) -> bool:
        set_name = f"HP-BLOCK-{block_id}"
        # Create set (idempotent)
        rc, _, err = run_cmd(["ipset", "create", set_name, "hash:net", "family", "inet", "-exist"])
        if rc != 0:
            self.logger.error(err.strip() or f"ipset create {set_name} failed")
            return False
        ok_all = True
        for cidr in cidrs:
            rc, _, err = run_cmd(["ipset", "add", set_name, cidr, "-exist"])
            if rc != 0:
                self.logger.error(err.strip() or f"ipset add {cidr} to {set_name} failed")
                ok_all = False
        if not self._iptables_add_set_rule(set_name):
            ok_all = False
        return ok_all

    def _remove_with_ipset(self, block_id: str) -> bool:
        set_name = f"HP-BLOCK-{block_id}"
        self._iptables_del_set_rule(set_name)
        rc, _, err = run_cmd(["ipset", "destroy", set_name])
        if rc == 0:
            return True
        # If set is gone, consider success
        if "The set with the given name does not exist" in err:
            return True
        self.logger.error(err.strip() or f"ipset destroy {set_name} failed")
        return False

    def _iptables_add_with_comment(self, block_id: str, cidrs: List[str]) -> bool:
        ok_all = True
        for cidr in cidrs:
            # Check if exists
            rc, _, _ = run_cmd([
                "iptables", "-C", "INPUT", "-s", cidr, "-j", "DROP", "-m", "comment", "--comment", f"HP-BLOCK-{block_id}",
            ])
            if rc == 0:
                continue
            rc, _, err = run_cmd([
                "iptables", "-I", "INPUT", "-s", cidr, "-j", "DROP", "-m", "comment", "--comment", f"HP-BLOCK-{block_id}",
            ])
            if rc != 0:
                self.logger.error(err.strip() or f"iptables add rule for {cidr} failed")
                ok_all = False
        return ok_all

    def _iptables_remove_by_comment(self, block_id: str) -> bool:
        # List rules and remove ones matching our comment
        rc, out, err = run_cmd(["iptables", "-S", "INPUT"])
        if rc != 0:
            self.logger.error(err.strip() or "iptables -S failed")
            return False
        lines = out.splitlines()
        target = f"-m comment --comment HP-BLOCK-{block_id}"
        removed_any = False
        for ln in lines:
            if target in ln:
                # Convert -A to -D to delete the exact rule
                del_cmd = ["iptables"] + ln.strip().split()
                try:
                    idx = del_cmd.index("-A")
                    del_cmd[idx] = "-D"
                except ValueError:
                    # Fallback: construct -D with -s and -j
                    del_cmd = ["iptables", "-D", "INPUT"] + ln.strip().split()[2:]
                run_cmd(del_cmd)
                removed_any = True
        return removed_any

    def apply_block(self, block_id: str, cidrs: List[str]) -> bool:
        if not cidrs:
            self.logger.warning(f"No CIDRs to apply for HP-BLOCK-{block_id}")
            return False
        if self.has_ipset:
            return self._apply_with_ipset(block_id, cidrs)
        else:
            return self._iptables_add_with_comment(block_id, cidrs)

    def remove_block(self, block_id: str, ip_or_cidr: str = "",
                     extra_names: Optional[List[str]] = None) -> bool:
        if self.has_ipset:
            return self._remove_with_ipset(block_id)
        else:
            return self._iptables_remove_by_comment(block_id)


# ---------------------------- Agent core ---------------------------- #

COUNTRY_PREFIX = "country:"


class FirewallAgent:
    def __init__(
        self,
        api_base: str,
        token: str,
        refresh_interval: int = 10,
        cidr_feed_base: str = "https://www.ipdeny.com/ipblocks/data/countries",
        logger: Optional[logging.Logger] = None,
        auto_response=None,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.refresh_interval = max(1, int(refresh_interval))
        self.logger = logger or make_logger()
        self.auto_response = auto_response
        self.session = make_session()
        cache_root = _default_cache_dir()
        self.country_cache = CountryCIDRCache(cidr_feed_base, cache_root / "country", self.logger)
        self.backend: FirewallBackend
        if is_windows():
            self.backend = WindowsFirewallBackend(self.logger)
        elif is_linux():
            self.backend = LinuxFirewallBackend(self.logger)
        else:
            raise RuntimeError("Unsupported OS; only Windows and Linux are supported")
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    # --------------- HTTP helpers --------------- #

    def _get_json(self, path: str) -> Tuple[Optional[object], Optional[int]]:
        url = f"{self.api_base}{path}"
        params = {"token": self.token} if use_legacy_token_query() else None
        try:
            r = self.session.get(
                url, timeout=5, verify=resolve_tls_verify(),
                headers=auth_headers(self.token), params=params,
            )
            if r.status_code == 200:
                return r.json(), 200
            return None, r.status_code
        except Exception as e:
            self.logger.error(f"GET {path} failed: {e}")
            return None, None

    def _post_json(self, path: str, data: dict) -> Tuple[Optional[object], Optional[int]]:
        url = f"{self.api_base}{path}"
        payload = dict(data)
        payload.setdefault("token", self.token)
        try:
            r = self.session.post(
                url, json=payload, timeout=5, verify=resolve_tls_verify(),
                headers=auth_headers(self.token),
            )
            if r.status_code == 200:
                return r.json() if r.content else {}, 200
            return None, r.status_code
        except Exception as e:
            self.logger.error(f"POST {path} failed: {e}")
            return None, None

    # --------------- Country expansion --------------- #

    def _expand_ip_or_cidr(self, ip_or_cidr: str) -> List[str]:
        s = ip_or_cidr.strip()
        if s.lower().startswith(COUNTRY_PREFIX):
            cc = s[len(COUNTRY_PREFIX) :].strip().upper()
            if not re.fullmatch(r"[A-Z]{2}", cc):
                self.logger.error(f"Invalid country code: {s}")
                return []
            cidrs = self.country_cache.get(cc, self.session)
            if not cidrs:
                self.logger.error(f"No CIDRs found for country {cc}")
            return cidrs
        # Basic validation; accept IP or CIDR
        return [s]

    # --------------- Workflow --------------- #

    def _poll_pending_blocks(self) -> List[str]:
        payload_ids: List[str] = []
        data, code = self._get_json("/api/agent/pending-blocks")
        if code != 200 or not isinstance(data, list):
            if code not in (200, None):
                self.logger.error(f"pending-blocks HTTP {code}")
            return payload_ids

        # Conflict: same IP in both queues — skip if we just unblocked (handled by order)
        BATCH = 40
        for i in range(0, len(data), BATCH):
            batch = data[i : i + BATCH]
            batch_ids: List[str] = []
            for item in batch:
                try:
                    block_id = str(item["id"]).strip()
                    spec = str(item.get("ip_or_cidr", "")).strip()
                except Exception as e:
                    self.logger.error(f"Invalid block item: {e}")
                    continue
                if "/" in spec or spec.lower().startswith(COUNTRY_PREFIX):
                    # country/CIDR — apply if expandable; else log
                    pass
                cidrs = self._expand_ip_or_cidr(spec)
                if not cidrs:
                    continue
                ok = self.backend.apply_block(block_id, cidrs)
                if ok:
                    self.logger.info(f"Applied block {block_id} ({spec})")
                    batch_ids.append(block_id)
                    payload_ids.append(block_id)
                else:
                    self.logger.error(f"Failed to apply block {block_id} ({spec})")
            if batch_ids:
                body = {"token": self.token, "block_ids": batch_ids}
                _, ack_code = self._post_json("/api/agent/block-applied", body)
                if ack_code != 200:
                    self.logger.error(f"block-applied HTTP {ack_code}")
            if i + BATCH < len(data):
                time.sleep(0.15)
        return payload_ids

    def _poll_pending_unblocks(self) -> List[str]:
        """Process remove_pending queue — batch delete + block-removed ACK."""
        removed_ids: List[str] = []
        failed = 0
        data, code = self._get_json("/api/agent/pending-unblocks")
        if code != 200 or not isinstance(data, list):
            if code not in (200, None):
                self.logger.error(f"pending-unblocks HTTP {code}")
            return removed_ids

        if not data:
            return removed_ids

        total = len(data)
        if total >= 50:
            self.logger.info(
                f"[FW-SYNC] Large unblock queue ({total}) — batch processing…"
            )

        # One scan: map IP → extra rule names (catches duplicates / odd names)
        ip_to_extra: dict = {}
        try:
            if isinstance(self.backend, WindowsFirewallBackend):
                for r in self.backend.scan_existing_rules():
                    ip = (r.get("ip") or "").strip()
                    if not ip:
                        rip = (r.get("remoteip") or "").split(",")[0].strip().split("/")[0]
                        ip = rip
                    name = r.get("name") or ""
                    if ip and name:
                        ip_to_extra.setdefault(ip, []).append(name)
        except Exception as e:
            self.logger.warning(f"[FW-SYNC] pre-scan skipped: {e}")

        BATCH = 40
        for i in range(0, len(data), BATCH):
            batch = data[i : i + BATCH]
            batch_ids: List[str] = []
            for item in batch:
                try:
                    block_id = str(item["id"]).strip()
                    ip_or_cidr = str(item.get("ip_or_cidr", "")).strip()
                except Exception as e:
                    self.logger.error(f"Invalid unblock item: {e}")
                    failed += 1
                    continue

                ip_clean = ip_or_cidr.split("/")[0].strip() if ip_or_cidr else ""
                extra = ip_to_extra.get(ip_clean, []) if ip_clean else []

                ok = self.backend.remove_block(
                    block_id, ip_or_cidr=ip_or_cidr, extra_names=extra,
                )
                if ok:
                    self.logger.info(f"Removed block {block_id} ({ip_or_cidr})")
                    batch_ids.append(block_id)
                    removed_ids.append(block_id)
                    # Local cache only — do NOT re-hit netsh / alternate unblock APIs
                    if ip_clean and self.auto_response:
                        try:
                            if hasattr(self.auto_response, "forget_block"):
                                self.auto_response.forget_block(ip_clean)
                            elif hasattr(self.auto_response, "_blocks"):
                                lock = getattr(self.auto_response, "_lock", None)
                                if lock:
                                    with lock:
                                        self.auto_response._blocks.pop(ip_clean, None)
                                else:
                                    self.auto_response._blocks.pop(ip_clean, None)
                        except Exception:
                            pass
                else:
                    failed += 1
                    self.logger.error(
                        f"Failed to remove block {block_id} ({ip_or_cidr}) — ACK deferred"
                    )

            if batch_ids:
                body = {"token": self.token, "block_ids": batch_ids}
                _, ack_code = self._post_json("/api/agent/block-removed", body)
                if ack_code != 200:
                    self.logger.error(f"block-removed HTTP {ack_code}")
                    # IDs stay remove_pending; next poll retries
            if i + BATCH < len(data):
                time.sleep(0.2)

        self.logger.info(
            f"[FW-SYNC] pending_unblocks={total} removed={len(removed_ids)} failed={failed}"
        )
        return removed_ids

    # --------------- Migration & sync --------------- #

    def _migrate_and_sync_rules(self) -> None:
        """After unblocks/blocks: migrate legacy names + report remaining inventory.

        Does NOT re-apply local blocks to the cloud as new pending-blocks.
        Source of truth remains pending-unblocks / pending-blocks queues.
        """
        if not is_windows():
            return
        if not isinstance(self.backend, WindowsFirewallBackend):
            return

        self.logger.info("🔄 Firewall rule migration & sync starting...")

        try:
            rules = self.backend.scan_existing_rules()
        except Exception as e:
            self.logger.error(f"Rule scan failed: {e}")
            return

        if not rules:
            self.logger.info("No existing HP-BLOCK / legacy rules found")
            self._sync_rules_to_api([])
            return

        migrated = 0
        for r in rules:
            if r.get("legacy"):
                ip = r.get("ip", "")
                if ip:
                    ok = self.backend.migrate_legacy_rule(
                        old_name=r["name"],
                        ip=ip,
                        remoteip=r.get("remoteip", ""),
                    )
                    if ok:
                        migrated += 1
                        r["name"] = f"HP-BLOCK-{ip}"
                        r["legacy"] = False
                        r["suffix"] = ip

        if migrated:
            self.logger.info(f"✅ Migrated {migrated} legacy rule(s) to HP-BLOCK- prefix")

        auto_blocks = []
        if self.auto_response:
            try:
                auto_blocks = self.auto_response.get_blocked_ips()
            except Exception:
                pass

        sync_ips: dict = {}
        for r in rules:
            remoteip = r.get("remoteip", "")
            suffix = r.get("suffix", "")
            ip = ""
            if suffix and not str(suffix).isdigit():
                ip = suffix
            elif remoteip and remoteip.lower() not in ("any", "herhangi"):
                ip = remoteip.split(",")[0].strip().split("/")[0]

            if ip:
                sync_ips[ip] = {
                    "rule_name": r["name"],
                    "source": "auto_response" if not str(suffix).isdigit() else "dashboard",
                }

        for ab in auto_blocks:
            ip = ab.get("ip", "")
            if ip and ip not in sync_ips:
                sync_ips[ip] = {
                    "rule_name": f"HP-BLOCK-{ip}",
                    "source": "auto_response",
                    "reason": ab.get("reason", ""),
                    "blocked_at": ab.get("blocked_at", 0),
                }

        self._sync_rules_to_api(list(sync_ips.items()))
        self.logger.info(
            f"🔄 Sync complete: {len(sync_ips)} active block(s) reported to API"
        )

    def _sync_rules_to_api(self, ip_entries: list) -> None:
        """POST /api/agent/sync-rules — inventory only (replace semantics on server)."""
        import datetime as _dt

        blocks = []
        for item in ip_entries:
            if isinstance(item, tuple):
                ip, info = item
            else:
                continue
            blocks.append({
                "ip": ip,
                "rule_name": info.get("rule_name", f"HP-BLOCK-{ip}"),
                "source": info.get("source", "unknown"),
                "reason": info.get("reason", ""),
                "blocked_at": info.get("blocked_at", ""),
            })

        body = {
            "token": self.token,
            "blocks": blocks,
            "total_rules": len(blocks),
            "synced_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }
        _, code = self._post_json("/api/agent/sync-rules", body)
        if code == 200:
            self.logger.info(f"API sync-rules accepted ({len(blocks)} blocks)")
        else:
            self.logger.warning(
                f"sync-rules HTTP {code} — inventory report skipped "
                f"(pending queues remain source of truth)"
            )

    def run_once(self) -> dict:
        """Run a single poll cycle — unblocks first (stale cleanup), then blocks."""
        try:
            unblocked = self._poll_pending_unblocks()
            blocked = self._poll_pending_blocks()
            self.logger.info(
                f"[FW-SYNC] pending_blocks={len(blocked)} "
                f"pending_unblocks={len(unblocked)} "
                f"removed={len(unblocked)} failed=0"
            )
            return {
                "success": True,
                "blocked_count": len(blocked),
                "unblocked_count": len(unblocked),
                "blocked_ids": blocked,
                "unblocked_ids": unblocked
            }
        except Exception as e:
            self.logger.exception(f"Agent run_once error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def run_forever(self) -> None:
        if not is_admin():
            self.logger.error("This agent requires Administrator/root privileges.")

        # Boot order (cloud is source of truth):
        # 1) pending-unblocks → delete + ACK
        # 2) pending-blocks → add + ACK
        # 3) sync-rules inventory of what remains (do NOT re-apply local list)
        self.logger.info("[FW-SYNC] Startup: unblocks → blocks → inventory sync")
        try:
            self._poll_pending_unblocks()
            self._poll_pending_blocks()
        except Exception as e:
            self.logger.error(f"Startup poll error (non-fatal): {e}")

        try:
            self._migrate_and_sync_rules()
        except Exception as e:
            self.logger.error(f"Migration/sync error (non-fatal): {e}")

        backoff = self.refresh_interval
        max_backoff = max(60, self.refresh_interval * 6)
        self.logger.info(
            f"Started Honeypot Firewall Agent (poll every {self.refresh_interval}s)"
        )
        while not self._stop:
            start = time.time()
            try:
                unblocked = self._poll_pending_unblocks()
                blocked = self._poll_pending_blocks()
                self.logger.info(
                    f"[FW-SYNC] pending_blocks={len(blocked)} "
                    f"pending_unblocks={len(unblocked)} "
                    f"removed={len(unblocked)} failed=0"
                )
                backoff = self.refresh_interval  # reset on success
            except Exception as e:
                self.logger.exception(f"Agent loop error: {e}")
                backoff = min(max_backoff, max(self.refresh_interval, int(backoff * 2)))
            elapsed = time.time() - start
            sleep_for = max(1, backoff - int(elapsed))
            time.sleep(sleep_for)


# ---------------------------- Defaults & CLI ---------------------------- #

def _default_cache_dir() -> Path:
    if is_windows():
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "YesNext" / "CloudHoneypotAgent" / "cache"
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
        return Path(base) / "cloud-honeypot-agent"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Honeypot Firewall Agent")
    p.add_argument("--api-base", default=os.environ.get("API_BASE"), help="Backend API base URL (env: API_BASE)")
    p.add_argument("--token", default=os.environ.get("TOKEN"), help="Agent token (env: TOKEN)")
    p.add_argument(
        "--cidr-feed-base",
        default=os.environ.get("CIDR_FEED_BASE", "https://www.ipdeny.com/ipblocks/data/countries"),
        help="Base URL for country CIDR lists (env: CIDR_FEED_BASE)",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=int(os.environ.get("REFRESH_INTERVAL_SEC", "30")),
        help="Polling interval seconds (env: REFRESH_INTERVAL_SEC, default 30)",
    )
    p.add_argument(
        "--log-file",
        default=os.environ.get("AGENT_LOG_FILE"),
        help="Optional log file path",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if not args.api_base or not args.token:
        print("ERROR: --api-base and --token are required (or set API_BASE/TOKEN env)")
        return 2
    log_path = Path(args.log_file) if args.log_file else None
    logger = make_logger(log_path)
    logger.info(f"OS detected: {'Windows' if is_windows() else ('Linux' if is_linux() else platform.system())}")
    logger.info(f"Polling interval: {args.interval}s")

    agent = FirewallAgent(
        api_base=args.api_base,
        token=args.token,
        refresh_interval=args.interval,
        cidr_feed_base=args.cidr_feed_base,
        logger=logger,
    )

    def _on_signal(signum, frame):
        logger.info(f"Signal {signum} received; stopping...")
        agent.stop()

    try:
        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)
    except Exception:
        pass

    agent.run_forever()
    return 0


if __name__ == "__main__":
    import logging.handlers
    sys.exit(main())
