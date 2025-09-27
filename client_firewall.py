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
from requests.adapters import HTTPAdapter
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

    def remove_block(self, block_id: str) -> bool:
        raise NotImplementedError


class WindowsFirewallBackend(FirewallBackend):
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def _delete_rule_by_name(self, name: str) -> None:
        # Deletes all rules with the given name across profiles for dir=in
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}", "dir=in",
        ])
        msg = out.strip() or err.strip()
        if msg:
            self.logger.info(msg)

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

    def remove_block(self, block_id: str) -> bool:
        name = f"HP-BLOCK-{block_id}"
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}", "dir=in",
        ])
        if rc == 0:
            if out.strip():
                self.logger.info(out.strip())
            return True
        # If nothing to delete, netsh may return a message but rc can be non-zero; treat as success if mentions 0 rules
        msg = (out + "\n" + err).lower()
        if "no rules match" in msg or "0 rule(s) deleted" in msg:
            self.logger.info(f"No rules found for {name}; considered removed")
            return True
        self.logger.error(err.strip() or f"Failed to delete {name} rc={rc}")
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

    def remove_block(self, block_id: str) -> bool:
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
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.refresh_interval = max(1, int(refresh_interval))
        self.logger = logger or make_logger()
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
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 200:
                return r.json(), 200
            return None, r.status_code
        except Exception as e:
            self.logger.error(f"GET {path} failed: {e}")
            return None, None

    def _post_json(self, path: str, data: dict) -> Tuple[Optional[object], Optional[int]]:
        url = f"{self.api_base}{path}"
        try:
            r = self.session.post(url, json=data, timeout=5)
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
        data, code = self._get_json(f"/api/agent/pending-blocks?token={self.token}")
        if code != 200 or not isinstance(data, list):
            if code not in (200, None):
                self.logger.error(f"pending-blocks HTTP {code}")
            return payload_ids
        for item in data:
            try:
                block_id = str(item["id"]).strip()
                spec = str(item.get("ip_or_cidr", "")).strip()
                reason = str(item.get("reason", ""))
                # expires_at can be used by server; here we enforce as given
            except Exception as e:
                self.logger.error(f"Invalid block item: {e}")
                continue
            cidrs = self._expand_ip_or_cidr(spec)
            if not cidrs:
                continue
            ok = self.backend.apply_block(block_id, cidrs)
            if ok:
                self.logger.info(f"Applied block {block_id} ({spec})")
                payload_ids.append(block_id)
            else:
                self.logger.error(f"Failed to apply block {block_id} ({spec})")
        if payload_ids:
            body = {"token": self.token, "block_ids": payload_ids}
            _, code = self._post_json("/api/agent/block-applied", body)
            if code != 200:
                self.logger.error(f"block-applied HTTP {code}")
        return payload_ids

    def _poll_pending_unblocks(self) -> List[str]:
        removed_ids: List[str] = []
        data, code = self._get_json(f"/api/agent/pending-unblocks?token={self.token}")
        if code != 200 or not isinstance(data, list):
            if code not in (200, None):
                self.logger.error(f"pending-unblocks HTTP {code}")
            return removed_ids
        for item in data:
            try:
                block_id = str(item["id"]).strip()
            except Exception as e:
                self.logger.error(f"Invalid unblock item: {e}")
                continue
            ok = self.backend.remove_block(block_id)
            if ok:
                self.logger.info(f"Removed block {block_id}")
                removed_ids.append(block_id)
            else:
                self.logger.error(f"Failed to remove block {block_id}")
        if removed_ids:
            body = {"token": self.token, "block_ids": removed_ids}
            _, code = self._post_json("/api/agent/block-removed", body)
            if code != 200:
                self.logger.error(f"block-removed HTTP {code}")
        return removed_ids

    def run_once(self) -> dict:
        """Run a single poll cycle and return results"""
        try:
            blocked = self._poll_pending_blocks()
            unblocked = self._poll_pending_unblocks()
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
        backoff = self.refresh_interval
        max_backoff = max(60, self.refresh_interval * 6)
        self.logger.info("Started Honeypot Firewall Agent")
        while not self._stop:
            start = time.time()
            try:
                self._poll_pending_blocks()
                self._poll_pending_unblocks()
                backoff = self.refresh_interval  # reset on success
            except Exception as e:
                self.logger.exception(f"Agent loop error: {e}")
                backoff = min(max_backoff, max(self.refresh_interval, int(backoff * 2)))
            # Sleep until next tick; if error, exponential backoff
            elapsed = time.time() - start
            sleep_for = max(1, backoff - int(elapsed))
            time.sleep(sleep_for)


# Legacy alias for backward compatibility
Agent = FirewallAgent


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
        default=int(os.environ.get("REFRESH_INTERVAL_SEC", "10")),
        help="Polling interval seconds (env: REFRESH_INTERVAL_SEC)",
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
