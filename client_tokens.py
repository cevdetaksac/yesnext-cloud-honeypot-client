#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Token Management — machine-scoped immutable client identity.

Token is the server's durable identity (like a MAC). It must:
  - Live in ProgramData (shared by SYSTEM daemon + user GUI)
  - Never be overwritten by a newly minted /register token
  - Never auto-re-register merely because load/decrypt failed

Create (/register) only when NO token file exists after migration.
"""

from __future__ import annotations

import os
import time
import hashlib
from typing import Optional, List

from client_helpers import ClientHelpers, log
from client_utils import TokenStore, _programdata_client_dir
from client_api import register_client_api


def get_machine_id() -> str:
    """Stable per-machine id (Windows MachineGuid preferred)."""
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            if guid:
                return str(guid).strip()
    except Exception:
        pass
    # Fallback: hostname + system drive serial (still machine-local)
    try:
        import ctypes
        vol_serial = ctypes.c_ulong(0)
        ctypes.windll.kernel32.GetVolumeInformationW(
            "C:\\", None, 0, ctypes.byref(vol_serial), None, None, None, 0
        )
        raw = f"{os.environ.get('COMPUTERNAME', '')}-{vol_serial.value}"
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:32]
    except Exception:
        return hashlib.sha256(
            (os.environ.get("COMPUTERNAME") or "unknown").encode("utf-8")
        ).hexdigest()[:32]


def get_canonical_token_path() -> str:
    """Machine-wide token path — same for SYSTEM and interactive user."""
    return os.path.join(_programdata_client_dir(), "token.dat")


def get_legacy_token_paths(app_dir: str = "") -> List[str]:
    """Historical locations that may hold a valid token (migrate → ProgramData)."""
    paths: List[str] = []
    seen = set()

    def _add(p: str):
        if not p:
            return
        norm = os.path.normcase(os.path.abspath(p))
        if norm in seen:
            return
        seen.add(norm)
        paths.append(p)

    # Prefer user AppData (interactive GUI often created the first identity)
    user_appdata = os.environ.get("APPDATA") or ""
    if user_appdata:
        _add(os.path.join(user_appdata, "YesNext", "CloudHoneypotClient", "token.dat"))

    # Explicit app_dir (may equal user AppData)
    if app_dir:
        _add(os.path.join(app_dir, "token.dat"))

    # SYSTEM profile used by CloudHoneypot-Background / SilentUpdater
    windir = os.environ.get("WINDIR", r"C:\Windows")
    _add(
        os.path.join(
            windir,
            "System32",
            "config",
            "systemprofile",
            "AppData",
            "Roaming",
            "YesNext",
            "CloudHoneypotClient",
            "token.dat",
        )
    )
    # WOW64 view sometimes used by 32-bit helpers
    _add(
        os.path.join(
            windir,
            "SysWOW64",
            "config",
            "systemprofile",
            "AppData",
            "Roaming",
            "YesNext",
            "CloudHoneypotClient",
            "token.dat",
        )
    )

    # Install / CWD leftovers
    try:
        import sys
        if getattr(sys, "frozen", False):
            _add(os.path.join(os.path.dirname(sys.executable), "token.dat"))
            _add(os.path.join(os.path.dirname(sys.executable), "token.txt"))
    except Exception:
        pass
    _add(os.path.join(os.getcwd(), "token.dat"))
    _add(os.path.join(os.getcwd(), "token.txt"))
    _add("token.txt")

    return paths


def get_token_file_paths(app_dir: str = "") -> tuple:
    """Return (canonical_token.dat, legacy_plain_token.txt) for TokenManager."""
    return get_canonical_token_path(), "token.txt"


def _is_plain_token_file(path: str) -> bool:
    return path.lower().endswith(".txt")


def _read_token_from_path(path: str) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return None
    try:
        if _is_plain_token_file(path):
            with open(path, "r", encoding="utf-8") as fh:
                tok = fh.read().strip()
            return tok or None
        return TokenStore.load(path)
    except Exception as e:
        log(f"[TOKEN] Failed reading {path}: {e}")
        return None


def migrate_token_to_canonical(app_dir: str = "") -> Optional[str]:
    """Find any existing valid token and copy it to ProgramData. Never /register."""
    canonical = get_canonical_token_path()
    existing = TokenStore.load(canonical)
    if existing:
        return existing

    for path in get_legacy_token_paths(app_dir):
        if os.path.normcase(os.path.abspath(path)) == os.path.normcase(
            os.path.abspath(canonical)
        ):
            continue
        tok = _read_token_from_path(path)
        if not tok:
            continue
        try:
            TokenStore.save(tok, canonical, overwrite=False)
            log(f"[TOKEN] Migrated durable identity from {path} -> {canonical}")
            # Best-effort cleanup of plain-text leftovers only
            if _is_plain_token_file(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
            return tok
        except Exception as e:
            log(f"[TOKEN] Migration save failed from {path}: {e}")
            # Still return token for this process even if ProgramData write failed
            return tok

    # Plain migrate helper (CWD token.txt) without clobbering a good file
    TokenStore.migrate_from_plain("token.txt", canonical, only_if_missing=True)
    return TokenStore.load(canonical)


def _registration_lock_path() -> str:
    return os.path.join(_programdata_client_dir(), "token_register.lock")


def _acquire_register_lock(timeout_sec: float = 30.0):
    """Exclusive lock so daemon + tray cannot double-register."""
    path = _registration_lock_path()
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, f"{os.getpid()}\n{time.time()}\n".encode("ascii", "ignore"))
            return fd
        except FileExistsError:
            # Stale lock? If older than 5 minutes, break it
            try:
                age = time.time() - os.path.getmtime(path)
                if age > 300:
                    os.remove(path)
                    continue
            except OSError:
                pass
            time.sleep(0.25)
        except OSError:
            time.sleep(0.25)
    return None


def _release_register_lock(fd) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.remove(_registration_lock_path())
    except OSError:
        pass


class TokenManager:
    """Machine-scoped token identity manager."""

    def __init__(self, api_url: str, server_name: str, token_file_new: str, token_file_old: str):
        self.api_url = api_url
        self.server_name = server_name
        # Always prefer canonical ProgramData path (ignore legacy caller path if different)
        self.token_file_new = get_canonical_token_path()
        self.token_file_old = token_file_old or "token.txt"
        self._app_dir_hint = os.path.dirname(token_file_new) if token_file_new else ""

    def get_token(self) -> Optional[str]:
        """Load only — never creates a new identity."""
        tok = migrate_token_to_canonical(self._app_dir_hint)
        if tok:
            return tok
        return TokenStore.load(self.token_file_new)

    def register_client(self, root_window=None, t_func=None) -> Optional[str]:
        """Register ONLY when no durable token exists. Uses machine_id for API upsert."""
        # Re-check under lock — another process may have just registered
        existing = self.get_token()
        if existing:
            log("[TOKEN] Register skipped — durable token already present")
            return existing

        lock_fd = _acquire_register_lock()
        if lock_fd is None:
            log("[TOKEN] Register lock timeout — refusing to mint a new identity")
            return self.get_token()

        try:
            existing = self.get_token()
            if existing:
                return existing

            # File exists but unreadable → NEVER mint (would orphan API identity)
            if os.path.isfile(self.token_file_new):
                log(
                    "[TOKEN] token.dat exists but could not be read — "
                    "refusing auto-register to protect identity"
                )
                return None

            machine_id = get_machine_id()
            for attempt in range(3):
                try:
                    ip = ClientHelpers.get_public_ip()

                    def save_token(tok):
                        # Refuse overwrite of a different existing token
                        TokenStore.save(tok, self.token_file_new, overwrite=False)

                    token = register_client_api(
                        self.api_url,
                        self.server_name,
                        ip,
                        save_token,
                        log,
                        machine_id=machine_id,
                    )
                    if token:
                        log(f"[TOKEN] Registered durable identity (machine_id={machine_id[:8]}...)")
                        return token

                    msg = "API kaydı başarısız. Tekrar deneniyor..."
                    if root_window:
                        try:
                            import tkinter.messagebox as messagebox
                            messagebox.showwarning("Uyarı", msg)
                        except Exception:
                            pass
                    log(msg)
                except Exception as e:
                    msg = f"API kaydı başarısız: {e}. Tekrar deneniyor..."
                    if root_window:
                        try:
                            import tkinter.messagebox as messagebox
                            messagebox.showwarning("Uyarı", msg)
                        except Exception:
                            pass
                    log(msg)
                time.sleep(5)

            if root_window and t_func:
                try:
                    import tkinter.messagebox as messagebox
                    messagebox.showwarning(t_func("warn"), t_func("api_registration_warning"))
                except Exception:
                    pass
            return None
        finally:
            _release_register_lock(lock_fd)

    def load_token(self, root_window=None, t_func=None) -> Optional[str]:
        """Load durable token; register only if no token file exists anywhere."""
        tok = self.get_token()
        if tok:
            return tok

        # Corrupt/unreadable canonical file → do not register
        if os.path.isfile(self.token_file_new):
            log("[TOKEN] Canonical token.dat present but unreadable — not re-registering")
            return None

        # Any legacy file present but unreadable → still do not mint
        for path in get_legacy_token_paths(self._app_dir_hint):
            if os.path.isfile(path):
                log(f"[TOKEN] Legacy token file present but unreadable ({path}) — not re-registering")
                return None

        log("[TOKEN] No durable token found — first-run registration")
        return self.register_client(root_window, t_func)


def create_token_manager(api_url: str, server_name: str, token_file_new: str, token_file_old: str) -> TokenManager:
    """Factory function to create TokenManager instance"""
    return TokenManager(api_url, server_name, token_file_new, token_file_old)
