#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security helpers: log redaction, TLS config, auth headers, command signing."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any, Dict, Mapping, Optional

_SENSITIVE_KEYS = frozenset({
    "token", "password", "secret", "authorization", "api_key", "apikey",
    "access_token", "refresh_token", "credential", "passwd",
})

_TOKEN_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def redact_sensitive(value: Any, depth: int = 0) -> Any:
    """Recursively mask sensitive fields for safe logging."""
    if depth > 8:
        return "***"
    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            key = str(k).lower()
            if key in _SENSITIVE_KEYS:
                out[k] = _mask_token(str(v))
            else:
                out[k] = redact_sensitive(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _TOKEN_RE.sub(lambda m: _mask_token(m.group(0)), value)
    return value


def _mask_token(value: str) -> str:
    value = str(value or "")
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def get_tls_verify() -> bool:
    """Return whether HTTPS certificate verification is enabled."""
    try:
        from client_utils import get_from_config
        return bool(get_from_config("api.tls_verify", True))
    except Exception:
        return True


def get_tls_ca_bundle() -> Optional[str]:
    """Optional custom CA bundle path from config."""
    try:
        from client_utils import get_from_config
        path = get_from_config("api.ca_bundle", "") or ""
        path = str(path).strip()
        if path and os.path.isfile(path):
            return path
    except Exception:
        pass
    return None


def _stable_ca_bundle_path() -> str:
    return os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext",
        "CloudHoneypotClient",
        "cacert.pem",
    )


_ENSURED_CA: Optional[str] = None


def ensure_ca_bundle() -> Optional[str]:
    """Return a durable CA bundle path for frozen (PyInstaller) apps.

    onefile extracts certifi into %TEMP%\\_MEI* which Windows/RDP can delete while
    the process still runs (or another instance's path gets cached). We copy the
    first valid cacert.pem into ProgramData and point SSL env vars there.
    """
    global _ENSURED_CA
    import sys
    import shutil

    if _ENSURED_CA and os.path.isfile(_ENSURED_CA):
        return _ENSURED_CA

    custom = get_tls_ca_bundle()
    if custom:
        _ENSURED_CA = custom
        os.environ["SSL_CERT_FILE"] = custom
        os.environ["REQUESTS_CA_BUNDLE"] = custom
        return custom

    stable = _stable_ca_bundle_path()
    candidates = []
    if os.path.isfile(stable):
        candidates.append(stable)

    mei = getattr(sys, "_MEIPASS", "") or ""
    if mei:
        candidates.append(os.path.join(mei, "certifi", "cacert.pem"))
        candidates.append(os.path.join(mei, "cacert.pem"))

    try:
        import certifi
        where = certifi.where()
        if where:
            candidates.append(where)
    except Exception:
        pass

    # Next to installed exe (optional drop-in)
    try:
        if getattr(sys, "frozen", False):
            exe_dir = os.path.dirname(sys.executable)
            candidates.append(os.path.join(exe_dir, "cacert.pem"))
            candidates.append(os.path.join(exe_dir, "certifi", "cacert.pem"))
    except Exception:
        pass

    src = next((p for p in candidates if p and os.path.isfile(p) and os.path.getsize(p) > 1000), None)
    if not src:
        return None

    try:
        os.makedirs(os.path.dirname(stable), exist_ok=True)
        if os.path.abspath(src) != os.path.abspath(stable):
            need = True
            if os.path.isfile(stable):
                try:
                    need = os.path.getsize(stable) != os.path.getsize(src)
                except OSError:
                    need = True
            if need:
                shutil.copy2(src, stable)
        if os.path.isfile(stable):
            src = stable
    except Exception:
        pass

    _ENSURED_CA = src
    os.environ["SSL_CERT_FILE"] = src
    os.environ["REQUESTS_CA_BUNDLE"] = src
    return src


def resolve_tls_verify():
    """Value suitable for requests `verify` parameter."""
    if not get_tls_verify():
        return False
    bundle = ensure_ca_bundle()
    if bundle:
        return bundle
    # Last resort: True lets requests use its default (may fail in broken onefile)
    return True


# Warm CA path as soon as this module loads (before first HTTPS call)
try:
    ensure_ca_bundle()
except Exception:
    pass


def auth_headers(token: Optional[str] = None) -> Dict[str, str]:
    """Build Authorization header for API calls."""
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def use_legacy_token_query() -> bool:
    """Query-string token (?token=) — off by default (Bearer header is canonical).

    Set api.legacy_token_query=true only for emergency rollback against old APIs.
    """
    try:
        from client_utils import get_from_config
        return bool(get_from_config("api.legacy_token_query", False))
    except Exception:
        return False


def command_signing_enabled() -> bool:
    try:
        from client_utils import get_from_config
        return bool(get_from_config("security.command_signing", True))
    except Exception:
        return True


def _signing_secret(token: str) -> bytes:
    machine = os.environ.get("COMPUTERNAME", "unknown")
    material = f"{token}|{machine}|yesnext-chp-v1"
    return hashlib.sha256(material.encode("utf-8")).digest()


def make_agent_self_proof(token: str, pid: int, exe_path: str) -> str:
    """HMAC-SHA256 self-proof for health/report (cloud helpers.make_agent_self_proof).

    message = \"v1|{pid}|{exe_path_normalized}\"
    """
    norm = (exe_path or "").strip().lower().replace("/", "\\")
    msg = f"v1|{int(pid)}|{norm}".encode("utf-8")
    key = (token or "").encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def normalize_exe_path(exe_path: str) -> str:
    return (exe_path or "").strip().lower().replace("/", "\\")


def sign_command(token: str, command_id: str, cmd_type: str, issued_at: str) -> str:
    """HMAC signature for outbound command results (client → server)."""
    msg = f"{command_id}|{cmd_type}|{issued_at}".encode("utf-8")
    return hmac.new(_signing_secret(token), msg, hashlib.sha256).hexdigest()


def verify_command_signature(
    token: str,
    command: Mapping[str, Any],
) -> bool:
    """Verify HMAC on inbound dashboard commands when signature is present."""
    if not command_signing_enabled():
        return True
    sig = command.get("signature")
    if not sig:
        # Transition period: accept unsigned commands with warning handled by caller
        return True
    command_id = str(command.get("id", command.get("command_id", "")))
    cmd_type = str(command.get("type", command.get("command", "")))
    issued_at = str(command.get("issued_at", command.get("created_at", "")))
    expected = sign_command(token, command_id, cmd_type, issued_at)
    return hmac.compare_digest(str(sig), expected)
