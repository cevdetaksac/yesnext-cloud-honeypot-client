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
    """Optional custom CA bundle path."""
    try:
        from client_utils import get_from_config
        path = get_from_config("api.ca_bundle", "") or ""
        path = str(path).strip()
        if path and os.path.isfile(path):
            return path
    except Exception:
        pass
    return None


def resolve_tls_verify():
    """Value suitable for requests `verify` parameter."""
    if not get_tls_verify():
        return False
    return get_tls_ca_bundle() or True


def auth_headers(token: Optional[str] = None) -> Dict[str, str]:
    """Build Authorization header for API calls."""
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def use_legacy_token_query() -> bool:
    """Backward-compatible query-string token (disable when backend supports headers)."""
    try:
        from client_utils import get_from_config
        return bool(get_from_config("api.legacy_token_query", True))
    except Exception:
        return True


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
