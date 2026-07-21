#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authenticode / WinVerifyTrust helpers (SUP-001b).

Default policy keeps current unsigned fleet working:
- verification runs only when ``updates.require_authenticode`` is true, or
  ``updates.allowed_publishers`` is a non-empty list.
- SHA-256 remains a separate optional integrity check.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, List, Optional


class AuthenticodeError(Exception):
    """Raised when Authenticode verification fails under enforce policy."""


def allowed_publishers_from_config() -> List[str]:
    try:
        from client_utils import get_from_config
        raw = get_from_config("updates.allowed_publishers", None)
        if raw is None:
            # Optional fallback to product marker (not enforced unless required).
            raw = get_from_config("updates.publisher", "")
        if isinstance(raw, str):
            return [raw.strip()] if raw.strip() else []
        if isinstance(raw, (list, tuple)):
            return [str(item).strip() for item in raw if str(item).strip()]
    except Exception:
        pass
    return []


def authenticode_required() -> bool:
    try:
        from client_utils import get_from_config
        if bool(get_from_config("updates.require_authenticode", False)):
            return True
        return bool(allowed_publishers_from_config())
    except Exception:
        return False


def verify_authenticode(
    path: str,
    *,
    allowed_publishers: Optional[Iterable[str]] = None,
) -> dict:
    """Return a redacted verification result; never includes certificate blobs."""
    result = {
        "path_ok": False,
        "signed": False,
        "trusted": False,
        "publisher": "",
        "error": "",
        "skipped": False,
    }
    if not path or not os.path.isfile(path):
        result["error"] = "file missing"
        return result
    result["path_ok"] = True
    if sys.platform != "win32":
        result["skipped"] = True
        result["error"] = "non-windows"
        return result

    try:
        publisher, trusted, err = _winverify_trust(path)
    except Exception:
        result["error"] = "winverify unavailable"
        return result

    result["signed"] = bool(publisher) or trusted
    result["trusted"] = bool(trusted)
    result["publisher"] = str(publisher or "")[:256]
    if err:
        result["error"] = str(err)[:160]

    allow = [
        str(item).strip().lower()
        for item in (allowed_publishers if allowed_publishers is not None
                     else allowed_publishers_from_config())
        if str(item).strip()
    ]
    if allow:
        pub = result["publisher"].lower()
        if not any(item in pub for item in allow):
            result["trusted"] = False
            if not result["error"]:
                result["error"] = "publisher not allowed"
    return result


def assert_update_authenticode(path: str) -> dict:
    """Enforce policy for update installers. Soft-skip when not required."""
    required = authenticode_required()
    info = verify_authenticode(path)
    if not required:
        info["skipped"] = True if not info.get("signed") else info.get("skipped")
        return info
    if info.get("skipped") and info.get("error") == "non-windows":
        return info
    if not info.get("trusted"):
        raise AuthenticodeError(info.get("error") or "authenticode verification failed")
    return info


def _winverify_trust(path: str):
    """Best-effort WinVerifyTrust + signer subject via WinAPI/PowerShell fallback."""
    # Prefer PowerShell Get-AuthenticodeSignature — available on target hosts and
    # easier to keep correct than full ctypes WINTRUST_DATA packing.
    import subprocess
    CREATE_NO_WINDOW = 0x08000000
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:HP_AUTH_PATH; "
        "if (-not $s) { 'ERR|missing'; exit 0 }; "
        "$pub = ''; "
        "if ($s.SignerCertificate) { $pub = $s.SignerCertificate.Subject }; "
        "$st = [string]$s.Status; "
        "Write-Output ($st + '|' + $pub)"
    )
    env = os.environ.copy()
    env["HP_AUTH_PATH"] = os.path.abspath(path)
    r = subprocess.run(
        [
            "powershell", "-NoProfile", "-NonInteractive", "-Command", script,
        ],
        capture_output=True, text=True, timeout=30,
        creationflags=CREATE_NO_WINDOW, env=env,
    )
    line = ((r.stdout or "").strip().splitlines() or [""])[-1]
    if "|" not in line:
        return "", False, "signature query failed"
    status, publisher = line.split("|", 1)
    status = status.strip()
    publisher = publisher.strip()
    if status == "Valid":
        return publisher, True, ""
    if status in ("NotSigned", "UnknownError", "ERR"):
        return publisher, False, f"status={status}"
    return publisher, False, f"status={status}"
