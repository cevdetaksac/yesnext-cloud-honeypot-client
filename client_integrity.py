#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runtime self-integrity check (REV-104) — observe only.

Reports whether the running frozen binary is Authenticode-trusted and feeds the
`binary_integrity` observe field consumed by `client_resilience.snapshot()` and
the cloud health report (contract 1.4.2, values: valid | invalid | unknown).

Design constraints (see docs/SECURITY_RESILIENCE_ROADMAP.md):
- Observe only. Never blocks startup, never kills/suspends anything.
- Unsigned dev/current fleet reports `unknown`, not `invalid`. `invalid` is
  reserved for a *present-but-broken* signature (tamper signal).
- No certificate blobs, hashes of secrets, or file contents are logged.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(*_a, **_k):
        pass


def _running_binary_path() -> str:
    """Absolute path of the running executable (frozen) or main script."""
    try:
        if getattr(sys, "frozen", False):
            return os.path.abspath(sys.executable)
    except Exception:
        pass
    try:
        return os.path.abspath(sys.argv[0] or sys.executable)
    except Exception:
        return ""


def evaluate_runtime_integrity() -> dict:
    """Return a redacted integrity verdict for the running binary.

    Result keys: status, frozen, signed, trusted, publisher, reason.
    """
    result = {
        "status": "unknown",
        "frozen": bool(getattr(sys, "frozen", False)),
        "signed": False,
        "trusted": False,
        "publisher": "",
        "reason": "",
    }

    if not result["frozen"]:
        # Source/dev runs cannot be Authenticode-verified meaningfully.
        result["reason"] = "not_frozen"
        return result
    if sys.platform != "win32":
        result["reason"] = "non_windows"
        return result

    path = _running_binary_path()
    if not path or not os.path.isfile(path):
        result["reason"] = "binary_missing"
        return result

    try:
        from client_authenticode import (
            authenticode_required,
            verify_authenticode,
        )
    except Exception:
        result["reason"] = "authenticode_unavailable"
        return result

    try:
        info = verify_authenticode(path)
    except Exception:
        result["reason"] = "verify_error"
        return result

    result["signed"] = bool(info.get("signed"))
    result["trusted"] = bool(info.get("trusted"))
    result["publisher"] = str(info.get("publisher") or "")[:256]

    if info.get("trusted"):
        result["status"] = "valid"
        result["reason"] = "authenticode_trusted"
    elif info.get("signed"):
        # A signature is present but does not validate → tamper/mismatch.
        result["status"] = "invalid"
        result["reason"] = info.get("error") or "signature_not_trusted"
    else:
        # No signature. Unknown by default; invalid only if policy requires it.
        try:
            required = authenticode_required()
        except Exception:
            required = False
        result["status"] = "invalid" if required else "unknown"
        result["reason"] = "unsigned_required" if required else "unsigned"

    return result


def check_and_record(*, log_result: bool = True) -> dict:
    """Evaluate integrity and publish the verdict to resilience state."""
    info = evaluate_runtime_integrity()
    try:
        from client_resilience import set_binary_integrity
        set_binary_integrity(info["status"])
    except Exception:
        pass
    if log_result:
        # Publisher/reason are safe to log; no cert material or hashes.
        log(
            f"[INTEGRITY] status={info['status']} frozen={info['frozen']} "
            f"signed={info['signed']} reason={info.get('reason', '')}"
        )
    return info


def check_async(delay_sec: float = 0.0) -> None:
    """Run the integrity check off the hot path (Authenticode spawns PowerShell)."""
    import threading

    def _run():
        try:
            if delay_sec > 0:
                import time
                time.sleep(delay_sec)
            check_and_record()
        except Exception as exc:  # pragma: no cover - defensive
            log(f"[INTEGRITY] check_async failed: {exc}")

    t = threading.Thread(target=_run, name="integrity-check", daemon=True)
    t.start()
