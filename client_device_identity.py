#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DEV-601 TPM device-identity capability probe (PoC, no enrollment).

Read-only capability detection. It does not generate/export keys, does not
attest, and never hard-locks the client when TPM is absent or cleared.
"""

from __future__ import annotations

import json
import os
import subprocess

CREATE_NO_WINDOW = 0x08000000


def observe_enabled() -> bool:
    try:
        from client_utils import get_from_config
        return bool(get_from_config("security.tpm_identity_observe", False))
    except Exception:
        return False


def probe_tpm() -> dict:
    result = {
        "mode": "observe",
        "enrolled": False,
        "tpm_present": None,
        "tpm_ready": None,
        "manufacturer_id": None,
        "key_non_exportable": None,
        "attestation": "not_implemented",
        "reenrollment_required": False,
        "error": "",
    }
    if os.name != "nt":
        result["error"] = "non_windows"
        return result
    script = (
        "$ErrorActionPreference='Stop'; $t=Get-Tpm; "
        "[pscustomobject]@{Present=[bool]$t.TpmPresent;"
        "Ready=[bool]$t.TpmReady;"
        "Manufacturer=[string]$t.ManufacturerIdTxt}|ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        if proc.returncode != 0:
            result["error"] = "tpm_query_failed"
            return result
        data = json.loads((proc.stdout or "").strip().splitlines()[-1])
        result["tpm_present"] = bool(data.get("Present"))
        result["tpm_ready"] = bool(data.get("Ready"))
        manufacturer = str(data.get("Manufacturer") or "")[:16]
        result["manufacturer_id"] = manufacturer or None
        result["error"] = "" if result["tpm_present"] else "tpm_unsupported"
    except Exception:
        result["error"] = "tpm_query_unavailable"
    return result
