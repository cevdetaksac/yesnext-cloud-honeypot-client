#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZT-602/603 operator-key set scaffolding (design/observe only).

No production signature verification is performed until the contract promotes
the algorithm, canonical serialization and key-distribution endpoint. This
module only validates a candidate public metadata set and reports rotation /
revocation readiness. Private key material is always rejected.
"""

from __future__ import annotations

from typing import Mapping

_PRIVATE_MARKERS = (
    "private_key", "privatekey", "secret", "seed", "credential",
)


def inspect_keyset(document: Mapping) -> dict:
    result = {
        "mode": "observe",
        "verify_enabled": False,
        "valid": False,
        "active_keys": 0,
        "revoked_keys": 0,
        "rotation_overlap": False,
        "private_material_rejected": False,
        "errors": [],
    }
    if not isinstance(document, Mapping):
        result["errors"].append("not_mapping")
        return result
    # Cloud stub may wrap under "keys" or include verify_enabled:false at root.
    if document.get("verify_enabled") is True:
        # Client never enables verify until algorithm vectors are promoted.
        result["errors"].append("verify_enabled_not_allowed")
        result["verify_enabled"] = False
    lowered = {str(key).lower() for key in document.keys()}
    if any(marker in lowered for marker in _PRIVATE_MARKERS):
        result["private_material_rejected"] = True
        result["errors"].append("private_material_present")
        return result
    keys = document.get("keys")
    if not isinstance(keys, list):
        result["errors"].append("keys_missing")
        return result
    seen = set()
    active = 0
    revoked = 0
    for item in keys[:32]:
        if not isinstance(item, Mapping):
            result["errors"].append("key_not_mapping")
            continue
        item_keys = {str(key).lower() for key in item.keys()}
        if any(marker in item_keys for marker in _PRIVATE_MARKERS):
            result["private_material_rejected"] = True
            result["errors"].append("private_material_present")
            continue
        key_id = str(item.get("key_id") or "")
        algorithm = str(item.get("algorithm") or "")
        public_key = str(item.get("public_key") or "")
        state = str(item.get("state") or "active").lower()
        if not key_id or key_id in seen:
            result["errors"].append("key_id_missing_or_duplicate")
            continue
        seen.add(key_id)
        if algorithm not in ("ed25519", "webauthn"):
            result["errors"].append("algorithm_not_promoted")
        if not public_key:
            result["errors"].append("public_key_missing")
        if state == "revoked":
            revoked += 1
        elif state in ("active", "next"):
            active += 1
        else:
            result["errors"].append("state_invalid")
    result["active_keys"] = active
    result["revoked_keys"] = revoked
    result["rotation_overlap"] = active >= 2
    result["valid"] = not result["errors"] and active >= 1
    return result


def observe_enabled() -> bool:
    try:
        from client_utils import get_from_config
        return bool(get_from_config("security.operator_keys_observe", False))
    except Exception:
        return False


def fetch_keyset(api_client, token: str) -> dict:
    """Poll GET /api/agent/operator-keys (observe stub). Never verifies."""
    status = {
        "mode": "observe",
        "verify_enabled": False,
        "fetched": False,
        "valid": False,
        "active_keys": 0,
        "revoked_keys": 0,
        "rotation_overlap": False,
        "private_material_rejected": False,
        "errors": ["disabled"],
    }
    if not observe_enabled():
        return status
    if not api_client or not token:
        status["errors"] = ["no_token_or_client"]
        return status
    try:
        resp = api_client.api_request(
            "GET", "agent/operator-keys", timeout=15
        )
        if not isinstance(resp, dict):
            status["errors"] = ["bad_response"]
            return status
        inspected = inspect_keyset(resp)
        inspected["fetched"] = True
        inspected["verify_enabled"] = False
        return inspected
    except Exception as exc:
        status["errors"] = [f"fetch_error:{exc}"[:120]]
        return status
