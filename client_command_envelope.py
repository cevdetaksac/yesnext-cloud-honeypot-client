#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command envelope v2 client scaffolding (ZT-601) — design/observe only.

The cloud design gate (`honeypot-contract/cloud/command-envelope-v2-design.md`)
is **not** promoted to a normative wire contract yet. Per the contract:

    "No code may emit a production version:2 command before gate 1."

This module therefore provides only:
- a deterministic candidate serialization + `params_hash` helper;
- a structural/expiry/params classifier used purely for *observe* telemetry;
- a truthful capability descriptor that stays ``off`` unless explicitly enabled.

It never verifies asymmetric operator signatures (no key distribution exists
yet), never accepts/rejects production commands, and never produces a v2 wire.
Enforcement and floor changes ship in a separate explicit contract release.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

# Capability values: "off" (default), "observe" (classify only, never enforce).
# "enforce" is intentionally NOT selectable client-side until contract gate 6.
CAPABILITY_OFF = "off"
CAPABILITY_OBSERVE = "observe"

ENVELOPE_VERSION = 2

# Fields the candidate envelope must carry (design gate; may change on promotion).
_REQUIRED_FIELDS = (
    "version",
    "tenant_id",
    "device_id",
    "command_id",
    "command_type",
    "params_hash",
    "issued_at",
    "expires_at",
    "nonce",
    "signature",
)


def capability() -> str:
    """Truthful capability descriptor; ``off`` unless config opts into observe.

    Config: ``security.command_envelope_v2`` in {"off","observe"} (default off).
    We never advertise ``enforce`` because no verifiable operator key exists.
    """
    try:
        from client_utils import get_from_config
        val = str(get_from_config("security.command_envelope_v2", "off")).lower()
    except Exception:
        val = "off"
    return CAPABILITY_OBSERVE if val == "observe" else CAPABILITY_OFF


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic candidate serialization (sorted keys, compact, UTF-8).

    NOTE: This is a *candidate* only. The normative choice between RFC 8785
    (JCS) and deterministic CBOR is still open in the design gate; number
    formatting edge cases must be pinned before any enforcement.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def params_hash(params: Optional[Mapping[str, Any]]) -> str:
    """`sha256:<lowercase-hex>` over the canonical serialization of params."""
    digest = hashlib.sha256(canonical_bytes(params or {})).hexdigest()
    return f"sha256:{digest}"


def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        txt = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def inspect_envelope_v2(
    envelope: Mapping[str, Any],
    *,
    params: Optional[Mapping[str, Any]] = None,
    now: Optional[datetime] = None,
) -> dict:
    """Classify a candidate v2 envelope for observe telemetry (no enforcement).

    Verdicts (never used to accept/reject production commands yet):
    - ``not_v2``            — missing/!=2 version;
    - ``malformed``         — required structural field missing;
    - ``expired``           — expires_at in the past;
    - ``params_mismatch``   — params_hash does not match provided params;
    - ``unverified_no_key`` — structurally valid but no operator key to verify;
    - ``structurally_ok``   — structurally valid (signature verification pending).
    """
    result = {
        "verdict": "not_v2",
        "has_signature": bool(envelope.get("signature")),
        "expired": None,
        "params_match": None,
    }
    if not isinstance(envelope, Mapping):
        result["verdict"] = "malformed"
        return result
    if int(envelope.get("version", 0) or 0) != ENVELOPE_VERSION:
        result["verdict"] = "not_v2"
        return result

    for field in _REQUIRED_FIELDS:
        if field not in envelope or envelope.get(field) in (None, ""):
            result["verdict"] = "malformed"
            return result

    expires = _parse_iso(str(envelope.get("expires_at", "")))
    ref = now or datetime.now(timezone.utc)
    if expires is not None:
        result["expired"] = ref > expires
        if result["expired"]:
            result["verdict"] = "expired"
            return result

    if params is not None:
        expected = params_hash(params)
        result["params_match"] = (expected == str(envelope.get("params_hash")))
        if not result["params_match"]:
            result["verdict"] = "params_mismatch"
            return result

    # Structurally valid. Asymmetric operator signature verification is out of
    # scope until key distribution (ZT-603) and contract promotion land.
    result["verdict"] = "unverified_no_key"
    return result
