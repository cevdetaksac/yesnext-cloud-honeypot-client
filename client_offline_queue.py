#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OOB-501 local offline urgent-event queue.

Bounded, idempotent, replay-safe local spool:
- payload is recursively redacted before persistence;
- Windows uses machine-scope DPAPI via TokenStore;
- each encrypted record is HMAC-protected and has a deterministic event id;
- FIFO load/ack helpers never perform network I/O themselves.

Default integration remains off until the ingest contract is promoted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from client_constants import MACHINE_DATA_DIR
from client_security_utils import redact_sensitive

QUEUE_FILE = os.path.join(MACHINE_DATA_DIR, "offline_urgent_queue_v1.jsonl")
MAX_RECORDS = 500
_lock = threading.Lock()


def _key(token: str) -> bytes:
    return hashlib.sha256(f"{token}|offline-queue-v1".encode("utf-8")).digest()


def _seal(raw: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("dpapi unavailable")
    from client_utils import TokenStore
    return TokenStore._crypt_protect(raw)


def _open(blob: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("dpapi unavailable")
    from client_utils import TokenStore
    return TokenStore._crypt_unprotect(blob)


def _record_id(event: dict) -> str:
    stable = json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(stable).hexdigest()


def enqueue(
    token: str,
    event: dict,
    *,
    path: str = QUEUE_FILE,
    max_records: int = MAX_RECORDS,
) -> Optional[str]:
    if not token or not isinstance(event, dict):
        return None
    safe = redact_sensitive(event)
    event_id = str(safe.get("event_id") or _record_id(safe))
    envelope = {
        "version": 1,
        "event_id": event_id,
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "payload": safe,
    }
    raw = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    try:
        encrypted = _seal(raw)
    except Exception:
        return None
    encoded = base64.b64encode(encrypted).decode("ascii")
    record = {
        "event_id": event_id,
        "blob": encoded,
        "hmac": hmac.new(_key(token), encrypted, hashlib.sha256).hexdigest(),
    }
    with _lock:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            existing = []
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as handle:
                    existing = [line.strip() for line in handle if line.strip()]
            # Idempotent enqueue: do not duplicate an existing event id.
            if any(f'"event_id":"{event_id}"' in line for line in existing):
                return event_id
            existing.append(json.dumps(record, separators=(",", ":")))
            existing = existing[-max(1, int(max_records)):]
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write("\n".join(existing) + "\n")
            os.replace(tmp, path)
            return event_id
        except Exception:
            return None


def load(
    token: str,
    *,
    path: str = QUEUE_FILE,
    limit: int = 50,
) -> list[dict]:
    if not token or not os.path.isfile(path):
        return []
    with _lock:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]
        except Exception:
            return []
    result = []
    for line in lines[:max(1, int(limit))]:
        try:
            record = json.loads(line)
            encrypted = base64.b64decode(record["blob"], validate=True)
            expected = hmac.new(_key(token), encrypted, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(record.get("hmac") or ""), expected):
                continue
            envelope = json.loads(_open(encrypted).decode("utf-8"))
            if envelope.get("event_id") != record.get("event_id"):
                continue
            result.append(envelope)
        except Exception:
            continue
    return result


def acknowledge(
    event_ids: list[str],
    *,
    path: str = QUEUE_FILE,
) -> int:
    ids = {str(item) for item in event_ids if str(item)}
    if not ids or not os.path.isfile(path):
        return 0
    with _lock:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]
            kept = []
            removed = 0
            for line in lines:
                try:
                    event_id = str(json.loads(line).get("event_id") or "")
                except Exception:
                    event_id = ""
                if event_id in ids:
                    removed += 1
                else:
                    kept.append(line)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                if kept:
                    handle.write("\n".join(kept) + "\n")
            os.replace(tmp, path)
            return removed
        except Exception:
            return 0
