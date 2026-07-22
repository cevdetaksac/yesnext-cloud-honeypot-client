#!/usr/bin/env python3
"""OOB-501 DPAPI/integrity-protected offline queue (contract api/10, 1.4.7)."""

import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import client_offline_queue as queue


class TestOfflineQueue(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "queue.jsonl")
        self.stats_path = os.path.join(self.tmp.name, "stats.json")
        self.crypto = [
            mock.patch.object(queue, "_seal", side_effect=lambda raw: b"DP" + raw),
            mock.patch.object(queue, "_open", side_effect=lambda raw: raw[2:]),
            mock.patch.object(queue, "STATS_FILE", self.stats_path),
        ]
        for patcher in self.crypto:
            patcher.start()
            self.addCleanup(patcher.stop)
        with queue._lock:
            queue._stats.update({
                "oldest_dropped": 0,
                "expired_dropped": 0,
                "too_large_rejected": 0,
            })
            queue._stats_loaded = True

    def test_round_trip_redacts_and_acknowledges(self):
        event_id = queue.enqueue(
            "token",
            {
                "event_type": "urgent",
                "password": "secret",
                "nested": {"turn_credential": "secret2"},
            },
            path=self.path,
        )
        self.assertTrue(event_id)
        loaded = queue.load("token", path=self.path)
        self.assertEqual(len(loaded), 1)
        text = str(loaded[0])
        self.assertNotIn("secret", text)
        self.assertNotIn("secret2", text)
        self.assertEqual(queue.acknowledge([event_id], path=self.path), 1)
        self.assertEqual(queue.load("token", path=self.path), [])

    def test_wrong_token_or_tamper_does_not_load(self):
        queue.enqueue("token", {"event_id": "e1"}, path=self.path)
        self.assertEqual(queue.load("wrong", path=self.path), [])
        with open(self.path, "r+", encoding="utf-8") as handle:
            content = handle.read().replace('"hmac":"', '"hmac":"00')
            handle.seek(0)
            handle.write(content)
            handle.truncate()
        self.assertEqual(queue.load("token", path=self.path), [])

    def test_enqueue_is_idempotent_and_bounded(self):
        queue.enqueue("token", {"event_id": "same"}, path=self.path)
        queue.enqueue("token", {"event_id": "same"}, path=self.path)
        for idx in range(5):
            queue.enqueue(
                "token", {"event_id": f"e{idx}"},
                path=self.path, max_records=3,
            )
        loaded = queue.load("token", path=self.path, limit=50)
        self.assertEqual(len(loaded), 3)
        self.assertEqual([item["event_id"] for item in loaded], ["e2", "e3", "e4"])
        self.assertGreaterEqual(queue.queue_stats()["oldest_dropped"], 2)
        # Durable counter survives "restart" (reload from stats file).
        with queue._lock:
            queue._stats.update({
                "oldest_dropped": 0,
                "expired_dropped": 0,
                "too_large_rejected": 0,
            })
            queue._stats_loaded = False
        self.assertGreaterEqual(queue.queue_stats()["oldest_dropped"], 2)

    def test_dpapi_unavailable_fails_closed_no_plaintext(self):
        with mock.patch.object(queue, "_seal", side_effect=RuntimeError("no dpapi")):
            result = queue.enqueue(
                "token", {"password": "secret"}, path=self.path
            )
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(self.path))

    def test_rejects_oversized_payload(self):
        huge = {"event_id": "big", "blob": "x" * (210 * 1024)}
        self.assertIsNone(queue.enqueue("token", huge, path=self.path))
        self.assertEqual(queue.queue_stats()["too_large_rejected"], 1)
        self.assertFalse(os.path.exists(self.path))

    def test_load_prunes_expired_ttl(self):
        event_id = queue.enqueue(
            "token", {"event_id": "old"}, path=self.path
        )
        self.assertTrue(event_id)
        with open(self.path, "r", encoding="utf-8") as handle:
            line = handle.readline().strip()
        record = json.loads(line)
        old_at = (
            datetime.now(timezone.utc) - timedelta(days=8)
        ).isoformat()
        envelope = {
            "version": 1,
            "event_id": "old",
            "queued_at": old_at,
            "payload": {"event_id": "old"},
        }
        raw = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        sealed = queue._seal(raw)
        record["blob"] = base64.b64encode(sealed).decode("ascii")
        record["hmac"] = hmac.new(
            queue._key("token"), sealed, hashlib.sha256
        ).hexdigest()
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        self.assertEqual(queue.load("token", path=self.path), [])
        self.assertEqual(queue.queue_stats()["expired_dropped"], 1)

    def test_drain_acks_duplicate_and_acked(self):
        queue.enqueue("token", {"event_id": "e1", "threat_type": "x"}, path=self.path)
        queue.enqueue("token", {"event_id": "e2", "threat_type": "y"}, path=self.path)
        seen = {}

        class _Api:
            def api_request(self, method, path, data=None, **_k):
                seen["path"] = path
                seen["count"] = len(data["events"])
                return {"acked": ["e1"], "duplicate": ["e2"], "rejected": []}

        with mock.patch.object(queue, "offline_queue_enabled", return_value=True):
            out = queue.drain_to_cloud(_Api(), "token", path=self.path)
        self.assertEqual(seen["path"], "alerts/urgent/batch")
        self.assertEqual(seen["count"], 2)
        self.assertEqual(out["acked"], 1)
        self.assertEqual(out["duplicate"], 1)
        self.assertEqual(queue.load("token", path=self.path), [])

    def test_drain_drops_non_transient_rejects_keeps_transient(self):
        queue.enqueue("token", {"event_id": "bad"}, path=self.path)
        queue.enqueue("token", {"event_id": "retry"}, path=self.path)
        queue.enqueue("token", {"event_id": "ok"}, path=self.path)

        class _Api:
            def api_request(self, method, path, data=None, **_k):
                return {
                    "acked": ["ok"],
                    "duplicate": [],
                    "rejected": [
                        {"event_id": "bad", "reason": "schema"},
                        {"event_id": "retry", "reason": "transient"},
                    ],
                }

        with mock.patch.object(queue, "offline_queue_enabled", return_value=True):
            out = queue.drain_to_cloud(_Api(), "token", path=self.path)
        self.assertEqual(out["dropped_rejected"], 1)
        remaining = [item["event_id"] for item in queue.load("token", path=self.path)]
        self.assertEqual(remaining, ["retry"])

    def test_drain_disabled_by_default(self):
        queue.enqueue("token", {"event_id": "e1"}, path=self.path)
        out = queue.drain_to_cloud(object(), "token", path=self.path)
        self.assertEqual(out["error"], "disabled_or_unconfigured")
        self.assertEqual(len(queue.load("token", path=self.path)), 1)


if __name__ == "__main__":
    unittest.main()
