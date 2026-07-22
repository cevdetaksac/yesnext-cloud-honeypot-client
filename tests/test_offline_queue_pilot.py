#!/usr/bin/env python3
"""OOB-501 pilot acceptance harness (contract api/10).

Closes client-side evidence for:
1. canary-shaped urgent spool while "offline" → drain on reconnect ACK;
2. 500-cap oldest-drop with durable ``oldest_dropped`` counter + health block.

Live 10m canary against a production dashboard still needs flag-on pilot ops;
this harness proves the same client code path without waiting wall-clock.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

import client_offline_queue as queue


class TestOfflineQueuePilotAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "queue.jsonl")
        self.stats_path = os.path.join(self.tmp.name, "stats.json")
        patches = [
            mock.patch.object(queue, "_seal", side_effect=lambda raw: b"DP" + raw),
            mock.patch.object(queue, "_open", side_effect=lambda raw: raw[2:]),
            mock.patch.object(queue, "STATS_FILE", self.stats_path),
            mock.patch.object(queue, "offline_queue_enabled", return_value=True),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        with queue._lock:
            queue._stats.update({
                "oldest_dropped": 0,
                "expired_dropped": 0,
                "too_large_rejected": 0,
            })
            queue._stats_loaded = True

    def test_canary_offline_then_reconnect_drain(self):
        """Acceptance: offline canary spool → reconnect batch → local row gone."""
        canary = {
            "event_id": "pilot-canary-001",
            "alert_id": "pilot-canary-001",
            "threat_type": "ransomware_canary_triggered",
            "severity": "critical",
            "title": "Canary triggered (pilot)",
            "description": "OOB-501 harness — no real file path",
            "source_ip": "127.0.0.1",
            "threat_score": 95,
        }
        # Offline: urgent POST failed → spool
        eid = queue.enqueue("token", canary, path=self.path)
        self.assertEqual(eid, "pilot-canary-001")
        self.assertEqual(len(queue.load("token", path=self.path)), 1)

        class _Api:
            def api_request(self, method, path, data=None, **_k):
                self.last = data
                ids = [e["event_id"] for e in data["events"]]
                return {"acked": ids, "duplicate": [], "rejected": []}

        api = _Api()
        # Reconnect: heartbeat/control-WS drain
        out = queue.drain_to_cloud(api, "token", path=self.path)
        self.assertEqual(out["attempted"], 1)
        self.assertEqual(out["acked"], 1)
        self.assertEqual(queue.load("token", path=self.path), [])
        payload = api.last["events"][0]["payload"]
        self.assertEqual(payload["threat_type"], "ransomware_canary_triggered")
        self.assertEqual(payload["severity"], "critical")

    def test_cap_500_oldest_drop_visible_in_health(self):
        """Acceptance: over-cap drops oldest and increments durable counter."""
        for idx in range(6):
            queue.enqueue(
                "token",
                {"event_id": f"e{idx}", "threat_type": "x"},
                path=self.path,
                max_records=5,
            )
        loaded = queue.load("token", path=self.path, limit=50)
        self.assertEqual([item["event_id"] for item in loaded], ["e1", "e2", "e3", "e4", "e5"])
        self.assertGreaterEqual(queue.queue_stats()["oldest_dropped"], 1)

        block = queue.health_observe_block("token", path=self.path)
        self.assertEqual(block["mode"], "observe")
        self.assertTrue(block["enabled"])
        self.assertEqual(block["pending"], 5)
        self.assertEqual(block["max_records"], 500)
        self.assertGreaterEqual(block["oldest_dropped"], 1)

        # Restart simulation
        with queue._lock:
            queue._stats.update({
                "oldest_dropped": 0,
                "expired_dropped": 0,
                "too_large_rejected": 0,
            })
            queue._stats_loaded = False
        self.assertGreaterEqual(queue.queue_stats()["oldest_dropped"], 1)


if __name__ == "__main__":
    unittest.main()
