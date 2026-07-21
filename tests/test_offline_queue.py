#!/usr/bin/env python3
"""OOB-501 DPAPI/integrity-protected offline queue."""

import os
import tempfile
import unittest
from unittest import mock

import client_offline_queue as queue


class TestOfflineQueue(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "queue.jsonl")
        self.crypto = [
            mock.patch.object(queue, "_seal", side_effect=lambda raw: b"DP" + raw),
            mock.patch.object(queue, "_open", side_effect=lambda raw: raw[2:]),
        ]
        for patcher in self.crypto:
            patcher.start()
            self.addCleanup(patcher.stop)

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

    def test_dpapi_unavailable_fails_closed_no_plaintext(self):
        with mock.patch.object(queue, "_seal", side_effect=RuntimeError("no dpapi")):
            result = queue.enqueue(
                "token", {"password": "secret"}, path=self.path
            )
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()
