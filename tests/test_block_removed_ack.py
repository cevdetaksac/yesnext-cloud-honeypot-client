#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Client 4.8.5: block-removed ACK must carry ips (not only block_ids)."""

import unittest
from unittest import mock

from client_firewall import FirewallAgent


class TestBlockRemovedAck(unittest.TestCase):
    def setUp(self):
        self.agent = FirewallAgent(
            api_base="https://example.test/api",
            token="tok",
            refresh_interval=30,
        )
        self.posts = []

        def fake_post(path, body):
            self.posts.append((path, dict(body)))
            # Simulate cloud: ids-only → updated 0; ip present → updated N
            updated = 0
            if body.get("ip") or body.get("ips"):
                updated = max(1, len(body.get("ips") or ([body["ip"]] if body.get("ip") else [])))
            return {"updated": updated, "status": "ok"}, 200

        self.agent._post_json = fake_post  # type: ignore

    def test_ack_sends_ids_and_ips(self):
        updated = self.agent._ack_blocks_removed(
            ["2582", "2649"], ["50.16.16.211", "178.62.3.223"],
        )
        self.assertEqual(len(self.posts), 1)
        path, body = self.posts[0]
        self.assertEqual(path, "/api/agent/block-removed")
        self.assertEqual(body["block_ids"], [2582, 2649])  # ints preferred
        self.assertEqual(body["ips"], ["50.16.16.211", "178.62.3.223"])
        self.assertGreater(updated, 0)

    def test_ack_fallback_per_ip_when_batch_updated_zero(self):
        def always_zero_then_ip(path, body):
            self.posts.append((path, dict(body)))
            # Batch (has ips list and/or block_ids) → cloud returns 0
            if body.get("ips") is not None or body.get("block_ids"):
                if "ip" in body and "ips" not in body:
                    return {"updated": 1, "status": "ok"}, 200
                return {"updated": 0, "status": "ok"}, 200
            if body.get("ip"):
                return {"updated": 1, "status": "ok"}, 200
            return {"updated": 0, "status": "ok"}, 200

        self.agent._post_json = always_zero_then_ip  # type: ignore
        updated = self.agent._ack_blocks_removed(
            ["1", "2"], ["9.9.9.9", "8.8.8.8"],
        )
        # First batch (updated=0) + two per-IP retries
        self.assertGreaterEqual(len(self.posts), 3)
        self.assertEqual(self.posts[0][1].get("ips"), ["9.9.9.9", "8.8.8.8"])
        self.assertEqual(self.posts[1][1].get("ip"), "9.9.9.9")
        self.assertEqual(self.posts[2][1].get("ip"), "8.8.8.8")
        self.assertEqual(updated, 2)

    def test_ack_single_ip_field(self):
        self.agent._ack_blocks_removed(["10"], ["1.2.3.4"])
        body = self.posts[0][1]
        self.assertEqual(body.get("ip"), "1.2.3.4")
        self.assertEqual(body.get("ips"), ["1.2.3.4"])


if __name__ == "__main__":
    unittest.main()
