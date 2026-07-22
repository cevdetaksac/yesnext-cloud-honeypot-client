#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""successful_logon must not auto HP-BLOCK; score caps + should_auto_block."""

import unittest
from unittest import mock

from client_threat_engine import (
    ThreatEngine,
    THREAT_SCORES,
    should_auto_block,
    SUCCESS_LOGON_SCORE_CAP,
    SUCCESS_LOGON_SCORE_CAP_SILENT,
    BARE_SUCCESS_TYPES,
)


class TestShouldAutoBlock(unittest.TestCase):
    def test_bare_success_never_blocks(self):
        for et in (
            "successful_logon",
            "successful_logon_rdp",
            "rdp_connection_succeeded",
            "rdp_session_logon",
            "rdp_login_success",
        ):
            self.assertFalse(should_auto_block(et), et)

    def test_whitelist_never_blocks(self):
        self.assertFalse(
            should_auto_block("honeypot_credential", is_whitelisted=True)
        )

    def test_brute_correlation_blocks(self):
        self.assertTrue(
            should_auto_block(
                "successful_logon_rdp",
                correlation_rule="brute_force_then_access",
                failed_attempts=5,
            )
        )

    def test_honeypot_blocks(self):
        self.assertTrue(should_auto_block("honeypot_credential"))


class TestSuccessfulLogonScoring(unittest.TestCase):
    def setUp(self):
        self.engine = ThreatEngine()
        self.alerts = []
        self.engine.on_alert = lambda a: self.alerts.append(a)

    def test_rdp_success_score_capped_and_no_block(self):
        # Stack typical RDP events
        for et, lid in (
            ("rdp_connection_succeeded", 1149),
            ("rdp_session_logon", 21),
            ("successful_logon", 4624),
        ):
            ev = {
                "event_type": et,
                "event_id": lid,
                "source_ip": "203.0.113.50",
                "target_service": "RDP",
                "logon_type": 10 if et == "successful_logon" else None,
                "username": "office.user",
            }
            self.engine.process_event(ev)

        self.assertTrue(self.alerts)
        for a in self.alerts:
            self.assertNotIn("block_ip", a.get("auto_response") or [], a)
            self.assertLessEqual(int(a.get("threat_score") or 0), SUCCESS_LOGON_SCORE_CAP_SILENT)
            self.assertLess(int(a.get("threat_score") or 0), 100)

        # Base table must stay below critical threshold for bare RDP success
        self.assertLess(THREAT_SCORES["successful_logon_rdp"], 81)
        self.assertLessEqual(THREAT_SCORES["successful_logon_rdp"], SUCCESS_LOGON_SCORE_CAP)

    def test_whitelist_lowers_score(self):
        self.engine._whitelist_ips.add("198.51.100.10")
        self.engine.process_event({
            "event_type": "successful_logon",
            "event_id": 4624,
            "source_ip": "198.51.100.10",
            "target_service": "RDP",
            "logon_type": 10,
            "username": "boss",
        })
        self.assertTrue(self.alerts)
        a = self.alerts[-1]
        self.assertNotIn("block_ip", a.get("auto_response") or [])
        self.assertLessEqual(int(a["threat_score"]), 25)

    def test_brute_then_success_still_blocks(self):
        ip = "198.51.100.99"
        for _ in range(5):
            self.engine.process_event({
                "event_type": "failed_logon",
                "event_id": 4625,
                "source_ip": ip,
                "target_service": "RDP",
                "username": "admin",
            })
        before = len(self.alerts)
        self.engine.process_event({
            "event_type": "successful_logon",
            "event_id": 4624,
            "source_ip": ip,
            "target_service": "RDP",
            "logon_type": 10,
            "username": "admin",
        })
        # Correlation brute_force_then_access should fire with block_ip
        blocked = [
            a for a in self.alerts[before:]
            if "block_ip" in (a.get("auto_response") or [])
        ]
        self.assertTrue(
            blocked,
            f"expected block after brute+success; alerts={[a.get('correlation_rule') for a in self.alerts[before:]]}",
        )
        self.assertEqual(blocked[-1].get("correlation_rule"), "brute_force_then_access")


if __name__ == "__main__":
    unittest.main()
