#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract 1.1.3: enriched ransomware canary wire payload."""

import unittest

from client_ransomware_shield import CanaryState, RansomwareShield
from client_system_health import SystemHealthMonitor


class _AlertPipeline:
    def __init__(self, order=None):
        self.alerts = []
        self.order = order

    def send_urgent(self, alert):
        if self.order is not None:
            self.order.append("urgent")
        self.alerts.append(alert)


class _ApiClient:
    def __init__(self):
        self.payload = None

    def api_request(self, method, path, data=None, **_kwargs):
        self.payload = data
        return {"status": "ok"}


class TestCanaryUrgentWire(unittest.TestCase):
    def test_containment_precedes_enriched_urgent(self):
        order = []
        pipeline = _AlertPipeline(order)
        shield = RansomwareShield(alert_pipeline=pipeline)

        def contain(trigger, focus_path=""):
            order.append("contain")
            return {
                "trigger": trigger,
                "suspects": [{
                    "image": "evil.exe",
                    "path": r"C:\Temp\evil.exe",
                    "pid": 4712,
                    "cmdline": "evil.exe --encrypt",
                    "sha256": "abc123",
                }],
                "actions": ["kill:4712:evil.exe", "ifeo:evil.exe"],
                "quarantine": {"active": True, "entries": 1, "kills": 1},
            }

        shield._contain_after_hit = contain
        shield._block_suspicious_ips = lambda _reason: None
        canary = CanaryState(
            path=r"C:\Users\x\Documents\.cloud-honeypot-canary\!000_budget.xlsx",
            sha256="before",
            size=10,
        )

        shield._on_canary_triggered(canary, "MODIFIED")

        self.assertEqual(order, ["contain", "urgent"])
        alert = pipeline.alerts[0]
        self.assertEqual(alert["threat_score"], 100)
        self.assertEqual(alert["target_service"], "SYSTEM")
        self.assertEqual(alert["recommended_action"], "isolate_host")
        context = alert["system_context"]["ransomware"]
        self.assertEqual(context["file"], canary.path)
        self.assertEqual(context["change_type"], "MODIFIED")
        self.assertEqual(context["suspects"][0]["pid"], 4712)
        process_event = alert["raw_events"][1]
        self.assertEqual(process_event["process_name"], "evil.exe")
        self.assertEqual(process_event["cmdline"], "evil.exe --encrypt")


class TestHealthRansomwareWire(unittest.TestCase):
    def test_health_snapshot_includes_quarantine_details(self):
        class Shield:
            _running = True
            _vss_count = 2

            @staticmethod
            def get_stats():
                return {"canary_alerts": 1}

            @staticmethod
            def get_quarantine():
                return {
                    "active": True,
                    "locked_at": "2026-07-21T00:00:00",
                    "trigger": r"canary MODIFIED: C:\bait.xlsx",
                    "entries": [{
                        "image": "evil.exe",
                        "path": r"C:\Temp\evil.exe",
                        "pid": 4712,
                        "cmdline": "evil.exe --encrypt",
                        "sha256": "abc123",
                        "ifeo": True,
                        "at": "2026-07-21T00:00:01",
                    }],
                }

        api = _ApiClient()
        monitor = SystemHealthMonitor(
            api_client=api,
            token_getter=lambda: "test-token",
            ransomware_shield=Shield(),
        )
        monitor._latest = {"cpu_percent": 0}

        self.assertTrue(monitor._send_report())
        snapshot = api.payload["snapshot"]
        self.assertFalse(snapshot["canary_files_intact"])
        self.assertEqual(snapshot["ransomware_shield_status"], "active")
        self.assertEqual(snapshot["vss_shadow_count"], 2)
        quarantine = snapshot["ransomware_quarantine"]
        self.assertTrue(quarantine["active"])
        self.assertEqual(quarantine["entries"][0]["pid"], 4712)
        self.assertEqual(
            quarantine["entries"][0]["cmdline"], "evil.exe --encrypt"
        )


if __name__ == "__main__":
    unittest.main()
