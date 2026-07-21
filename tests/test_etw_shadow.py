#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RANS-301 shadow sensor surface — no elevated ETW session required."""

import unittest

from client_etw_shadow import EtwShadowSensor


class TestEtwShadow(unittest.TestCase):
    def test_capabilities_never_claim_live_provider_or_containment(self):
        sensor = EtwShadowSensor(window_sec=30)
        caps = sensor.capabilities()
        self.assertFalse(caps["etw_file_io"])
        self.assertFalse(caps["auto_containment"])
        self.assertEqual(caps["mode"], "shadow")

    def test_ingest_and_sample_counts_without_side_effects(self):
        sensor = EtwShadowSensor(window_sec=60)
        sensor.ingest_test_event(op="rename", pid=4242, path=r"C:\temp\a.doc")
        sensor.ingest_test_event(op="write", pid=4242, path=r"C:\temp\a.doc")
        sensor.ingest_test_event(op="write", pid=99, path=r"C:\temp\b.doc")
        sensor.mark_provider_restart()
        sample = sensor.sample()
        self.assertEqual(sample["events_in_window"], 3)
        self.assertEqual(sample["ops"]["write"], 2)
        self.assertEqual(sample["ops"]["rename"], 1)
        self.assertEqual(sample["provider_restarts"], 1)
        self.assertFalse(sample["auto_containment"])
        self.assertFalse(sample["available"])


if __name__ == "__main__":
    unittest.main()
