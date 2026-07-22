#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RANS-301 shadow sensor surface — no elevated ETW session required."""

import unittest
from unittest import mock

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

    def test_correlation_is_bounded_shadow_only(self):
        sensor = EtwShadowSensor(window_sec=60)
        for idx in range(35):
            sensor.ingest_test_event(
                op="write",
                pid=4242,
                path=f"C:/data/file-{idx}.docx",
                image="sample.exe",
                process_start_time=1.0,
            )
        for idx in range(22):
            sensor.ingest_test_event(
                op="rename",
                pid=4242,
                path=f"C:/data/renamed-{idx}.locked",
                image="sample.exe",
                process_start_time=1.0,
            )
        sample = sensor.sample()
        correlation = sample["correlation"]
        self.assertEqual(correlation["mode"], "shadow")
        self.assertFalse(correlation["auto_containment"])
        self.assertEqual(correlation["candidate_count"], 1)
        candidate = correlation["candidates"][0]
        self.assertEqual(candidate["pid"], 4242)
        self.assertIn("file_fanout", candidate["signals"])
        self.assertIn("rename_burst", candidate["signals"])
        self.assertIn("write_burst", candidate["signals"])
        # Raw file paths and image names must never leave the sensor.
        self.assertNotIn("file-1.docx", str(sample))
        self.assertNotIn("sample.exe", str(sample))
        self.assertFalse(sample["available"])

    def test_status_names_stub_source_and_no_provider(self):
        sensor = EtwShadowSensor(window_sec=30)
        sample = sensor.sample()
        self.assertEqual(sample["source"], "stub")
        self.assertEqual(sample["fallback"], "none")
        self.assertFalse(sample["provider_attached"])
        self.assertFalse(sample["available"])

    def test_psutil_fallback_is_named_and_bounded(self):
        sensor = EtwShadowSensor(window_sec=60, enable_psutil_fallback=True)

        class _IO:
            write_count = 10
            write_bytes = 1000

        class _IO2:
            write_count = 50
            write_bytes = 9000

        with mock.patch.dict("sys.modules", {"psutil": mock.Mock()}):
            import sys
            fake = sys.modules["psutil"]
            fake.disk_io_counters.side_effect = [_IO(), _IO2()]
            sensor._sample_psutil_fallback()  # seed prev
            sensor._sample_psutil_fallback()
        sample = sensor.sample()
        self.assertEqual(sample["source"], "psutil_io")
        self.assertEqual(sample["fallback"], "psutil")
        self.assertFalse(sample["provider_attached"])
        self.assertFalse(sample["available"])
        self.assertFalse(sample["auto_containment"])
        # write_count delta 40, capped at 32 synthetic events
        self.assertEqual(sample["events_in_window"], 32)
        self.assertNotIn("C:\\", str(sample))


if __name__ == "__main__":
    unittest.main()
