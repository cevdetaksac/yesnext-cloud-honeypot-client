#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Health anomaly classification — disk full != ransomware."""

import unittest

from client_system_health import (
    METRIC_CONFIG,
    SystemHealthMonitor,
    _BENIGN_DISK_IO_NAMES,
)


class TestMetricCategories(unittest.TestCase):
    def test_disk_usage_is_capacity_not_ransomware(self):
        cfg = METRIC_CONFIG["disk_usage_percent"]
        self.assertEqual(cfg[4], "capacity")
        self.assertNotIn("ransomware", cfg[2].lower())
        self.assertGreaterEqual(cfg[1], 98)

    def test_disk_io_default_is_performance(self):
        self.assertEqual(METRIC_CONFIG["disk_io_write_rate"][4], "performance")
        self.assertNotIn("ransomware", METRIC_CONFIG["disk_io_write_rate"][2].lower())


class TestBenignDiskIo(unittest.TestCase):
    def setUp(self):
        self.m = SystemHealthMonitor()

    def test_cursor_is_benign(self):
        procs = [
            {"name": "Cursor.exe", "exe": r"C:\Users\x\AppData\Local\Programs\cursor\Cursor.exe",
             "pid": 1, "write_mb": 100, "read_mb": 10},
            {"name": "svchost.exe", "exe": r"C:\Windows\System32\svchost.exe",
             "pid": 2, "write_mb": 50, "read_mb": 1},
        ]
        self.assertTrue(self.m._is_benign_disk_io(procs))

    def test_unknown_temp_writer_not_benign(self):
        procs = [
            {"name": "encryptor.exe", "exe": r"C:\Users\x\AppData\Local\Temp\encryptor.exe",
             "pid": 9, "write_mb": 999, "read_mb": 1},
        ]
        self.assertFalse(self.m._is_benign_disk_io(procs))

    def test_benign_name_list_has_cursor(self):
        self.assertTrue(any("cursor" in n for n in _BENIGN_DISK_IO_NAMES))


if __name__ == "__main__":
    unittest.main()
