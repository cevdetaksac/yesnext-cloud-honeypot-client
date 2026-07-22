#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for motor priority + resource formatting."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestFormatBps(unittest.TestCase):
    def test_bands(self):
        from client_resources import format_bps
        self.assertEqual(format_bps(500), "500B/s")
        self.assertEqual(format_bps(2048), "2KB/s")
        self.assertEqual(format_bps(2.5 * 1024 * 1024), "2.5MB/s")
        self.assertEqual(format_bps(None), "—")
        self.assertEqual(format_bps(0), "0B/s")


class TestPriorityResolve(unittest.TestCase):
    def test_realtime_downgraded(self):
        from client_process_priority import _resolve_level
        self.assertEqual(_resolve_level("realtime"), "above_normal")
        self.assertEqual(_resolve_level("REAL_TIME"), "above_normal")
        self.assertEqual(_resolve_level("high"), "high")
        self.assertEqual(_resolve_level("bogus"), "above_normal")

    @patch("client_process_priority.ctypes.WinDLL")
    def test_apply_never_realtime(self, mock_windll):
        from client_process_priority import (
            ABOVE_NORMAL_PRIORITY_CLASS,
            apply_motor_priority,
        )
        mock_k = MagicMock()
        mock_windll.return_value = mock_k
        mock_k.GetCurrentProcess.return_value = 1
        mock_k.SetPriorityClass.return_value = 1
        apply_motor_priority("realtime")
        args = mock_k.SetPriorityClass.call_args[0]
        self.assertEqual(args[1], ABOVE_NORMAL_PRIORITY_CLASS)


class TestCollectResourcesShape(unittest.TestCase):
    def test_keys_present(self):
        from client_resources import collect_resources
        hm = MagicMock()
        hm.get_snapshot.return_value = {
            "cpu_percent": 12.3,
            "memory_percent": 45.6,
            "net_recv_bps": 1000,
            "net_sent_bps": 2000,
        }
        with patch("client_resources._proc_handle") as ph:
            proc = MagicMock()
            proc.cpu_percent.return_value = 1.5
            mi = MagicMock()
            mi.rss = 80 * 1024 * 1024
            proc.memory_info.return_value = mi
            proc.io_counters.side_effect = Exception("skip")
            ph.return_value = proc
            out = collect_resources(hm)
        self.assertEqual(out["host_cpu_percent"], 12.3)
        self.assertEqual(out["host_memory_percent"], 45.6)
        self.assertEqual(out["net_recv_bps"], 1000.0)
        self.assertIn("process_cpu_percent", out)
        self.assertIn("priority", out)


if __name__ == "__main__":
    unittest.main()
