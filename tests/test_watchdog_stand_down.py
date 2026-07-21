#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stand-down must suppress ensure_daemon_running (SR invariant)."""

import unittest
from unittest import mock

import client_daemon_ipc as ipc


class TestWatchdogStandDown(unittest.TestCase):
    def test_ensure_daemon_running_skips_on_stand_down(self):
        logs = []
        with mock.patch.object(ipc, "is_motor_healthy", return_value=False), mock.patch(
            "client_resilience.is_legitimate_stand_down", return_value=True
        ), mock.patch(
            "client_resilience.note_stand_down"
        ) as note:
            ok = ipc.ensure_daemon_running(log_func=logs.append, wait_sec=1.0)
        self.assertFalse(ok)
        note.assert_called()
        self.assertTrue(any("stand-down" in line.lower() for line in logs))


if __name__ == "__main__":
    unittest.main()
