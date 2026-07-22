#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Uninstall PIN gate unit tests."""

import os
import tempfile
import unittest
from unittest import mock

import client_gui_lock as gl
import client_uninstall_gate as gate


class TestUninstallGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patchers = [
            mock.patch.object(gl, "_programdata_dir", return_value=self.tmp.name),
        ]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)
        with gl.GuiLock._instance_lock:
            gl.GuiLock._instance = None

    def test_no_pin_silent_authorized(self):
        events = []
        with mock.patch.object(gate, "_emit", side_effect=lambda *a, **k: events.append((a, k))), \
                mock.patch.object(gate, "_arm_uninstall_stand_down"):
            code = gate.run_uninstall_gate(["--silent"])
        self.assertEqual(code, 0)
        types = [a[0] for a, _ in events]
        self.assertIn("uninstall_requested", types)
        self.assertIn("uninstall_authorized", types)

    def test_wrong_pin_fails(self):
        lock = gl.GuiLock.instance()
        lock.set_pin("1234")
        events = []
        with mock.patch.object(gate, "_emit", side_effect=lambda *a, **k: events.append((a, k))), \
                mock.patch.object(gate, "_arm_uninstall_stand_down") as arm:
            code = gate.run_uninstall_gate(["--silent", "--pin", "9999"])
        self.assertEqual(code, 1)
        arm.assert_not_called()
        types = [a[0] for a, _ in events]
        self.assertIn("uninstall_pin_failed", types)

    def test_correct_pin_authorizes(self):
        lock = gl.GuiLock.instance()
        lock.set_pin("5678")
        events = []
        with mock.patch.object(gate, "_emit", side_effect=lambda *a, **k: events.append((a, k))), \
                mock.patch.object(gate, "_arm_uninstall_stand_down") as arm:
            code = gate.run_uninstall_gate(["--silent", "--pin", "5678"])
        self.assertEqual(code, 0)
        arm.assert_called_once()
        types = [a[0] for a, _ in events]
        self.assertIn("uninstall_authorized", types)
        # details must not contain pin
        for a, k in events:
            blob = str(a) + str(k)
            self.assertNotIn("5678", blob)


if __name__ == "__main__":
    unittest.main()
