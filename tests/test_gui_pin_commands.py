#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract 1.3.11 (client 4.8.3): dashboard GUI PIN set/reset commands."""

import os
import tempfile
import unittest
from unittest import mock

import client_gui_lock
from client_gui_lock import GuiLock
from client_remote_commands import (
    ALLOWED_COMMANDS,
    REQUIRES_CONFIRMATION,
    RemoteCommandExecutor,
)


class _TempPinStore:
    """Redirect gui_lock.json into a temp dir + fresh GuiLock singleton."""

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patcher = mock.patch.object(
            client_gui_lock, "_programdata_dir", return_value=self.tmp.name,
        )
        self.patcher.start()
        self._saved_instance = GuiLock._instance
        GuiLock._instance = None
        return self

    def __exit__(self, *exc):
        GuiLock._instance = self._saved_instance
        self.patcher.stop()
        self.tmp.cleanup()
        return False


class TestPinCommandsWhitelist(unittest.TestCase):
    def test_whitelisted_and_confirmed(self):
        for ct in ("set_gui_pin", "clear_gui_pin"):
            self.assertIn(ct, ALLOWED_COMMANDS)
            self.assertIn(ct, REQUIRES_CONFIRMATION)


class TestPinCommandValidation(unittest.TestCase):
    def setUp(self):
        self.ex = RemoteCommandExecutor(token_getter=lambda: "")

    def test_set_pin_missing(self):
        r = self.ex._validate({"command_type": "set_gui_pin", "params": {}})
        self.assertEqual(r, "missing_pin")

    def test_set_pin_non_digit(self):
        r = self.ex._validate({"command_type": "set_gui_pin",
                               "params": {"pin": "abcd12"}})
        self.assertEqual(r, "invalid_pin_format")

    def test_set_pin_too_short(self):
        r = self.ex._validate({"command_type": "set_gui_pin",
                               "params": {"pin": "123"}})
        self.assertEqual(r, "invalid_pin_format")

    def test_set_pin_too_long(self):
        r = self.ex._validate({"command_type": "set_gui_pin",
                               "params": {"pin": "1" * 13}})
        self.assertEqual(r, "invalid_pin_format")

    def test_set_pin_valid(self):
        r = self.ex._validate({"command_type": "set_gui_pin",
                               "params": {"pin": "12345678"}})
        self.assertIsNone(r)

    def test_clear_pin_valid(self):
        r = self.ex._validate({"command_type": "clear_gui_pin", "params": {}})
        self.assertIsNone(r)


class TestPinCommandExecution(unittest.TestCase):
    def setUp(self):
        self.ex = RemoteCommandExecutor(token_getter=lambda: "")

    def test_set_then_clear_pin(self):
        with _TempPinStore():
            res = self.ex._cmd_set_gui_pin({"pin": "246810"})
            self.assertTrue(res["success"], res)
            # PIN value must never leak into the result payload
            self.assertNotIn("246810", str(res))

            lock = GuiLock.instance()
            self.assertTrue(lock.has_pin())
            ok, _ = lock.verify_pin("246810", unlock_on_success=False)
            self.assertTrue(ok)

            res = self.ex._cmd_clear_gui_pin({})
            self.assertTrue(res["success"], res)
            self.assertFalse(lock.has_pin())

    def test_set_pin_invalid_rejected_by_lock(self):
        with _TempPinStore():
            res = self.ex._cmd_set_gui_pin({"pin": "12ab"})
            self.assertFalse(res["success"])


class TestGuiLockExternalReload(unittest.TestCase):
    """GUI process must pick up daemon-written PIN changes via file mtime."""

    def test_external_change_forces_relock(self):
        with _TempPinStore():
            lock = GuiLock.instance()
            lock.set_pin("111111")
            self.assertTrue(lock.is_session_unlocked())

            # Simulate the daemon (another process) overwriting the store
            other = GuiLock()
            other.set_pin("222222", source="dashboard")
            path = client_gui_lock._lock_path()
            os.utime(path, (os.path.getmtime(path) + 5,) * 2)

            # Old PIN no longer verifies; session forced to re-auth
            ok, _ = lock.verify_pin("111111", unlock_on_success=False)
            self.assertFalse(ok)
            ok, _ = lock.verify_pin("222222", unlock_on_success=False)
            self.assertTrue(ok)

    def test_external_clear_detected(self):
        with _TempPinStore():
            lock = GuiLock.instance()
            lock.set_pin("333333")
            self.assertTrue(lock.has_pin())

            os.remove(client_gui_lock._lock_path())
            self.assertFalse(lock.has_pin())


if __name__ == "__main__":
    unittest.main()
