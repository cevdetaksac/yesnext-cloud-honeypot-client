#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI singleton / handoff smoke tests (mutex names + helpers)."""

import unittest
import uuid
from unittest import mock


class TestGuiSingletonConstants(unittest.TestCase):
    def test_gui_mutex_is_local_session_scoped(self):
        from client_constants import GUI_MUTEX_NAME, GUI_SHOW_EVENT_NAME, DAEMON_MUTEX_NAME
        self.assertTrue(GUI_MUTEX_NAME.startswith("Local\\"))
        self.assertTrue(GUI_SHOW_EVENT_NAME.startswith("Local\\"))
        self.assertTrue(DAEMON_MUTEX_NAME.startswith("Global\\"))
        self.assertNotEqual(GUI_MUTEX_NAME, DAEMON_MUTEX_NAME)


class TestHandoffHelpers(unittest.TestCase):
    def test_signal_show_creates_named_event(self):
        import win32api
        import win32event
        import winerror
        from client_constants import GUI_SHOW_EVENT_NAME
        from client_instance import signal_existing_gui_show

        self.assertTrue(signal_existing_gui_show())
        # Event should be openable by name
        h = win32event.CreateEvent(None, False, False, GUI_SHOW_EVENT_NAME)
        self.assertIsNotNone(h)
        win32api.CloseHandle(h)

    def test_gui_mutex_exclusive(self):
        import win32api
        import win32event
        import client_instance as ci

        # Reset module globals for isolation
        if ci._GUI_MUTEX_HANDLE:
            try:
                win32api.CloseHandle(ci._GUI_MUTEX_HANDLE)
            except Exception:
                pass
            ci._GUI_MUTEX_HANDLE = None

        # Never contend with a real GUI that may be running on the developer's
        # desktop. The helper semantics are independent of the production name.
        test_mutex_name = f"Local\\CloudHoneypotGuiTest-{uuid.uuid4()}"
        with mock.patch.object(ci, "GUI_MUTEX_NAME", test_mutex_name):
            self.assertTrue(ci.try_acquire_gui_mutex())
            # Second acquire in the same process sees ALREADY_EXISTS because
            # the first handle is held.
            self.assertFalse(ci.try_acquire_gui_mutex())

        try:
            win32api.CloseHandle(ci._GUI_MUTEX_HANDLE)
        except Exception:
            pass
        ci._GUI_MUTEX_HANDLE = None


if __name__ == "__main__":
    unittest.main()
