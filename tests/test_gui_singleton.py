#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI singleton / handoff smoke tests (mutex names + helpers)."""

import unittest
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
        import winerror
        from client_constants import GUI_MUTEX_NAME
        import client_instance as ci

        # Reset module globals for isolation
        if ci._GUI_MUTEX_HANDLE:
            try:
                win32api.CloseHandle(ci._GUI_MUTEX_HANDLE)
            except Exception:
                pass
            ci._GUI_MUTEX_HANDLE = None

        self.assertTrue(ci.try_acquire_gui_mutex())
        # Second acquire in same process still sees ALREADY_EXISTS on CreateMutex
        # because first handle is held — try_acquire should return False
        self.assertFalse(ci.try_acquire_gui_mutex())

        try:
            win32api.CloseHandle(ci._GUI_MUTEX_HANDLE)
        except Exception:
            pass
        ci._GUI_MUTEX_HANDLE = None


if __name__ == "__main__":
    unittest.main()
