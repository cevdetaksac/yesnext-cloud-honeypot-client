#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lifecycle hygiene §8 — no double POST / gui_quit thrash."""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import client_lifecycle as lc


class TestLifecycleDedupe(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        lc._MACHINE_DIR = self._td.name
        lc.LIFECYCLE_LOG = os.path.join(self._td.name, "lifecycle.log")
        lc.LIFECYCLE_QUEUE = os.path.join(self._td.name, "lifecycle_queue.jsonl")
        lc._last_emit_key = None
        lc._last_emit_mono = 0.0
        lc._last_gui_quit_mono = 0.0

    def tearDown(self):
        self._td.cleanup()

    def test_same_second_dedupe(self):
        a = lc.emit("client_startup", "a")
        b = lc.emit("client_startup", "b")
        self.assertIsNotNone(a)
        self.assertIsNone(b)

    def test_gui_quit_rate_limit(self):
        a = lc.emit("gui_quit", "1")
        b = lc.emit("gui_quit", "2")
        self.assertIsNotNone(a)
        self.assertIsNone(b)

    def test_report_now_no_double_flush_post(self):
        posts = []

        class API:
            def report_lifecycle_event(self, token, event):
                posts.append(dict(event))
                return True

        with mock.patch.object(lc, "load_token", return_value="t"):
            ok = lc.report_now(
                "client_startup", "app_init", {},
                api_client=API(), token="t",
            )
        self.assertTrue(ok)
        self.assertEqual(len(posts), 1)
        # Queue copy dropped — flush would be empty
        self.assertFalse(os.path.isfile(lc.LIFECYCLE_QUEUE) and
                         os.path.getsize(lc.LIFECYCLE_QUEUE) > 0)


if __name__ == "__main__":
    unittest.main()
