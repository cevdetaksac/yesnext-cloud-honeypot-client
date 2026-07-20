#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for update UI banner reconcile / clear."""

import json
import os
import tempfile
import unittest
from unittest import mock

import client_update_ui as uui


class TestReconcileFailedBanner(unittest.TestCase):
    def setUp(self):
        self._tdir = tempfile.mkdtemp()
        self._path = os.path.join(self._tdir, "update_ui_status.json")
        self._patcher = mock.patch.object(uui, "_status_path", return_value=self._path)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        try:
            if os.path.isfile(self._path):
                os.remove(self._path)
            os.rmdir(self._tdir)
        except OSError:
            pass

    def _write(self, payload: dict):
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

    def test_clears_obsolete_failed_when_newer(self):
        self._write({
            "phase": "failed",
            "from_version": "4.5.43",
            "to_version": "4.5.45",
            "error": "install_did_not_complete",
            "updated_at": 1.0,
            "phase_started_at": 1.0,
        })
        st = uui.get_update_ui_status(current_version="4.5.49")
        self.assertIsNone(st)
        self.assertFalse(os.path.isfile(self._path))

    def test_keeps_failed_if_still_behind_target(self):
        self._write({
            "phase": "failed",
            "from_version": "4.5.49",
            "to_version": "4.5.50",
            "error": "install_did_not_complete",
            "updated_at": 9999999999.0,
            "phase_started_at": 9999999999.0,
        })
        st = uui.get_update_ui_status(current_version="4.5.49", max_age_sec=1e12)
        self.assertIsNotNone(st)
        self.assertEqual(st.get("phase"), "failed")


if __name__ == "__main__":
    unittest.main()
