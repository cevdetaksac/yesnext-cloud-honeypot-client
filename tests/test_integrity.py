#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REV-104 — runtime self-integrity verdict (observe only).

`invalid` must be reserved for present-but-broken signatures (tamper). Unsigned
dev/current fleet must report `unknown` so the observe field never false-alarms.
"""

import unittest
from unittest import mock

import client_integrity as integrity


class TestRuntimeIntegrity(unittest.TestCase):
    def test_source_run_reports_unknown_not_invalid(self):
        with mock.patch.object(integrity.sys, "frozen", False, create=True):
            info = integrity.evaluate_runtime_integrity()
        self.assertEqual(info["status"], "unknown")
        self.assertEqual(info["reason"], "not_frozen")

    def _frozen_win(self):
        return [
            mock.patch.object(integrity.sys, "frozen", True, create=True),
            mock.patch.object(integrity.sys, "platform", "win32"),
            mock.patch.object(integrity, "_running_binary_path",
                              return_value=r"C:\fake\honeypot-client.exe"),
            mock.patch("os.path.isfile", return_value=True),
        ]

    def _run_with(self, verify_return, required=False):
        patches = self._frozen_win()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with mock.patch("client_authenticode.verify_authenticode",
                        return_value=verify_return), \
                mock.patch("client_authenticode.authenticode_required",
                           return_value=required):
            return integrity.evaluate_runtime_integrity()

    def test_trusted_signature_is_valid(self):
        info = self._run_with({
            "signed": True, "trusted": True, "publisher": "CN=YesNext", "error": "",
        })
        self.assertEqual(info["status"], "valid")
        self.assertTrue(info["trusted"])

    def test_present_but_broken_signature_is_invalid(self):
        info = self._run_with({
            "signed": True, "trusted": False, "publisher": "CN=X",
            "error": "status=HashMismatch",
        })
        self.assertEqual(info["status"], "invalid")
        self.assertIn("HashMismatch", info["reason"])

    def test_unsigned_is_unknown_by_default(self):
        info = self._run_with({
            "signed": False, "trusted": False, "publisher": "", "error": "",
        })
        self.assertEqual(info["status"], "unknown")
        self.assertEqual(info["reason"], "unsigned")

    def test_unsigned_becomes_invalid_when_policy_requires(self):
        info = self._run_with({
            "signed": False, "trusted": False, "publisher": "", "error": "",
        }, required=True)
        self.assertEqual(info["status"], "invalid")

    def test_check_and_record_writes_binary_integrity(self):
        recorded = {}
        with mock.patch.object(integrity, "evaluate_runtime_integrity",
                               return_value={"status": "valid", "frozen": True,
                                             "signed": True, "reason": "ok"}), \
                mock.patch("client_resilience.set_binary_integrity",
                           side_effect=lambda v: recorded.setdefault("v", v)):
            info = integrity.check_and_record(log_result=False)
        self.assertEqual(info["status"], "valid")
        self.assertEqual(recorded["v"], "valid")

    def test_no_certificate_material_in_result(self):
        info = self._run_with({
            "signed": True, "trusted": True,
            "publisher": "CN=YesNext Technology, O=YesNext", "error": "",
        })
        # Only a bounded publisher subject is kept; no raw cert/thumbprint blob.
        self.assertLessEqual(len(info["publisher"]), 256)
        self.assertNotIn("thumbprint", info)
        self.assertNotIn("certificate", info)


if __name__ == "__main__":
    unittest.main()
