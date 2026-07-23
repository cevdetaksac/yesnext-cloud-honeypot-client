#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""System Recovery allowlist — contract 1.4.13."""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import client_system_recovery as sr


class TestDiffAndPlan(unittest.TestCase):
    def test_policy_bad_detected(self):
        live = {
            "policies": {
                "policy.taskmgr": {
                    "value": 1, "healthy": 0, "hive": "HKCU",
                    "key": r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                    "name": "DisableTaskMgr", "group": "policy",
                }
            },
            "services": {},
            "firewall": {"domain": "on", "private": "on", "public": "on"},
        }
        baseline = {"policies": {}, "services": {}, "firewall": {}}
        changes = sr.diff_against(baseline=baseline, live=live)
        ids = {c["id"] for c in changes}
        self.assertIn("policy.taskmgr", ids)

    def test_plan_includes_reg_set(self):
        with mock.patch.object(sr, "diff_against", return_value=[{
            "id": "policy.taskmgr",
            "group": "policy",
            "kind": "reg",
            "hive": "HKCU",
            "key": r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "name": "DisableTaskMgr",
            "from": 0,
            "to": 1,
        }]):
            plan = sr.plan_restore(targets=["policy"])
        self.assertEqual(plan[0]["action"], "reg_set")
        self.assertEqual(plan[0]["to"], 0)

    def test_firewall_off_detected(self):
        live = {
            "policies": {},
            "services": {},
            "firewall": {"domain": "on", "private": "off", "public": "on"},
        }
        changes = sr.diff_against(baseline={}, live=live)
        self.assertTrue(any(c["id"] == "firewall.private" for c in changes))

    def test_severity_escalates(self):
        changes = [
            {"id": "policy.taskmgr", "group": "policy"},
            {"id": "policy.regedit", "group": "policy"},
            {"id": "firewall.public", "group": "firewall"},
        ]
        sev, score = sr.classify_drift_severity(changes)
        self.assertEqual(sev, "high")
        self.assertGreaterEqual(score, 70)

    def test_commands_registered(self):
        from client_remote_commands import (
            ALLOWED_COMMANDS, REQUIRES_CONFIRMATION,
            system_recovery_restore_requires_confirm,
        )
        for c in (
            "system_recovery_snapshot",
            "list_system_recovery",
            "system_recovery_diff",
            "system_recovery_restore",
        ):
            self.assertIn(c, ALLOWED_COMMANDS)
        self.assertIn("system_recovery_restore", REQUIRES_CONFIRMATION)
        self.assertFalse(
            system_recovery_restore_requires_confirm({"dry_run": True})
        )
        self.assertTrue(system_recovery_restore_requires_confirm({}))


class TestSnapshotSign(unittest.TestCase):
    def test_roundtrip_sign(self):
        with tempfile.TemporaryDirectory() as d:
            sr.MACHINE_DATA_DIR = d
            sr.SNAPSHOT_FILE = os.path.join(d, "system_recovery.json")
            sr.SNAPSHOT_HISTORY_DIR = os.path.join(d, "hist")
            sr.TOKEN_FILE = os.path.join(d, "token.dat")
            with open(sr.TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write("test-token")
            with mock.patch.object(sr, "capture_live", return_value={
                "policies": {},
                "services": {},
                "firewall": {"domain": "on", "private": "on", "public": "on"},
                "captured_at": "2026-07-23T12:00:00Z",
            }):
                saved = sr.save_snapshot()
            self.assertTrue(sr.verify_snapshot(saved))
            self.assertEqual(saved["version"], 1)


class TestHkcuInteractive(unittest.TestCase):
    def test_read_prefers_bad_across_sids(self):
        with mock.patch.object(sr, "_interactive_user_sids", return_value=["S-1-5-21-1", "S-1-5-21-2"]):
            with mock.patch.object(sr, "_read_dword_at") as rd:
                def _side(root, subkey, name):
                    if "S-1-5-21-1" in subkey:
                        return 0
                    if "S-1-5-21-2" in subkey:
                        return 1
                    return None
                rd.side_effect = _side
                self.assertEqual(
                    sr.read_reg_dword(
                        "HKCU",
                        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                        "DisableTaskMgr",
                    ),
                    1,
                )

    def test_write_fans_out_to_sids(self):
        with mock.patch.object(sr, "_interactive_user_sids", return_value=["S-1-5-21-9"]):
            with mock.patch.object(sr, "_write_dword_at", return_value=True) as wr:
                ok = sr.write_reg_dword(
                    "HKCU",
                    r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                    "DisableTaskMgr",
                    0,
                )
                self.assertTrue(ok)
                self.assertGreaterEqual(wr.call_count, 1)
                paths = [c.args[1] for c in wr.call_args_list]
                self.assertTrue(any("S-1-5-21-9" in p for p in paths))


if __name__ == "__main__":
    unittest.main()
