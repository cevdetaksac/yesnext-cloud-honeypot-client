# -*- coding: utf-8 -*-
"""Defense Policy P0 — matrix, signed cache, anti-bait, allowlist (client ≥4.9.16)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

import client_defense_policy as dp


class TestDefensePolicyMatrix(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self._patchers = [
            mock.patch.object(dp, "MACHINE_DATA_DIR", self._td.name),
            mock.patch.object(
                dp, "POLICY_FILE", os.path.join(self._td.name, "defense_policy.json")
            ),
            mock.patch.object(
                dp,
                "POLICY_LKG_FILE",
                os.path.join(self._td.name, "defense_policy.lkg.json"),
            ),
            mock.patch.object(
                dp,
                "ALLOWLIST_FILE",
                os.path.join(self._td.name, "defense_allowlist.json"),
            ),
            mock.patch.object(
                dp, "SNAPSHOT_DIR", os.path.join(self._td.name, "snaps")
            ),
            mock.patch.object(
                dp, "TOKEN_FILE", os.path.join(self._td.name, "token.dat")
            ),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)
        with open(dp.TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write("test-token-abc")
        # Reset module state
        with dp._lock:
            dp._state.update({
                "policy_name": "balanced",
                "policy_version": "",
                "isolate_armed": False,
                "rules": dict(dp.PRESET_RULES["balanced"]),
                "sig_ok": True,
                "source": "test",
                "updated_at": "",
                "tamper_alerted": False,
            })
            dp._allowlist = {"entries": []}
            dp._snapshot_last.clear()
        dp.set_tamper_alert_callback(None)

    def test_balanced_defaults_kill_canary_no_isolate(self):
        dp.apply_from_config({
            "protection": {
                "defense_policy": "balanced",
                "defense_rules": dict(dp.PRESET_RULES["balanced"]),
            }
        })
        plan = dp.process_action_plan("canary_write")
        self.assertEqual(plan["action"], "kill_quarantine")
        self.assertTrue(plan["kill"])
        self.assertFalse(plan["isolate_network"])
        self.assertFalse(dp.allows_network_isolate())

    def test_fresh_hydrate_is_observe(self):
        st = dp.hydrate_from_disk()
        self.assertEqual(st["policy_name"], "observe")
        self.assertEqual(dp.process_action_plan("canary_write")["action"], "alert_only")
        self.assertTrue(st.get("observe_auto_promote_enabled"))
        self.assertEqual(int(st.get("observe_auto_promote_days") or 0), 3)

    def test_auto_promote_observe_to_balanced(self):
        dp.apply_from_config({
            "protection": {
                "defense_policy": "observe",
                "observe_started_at": "2020-01-01T00:00:00Z",
                "observe_auto_promote_days": 3,
                "observe_auto_promote_enabled": True,
                "defense_policy_locked": False,
                "defense_rules": dict(dp.PRESET_RULES["observe"]),
            }
        })
        self.assertTrue(dp.promote_due_info().get("due"))
        st = dp.maybe_auto_promote()
        self.assertEqual(st["policy_name"], "balanced")
        self.assertEqual(dp.process_action_plan("canary_write")["action"], "kill_quarantine")
        self.assertFalse(dp.allows_network_isolate())

    def test_resign_on_token_race_not_tamper(self):
        # Write a structurally valid cache with a wrong sig
        payload = dp.build_effective(
            policy_name="observe",
            rules=dp.PRESET_RULES["observe"],
            observe_started_at="2026-07-23T00:00:00Z",
        )
        payload["sig"] = "00" * 32
        with open(dp.POLICY_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        st = dp.hydrate_from_disk()
        self.assertEqual(st["policy_name"], "observe")
        self.assertEqual(st["source"], "programdata_resign")
        self.assertTrue(st["sig_ok"])
        self.assertTrue(dp.verify_payload(dp._read_json(dp.POLICY_FILE)))


    def test_observe_alert_only_canary(self):
        dp.apply_from_config({
            "protection": {
                "defense_policy": "observe",
                "defense_policy_version": "1.4.18-def-3",
                "defense_rules": dict(dp.PRESET_RULES["observe"]),
            }
        })
        plan = dp.process_action_plan("canary_write")
        self.assertEqual(plan["action"], "alert_only")
        self.assertTrue(plan["alert_only"])
        self.assertFalse(plan["contain"])

    def test_strip_auto_isolate_on_balanced(self):
        st = dp.apply_from_config({
            "protection": {
                "defense_policy": "balanced",
                "defense_rules": {
                    "canary_write": "auto_isolate_network",
                    "vss_deletion": "kill_quarantine",
                },
            }
        })
        self.assertEqual(st["rules"]["canary_write"], "kill_quarantine")
        self.assertNotIn("auto_isolate_network", st["rules"].values())

    def test_paranoid_unarmed_strips_isolate(self):
        st = dp.apply_from_config({
            "protection": {
                "defense_policy": "paranoid",
                "isolate_armed": False,
                "defense_rules": {
                    **dp.PRESET_RULES["paranoid"],
                    "canary_write": "auto_isolate_network",
                },
            }
        })
        self.assertNotEqual(st["rules"]["canary_write"], "auto_isolate_network")
        self.assertFalse(dp.allows_network_isolate())

    def test_signed_cache_roundtrip(self):
        dp.apply_from_config({
            "protection": {
                "defense_policy": "balanced",
                "defense_policy_version": "v1",
                "defense_rules": dp.PRESET_RULES["balanced"],
            }
        })
        self.assertTrue(os.path.isfile(dp.POLICY_FILE))
        with open(dp.POLICY_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self.assertTrue(dp.verify_payload(raw))
        st = dp.hydrate_from_disk()
        self.assertEqual(st["policy_version"], "v1")
        self.assertTrue(st["sig_ok"])

    def test_tamper_falls_to_lkg_or_observe_no_isolate(self):
        dp.apply_from_config({
            "protection": {
                "defense_policy": "balanced",
                "defense_policy_version": "good",
                "defense_rules": dp.PRESET_RULES["balanced"],
            }
        })
        # Promote LKG by applying again
        dp.apply_from_config({
            "protection": {
                "defense_policy": "balanced",
                "defense_policy_version": "good2",
                "defense_rules": dp.PRESET_RULES["balanced"],
            }
        })
        # Corrupt cache
        with open(dp.POLICY_FILE, "w", encoding="utf-8") as f:
            f.write('{"policy_name":"paranoid","isolate_armed":true,"sig":"bad"}')
        alerts = []
        dp.set_tamper_alert_callback(lambda a: alerts.append(a))
        st = dp.hydrate_from_disk()
        self.assertIn(st["source"], ("tamper_lkg", "tamper_observe"))
        self.assertFalse(st.get("isolate_armed"))
        self.assertFalse(dp.allows_network_isolate())
        self.assertTrue(alerts)
        self.assertEqual(alerts[0]["threat_type"], "defense_policy_tamper")
        self.assertFalse(alerts[0]["details"].get("isolate"))

    def test_cloud_bad_sig_fail_safe(self):
        # Foreign/invalid defense sig must NOT escalate to tamper_observe
        st = dp.apply_from_config({
            "protection": {
                "defense_policy": "balanced",
                "defense_policy_version": "v1",
                "defense_rules": dp.PRESET_RULES["balanced"],
                "defense_rules_sig": "deadbeef" * 8,
            }
        })
        self.assertEqual(st["policy_name"], "balanced")
        self.assertIn("unsigned", st.get("source") or "")
        self.assertTrue(st.get("sig_ok"))
        self.assertFalse(dp.allows_network_isolate())

    def test_allow_process_skips_match(self):
        r = dp.allow_process(
            path=r"C:\Tools\backup.exe",
            image="backup.exe",
            sha256="abc123",
            reason="unit",
        )
        self.assertTrue(r["success"])
        self.assertTrue(
            dp.is_process_allowed(path=r"C:\Tools\backup.exe", image="backup.exe")
        )
        self.assertTrue(dp.is_process_allowed(sha256="ABC123"))
        self.assertFalse(dp.is_process_allowed(image="evil.exe"))

    def test_protected_image_hard_deny(self):
        self.assertTrue(dp.is_protected_image("lsass.exe"))
        self.assertTrue(dp.is_protected_image("services.exe"))
        bad = dp.allow_process(image="lsass.exe")
        self.assertFalse(bad["success"])

    def test_high_io_never_kill(self):
        st = dp.apply_from_config({
            "protection": {
                "defense_policy": "paranoid",
                "isolate_armed": True,
                "defense_rules": {"high_io_rate": "kill_quarantine"},
            }
        })
        self.assertEqual(st["rules"]["high_io_rate"], "alert_only")

    def test_reject_isolate_command_helper(self):
        dp.apply_from_config({
            "protection": {"defense_policy": "balanced"}
        })
        rej = dp.reject_auto_isolate()
        self.assertFalse(rej["success"])
        self.assertEqual(rej["error"], "isolate_rejected_policy")

    def test_snapshot_dedupe(self):
        calls = []

        def fake_capture(path, **_kw):
            calls.append(path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(b"\xff\xd8\xfffake")
            return True

        with mock.patch(
            "client_remote_desktop.capture_once_to_file", side_effect=fake_capture
        ):
            a1 = {}
            m1 = dp.maybe_capture_session_snapshot("canary_write", alert_attach=a1)
            m2 = dp.maybe_capture_session_snapshot("canary_write", alert_attach={})
            self.assertIsNotNone(m1)
            self.assertIsNone(m2)  # dedupe
            self.assertEqual(len(calls), 1)
            self.assertIn("session_snapshot", a1.get("system_context") or {})


class TestAllowProcessCommand(unittest.TestCase):
    def test_catalog(self):
        from client_remote_commands import (
            ALLOWED_COMMANDS,
            REQUIRES_CONFIRMATION,
            RemoteCommandExecutor,
        )
        self.assertIn("allow_process", ALLOWED_COMMANDS)
        self.assertIn("allow_process", REQUIRES_CONFIRMATION)
        self.assertIn("isolate_host", ALLOWED_COMMANDS)
        self.assertIn("isolate_host", REQUIRES_CONFIRMATION)
        ex = RemoteCommandExecutor()
        with mock.patch(
            "client_defense_policy.allow_process",
            return_value={"success": True, "message": "allowed", "data": {}},
        ):
            r = ex._cmd_allow_process({
                "path": r"C:\a.exe",
                "image": "a.exe",
            })
        self.assertTrue(r["success"])

    def test_isolate_rejected_on_balanced(self):
        from client_remote_commands import RemoteCommandExecutor
        with mock.patch("client_defense_policy.allows_network_isolate", return_value=False):
            r = RemoteCommandExecutor()._cmd_isolate_host({})
        self.assertFalse(r["success"])
        self.assertEqual(r["error"], "isolate_rejected_policy")


if __name__ == "__main__":
    unittest.main()
