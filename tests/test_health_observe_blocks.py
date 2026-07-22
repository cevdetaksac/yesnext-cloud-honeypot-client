"""Contract 1.4.5 observe-health blocks (additive; enforce always False).

Missing blocks mean legacy on the cloud side. These tests cover signing,
event-log/password_burst shape, and health/report assembly for promoted P1
fields.
"""

import unittest
from unittest import mock


class FakeExecutor:
    def __init__(self, stats):
        self._stats = stats

    def get_signing_health(self):
        from client_remote_commands import RemoteCommandExecutor
        return RemoteCommandExecutor.get_signing_health(self)


class TestCommandSigningHealth(unittest.TestCase):
    def test_observe_block_shape_and_enforce_off(self):
        ex = FakeExecutor({
            "signature_ok": 5,
            "signature_missing": 2,
            "signature_invalid": 0,
            "signature_no_token": 1,
            "signature_disabled": 0,
        })
        block = ex.get_signing_health()
        self.assertIn("observe", block)
        self.assertFalse(block["enforce"])
        self.assertEqual(block["ok"], 5)
        self.assertEqual(block["missing"], 2)
        self.assertEqual(block["invalid"], 0)
        self.assertEqual(block["no_token"], 1)
        self.assertEqual(block["last_error"], "")

    def test_missing_counters_default_to_zero(self):
        ex = FakeExecutor({})
        block = ex.get_signing_health()
        for k in ("ok", "missing", "invalid", "no_token", "disabled"):
            self.assertEqual(block[k], 0)


class TestEventLogHealth(unittest.TestCase):
    def test_health_block_has_no_raw_events_and_lists_ids(self):
        from client_eventlog import EventLogWatcher, WATCHED_CHANNELS

        watcher = EventLogWatcher.__new__(EventLogWatcher)
        watcher._running = False
        watcher._stats = {
            "events_processed": 3,
            "events_filtered": 1,
            "errors": 0,
            "channels_active": 1,
        }
        watcher.identity_correlator = None
        block = watcher.get_health()
        self.assertIn("watched_ids", block)
        self.assertNotIn("events", block)
        self.assertNotIn("raw_data", block)
        self.assertIn(4723, block["watched_ids"])
        self.assertIn(4724, block["watched_ids"])
        self.assertEqual(block["channels_total"], len(WATCHED_CHANNELS))
        burst = block["password_burst"]
        self.assertIsInstance(burst, dict)
        self.assertFalse(burst["auto_lockout"])
        self.assertEqual(burst["mode"], "observe")
        self.assertEqual(burst["events"], 0)


class TestHealthReportAssembly(unittest.TestCase):
    def test_promoted_p1_blocks_on_snapshot(self):
        from client_system_health import SystemHealthMonitor

        class _Api:
            def __init__(self):
                self.payload = None

            def api_request(self, method, path, data=None, **_kwargs):
                self.payload = data
                return {"status": "ok"}

        class _Shield:
            _running = True
            _vss_count = 1

            @staticmethod
            def get_stats():
                return {
                    "canary_alerts": 0,
                    "canary_coverage": {
                        "mode": "observe",
                        "configured": True,
                        "files_total": 2,
                        "files_intact": 2,
                        "files_missing": 0,
                        "roots_covered": 1,
                        "coverage_ok": True,
                    },
                }

            @staticmethod
            def get_quarantine():
                return {"active": False, "entries": []}

        class _SM:
            @staticmethod
            def get_deception_health():
                return [{
                    "service": "SSH",
                    "port": 22,
                    "status": "started",
                    "handler_limit": 48,
                    "handlers_rejected": 0,
                    "backlog": 0,
                    "rate_limit_per_ip_min": 10,
                    "resource_budgeted": True,
                    "protocol_aware": True,
                    "fingerprint_profile": "static_legacy",
                    "bypass_coverage_required": True,
                }]

        class _Etw:
            @staticmethod
            def status():
                return {
                    "available": False,
                    "provider_attached": False,
                    "mode": "shadow",
                    "source": "stub",
                    "fallback": "none",
                    "auto_containment": False,
                    "correlation": {
                        "mode": "shadow",
                        "auto_containment": False,
                        "candidates": [],
                        "candidate_count": 0,
                    },
                    "error": "etw consumer not attached (shadow stub)",
                }

        class _Watcher:
            def get_health(self):
                from client_identity_correlation import PasswordBurstCorrelator
                return {
                    "available": True,
                    "running": False,
                    "channels_active": 0,
                    "channels_total": 1,
                    "events_processed": 0,
                    "events_filtered": 0,
                    "errors": 0,
                    "watched_ids": [4723, 4724],
                    "password_burst": PasswordBurstCorrelator.idle_status(),
                }

        api = _Api()
        monitor = SystemHealthMonitor(
            api_client=api,
            token_getter=lambda: "tok",
            ransomware_shield=_Shield(),
        )
        monitor._latest = {"cpu_percent": 0}
        monitor.etw_shadow = _Etw()
        monitor.event_watcher = _Watcher()
        monitor.service_manager = _SM()
        monitor.remote_commands = FakeExecutor({})

        with mock.patch(
            "client_resilience_p1.acl_drift_enabled", return_value=True
        ), mock.patch(
            "client_resilience_p1.acl_drift_status",
            return_value={
                "observe": True,
                "enforce": False,
                "baseline_valid": True,
                "entries_checked": 1,
                "changed": 0,
                "missing": 0,
                "status": "healthy",
            },
        ), mock.patch(
            "client_device_identity.observe_enabled", return_value=True
        ), mock.patch(
            "client_device_identity.probe_tpm",
            return_value={
                "mode": "observe",
                "enrolled": False,
                "tpm_present": False,
                "tpm_ready": False,
                "attestation": "not_implemented",
                "reenrollment_required": False,
                "error": "tpm_unsupported",
            },
        ):
            self.assertTrue(monitor._send_report())

        snap = api.payload["snapshot"]
        self.assertEqual(snap["canary_coverage"]["files_total"], 2)
        self.assertEqual(snap["deception_health"][0]["fingerprint_profile"],
                         "static_legacy")
        self.assertEqual(snap["etw_shadow"]["source"], "stub")
        self.assertEqual(snap["etw_shadow"]["fallback"], "none")
        self.assertFalse(snap["etw_shadow"]["auto_containment"])
        self.assertIsInstance(snap["event_log_health"]["password_burst"], dict)
        self.assertFalse(snap["event_log_health"]["password_burst"]["auto_lockout"])
        self.assertFalse(snap["access_integrity"]["enforce"])
        self.assertEqual(snap["device_identity"]["mode"], "observe")
        self.assertFalse(snap["command_signing"]["enforce"])
        blob = str(snap["canary_coverage"]) + str(snap["access_integrity"])
        self.assertNotIn("C:\\", blob)
        self.assertNotIn("principal", blob.lower())


class TestNetworkRestoreConfirm(unittest.TestCase):
    def test_dry_run_does_not_require_confirm(self):
        from client_remote_commands import network_restore_requires_confirm
        self.assertFalse(network_restore_requires_confirm({"dry_run": True}))
        self.assertTrue(network_restore_requires_confirm({}))
        self.assertTrue(network_restore_requires_confirm({"dry_run": False}))


class TestGuardianHeartbeatObserve(unittest.TestCase):
    def test_disabled_by_default_and_never_enforces(self):
        from client_guardian_service import observe_motor_heartbeat_proof
        with mock.patch(
            "client_utils.get_from_config", return_value=False
        ):
            out = observe_motor_heartbeat_proof()
        self.assertFalse(out["checked"])
        self.assertFalse(out["enforce"])
        self.assertEqual(out["reason"], "disabled")


if __name__ == "__main__":
    unittest.main()
