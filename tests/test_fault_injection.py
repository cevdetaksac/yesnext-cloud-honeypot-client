#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QA-001 — fault-injection harness for resilience/recovery paths.

Simulates motor/Guardian failures, restart storms, backoff windows and
legitimate stand-downs *without* SCM, a live service or real processes. The
harness drives the same public API the production recovery loops use so the
storm breaker and stand-down invariants are exercised deterministically.

Invariants asserted:
- recovery is deferred (not abandoned) while backoff is pending;
- recovery becomes allowed again once the backoff window elapses;
- a restart storm never permanently blocks recovery;
- a legitimate stand-down suppresses recovery and clears the storm flag;
- Guardian self-heal respects the same storm breaker and never loops unbounded.
"""

import os
import tempfile
import time
import unittest
from unittest import mock

import client_resilience as resilience


class _ResilienceHarness(unittest.TestCase):
    """Base class: isolated on-disk state + compressed backoff/storm knobs."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        state_path = os.path.join(self._tmpdir.name, "resilience_state.json")
        patches = [
            mock.patch.object(resilience, "STATE_FILE", state_path),
            mock.patch.object(resilience, "STORM_WINDOW_SEC", 60),
            mock.patch.object(resilience, "STORM_THRESHOLD", 3),
            mock.patch.object(resilience, "RECOVERY_BACKOFF_SEC", [1, 2, 4, 8, 16]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with resilience._lock:
            resilience._state = {
                "version": "test",
                "daemon_restarts": [],
                "guardian_restarts": [],
                "last_recovery_ms": 0,
                "last_recovery_leg": "",
                "last_recovery_ok": False,
                "restart_storm": False,
                "stand_down_reason": "",
                "binary_integrity": "unknown",
                "guardian_exit_code": None,
            }


class TestMotorRecoveryFaultInjection(_ResilienceHarness):
    def test_backoff_defers_then_reallows_after_window(self):
        base = time.time()
        # Inject 3 consecutive failed recoveries at t=base.
        with mock.patch.object(resilience, "_now", return_value=base):
            for _ in range(3):
                resilience.record_recovery_attempt("daemon", ok=False, duration_ms=5)
            allowed, wait = resilience.should_attempt_recovery("daemon")
        self.assertFalse(allowed, "recovery must be deferred while backoff pending")
        self.assertGreater(wait, 0)

        # Jump past the backoff window: recovery must be allowed again.
        with mock.patch.object(resilience, "_now", return_value=base + wait + 1):
            allowed_after, _ = resilience.should_attempt_recovery("daemon")
        self.assertTrue(allowed_after, "recovery must never be abandoned permanently")

    def test_storm_flag_does_not_block_forever(self):
        base = time.time()
        with mock.patch.object(resilience, "_now", return_value=base):
            for _ in range(5):
                resilience.record_recovery_attempt("daemon", ok=False, duration_ms=1)
            self.assertTrue(resilience.snapshot()["restart_storm"])
        # After the full storm window, old stamps prune and recovery reopens.
        with mock.patch.object(resilience, "_now", return_value=base + 61):
            allowed, _ = resilience.should_attempt_recovery("daemon")
            self.assertTrue(allowed)
            self.assertFalse(resilience.snapshot()["restart_storm"])

    def test_successful_recovery_records_metrics(self):
        resilience.record_recovery_attempt("daemon", ok=True, duration_ms=1840)
        snap = resilience.snapshot()
        self.assertEqual(snap["last_recovery_ms"], 1840)
        self.assertEqual(snap["last_recovery_leg"], "daemon")
        self.assertTrue(snap["last_recovery_ok"])
        self.assertEqual(snap["daemon_restarts_24h"], 1)


class TestStandDownFaultInjection(_ResilienceHarness):
    def test_stand_down_suppresses_daemon_recovery(self):
        import client_daemon_ipc as ipc

        logs = []
        with mock.patch.object(ipc, "is_motor_healthy", return_value=False), \
                mock.patch("client_resilience.is_legitimate_stand_down",
                           return_value=True):
            ok = ipc.ensure_daemon_running(log_func=logs.append, wait_sec=1.0)
        self.assertFalse(ok)
        self.assertTrue(any("stand-down" in ln.lower() for ln in logs))
        # Stand-down must have been recorded and normalized to the enum.
        self.assertEqual(resilience.snapshot()["stand_down_reason"], "update")

    def test_stand_down_clears_active_storm(self):
        base = time.time()
        with mock.patch.object(resilience, "_now", return_value=base):
            for _ in range(4):
                resilience.record_recovery_attempt("daemon", ok=False, duration_ms=1)
            self.assertTrue(resilience.snapshot()["restart_storm"])
            resilience.note_stand_down("operator_pin")
            snap = resilience.snapshot()
        self.assertFalse(snap["restart_storm"])
        self.assertEqual(snap["stand_down_reason"], "operator_pin")


class TestGuardianSelfHealFaultInjection(_ResilienceHarness):
    """Patch the guardian service surface with individually-tracked mocks."""

    def _patch_guardian(self, *, running, installed=True, ensure_ok=False):
        self._ensure_mock = mock.Mock(return_value=ensure_ok)
        patches = [
            mock.patch("client_guardian_service.is_guardian_service_running",
                       return_value=running),
            mock.patch("client_guardian_service.is_guardian_service_installed",
                       return_value=installed),
            mock.patch("client_guardian_service.ensure_guardian_service_running",
                       self._ensure_mock),
            mock.patch.object(resilience, "refresh_guardian_exit_code",
                              return_value=1),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_installed_but_not_running_heals_then_defers(self):
        base = time.time()
        with mock.patch("client_resilience.is_legitimate_stand_down",
                        return_value=False):
            self._patch_guardian(running=False, ensure_ok=False)
            with mock.patch.object(resilience, "_now", return_value=base):
                # First heal runs ensure(); it fails → backoff arms.
                first = resilience.ensure_guardian_with_backoff()
                # Within the backoff window further heals must defer, not spin.
                deferred = [resilience.ensure_guardian_with_backoff() for _ in range(3)]
            # After the backoff window a fresh heal is allowed again.
            with mock.patch.object(resilience, "_now", return_value=base + 30):
                reopened = resilience.ensure_guardian_with_backoff()
        self.assertFalse(first)
        self.assertTrue(all(r is False for r in deferred))
        self.assertFalse(reopened)
        # ensure() ran once in the first window and once after it reopened.
        self.assertEqual(self._ensure_mock.call_count, 2)

    def test_stand_down_skips_guardian_heal(self):
        with mock.patch("client_resilience.is_legitimate_stand_down",
                        return_value=True):
            self._patch_guardian(running=False)
            ok = resilience.ensure_guardian_with_backoff()
        self.assertTrue(ok, "stand-down returns True (intentional no-op)")
        self._ensure_mock.assert_not_called()

    def test_already_running_guardian_is_noop(self):
        with mock.patch("client_resilience.is_legitimate_stand_down",
                        return_value=False):
            self._patch_guardian(running=True)
            ok = resilience.ensure_guardian_with_backoff()
        self.assertTrue(ok)
        self._ensure_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
