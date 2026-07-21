#!/usr/bin/env python3
"""ID-402/403 password burst observe correlation."""

import unittest
from unittest import mock

from client_identity_correlation import PasswordBurstCorrelator


class TestPasswordBurstCorrelator(unittest.TestCase):
    def test_irrelevant_events_ignored(self):
        correlator = PasswordBurstCorrelator(threshold=3)
        correlator.record({"event_type": "logon_success"})
        self.assertEqual(correlator.status()["events"], 0)

    def test_burst_detected_without_auto_lockout(self):
        correlator = PasswordBurstCorrelator(window_sec=300, threshold=3)
        for idx in range(3):
            correlator.record({
                "event_type": "password_reset_attempt",
                "actor_username": "admin",
                "username": f"user{idx}",
                "result": "success",
                "event_id": 4724,
                "password": "must-not-be-retained",
                "raw_data": {"Secret": "must-not-be-retained"},
            })
        status = correlator.status()
        self.assertTrue(status["burst_detected"])
        self.assertFalse(status["auto_lockout"])
        self.assertEqual(status["unique_targets"], 3)
        self.assertNotIn("password", str(status).lower())
        self.assertNotIn("must-not-be-retained", str(status))

    def test_old_events_expire(self):
        correlator = PasswordBurstCorrelator(window_sec=30, threshold=2)
        with mock.patch("client_identity_correlation.time.time", return_value=100.0):
            correlator.record({
                "event_type": "password_change_attempt",
                "actor_username": "a", "username": "u", "event_id": 4723,
            })
        with mock.patch("client_identity_correlation.time.time", return_value=131.0):
            status = correlator.status()
        self.assertEqual(status["events"], 0)
        self.assertFalse(status["burst_detected"])


if __name__ == "__main__":
    unittest.main()
