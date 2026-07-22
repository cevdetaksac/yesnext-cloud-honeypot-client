#!/usr/bin/env python3
"""RES-103/105/106 observe helpers."""

import os
import tempfile
import unittest
from datetime import datetime
from unittest import mock

import client_resilience_p1 as p1


class TestSignedHeartbeat(unittest.TestCase):
    def test_proof_is_deterministic_and_bound_to_status(self):
        kwargs = dict(
            hostname="SERVER-A",
            status="online",
            running=True,
            issued_at="2026-07-22T01:00:00.000000Z",
        )
        first = p1.make_heartbeat_proof("token", **kwargs)
        second = p1.make_heartbeat_proof("token", **kwargs)
        self.assertEqual(first["signature"], second["signature"])
        changed = p1.make_heartbeat_proof(
            "token", **{**kwargs, "status": "offline"}
        )
        self.assertNotEqual(first["signature"], changed["signature"])
        self.assertFalse(first["enforce"])

    def test_candidate_is_default_off(self):
        with mock.patch.object(p1, "heartbeat_observe_enabled", return_value=False):
            self.assertIsNone(p1.build_heartbeat_observe(
                "token", hostname="host", status="online", running=True
            ))

    def test_verify_accepts_valid_and_rejects_tamper_or_stale(self):
        issued = "2026-07-22T01:00:00.000000Z"
        proof = p1.make_heartbeat_proof(
            "token",
            hostname="SERVER-A",
            status="online",
            running=True,
            issued_at=issued,
        )
        now = datetime.fromisoformat("2026-07-22T01:01:00+00:00")
        ok = p1.verify_heartbeat_proof(
            "token",
            proof,
            hostname="SERVER-A",
            status="online",
            running=True,
            max_age_sec=300,
            now=now,
        )
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["reason"], "ok")
        self.assertFalse(ok["enforce"])

        bad = dict(proof)
        bad["signature"] = "0" * 64
        self.assertEqual(
            p1.verify_heartbeat_proof(
                "token",
                bad,
                hostname="SERVER-A",
                status="online",
                running=True,
                now=now,
            )["reason"],
            "bad_signature",
        )

        stale_now = datetime.fromisoformat("2026-07-22T02:00:00+00:00")
        self.assertEqual(
            p1.verify_heartbeat_proof(
                "token",
                proof,
                hostname="SERVER-A",
                status="online",
                running=True,
                max_age_sec=300,
                now=stale_now,
            )["reason"],
            "stale",
        )


class TestAclDrift(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.baseline = os.path.join(self.tmp.name, "baseline.json")

    @staticmethod
    def entries(acl_hash="a"):
        return [{
            "path_hash": "p1",
            "exists": True,
            "acl_hash": acl_hash,
            "readable": True,
        }]

    def test_baseline_hmac_rejects_tamper(self):
        self.assertTrue(p1.save_acl_baseline(
            "token", self.entries(), path=self.baseline
        ))
        self.assertIsNotNone(p1.load_acl_baseline(
            "token", path=self.baseline
        ))
        self.assertIsNone(p1.load_acl_baseline(
            "wrong-token", path=self.baseline
        ))

    def test_drift_summary_never_contains_raw_acl(self):
        with mock.patch.object(p1, "acl_drift_enabled", return_value=True), \
                mock.patch.object(
                    p1, "collect_acl_fingerprints",
                    side_effect=[self.entries("a"), self.entries("b")],
                ):
            created = p1.acl_drift_status(
                "token", paths=["x"], baseline_path=self.baseline
            )
            drifted = p1.acl_drift_status(
                "token", paths=["x"], baseline_path=self.baseline
            )
        self.assertEqual(created["status"], "baseline_created")
        self.assertEqual(drifted["status"], "degraded")
        self.assertEqual(drifted["changed"], 1)
        serialized = str(drifted).lower()
        self.assertNotIn("principal", serialized)
        self.assertNotIn("acl_hash", serialized)
        self.assertFalse(drifted["enforce"])

    def test_disabled_does_not_create_baseline(self):
        with mock.patch.object(p1, "acl_drift_enabled", return_value=False), \
                mock.patch.object(p1, "collect_acl_fingerprints",
                                  return_value=self.entries()):
            status = p1.acl_drift_status(
                "token", paths=["x"], baseline_path=self.baseline
            )
        self.assertEqual(status["status"], "disabled")
        self.assertFalse(os.path.exists(self.baseline))


if __name__ == "__main__":
    unittest.main()
