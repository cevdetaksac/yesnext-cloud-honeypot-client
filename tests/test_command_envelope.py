#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZT-601 — command envelope v2 scaffolding (design/observe only).

Guards the contract invariant: the client must not verify asymmetric operator
signatures or emit a production version:2 wire before the design gate promotes.
These tests pin the deterministic hash + classifier and the truthful, never-
enforce capability descriptor.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import client_command_envelope as env


def _valid_envelope(**overrides):
    base = {
        "version": 2,
        "tenant_id": "t-1",
        "device_id": "d-1",
        "command_id": "c-1",
        "command_type": "network_restore",
        "params_hash": env.params_hash({"a": 1}),
        "issued_at": "2026-07-22T00:00:00.000000Z",
        "expires_at": "2999-01-01T00:00:00.000000Z",
        "nonce": "bm9uY2U",
        "operator_id": "op-1",
        "key_id": "k-1",
        "policy_version": "p-1",
        "approvals": [],
        "signature": "c2ln",
    }
    base.update(overrides)
    return base


class TestParamsHash(unittest.TestCase):
    def test_hash_is_deterministic_and_order_independent(self):
        h1 = env.params_hash({"a": 1, "b": 2})
        h2 = env.params_hash({"b": 2, "a": 1})
        self.assertEqual(h1, h2)
        self.assertTrue(h1.startswith("sha256:"))
        self.assertEqual(len(h1.split(":", 1)[1]), 64)

    def test_empty_and_none_params_hash_equal(self):
        self.assertEqual(env.params_hash(None), env.params_hash({}))


class TestCapability(unittest.TestCase):
    def test_default_is_off(self):
        with mock.patch("client_utils.get_from_config", return_value="off"):
            self.assertEqual(env.capability(), env.CAPABILITY_OFF)

    def test_observe_opt_in(self):
        with mock.patch("client_utils.get_from_config", return_value="observe"):
            self.assertEqual(env.capability(), env.CAPABILITY_OBSERVE)

    def test_enforce_is_never_advertised(self):
        # Even if config is tampered to "enforce", client must not advertise it.
        with mock.patch("client_utils.get_from_config", return_value="enforce"):
            self.assertEqual(env.capability(), env.CAPABILITY_OFF)


class TestEnvelopeInspection(unittest.TestCase):
    def test_non_v2_is_not_v2(self):
        self.assertEqual(env.inspect_envelope_v2({"version": 1})["verdict"], "not_v2")

    def test_missing_required_field_is_malformed(self):
        bad = _valid_envelope()
        del bad["nonce"]
        self.assertEqual(env.inspect_envelope_v2(bad)["verdict"], "malformed")

    def test_expired_envelope(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        e = _valid_envelope(expires_at=past)
        self.assertEqual(env.inspect_envelope_v2(e)["verdict"], "expired")

    def test_params_mismatch(self):
        e = _valid_envelope(params_hash=env.params_hash({"a": 1}))
        out = env.inspect_envelope_v2(e, params={"a": 999})
        self.assertEqual(out["verdict"], "params_mismatch")
        self.assertFalse(out["params_match"])

    def test_structurally_valid_stays_unverified_without_key(self):
        e = _valid_envelope(params_hash=env.params_hash({"a": 1}))
        out = env.inspect_envelope_v2(e, params={"a": 1})
        # Contract invariant: no asymmetric verification / acceptance yet.
        self.assertEqual(out["verdict"], "unverified_no_key")
        self.assertTrue(out["params_match"])

    def test_module_exposes_no_verify_or_emit_api(self):
        # Guard against accidentally shipping production verify/emit surface.
        for forbidden in ("verify_signature", "emit_v2", "sign_envelope",
                          "accept_command"):
            self.assertFalse(hasattr(env, forbidden),
                             f"{forbidden} must not exist before contract gate")


if __name__ == "__main__":
    unittest.main()
