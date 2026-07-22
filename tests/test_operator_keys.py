#!/usr/bin/env python3
"""ZT-602/603 operator public-key metadata scaffolding."""

import unittest
from unittest import mock

from client_operator_keys import inspect_keyset


class TestOperatorKeyset(unittest.TestCase):
    def test_rotation_overlap_and_revocation(self):
        status = inspect_keyset({"keys": [
            {"key_id": "current", "algorithm": "ed25519",
             "public_key": "pub1", "state": "active"},
            {"key_id": "next", "algorithm": "ed25519",
             "public_key": "pub2", "state": "next"},
            {"key_id": "old", "algorithm": "ed25519",
             "public_key": "pub0", "state": "revoked"},
        ]})
        self.assertTrue(status["valid"])
        self.assertTrue(status["rotation_overlap"])
        self.assertEqual(status["revoked_keys"], 1)
        self.assertFalse(status["verify_enabled"])

    def test_private_material_is_rejected(self):
        status = inspect_keyset({"keys": [{
            "key_id": "bad", "algorithm": "ed25519",
            "public_key": "pub", "private_key": "secret", "state": "active",
        }]})
        self.assertFalse(status["valid"])
        self.assertTrue(status["private_material_rejected"])
        self.assertNotIn("secret", str(status))

    def test_unknown_algorithm_not_promoted(self):
        status = inspect_keyset({"keys": [{
            "key_id": "k", "algorithm": "rsa", "public_key": "pub",
            "state": "active",
        }]})
        self.assertFalse(status["valid"])
        self.assertIn("algorithm_not_promoted", status["errors"])

    def test_fetch_keyset_disabled_and_stub_safe(self):
        from client_operator_keys import fetch_keyset
        with mock.patch(
            "client_operator_keys.observe_enabled", return_value=False
        ):
            disabled = fetch_keyset(object(), "tok")
        self.assertFalse(disabled["verify_enabled"])
        self.assertIn("disabled", disabled["errors"])

        class _Api:
            def api_request(self, method, path, **_k):
                seen["path"] = path
                return {"verify_enabled": False, "keys": []}

        seen = {}
        with mock.patch(
            "client_operator_keys.observe_enabled", return_value=True
        ):
            stub = fetch_keyset(_Api(), "tok")
        self.assertEqual(seen["path"], "agent/operator-keys")
        self.assertTrue(stub["fetched"])
        self.assertFalse(stub["verify_enabled"])
        self.assertFalse(stub["valid"])


if __name__ == "__main__":
    unittest.main()
