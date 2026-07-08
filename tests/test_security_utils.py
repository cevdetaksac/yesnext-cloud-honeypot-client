#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for security utilities."""

import unittest

from client_security_utils import (
    redact_sensitive,
    sign_command,
    verify_command_signature,
)


class TestRedactSensitive(unittest.TestCase):
    def test_masks_token_key(self):
        out = redact_sensitive({"token": "0ea8836b-56e2-4f87-b6e4-9fa250199715"})
        self.assertNotIn("0ea8836b-56e2", out["token"])
        self.assertIn("…", out["token"])

    def test_masks_password(self):
        out = redact_sensitive({"username": "admin", "password": "secret123"})
        self.assertEqual(out["username"], "admin")
        self.assertNotEqual(out["password"], "secret123")

    def test_uuid_in_string(self):
        s = "token=0ea8836b-56e2-4f87-b6e4-9fa250199715 done"
        out = redact_sensitive(s)
        self.assertNotIn("0ea8836b-56e2-4f87-b6e4-9fa250199715", out)


class TestCommandSigning(unittest.TestCase):
    def test_sign_and_verify(self):
        token = "test-token-uuid"
        cmd = {
            "id": "cmd-1",
            "type": "block_ip",
            "issued_at": "2026-07-08T12:00:00+00:00",
            "signature": sign_command(token, "cmd-1", "block_ip", "2026-07-08T12:00:00+00:00"),
        }
        self.assertTrue(verify_command_signature(token, cmd))

    def test_reject_tampered(self):
        token = "test-token"
        cmd = {
            "id": "cmd-1",
            "type": "block_ip",
            "issued_at": "2026-07-08T12:00:00+00:00",
            "signature": "deadbeef",
        }
        self.assertFalse(verify_command_signature(token, cmd))


if __name__ == "__main__":
    unittest.main()
