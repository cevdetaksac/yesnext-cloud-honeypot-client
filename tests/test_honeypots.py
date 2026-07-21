#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for honeypot helpers."""

import time
import unittest

from client_honeypots import HTTPHoneypot, _RateLimiter


class TestHTTPFormParse(unittest.TestCase):
    def test_parse_credentials(self):
        hp = HTTPHoneypot(port=8080, on_credential=lambda *a: None)
        user, pwd = hp._parse_form("username=admin%40local&password=Pass%23123")
        self.assertEqual(user, "admin@local")
        self.assertEqual(pwd, "Pass#123")

    def test_health_exposes_budgets_without_credentials(self):
        hp = HTTPHoneypot(port=8080, on_credential=lambda *a: None)
        health = hp.get_health()
        self.assertTrue(health["resource_budgeted"])
        self.assertTrue(health["protocol_aware"])
        self.assertGreater(health["handler_limit"], 0)
        self.assertGreater(health["rate_limit_per_ip_min"], 0)
        self.assertEqual(health["fingerprint_profile"], "static_legacy")
        self.assertNotIn("credential", str(health).lower())


class TestRateLimiter(unittest.TestCase):
    def test_allows_under_limit(self):
        rl = _RateLimiter(max_per_min=3)
        self.assertTrue(rl.allow("1.2.3.4:SSH"))
        self.assertTrue(rl.allow("1.2.3.4:SSH"))
        self.assertTrue(rl.allow("1.2.3.4:SSH"))

    def test_blocks_over_limit(self):
        rl = _RateLimiter(max_per_min=2)
        self.assertTrue(rl.allow("ip:FTP"))
        self.assertTrue(rl.allow("ip:FTP"))
        self.assertFalse(rl.allow("ip:FTP"))


if __name__ == "__main__":
    unittest.main()
