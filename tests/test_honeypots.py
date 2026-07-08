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
