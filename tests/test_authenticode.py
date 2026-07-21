#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUP-001b policy tests — no real certificate required."""

import tempfile
import unittest
from unittest import mock

from client_authenticode import (
    AuthenticodeError,
    assert_update_authenticode,
    verify_authenticode,
)


class TestAuthenticodePolicy(unittest.TestCase):
    def test_soft_skip_when_not_required(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            path = fh.name
            fh.write(b"installer")
        try:
            with mock.patch(
                "client_authenticode.authenticode_required", return_value=False
            ), mock.patch(
                "client_authenticode._winverify_trust",
                return_value=("", False, "status=NotSigned"),
            ):
                info = assert_update_authenticode(path)
            self.assertTrue(info.get("skipped"))
        finally:
            import os
            os.remove(path)

    def test_enforce_rejects_unsigned_when_required(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            path = fh.name
            fh.write(b"installer")
        try:
            with mock.patch(
                "client_authenticode.authenticode_required", return_value=True
            ), mock.patch(
                "client_authenticode._winverify_trust",
                return_value=("", False, "status=NotSigned"),
            ):
                with self.assertRaises(AuthenticodeError):
                    assert_update_authenticode(path)
        finally:
            import os
            os.remove(path)

    def test_publisher_allowlist(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            path = fh.name
            fh.write(b"installer")
        try:
            with mock.patch(
                "client_authenticode._winverify_trust",
                return_value=("CN=Evil Corp", True, ""),
            ):
                info = verify_authenticode(
                    path, allowed_publishers=["YesNext Technology"]
                )
            self.assertFalse(info["trusted"])
            self.assertEqual(info["error"], "publisher not allowed")
            self.assertNotIn("Evil", info["error"])
        finally:
            import os
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
