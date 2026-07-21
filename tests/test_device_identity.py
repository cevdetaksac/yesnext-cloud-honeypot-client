#!/usr/bin/env python3
"""DEV-601 TPM capability probe is read-only and recoverable."""

import json
import unittest
from unittest import mock

import client_device_identity as identity


class _Proc:
    returncode = 0
    stdout = json.dumps({
        "Present": True, "Ready": True, "Manufacturer": "IFX",
    })
    stderr = ""


class TestDeviceIdentity(unittest.TestCase):
    def test_non_windows_is_unsupported_not_failure(self):
        with mock.patch.object(identity.os, "name", "posix"):
            status = identity.probe_tpm()
        self.assertIsNone(status["tpm_present"])
        self.assertFalse(status["enrolled"])
        self.assertEqual(status["attestation"], "not_implemented")

    def test_windows_probe_never_enrolls_or_exports_key(self):
        with mock.patch.object(identity.os, "name", "nt"), \
                mock.patch.object(identity.subprocess, "run", return_value=_Proc()):
            status = identity.probe_tpm()
        self.assertTrue(status["tpm_present"])
        self.assertTrue(status["tpm_ready"])
        self.assertFalse(status["enrolled"])
        self.assertIsNone(status["key_non_exportable"])
        self.assertNotIn("private", str(status).lower())

    def test_feature_default_off(self):
        with mock.patch("client_utils.get_from_config", return_value=False):
            self.assertFalse(identity.observe_enabled())


if __name__ == "__main__":
    unittest.main()
