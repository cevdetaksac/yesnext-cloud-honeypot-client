#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Update immortality / PS 5.1 hardening tests."""

import os
import tempfile
import time
import unittest

from client_update_hardening import (
    EMERGENCY_UPDATE_BOOTSTRAP_PS1,
    assert_file_is_ascii,
    detect_launcher_only_storm,
    normalize_ps1_to_ascii,
    preflight_update_ready,
    validate_powershell_parse,
    write_ascii_ps1,
    write_emergency_bootstrap,
)


class TestNormalizeAscii(unittest.TestCase):
    def test_strips_emdash(self):
        raw = "waiting \u2014 up to 10s"
        out = normalize_ps1_to_ascii(raw)
        self.assertNotIn("\u2014", out)
        self.assertIn("-", out)
        self.assertTrue(all(ord(c) < 128 for c in out))

    def test_smart_quotes(self):
        raw = "\u201chello\u201d \u2018x\u2019"
        out = normalize_ps1_to_ascii(raw)
        self.assertEqual(out, '"hello" \'x\'')

    def test_emergency_bootstrap_is_ascii(self):
        self.assertTrue(all(ord(c) < 128 for c in EMERGENCY_UPDATE_BOOTSTRAP_PS1))
        self.assertIn("=== update-and-install start ===", EMERGENCY_UPDATE_BOOTSTRAP_PS1)


class TestWriteAndParse(unittest.TestCase):
    def setUp(self):
        self._tdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tdir, ignore_errors=True)

    def test_write_rejects_non_ascii_payload(self):
        path = os.path.join(self._tdir, "bad.ps1")
        # write_ascii_ps1 normalizes — so result must be ascii
        self.assertTrue(write_ascii_ps1(path, "try { } catch { } # \u2014 dash"))
        self.assertTrue(assert_file_is_ascii(path))
        data = open(path, "rb").read()
        self.assertNotIn(b"\xe2\x80\x94", data)

    def test_broken_utf8_emdash_file_fails_ascii_gate(self):
        path = os.path.join(self._tdir, "broken.ps1")
        # Simulate old staged helper: UTF-8 em-dash, no BOM
        body = b'try {\n  Write-Host "hi \xe2\x80\x94 there"\n} catch {}\n'
        with open(path, "wb") as fh:
            fh.write(body)
        self.assertFalse(assert_file_is_ascii(path))

    def test_repo_helper_stages_and_parses(self):
        src = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "scripts",
            "update-and-install.ps1",
        )
        src = os.path.normpath(src)
        self.assertTrue(os.path.isfile(src), f"missing {src}")
        raw = open(src, "r", encoding="utf-8", errors="replace").read()
        dst = os.path.join(self._tdir, "update-and-install.ps1")
        self.assertTrue(write_ascii_ps1(dst, raw))
        ok, detail = validate_powershell_parse(dst)
        self.assertTrue(ok, detail)

    def test_update_lock_survives_until_new_daemon_is_ready(self):
        src = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "scripts", "update-and-install.ps1",
        ))
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        ensure_idx = raw.rfind("Ensure-DaemonMotor -ExePath $exe")
        clear_idx = raw.rfind("Clear-UpdateLock")
        self.assertGreater(ensure_idx, 0)
        self.assertGreater(
            clear_idx,
            ensure_idx,
            "update lock must be cleared only after the new daemon is ready",
        )

    def test_emergency_bootstrap_parses(self):
        dst = os.path.join(self._tdir, "emergency.ps1")
        path = write_emergency_bootstrap(dst)
        self.assertIsNotNone(path)
        ok, detail = validate_powershell_parse(path)
        self.assertTrue(ok, detail)

    def test_stage_update_install_helper_api(self):
        # Import after path setup — uses real scripts/
        import client_utils as cu

        # Point staging at temp via monkeypatch of helper dir
        orig = cu._update_helper_staging_dir
        cu._update_helper_staging_dir = lambda: self._tdir
        try:
            path = cu.stage_update_install_helper(allow_emergency=True)
            self.assertIsNotNone(path)
            self.assertTrue(assert_file_is_ascii(path))
            ok, detail = validate_powershell_parse(path)
            self.assertTrue(ok, detail)
        finally:
            cu._update_helper_staging_dir = orig


class TestPreflightAndStorm(unittest.TestCase):
    def setUp(self):
        self._tdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tdir, ignore_errors=True)

    def test_preflight_missing(self):
        ok, detail = preflight_update_ready(os.path.join(self._tdir, "nope.exe"))
        self.assertFalse(ok)
        self.assertEqual(detail, "installer_missing")

    def test_preflight_too_small(self):
        path = os.path.join(self._tdir, "tiny.exe")
        with open(path, "wb") as fh:
            fh.write(b"MZ" + b"\0" * 100)
        ok, detail = preflight_update_ready(path)
        self.assertFalse(ok)
        self.assertTrue(detail.startswith("installer_too_small"), detail)

    def test_launcher_storm(self):
        log_path = os.path.join(self._tdir, "update-install.log")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = [f"[{now}] launcher start launch-{i}-x pid={i}\n" for i in range(6)]
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        self.assertTrue(detect_launcher_only_storm(log_path, min_hits=4))

    def test_no_storm_when_helper_started(self):
        log_path = os.path.join(self._tdir, "update-install.log")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "w", encoding="utf-8") as fh:
            for i in range(6):
                fh.write(f"[{now}] launcher start launch-{i}-x pid={i}\n")
            fh.write(f"[{now}] === update-and-install start ===\n")
        self.assertFalse(detect_launcher_only_storm(log_path, min_hits=4))


class TestRealStagedRegression(unittest.TestCase):
    """Reproduce the production bug: UTF-8 em-dash without BOM breaks PS 5.1 parse."""

    def setUp(self):
        self._tdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tdir, ignore_errors=True)

    def test_emdash_script_fails_parse_gate_ascii(self):
        path = os.path.join(self._tdir, "uai.ps1")
        # Minimal try/catch with em-dash inside a double-quoted string (the real failure mode)
        broken = (
            'try {\n'
            '  Write-Host "Installer PID=$($p.Id) \u2014 waiting"\n'
            '} catch {\n'
            '  exit 1\n'
            '}\n'
        )
        # Write as UTF-8 without BOM (what broke production)
        with open(path, "wb") as fh:
            fh.write(broken.encode("utf-8"))
        self.assertFalse(assert_file_is_ascii(path))
        # After normalize+rewrite, parse must succeed
        fixed = os.path.join(self._tdir, "fixed.ps1")
        self.assertTrue(write_ascii_ps1(fixed, broken))
        ok, detail = validate_powershell_parse(fixed)
        self.assertTrue(ok, detail)


if __name__ == "__main__":
    unittest.main()
