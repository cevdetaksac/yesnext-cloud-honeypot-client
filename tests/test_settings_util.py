# -*- coding: utf-8 -*-
"""Tests for client_settings_util — settings schema + patch builder."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_settings_util import (  # noqa: E402
    SECTIONS,
    build_threat_config_patch,
    extract_settings_values,
)


class TestExtractSettingsValues(unittest.TestCase):
    def test_defaults_for_empty_config(self):
        values = extract_settings_values({})
        self.assertTrue(values["alert_email_enabled"])
        self.assertEqual(values["auto_block_threshold"], 3)
        self.assertEqual(values["silent_hours.mode"], "night_only")

    def test_nested_silent_hours_flattened(self):
        cfg = {
            "silent_hours": {
                "enabled": True,
                "mode": "outside_working",
                "night_start": "23:30",
            },
            "auto_block_threshold": "7",
        }
        values = extract_settings_values(cfg)
        self.assertTrue(values["silent_hours.enabled"])
        self.assertEqual(values["silent_hours.mode"], "outside_working")
        self.assertEqual(values["silent_hours.night_start"], "23:30")
        self.assertEqual(values["auto_block_threshold"], 7)

    def test_invalid_choice_falls_back_to_default(self):
        values = extract_settings_values({"min_severity_for_email": "banana"})
        self.assertEqual(values["min_severity_for_email"], "medium")

    def test_every_section_field_has_a_value(self):
        values = extract_settings_values({})
        for _sec, fields in SECTIONS:
            for flat_key, _kind, _label, _extra in fields:
                self.assertIn(flat_key, values)


class TestBuildPatch(unittest.TestCase):
    def test_valid_values_build_nested_patch(self):
        patch, errors = build_threat_config_patch({
            "alert_email_enabled": True,
            "auto_block_threshold": "5",
            "silent_hours.enabled": True,
            "silent_hours.night_start": "22:00",
        })
        self.assertEqual(errors, [])
        self.assertEqual(patch["auto_block_threshold"], 5)
        self.assertEqual(patch["silent_hours"]["night_start"], "22:00")
        self.assertTrue(patch["silent_hours"]["enabled"])

    def test_bad_time_rejected(self):
        patch, errors = build_threat_config_patch(
            {"silent_hours.night_start": "25:99"}
        )
        self.assertIn("silent_hours.night_start", errors)
        self.assertNotIn("silent_hours", patch)

    def test_int_out_of_range_rejected(self):
        _patch, errors = build_threat_config_patch({"auto_block_threshold": 0})
        self.assertIn("auto_block_threshold", errors)
        _patch2, errors2 = build_threat_config_patch({"auto_block_threshold": 1000})
        self.assertIn("auto_block_threshold", errors2)

    def test_webhook_enabled_requires_url(self):
        _patch, errors = build_threat_config_patch({
            "webhook_enabled": True,
            "webhook_url": "not-a-url",
        })
        self.assertIn("webhook_url", errors)

    def test_webhook_enabled_with_https_ok(self):
        patch, errors = build_threat_config_patch({
            "webhook_enabled": True,
            "webhook_url": "https://example.com/hook",
        })
        self.assertEqual(errors, [])
        self.assertTrue(patch["webhook_enabled"])

    def test_unknown_keys_ignored(self):
        patch, errors = build_threat_config_patch({"hack_the_planet": 1})
        self.assertEqual(patch, {})
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
