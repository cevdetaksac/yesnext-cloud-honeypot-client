#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Client 4.8.4: GUI whitelist must merge with cloud SoT, never overwrite.

Frontend-only GUI has no engine objects (threat_engine/auto_response/
event_watcher are None). 4.8.3 read only those local sets, so a quick
whitelist add pushed an EMPTY whitelist_ips to the cloud and the table
kept showing "Whitelist bos".
"""

import unittest
from unittest import mock

from client_gui import ModernGUI


class _FakeAPI:
    def __init__(self, cloud_wl):
        self.cloud_wl = list(cloud_wl)
        self.posted = None

    def fetch_threat_config(self, token):
        return {"whitelist_ips": list(self.cloud_wl)}

    def update_threat_config(self, token, patch):
        self.posted = patch
        self.cloud_wl = list(patch.get("whitelist_ips") or [])
        return {"whitelist_ips": list(self.cloud_wl)}


class _FakeApp:
    def __init__(self, api):
        self.api_client = api
        self.state = {"token": "tok"}
        self.threat_engine = None
        self.auto_response = None
        self.event_watcher = None


class _GuiStub:
    """Bare object carrying only what _persist_whitelist_to_cloud needs."""

    def __init__(self, api):
        self.app = _FakeApp(api)

    _cloud_whitelist_ips = ModernGUI._cloud_whitelist_ips
    _persist_whitelist_to_cloud = ModernGUI._persist_whitelist_to_cloud


class TestWhitelistCloudMerge(unittest.TestCase):
    def test_add_merges_with_existing_cloud_set(self):
        api = _FakeAPI(["9.9.9.9"])
        gui = _GuiStub(api)
        ok = gui._persist_whitelist_to_cloud(add=["1.1.1.1"])
        self.assertTrue(ok)
        self.assertEqual(api.posted, {"whitelist_ips": ["1.1.1.1", "9.9.9.9"]})

    def test_frontend_only_add_does_not_wipe_cloud(self):
        # No engines at all (frontend GUI) — cloud entries must survive
        api = _FakeAPI(["8.8.8.8", "9.9.9.9"])
        gui = _GuiStub(api)
        gui._persist_whitelist_to_cloud(add=["1.1.1.1"])
        self.assertIn("8.8.8.8", api.cloud_wl)
        self.assertIn("9.9.9.9", api.cloud_wl)
        self.assertIn("1.1.1.1", api.cloud_wl)

    def test_remove_deletes_only_target(self):
        api = _FakeAPI(["1.1.1.1", "9.9.9.9"])
        gui = _GuiStub(api)
        ok = gui._persist_whitelist_to_cloud(remove=["1.1.1.1"])
        self.assertTrue(ok)
        self.assertEqual(api.posted, {"whitelist_ips": ["9.9.9.9"]})

    def test_cache_updated_from_effective_response(self):
        api = _FakeAPI([])
        gui = _GuiStub(api)
        gui._persist_whitelist_to_cloud(add=["1.1.1.1"])
        # Table refresh path reads the cache without another fetch
        self.assertEqual(gui._cloud_whitelist_ips(), {"1.1.1.1"})

    def test_no_token_returns_false(self):
        api = _FakeAPI(["9.9.9.9"])
        gui = _GuiStub(api)
        gui.app.state = {"token": ""}
        self.assertFalse(gui._persist_whitelist_to_cloud(add=["1.1.1.1"]))
        self.assertIsNone(api.posted)


if __name__ == "__main__":
    unittest.main()
