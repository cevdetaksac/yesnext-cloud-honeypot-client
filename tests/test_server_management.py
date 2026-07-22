#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract 1.4.8 Server Management command surface tests."""

import unittest
from unittest import mock

from client_remote_commands import (
    ALLOWED_COMMANDS,
    PROTECTED_SERVICES,
    RemoteCommandExecutor,
)
from client_server_management import normalize_service_name


class TestServerManagementSurface(unittest.TestCase):
    def setUp(self):
        self.ex = RemoteCommandExecutor(
            api_client=None,
            token_getter=lambda: "",
        )

    def test_list_services_whitelisted(self):
        self.assertIn("list_services", ALLOWED_COMMANDS)

    def test_normalize_name_or_service_name(self):
        self.assertEqual(normalize_service_name({"name": "Spooler"}), "Spooler")
        self.assertEqual(
            normalize_service_name({"service_name": "Spooler"}), "Spooler"
        )
        self.assertEqual(
            normalize_service_name({"name": "A", "service_name": "B"}), "A"
        )

    def test_service_commands_accept_name_key(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            for ct in ("start_service", "stop_service", "restart_service"):
                if ct == "restart_service":
                    with mock.patch.object(self.ex, "_cmd_stop_service",
                                           return_value={"success": True}):
                        with mock.patch.object(self.ex, "_cmd_start_service",
                                               return_value={"success": True}) as start:
                            out = self.ex._cmd_restart_service({"name": "Spooler"})
                            self.assertTrue(out["success"])
                            start.assert_called()
                else:
                    out = getattr(self.ex, f"_cmd_{ct}")({"name": "Spooler"})
                    self.assertTrue(out["success"], ct)
                    args = run.call_args[0][0]
                    self.assertIn("Spooler", args)

    def test_protected_service_refused(self):
        name = next(iter(PROTECTED_SERVICES))
        out = self.ex._cmd_stop_service({"name": name})
        self.assertFalse(out["success"])
        self.assertEqual(out["error"], "PROTECTED_SERVICE")

    def test_list_services_handler_shape(self):
        fake = [
            {
                "name": "Spooler",
                "display_name": "Print Spooler",
                "status": "Running",
                "start_type": "Automatic",
                "pid": 1234,
            }
        ]
        with mock.patch(
            "client_server_management.list_windows_services",
            return_value=fake,
        ):
            out = self.ex._cmd_list_services({
                "include_drivers": False,
                "include_stopped": True,
            })
        self.assertTrue(out["success"])
        self.assertEqual(out["data"]["services"][0]["name"], "Spooler")
        self.assertIn("display_name", out["data"]["services"][0])
        self.assertIn("status", out["data"]["services"][0])
        self.assertIn("start_type", out["data"]["services"][0])


if __name__ == "__main__":
    unittest.main()
