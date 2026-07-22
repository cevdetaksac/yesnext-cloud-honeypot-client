#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Presence signal unit tests (contract 1.4.12)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestPresenceSignals(unittest.TestCase):
    def setUp(self):
        import client_presence as p
        p.reset_goodbye_flag()
        p.configure(control_ws=None, api_client=None, token_getter=lambda: "")

    def test_ws_presence_preferred(self):
        import client_presence as p
        ws = MagicMock()
        ws.send_presence.return_value = True
        p.configure(control_ws=ws, token_getter=lambda: "tok")
        with patch.object(p, "http_presence") as http:
            ok = p.signal_presence("suspend", "sleep")
            self.assertTrue(ok)
            ws.send_presence.assert_called_once_with("suspend", "sleep")
            http.assert_not_called()

    def test_http_fallback_when_ws_fails(self):
        import client_presence as p
        ws = MagicMock()
        ws.send_presence.return_value = False
        p.configure(control_ws=ws, token_getter=lambda: "tok")
        with patch.object(p, "http_presence", return_value=True) as http:
            ok = p.signal_presence("suspend", "sleep")
            self.assertTrue(ok)
            http.assert_called_once()

    def test_goodbye_idempotent(self):
        import client_presence as p
        ws = MagicMock()
        ws.send_goodbye.return_value = True
        p.configure(control_ws=ws, token_getter=lambda: "tok")
        self.assertTrue(p.signal_goodbye("shutdown"))
        self.assertTrue(p.signal_goodbye("shutdown"))
        self.assertEqual(ws.send_goodbye.call_count, 1)

    def test_online_on_connect_flag(self):
        import client_presence as p
        ws = MagicMock()
        ws.send_presence.return_value = True
        p.configure(control_ws=ws, token_getter=lambda: "tok")
        p.mark_online_on_next_connect()
        p.on_control_ws_connected()
        ws.send_presence.assert_called_with("online", "resume")


class TestControlWsPresenceHelpers(unittest.TestCase):
    def test_send_presence_payload(self):
        from client_control_ws import AgentControlWebSocket
        ws = AgentControlWebSocket()
        ws._connected = True
        with patch.object(ws, "send_json", return_value=True) as send:
            self.assertTrue(ws.send_presence("suspend", "sleep"))
            payload = send.call_args[0][0]
            self.assertEqual(payload["t"], "presence")
            self.assertEqual(payload["state"], "suspend")
            self.assertEqual(payload["reason"], "sleep")

    def test_send_goodbye_payload(self):
        from client_control_ws import AgentControlWebSocket
        ws = AgentControlWebSocket()
        ws._connected = True
        with patch.object(ws, "send_json", return_value=True) as send:
            self.assertTrue(ws.send_goodbye("update"))
            payload = send.call_args[0][0]
            self.assertEqual(payload["t"], "goodbye")
            self.assertEqual(payload["reason"], "update")


if __name__ == "__main__":
    unittest.main()
