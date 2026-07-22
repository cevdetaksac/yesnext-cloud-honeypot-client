#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Whitelist must never stay blocked."""

import unittest
from unittest import mock

from client_auto_response import AutoResponse


class TestWhitelistNeverBlock(unittest.TestCase):
    def setUp(self):
        self.ar = AutoResponse(whitelist_ips={"203.0.113.10"})
        self.ar._run_system_cmd = mock.Mock(return_value=True)
        self.ar._run_system_cmd_detail = mock.Mock(return_value=(True, "Ok."))
        self.ar._report_block_to_api = mock.Mock()
        self.ar._report_block_applied = mock.Mock()
        self.ar._report_unblock_to_api = mock.Mock()

    def test_block_ip_skips_and_clears_whitelist(self):
        with mock.patch.object(self.ar, "unblock_ip", return_value=True) as unb:
            ok = self.ar.block_ip("203.0.113.10", reason="should_not")
        self.assertFalse(ok)
        unb.assert_called_once_with("203.0.113.10")

    def test_update_whitelist_enforces_unblock(self):
        with self.ar._lock:
            from client_auto_response import BlockRecord
            self.ar._blocks["198.51.100.1"] = BlockRecord(
                ip="198.51.100.1",
                rule_name="HP-BLOCK-198.51.100.1",
                reason="old",
                blocked_at=1.0,
                unblock_at=0,
                auto_unblock=False,
            )
        with mock.patch.object(self.ar, "unblock_ip", return_value=True) as unb:
            self.ar.update_whitelist({"198.51.100.1", "203.0.113.10"})
        # Both whitelist IPs should be cleared
        called = {c.args[0] for c in unb.call_args_list}
        self.assertIn("198.51.100.1", called)
        self.assertIn("203.0.113.10", called)


if __name__ == "__main__":
    unittest.main()
