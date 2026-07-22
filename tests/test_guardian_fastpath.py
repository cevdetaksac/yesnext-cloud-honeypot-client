#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest

from client_guardian_service import is_guardian_argv


class TestGuardianArgv(unittest.TestCase):
    def test_mode_flag_forms(self):
        self.assertTrue(is_guardian_argv(["--mode", "guardian"]))
        self.assertTrue(is_guardian_argv(["--mode=guardian"]))
        self.assertFalse(is_guardian_argv(["--mode", "daemon"]))
        self.assertFalse(is_guardian_argv([]))


if __name__ == "__main__":
    unittest.main()
