#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Encoder probe / options — no GPU required."""

import unittest

from client_rd_encoder import _codec_options, encoder_info


class TestRdEncoder(unittest.TestCase):
    def test_encoder_info_has_label(self):
        info = encoder_info()
        self.assertIn(info["label"], ("nvenc", "qsv", "amf", "x264"))
        self.assertTrue(info["ffmpeg"])

    def test_x264_options_are_zerolatency(self):
        opts = _codec_options("libx264")
        self.assertEqual(opts.get("tune"), "zerolatency")
        self.assertEqual(opts.get("preset"), "ultrafast")

    def test_nvenc_options_prefer_low_latency(self):
        opts = _codec_options("h264_nvenc")
        self.assertIn(opts.get("tune"), ("ll", "ull", "llhq", "llhp"))


if __name__ == "__main__":
    unittest.main()
