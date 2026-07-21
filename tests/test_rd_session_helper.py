#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Focused tests for persistent remote-desktop session IPC."""

import hashlib
import hmac
import json
import socket
import struct
import threading
import unittest

from client_rd_session_helper import (
    ProtocolError,
    SecureFramedSocket,
    PersistentSessionHelper,
)
from client_remote_desktop import RemoteDesktopStreamer


SECRET = b"s" * 32


class TestSecureFraming(unittest.TestCase):
    def test_binary_round_trip_is_framed_and_ordered(self):
        left, right = socket.socketpair()
        sender = SecureFramedSocket(left, SECRET)
        receiver = SecureFramedSocket(right, SECRET)
        try:
            sender.send("F", {"width": 640, "native_width": 1920}, b"\xff\xd8jpeg\xff\xd9")
            kind, header, payload = receiver.recv()
            self.assertEqual(kind, "F")
            self.assertEqual(header["width"], 640)
            self.assertEqual(header["native_width"], 1920)
            self.assertEqual(payload, b"\xff\xd8jpeg\xff\xd9")
        finally:
            sender.close()
            receiver.close()

    def test_rejects_bad_message_authentication(self):
        left, right = socket.socketpair()
        receiver = SecureFramedSocket(right, SECRET)
        header = json.dumps({"x": 1}, separators=(",", ":")).encode()
        prefix = struct.pack("!4sBIIQ", b"RDH1", ord("H"), len(header), 0, 0)
        bad_mac = hmac.new(b"z" * 32, prefix + header, hashlib.sha256).digest()
        left.sendall(prefix + header + bad_mac)
        try:
            with self.assertRaises(ProtocolError):
                receiver.recv()
        finally:
            left.close()
            receiver.close()


class TestPersistentHelperLifecycle(unittest.TestCase):
    def setUp(self):
        self.launches = 0
        self.helper_stopped = threading.Event()
        self.connection_args = {}

    def _build_command(self, secret, port, config):
        self.connection_args = {"secret": secret, "port": port}
        return "fake-helper"

    def _launch(self, session_id, command):
        self.launches += 1

        def fake_helper():
            raw = socket.create_connection(("127.0.0.1", self.connection_args["port"]))
            channel = SecureFramedSocket(raw, bytes.fromhex(self.connection_args["secret"]))
            channel.send("H", {"session_id": session_id})
            kind, config, _ = channel.recv()
            self.assertEqual(kind, "C")
            self.assertEqual(config["quality"], 40)
            channel.send("F", {
                "width": 1280,
                "height": 720,
                "native_width": 1920,
                "native_height": 1080,
                "method": "fake",
            }, b"\xff\xd8frame\xff\xd9")
            while True:
                kind, header, _ = channel.recv()
                if kind == "I":
                    channel.send("A", {"id": header["id"], "ok": True})
                elif kind == "C":
                    self.last_config = header
                elif kind == "S":
                    self.helper_stopped.set()
                    break
            channel.close()

        threading.Thread(target=fake_helper, daemon=True).start()
        return True

    def test_start_probe_full_duplex_input_and_stop(self):
        helper = PersistentSessionHelper(
            7, self._launch, self._build_command, lambda _message: None
        )
        self.assertTrue(helper.start({"fps": 6, "quality": 40}, timeout=2))
        frame = helper.wait_frame(timeout=2)
        self.assertIsNotNone(frame)
        frame_id, jpeg, meta = frame
        self.assertGreater(frame_id, 0)
        self.assertEqual(jpeg, b"\xff\xd8frame\xff\xd9")
        self.assertEqual((meta["native_width"], meta["native_height"]), (1920, 1080))
        self.assertTrue(helper.send_input({"event": "move", "x": 0.5, "y": 0.5}))
        self.assertTrue(helper.update_config({"quality": 55}))
        self.assertEqual(self.launches, 1)
        helper.stop()
        self.assertTrue(self.helper_stopped.wait(2))
        self.assertEqual(self.last_config["quality"], 55)

    def test_clean_restart_creates_one_new_helper(self):
        helper = PersistentSessionHelper(
            7, self._launch, self._build_command, lambda _message: None
        )
        self.assertTrue(helper.start({"fps": 6, "quality": 40}, timeout=2))
        self.assertIsNotNone(helper.wait_frame(timeout=2))
        helper.stop()
        self.assertTrue(self.helper_stopped.wait(2))
        self.helper_stopped.clear()
        self.assertTrue(helper.start({"fps": 6, "quality": 40}, timeout=2))
        self.assertIsNotNone(helper.wait_frame(timeout=2))
        self.assertEqual(self.launches, 2)
        helper.stop()
        self.assertTrue(self.helper_stopped.wait(2))

    def test_launch_failure_is_clean(self):
        helper = PersistentSessionHelper(
            7, lambda _sid, _cmd: False, self._build_command, lambda _message: None
        )
        self.assertFalse(helper.start({"fps": 6}, timeout=0.1))
        self.assertFalse(helper.connected)
        self.assertIn("CreateProcessAsUser", helper.error)


class _FakeMailbox:
    connected = True

    def wait_frame(self, after_id, timeout):
        return (
            after_id + 1,
            b"\xff\xd8frame\xff\xd9",
            {
                "width": 800,
                "height": 450,
                "native_width": 1600,
                "native_height": 900,
                "method": "unit",
            },
        )

    def send_input(self, event, timeout=2, wait=False):
        self.last_event = event
        return True


class TestStreamerBridgeIntegration(unittest.TestCase):
    def test_native_and_encoded_dimensions_remain_separate(self):
        rd = RemoteDesktopStreamer()
        rd._session_helper = _FakeMailbox()
        jpeg, width, height = rd._grab_via_persistent_helper()
        self.assertTrue(jpeg.startswith(b"\xff\xd8"))
        self.assertEqual((width, height), (800, 450))
        self.assertEqual((rd._capture_w, rd._capture_h), (800, 450))
        self.assertEqual((rd._screen_w, rd._screen_h), (1600, 900))

    def test_cross_session_input_uses_helper(self):
        rd = RemoteDesktopStreamer()
        mailbox = _FakeMailbox()
        rd._session_helper = mailbox
        rd._use_user_helper = True
        rd._running = True
        result = rd.apply_input({"event": "move", "x": 0.25, "y": 0.75})
        self.assertTrue(result["success"])
        self.assertEqual(mailbox.last_event["event"], "move")


if __name__ == "__main__":
    unittest.main()
