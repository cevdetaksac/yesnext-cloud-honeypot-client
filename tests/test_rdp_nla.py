#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for RDP NLA / NetNTLMv2 helpers."""

import struct
import unittest

from client_rdp_nla import (
    PROTOCOL_HYBRID,
    PROTOCOL_HYBRID_EX,
    build_ntlmssp_type2,
    build_tsrequest_with_token,
    find_ntlmssp,
    ntlm_message_type,
    parse_ntlmssp_type3,
    parse_tsrequest_version,
    selected_nla_protocol,
    wants_nla,
)


class TestNlaProtocolFlags(unittest.TestCase):
    def test_wants_nla(self):
        self.assertTrue(wants_nla(PROTOCOL_HYBRID))
        self.assertTrue(wants_nla(PROTOCOL_HYBRID_EX))
        self.assertTrue(wants_nla(PROTOCOL_HYBRID | 0x01))
        self.assertFalse(wants_nla(0))
        self.assertFalse(wants_nla(0x01))  # SSL only

    def test_selected_prefers_hybrid_ex(self):
        self.assertEqual(
            selected_nla_protocol(PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX),
            PROTOCOL_HYBRID_EX,
        )
        self.assertEqual(selected_nla_protocol(PROTOCOL_HYBRID), PROTOCOL_HYBRID)


class TestNtlmType2(unittest.TestCase):
    def test_build_type2(self):
        chal = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        msg = build_ntlmssp_type2(chal, target_name="WORKGROUP")
        self.assertEqual(ntlm_message_type(msg), 2)
        self.assertIn(chal, msg)
        self.assertTrue(msg.startswith(b"NTLMSSP\x00"))


class TestTsRequest(unittest.TestCase):
    def test_roundtrip_find_ntlm(self):
        chal = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        type2 = build_ntlmssp_type2(chal)
        ts = build_tsrequest_with_token(6, type2)
        self.assertEqual(ts[0], 0x30)
        idx = find_ntlmssp(ts)
        self.assertGreaterEqual(idx, 0)
        self.assertEqual(ntlm_message_type(ts, idx), 2)
        self.assertEqual(parse_tsrequest_version(ts), 6)


class TestParseType3(unittest.TestCase):
    def _build_type3(self, user: str, domain: str, nt_resp: bytes) -> bytes:
        user_b = user.encode("utf-16-le")
        domain_b = domain.encode("utf-16-le")
        lm = b"\x00" * 24
        # Layout: header 88 bytes typical minimal with offsets after fixed fields
        # Fixed header through EncryptedRandomSessionKey fields = 64 bytes before payload
        # Simpler: build with offsets pointing after 88-byte header
        header_size = 88
        payload = lm + nt_resp + domain_b + user_b
        # lm at 12, nt at 20, domain at 28, user at 36, workstation at 44 (empty),
        # session key at 52 (empty), flags at 60
        msg = bytearray(header_size + len(payload))
        msg[0:8] = b"NTLMSSP\x00"
        struct.pack_into("<I", msg, 8, 3)
        off = header_size
        # LM
        struct.pack_into("<HHI", msg, 12, len(lm), len(lm), off)
        msg[off : off + len(lm)] = lm
        off += len(lm)
        # NT
        struct.pack_into("<HHI", msg, 20, len(nt_resp), len(nt_resp), off)
        msg[off : off + len(nt_resp)] = nt_resp
        off += len(nt_resp)
        # Domain
        struct.pack_into("<HHI", msg, 28, len(domain_b), len(domain_b), off)
        msg[off : off + len(domain_b)] = domain_b
        off += len(domain_b)
        # User
        struct.pack_into("<HHI", msg, 36, len(user_b), len(user_b), off)
        msg[off : off + len(user_b)] = user_b
        # workstation empty
        struct.pack_into("<HHI", msg, 44, 0, 0, off)
        # session key empty
        struct.pack_into("<HHI", msg, 52, 0, 0, off)
        struct.pack_into("<I", msg, 60, 0xE2888215)
        return bytes(msg)

    def test_parse_v2(self):
        chal = b"AABBCCDD"
        nt_proof = bytes(range(16))
        blob = bytes(range(16, 48))
        nt_resp = nt_proof + blob
        msg = self._build_type3("admin", "CORP", nt_resp)
        parsed = parse_ntlmssp_type3(msg, chal)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["kind"], "netntlmv2")
        self.assertEqual(parsed["username"], "admin")
        self.assertEqual(parsed["domain"], "CORP")
        self.assertIn(chal.hex(), parsed["hash_line"])
        self.assertIn(nt_proof.hex(), parsed["hash_line"])
        self.assertTrue(parsed["hash_line"].startswith("admin::CORP:"))

    def test_parse_v1(self):
        chal = b"11223344"
        nt_resp = b"\xAA" * 24
        msg = self._build_type3("bob", "", nt_resp)
        parsed = parse_ntlmssp_type3(msg, chal)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["kind"], "netntlmv1")
        self.assertEqual(parsed["username"], "bob")


if __name__ == "__main__":
    unittest.main()
