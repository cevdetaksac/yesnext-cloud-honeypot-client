#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ID-401: Security Event Log 4723/4724 mapping (no live Event Log required)."""

import unittest

from client_alerts import _THREAT_CATEGORY
from client_eventlog import (
    EVENT_TYPE_MAP,
    EventLogWatcher,
    WATCHED_CHANNELS,
    _build_xpath,
)
from client_threat_engine import THREAT_SCORES


class TestPasswordChangeEvents(unittest.TestCase):
    def test_security_channel_watches_4723_and_4724(self):
        security = WATCHED_CHANNELS["Security"]
        self.assertIn(4723, security)
        self.assertIn(4724, security)
        self.assertEqual(EVENT_TYPE_MAP[4723], "password_change_attempt")
        self.assertEqual(EVENT_TYPE_MAP[4724], "password_reset_attempt")
        xpath = _build_xpath(security)
        self.assertIn("EventID=4723", xpath)
        self.assertIn("EventID=4724", xpath)

    def test_threat_scores_and_batch_category(self):
        self.assertGreaterEqual(THREAT_SCORES["password_change_attempt"], 60)
        self.assertGreaterEqual(THREAT_SCORES["password_reset_attempt"], 70)
        self.assertEqual(
            _THREAT_CATEGORY["password_change_attempt"], "account_modified"
        )
        self.assertEqual(
            _THREAT_CATEGORY["password_reset_attempt"], "account_modified"
        )

    def test_extractors_prefer_target_and_subject_without_secrets(self):
        data = {
            "TargetUserName": "victim",
            "TargetDomainName": "CORP",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "Status": "0x0",
            "Password": "must-not-survive",
        }
        self.assertEqual(
            EventLogWatcher._extract_username(data, 4724), "victim"
        )
        self.assertEqual(
            EventLogWatcher._extract_actor_username(data, 4724), "admin"
        )
        self.assertEqual(
            EventLogWatcher._extract_domain(data, "SubjectDomainName", 4724),
            "CORP",
        )
        self.assertEqual(EventLogWatcher._extract_result(data, 4724), "success")
        safe = EventLogWatcher._sanitize_event_data(data, 4724)
        self.assertNotIn("Password", safe)
        self.assertIn("TargetUserName", safe)
        # Non-identity events do not invent an actor field
        self.assertEqual(
            EventLogWatcher._extract_actor_username(data, 4624), ""
        )


if __name__ == "__main__":
    unittest.main()
