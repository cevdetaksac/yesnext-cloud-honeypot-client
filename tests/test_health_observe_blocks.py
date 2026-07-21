"""Contract 1.4.2 observe-health blocks (command_signing / event_log_health).

These blocks are additive and observe-only. Missing means legacy on the cloud
side; enforce must always be False during the transition.
"""

import unittest


class FakeExecutor:
    def __init__(self, stats):
        self._stats = stats

    # Reuse the real method without constructing the full executor.
    def get_signing_health(self):
        from client_remote_commands import RemoteCommandExecutor
        return RemoteCommandExecutor.get_signing_health(self)


class TestCommandSigningHealth(unittest.TestCase):
    def test_observe_block_shape_and_enforce_off(self):
        ex = FakeExecutor({
            "signature_ok": 5,
            "signature_missing": 2,
            "signature_invalid": 0,
            "signature_no_token": 1,
            "signature_disabled": 0,
        })
        block = ex.get_signing_health()
        self.assertIn("observe", block)
        self.assertFalse(block["enforce"])
        self.assertEqual(block["ok"], 5)
        self.assertEqual(block["missing"], 2)
        self.assertEqual(block["invalid"], 0)
        self.assertEqual(block["no_token"], 1)
        self.assertEqual(block["last_error"], "")

    def test_missing_counters_default_to_zero(self):
        ex = FakeExecutor({})
        block = ex.get_signing_health()
        for k in ("ok", "missing", "invalid", "no_token", "disabled"):
            self.assertEqual(block[k], 0)


class TestEventLogHealth(unittest.TestCase):
    def test_health_block_has_no_raw_events_and_lists_ids(self):
        from client_eventlog import EventLogWatcher, WATCHED_CHANNELS

        watcher = EventLogWatcher.__new__(EventLogWatcher)
        watcher._running = False
        watcher._stats = {
            "events_processed": 3,
            "events_filtered": 1,
            "errors": 0,
            "channels_active": 1,
        }
        block = watcher.get_health()
        self.assertIn("watched_ids", block)
        self.assertNotIn("events", block)
        self.assertNotIn("raw_data", block)
        # ID-401 event ids must be advertised in the sensor health.
        self.assertIn(4723, block["watched_ids"])
        self.assertIn(4724, block["watched_ids"])
        self.assertEqual(block["channels_total"], len(WATCHED_CHANNELS))


if __name__ == "__main__":
    unittest.main()
