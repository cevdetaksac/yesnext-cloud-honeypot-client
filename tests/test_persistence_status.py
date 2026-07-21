import unittest
from unittest import mock

import client_tamper


class TestPersistenceStatus(unittest.TestCase):
    @mock.patch(
        "client_guardian_service.is_guardian_service_installed",
        return_value=True,
    )
    @mock.patch(
        "client_guardian_service.is_guardian_service_running",
        return_value=True,
    )
    @mock.patch("client_daemon_ipc.is_motor_healthy")
    def test_daemon_override_never_recurses_into_status_socket(
        self, motor_probe, _service_running, _service_installed
    ):
        status = client_tamper.get_persistence_status(daemon_ok_override=True)
        motor_probe.assert_not_called()
        self.assertTrue(status["daemon_ok"])
        self.assertTrue(status["service_ok"])
        self.assertTrue(status["service_installed"])

    @mock.patch(
        "client_guardian_service.is_guardian_service_installed",
        return_value=True,
    )
    @mock.patch(
        "client_guardian_service.is_guardian_service_running",
        return_value=True,
    )
    @mock.patch("client_daemon_ipc.is_motor_healthy", return_value=False)
    def test_external_health_call_still_probes_daemon(
        self, motor_probe, _service_running, _service_installed
    ):
        status = client_tamper.get_persistence_status()
        motor_probe.assert_called_once_with()
        self.assertFalse(status["daemon_ok"])


if __name__ == "__main__":
    unittest.main()
