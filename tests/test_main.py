import sys
import json
import unittest
import unittest.mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from risk_engine import calculate_event_risk, calculate_risk


class TestRiskEngine(unittest.TestCase):

    def test_info_risk(self):
        result = calculate_event_risk({"severity": "INFO"})
        self.assertEqual(result, {"score": 0, "level": "LOW"})

    def test_warning_risk(self):
        result = calculate_event_risk({"severity": "WARNING"})
        self.assertEqual(result, {"score": 25, "level": "WARNING"})

    def test_high_risk(self):
        result = calculate_event_risk({"severity": "HIGH"})
        self.assertEqual(result, {"score": 50, "level": "HIGH"})

    def test_critical_risk(self):
        result = calculate_event_risk({"severity": "CRITICAL"})
        self.assertEqual(result, {"score": 75, "level": "CRITICAL"})

    def test_combined_risk(self):
        alerts = [
            {"severity": "WARNING"},
            {"severity": "HIGH"},
        ]
        result = calculate_risk(alerts)
        self.assertEqual(result, {"score": 75, "level": "CRITICAL"})

    def test_missing_severity_is_unknown(self):
        result = calculate_event_risk({})
        self.assertEqual(result, {"score": None, "level": "UNKNOWN"})

    def test_unknown_severity_is_unknown(self):
        result = calculate_event_risk({"severity": "UNKNOWN"})
        self.assertEqual(result, {"score": None, "level": "UNKNOWN"})


class TestPolicyConfiguration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        policy_path = PROJECT_ROOT / "config" / "policy.json"
        with policy_path.open("r", encoding="utf-8-sig") as file:
            cls.policy = json.load(file)

    def test_policy_version_exists(self):
        self.assertEqual(self.policy.get("policy_version"), "1.0")

    def test_monitoring_is_enabled(self):
        self.assertIs(self.policy["monitoring"]["enabled"], True)

    def test_all_monitoring_switches_are_enabled(self):
        monitoring = self.policy["monitoring"]
        self.assertIs(monitoring["monitor_processes"], True)
        self.assertIs(monitoring["monitor_network"], True)
        self.assertIs(monitoring["monitor_files"], True)

    def test_scan_interval_is_positive_integer(self):
        interval = self.policy["monitoring"]["scan_interval_seconds"]
        self.assertIsInstance(interval, int)
        self.assertNotIsInstance(interval, bool)
        self.assertGreater(interval, 0)

    def test_automatic_blocking_is_disabled(self):
        self.assertIs(
            self.policy["response"]["automatic_blocking"],
            False,
        )


class TestMonitoringSwitchBehavior(unittest.TestCase):

    def setUp(self):
        from unittest.mock import patch
        import main

        self.main = main
        self.patchers = [
            patch.object(main, "get_running_processes", return_value=[]),
            patch.object(main, "get_network_connections", return_value=[]),
            patch.object(main, "monitor_directory", return_value=[]),
            patch.object(main, "log_event"),
        ]

        self.mocks = [patcher.start() for patcher in self.patchers]
        self.addCleanup(self.stop_patches)

        self.original_policy = main.POLICY
        main.POLICY = {
            **main.POLICY,
            "monitoring": {
                **main.POLICY["monitoring"],
                "monitor_processes": False,
                "monitor_network": False,
                "monitor_files": False,
            },
        }

        self.addCleanup(self.restore_policy)

    def stop_patches(self):
        for patcher in reversed(self.patchers):
            patcher.stop()

    def restore_policy(self):
        self.main.POLICY = self.original_policy

    def test_disabled_process_monitor_is_not_called(self):
        with unittest.mock.patch.object(
            self.main, "get_running_processes"
        ) as monitor:
            with unittest.mock.patch("builtins.print"):
                self.main.run_scan()
            monitor.assert_not_called()

    def test_disabled_network_monitor_is_not_called(self):
        with unittest.mock.patch.object(
            self.main, "get_network_connections"
        ) as monitor:
            with unittest.mock.patch("builtins.print"):
                self.main.run_scan()
            monitor.assert_not_called()

    def test_disabled_file_monitor_is_not_called(self):
        with unittest.mock.patch.object(
            self.main, "monitor_directory"
        ) as monitor:
            with unittest.mock.patch("builtins.print"):
                self.main.run_scan()
            monitor.assert_not_called()


class TestResponsePolicyBehavior(unittest.TestCase):

    def test_logging_disabled_does_not_write_event(self):
        import main
        from unittest.mock import patch

        original_policy = main.POLICY
        try:
            main.POLICY = {
                **original_policy,
                "response": {
                    **original_policy.get("response", {}),
                    "log_events": False,
                },
            }

            with patch("pathlib.Path.open") as mocked_open:
                result = main.log_event(
                    "TEST", "INFO", "Logging-disabled test"
                )

            self.assertIsNone(result)
            mocked_open.assert_not_called()
        finally:
            main.POLICY = original_policy

    def test_logging_enabled_writes_event(self):
        import main
        from unittest.mock import mock_open, patch

        original_policy = main.POLICY
        try:
            main.POLICY = {
                **original_policy,
                "response": {
                    **original_policy.get("response", {}),
                    "log_events": True,
                },
            }

            fake_file = mock_open()
            with patch("pathlib.Path.open", fake_file):
                result = main.log_event(
                    "TEST", "INFO", "Logging-enabled test"
                )

            self.assertEqual(result["event_type"], "TEST")
            fake_file.assert_called_once_with("a", encoding="utf-8")
            fake_file().write.assert_called_once()
        finally:
            main.POLICY = original_policy

    def test_voice_disabled_does_not_speak(self):
        import alert_system
        from unittest.mock import patch

        alert = {
            "severity": "WARNING",
            "rule": "TEST_RULE",
            "reason": "Test warning",
        }

        with patch.object(alert_system, "speak_alert") as mocked_speech:
            with patch("builtins.print"):
                alert_system.show_alert(
                    alert,
                    {"score": 25, "level": "WARNING"},
                    {"source": "TEST"},
                    voice_enabled=False,
                )

        mocked_speech.assert_not_called()

    def test_voice_enabled_speaks_for_warning(self):
        import alert_system
        from unittest.mock import patch

        alert = {
            "severity": "WARNING",
            "rule": "TEST_RULE",
            "reason": "Test warning",
        }

        with patch.object(alert_system, "speak_alert") as mocked_speech:
            with patch("builtins.print"):
                alert_system.show_alert(
                    alert,
                    {"score": 25, "level": "WARNING"},
                    {"source": "TEST"},
                    voice_enabled=True,
                )

        mocked_speech.assert_called_once()


if __name__ == "__main__":
    unittest.main()
