import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

import incident_report


class TestIncidentReport(unittest.TestCase):

    def test_load_valid_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "events.jsonl"
            log_file.write_text(
                '{"event_type":"SYSTEM","severity":"INFO","message":"Started"}\n',
                encoding="utf-8",
            )

            with patch.object(incident_report, "LOG_FILE", log_file):
                events, invalid = incident_report.load_events()

            self.assertEqual(len(events), 1)
            self.assertEqual(invalid, 0)

    def test_invalid_json_is_counted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "events.jsonl"
            log_file.write_text(
                '{"severity":"INFO"}\nnot valid json\n',
                encoding="utf-8",
            )

            with patch.object(incident_report, "LOG_FILE", log_file):
                events, invalid = incident_report.load_events()

            self.assertEqual(len(events), 1)
            self.assertEqual(invalid, 1)

    def test_missing_log_raises_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_log = Path(temp_dir) / "missing.jsonl"

            with patch.object(incident_report, "LOG_FILE", missing_log):
                with self.assertRaises(FileNotFoundError):
                    incident_report.load_events()

    def test_warning_is_reported_for_review(self):
        events = [
            {
                "timestamp": "2026-10-08T12:00:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Test warning",
                "details": {"process": "example.exe"},
            }
        ]

        report = incident_report.build_report(events, 0)

        self.assertIn("Potential findings requiring review: 1", report)
        self.assertIn("Test warning", report)
        self.assertIn("example.exe", report)

    def test_info_event_is_not_a_finding(self):
        events = [
            {
                "event_type": "SYSTEM",
                "severity": "INFO",
                "message": "Normal startup",
                "details": {},
            }
        ]

        report = incident_report.build_report(events, 0)

        self.assertIn("Potential findings requiring review: 0", report)
        self.assertIn("No WARNING, HIGH, or CRITICAL events were found.", report)


    def test_repeated_finding_is_grouped(self):
        events = [
            {
                "timestamp": "2026-10-08T10:00:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Test warning",
                "details": {
                    "rule": "TEST_RULE",
                    "process": "demo.exe",
                    "pid": 100,
                },
            },
            {
                "timestamp": "2026-10-08T10:05:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Test warning",
                "details": {
                    "rule": "TEST_RULE",
                    "process": "demo.exe",
                    "pid": 200,
                },
            },
        ]

        groups = incident_report.group_findings(events)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["occurrences"], 2)
        self.assertEqual(
            groups[0]["first_seen"], "2026-10-08T10:00:00-04:00"
        )
        self.assertEqual(
            groups[0]["last_seen"], "2026-10-08T10:05:00-04:00"
        )

    def test_different_processes_remain_separate(self):
        events = [
            {
                "timestamp": "2026-10-08T10:00:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Test warning",
                "details": {
                    "rule": "TEST_RULE",
                    "process": "first.exe",
                },
            },
            {
                "timestamp": "2026-10-08T10:01:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Test warning",
                "details": {
                    "rule": "TEST_RULE",
                    "process": "second.exe",
                },
            },
        ]

        groups = incident_report.group_findings(events)

        self.assertEqual(len(groups), 2)
        self.assertTrue(
            all(group["occurrences"] == 1 for group in groups)
        )



    def test_csv_export_writes_headers_and_finding(self):
        events = [
            {
                "timestamp": "2026-10-08T10:00:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Test CSV warning",
                "details": {
                    "rule": "TEST_CSV_RULE",
                    "process": "demo.exe",
                    "pid": 123,
                },
            }
        ]

        groups = incident_report.group_findings(events)

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_file = Path(temp_dir) / "findings.csv"

            with patch.object(incident_report, "REPORT_DIR", Path(temp_dir)), \
                 patch.object(incident_report, "REPORT_CSV", csv_file):
                result = incident_report.export_csv(groups)

            import csv
            with result.open("r", encoding="utf-8-sig", newline="") as file:
                rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "WARNING")
        self.assertEqual(rows[0]["rule"], "TEST_CSV_RULE")
        self.assertEqual(rows[0]["process"], "demo.exe")
        self.assertEqual(rows[0]["occurrences"], "1")
        self.assertEqual(rows[0]["message"], "Test CSV warning")

    def test_csv_export_preserves_group_occurrence_count(self):
        events = [
            {
                "timestamp": "2026-10-08T10:00:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Repeated warning",
                "details": {
                    "rule": "REPEATED_RULE",
                    "process": "demo.exe",
                    "pid": 100,
                },
            },
            {
                "timestamp": "2026-10-08T10:05:00-04:00",
                "event_type": "DETECTION",
                "severity": "WARNING",
                "message": "Repeated warning",
                "details": {
                    "rule": "REPEATED_RULE",
                    "process": "demo.exe",
                    "pid": 200,
                },
            },
        ]

        groups = incident_report.group_findings(events)

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_file = Path(temp_dir) / "findings.csv"

            with patch.object(incident_report, "REPORT_DIR", Path(temp_dir)), \
                 patch.object(incident_report, "REPORT_CSV", csv_file):
                result = incident_report.export_csv(groups)

            import csv
            with result.open("r", encoding="utf-8-sig", newline="") as file:
                rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["occurrences"], "2")
        self.assertEqual(rows[0]["first_seen"], events[0]["timestamp"])
        self.assertEqual(rows[0]["last_seen"], events[1]["timestamp"])
        self.assertEqual(rows[0]["observed_pids"], "100, 200")

if __name__ == "__main__":
    unittest.main()
