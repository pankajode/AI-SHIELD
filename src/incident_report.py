from collections import Counter
from datetime import datetime
from pathlib import Path
import csv
import json


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "logs" / "events.jsonl"
REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_FILE = REPORT_DIR / "incident_report.txt"
REPORT_CSV = REPORT_DIR / "incident_report.csv"

SEVERITIES = ("INFO", "WARNING", "HIGH", "CRITICAL")


def load_events():
    events = []
    invalid_lines = 0

    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Event log not found: {LOG_FILE}")

    with LOG_FILE.open("r", encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
                else:
                    invalid_lines += 1
                    print(f"Warning: JSON on line {line_number} is not an object.")
            except json.JSONDecodeError:
                invalid_lines += 1
                print(f"Warning: Invalid JSON on log line {line_number}.")

    return events, invalid_lines


def finding_identity(event):
    details = event.get("details", {})
    if not isinstance(details, dict):
        details = {}

    # Prefer stable identifiers over PID, since PIDs can change between runs.
    for key in ("file", "path", "executable", "process", "process_name",
                "remote_address"):
        value = details.get(key)
        if value and str(value).strip().lower() not in {"unknown", "none"}:
            return f"{key}:{str(value).strip().lower()}"

    # If there is no stable identity, use the PID to avoid merging
    # unrelated unknown processes.
    if details.get("pid") is not None:
        return f"pid:{details['pid']}"

    return "no-identity"


def finding_key(event):
    details = event.get("details", {})
    if not isinstance(details, dict):
        details = {}

    severity = str(event.get("severity", "UNKNOWN")).upper()
    event_type = str(event.get("event_type", "UNKNOWN"))
    rule = str(details.get("rule", event.get("rule", "UNKNOWN")))
    message = str(event.get("message", "No message"))

    return (
        severity,
        event_type,
        rule,
        finding_identity(event),
        message,
    )


def parse_timestamp(event):
    value = event.get("timestamp", "")
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def group_findings(events):
    groups = {}

    for event in events:
        severity = str(event.get("severity", "UNKNOWN")).upper()
        if severity not in {"WARNING", "HIGH", "CRITICAL"}:
            continue

        key = finding_key(event)
        groups.setdefault(key, []).append(event)

    result = []

    for key, group_events in groups.items():
        valid_times = [
            (parse_timestamp(event), event.get("timestamp", "Unknown"))
            for event in group_events
        ]
        valid_times = [item for item in valid_times if item[0] is not None]
        valid_times.sort(key=lambda item: item[0])

        first_seen = valid_times[0][1] if valid_times else "Unknown"
        last_seen = valid_times[-1][1] if valid_times else "Unknown"

        result.append({
            "key": key,
            "events": group_events,
            "occurrences": len(group_events),
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    result.sort(
        key=lambda group: (
            {"CRITICAL": 3, "HIGH": 2, "WARNING": 1}.get(
                group["key"][0], 0
            ),
            group["occurrences"],
        ),
        reverse=True,
    )

    return result


def build_report(events, invalid_lines):
    now = datetime.now().astimezone().isoformat()
    severity_counts = Counter()
    event_type_counts = Counter()

    for event in events:
        severity_counts[
            str(event.get("severity", "UNKNOWN")).upper()
        ] += 1
        event_type_counts[
            str(event.get("event_type", "UNKNOWN"))
        ] += 1

    findings = group_findings(events)
    finding_occurrences = sum(
        group["occurrences"] for group in findings
    )

    lines = [
        "AI-SHIELD INCIDENT REPORT",
        "=" * 60,
        f"Report generated: {now}",
        f"Source log: {LOG_FILE}",
        "",
        "SUMMARY",
        "-" * 60,
        f"Total valid events: {len(events)}",
        f"Invalid log lines: {invalid_lines}",
        f"Potential findings requiring review: {finding_occurrences}",
        f"Unique finding groups: {len(findings)}",
        "",
        "EVENT COUNTS BY SEVERITY",
        "-" * 60,
    ]

    for severity in (*SEVERITIES, "UNKNOWN"):
        lines.append(f"{severity}: {severity_counts.get(severity, 0)}")

    for severity in sorted(
        item for item in severity_counts
        if item not in SEVERITIES and item != "UNKNOWN"
    ):
        lines.append(f"{severity}: {severity_counts[severity]}")

    lines.extend(["", "EVENT COUNTS BY TYPE", "-" * 60])

    if event_type_counts:
        for event_type, count in event_type_counts.most_common():
            lines.append(f"{event_type}: {count}")
    else:
        lines.append("No events recorded.")

    lines.extend([
        "",
        "FINDINGS GROUPED FOR REVIEW",
        "-" * 60,
        "Repeated matching events are grouped; they are not proof of one incident.",
        "Review context before deciding whether an event is a threat.",
        "",
    ])

    if findings:
        for index, group in enumerate(findings, start=1):
            event = group["events"][0]
            details = event.get("details", {})
            if not isinstance(details, dict):
                details = {}

            lines.extend([
                f"Finding group {index}",
                f"Occurrences: {group['occurrences']}",
                f"First seen: {group['first_seen']}",
                f"Last seen: {group['last_seen']}",
                f"Severity: {str(event.get('severity', 'UNKNOWN')).upper()}",
                f"Type: {event.get('event_type', 'UNKNOWN')}",
                f"Message: {event.get('message', 'No message')}",
            ])

            for key in (
                "rule", "process", "process_name", "pid", "executable",
                "file", "path", "remote_address", "reason"
            ):
                value = details.get(key)
                if value is not None:
                    lines.append(f"{key}: {value}")

            pids = sorted({
                str(item.get("details", {}).get("pid"))
                for item in group["events"]
                if isinstance(item.get("details"), dict)
                and item["details"].get("pid") is not None
            })
            if len(pids) > 1:
                lines.append(f"Observed PIDs: {', '.join(pids)}")

            lines.extend(["", "-" * 60, ""])
    else:
        lines.append("No WARNING, HIGH, or CRITICAL events were found.")

    lines.extend([
        "",
        "IMPORTANT NOTES",
        "-" * 60,
        "- The original event log is not modified.",
        "- Grouping is based on severity, event type, rule, identity, and message.",
        "- Similar grouped events may still represent separate incidents.",
        "- Informational events are not automatically considered threats.",
        "- Findings require human review and additional context.",
    ])

    return "\n".join(lines) + "\n"



def export_csv(findings):
    fieldnames = [
        "severity",
        "event_type",
        "rule",
        "identity",
        "occurrences",
        "first_seen",
        "last_seen",
        "message",
        "process",
        "process_name",
        "pid",
        "executable",
        "file",
        "path",
        "remote_address",
        "reason",
        "observed_pids",
    ]

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with REPORT_CSV.open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for group in findings:
            event = group["events"][0]
            details = event.get("details", {})
            if not isinstance(details, dict):
                details = {}

            pids = sorted({
                str(item.get("details", {}).get("pid"))
                for item in group["events"]
                if isinstance(item.get("details"), dict)
                and item["details"].get("pid") is not None
            })

            writer.writerow({
                "severity": str(event.get("severity", "UNKNOWN")).upper(),
                "event_type": event.get("event_type", "UNKNOWN"),
                "rule": details.get("rule", event.get("rule", "UNKNOWN")),
                "identity": group["key"][3],
                "occurrences": group["occurrences"],
                "first_seen": group["first_seen"],
                "last_seen": group["last_seen"],
                "message": event.get("message", "No message"),
                "process": details.get("process", ""),
                "process_name": details.get("process_name", ""),
                "pid": details.get("pid", ""),
                "executable": details.get("executable", ""),
                "file": details.get("file", ""),
                "path": details.get("path", ""),
                "remote_address": details.get("remote_address", ""),
                "reason": details.get("reason", ""),
                "observed_pids": ", ".join(pids),
            })

    return REPORT_CSV

def main():
    events, invalid_lines = load_events()
    report = build_report(events, invalid_lines)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(report, encoding="utf-8")

    findings = group_findings(events)
    occurrences = sum(group["occurrences"] for group in findings)
    csv_path = export_csv(findings)

    print("AI-SHIELD incident reports created.")
    print(f"Events analyzed: {len(events)}")
    print(f"Invalid log lines: {invalid_lines}")
    print(f"Finding occurrences: {occurrences}")
    print(f"Unique finding groups: {len(findings)}")
    print(f"Text report: {REPORT_FILE}")
    print(f"CSV report: {csv_path}")


if __name__ == "__main__":
    main()
