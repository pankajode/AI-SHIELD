from datetime import datetime
from pathlib import Path
import json
import time

from process_monitor import get_running_processes
from network_monitor import get_network_connections
from file_monitor import (
    monitor_directory,
    detect_new_files,
)
from detection_engine import (
    analyze_process,
    analyze_network,
    analyze_file,
)
from risk_engine import calculate_event_risk
from alert_system import show_alert


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "logs" / "events.jsonl"

POLICY_FILE = PROJECT_ROOT / "config" / "policy.json"


def load_policy():
    try:
        with POLICY_FILE.open("r", encoding="utf-8-sig") as file:
            policy = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Unable to load security policy: {error}") from error

    monitoring = policy.get("monitoring")
    if not isinstance(monitoring, dict):
        raise ValueError("Policy must contain a monitoring object.")

    interval = monitoring.get("scan_interval_seconds")
    if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1:
        raise ValueError("scan_interval_seconds must be a positive integer.")

    if monitoring.get("enabled") is not True:
        raise ValueError("Monitoring is disabled by policy.")

    return policy


POLICY = load_policy()
MONITOR_INTERVAL = POLICY["monitoring"]["scan_interval_seconds"]

# Keeps track of detections already seen during this run.
seen_detections = set()

# Keeps track of processes seen during the previous scan.
known_processes = set()

# Keeps track of files seen during the previous scan.
known_files = []


def log_event(event_type, severity, message, details=None):
    response_policy = POLICY.get("response", {})

    # Logging can be disabled through config/policy.json.
    if response_policy.get("log_events", True) is not True:
        return None

    event = {
        "timestamp": datetime.now().astimezone().isoformat(),
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "details": details or {},
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return event


def get_detection_key(alert, source, details):
    return (
        source,
        alert.get("rule", "UNKNOWN"),
        details.get("pid"),
        details.get("process"),
        details.get("executable"),
        details.get("file"),
        details.get("remote_address"),
    )


def record_detection(alert, source, details):
    detection_key = get_detection_key(
        alert,
        source,
        details,
    )

    if detection_key in seen_detections:
        return False

    seen_detections.add(detection_key)

    risk = calculate_event_risk(alert)

    detection_details = {
        "rule": alert["rule"],
        "source": source,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        **details,
    }

    log_event(
        event_type="DETECTION",
        severity=alert["severity"],
        message=alert["reason"],
        details=detection_details,
    )

    show_alert(
        alert,
        risk,
        {
            "source": source,
            **details,
        },
        voice_enabled=(
            POLICY.get("response", {}).get("voice_alerts", True) is True
        ),
    )

    return True


def detect_new_processes(processes):
    global known_processes

    current_processes = set()

    for process in processes:
        pid = process.get("pid")

        if pid is not None:
            current_processes.add(pid)

    # First scan establishes the baseline.
    if not known_processes:
        known_processes = current_processes
        return []

    new_process_ids = current_processes - known_processes

    new_processes = []

    for process in processes:
        if process.get("pid") in new_process_ids:
            new_processes.append(process)

    known_processes = current_processes

    return new_processes


def detect_new_files_from_baseline(files):
    global known_files

    # First scan establishes the baseline.
    if not known_files:
        known_files = files
        return []

    new_files = detect_new_files(
        known_files,
        files,
    )

    known_files = files

    return new_files


def run_scan():
    new_process_count = 0
    process_detection_count = 0
    network_detection_count = 0
    file_detection_count = 0
    new_file_count = 0

    # -------------------------------------------------
    if POLICY["monitoring"]["monitor_processes"]:
        # PROCESS MONITOR
        # -------------------------------------------------

        processes = get_running_processes()

        print("Process monitor: ACTIVE")
        print(f"Processes detected: {len(processes)}")

        log_event(
            event_type="PROCESS_SCAN",
            severity="INFO",
            message="Process scan completed.",
            details={"process_count": len(processes)},
        )

        # Detect newly appearing processes.
        new_processes = detect_new_processes(processes)

        for process in new_processes:
            new_process_alert = {
                "severity": "INFO",
                "rule": "NEW_PROCESS_DETECTED",
                "reason": (
                    f"A new process appeared since the previous scan: "
                    f"{process['name']}"
                ),
            }

            recorded = record_detection(
                new_process_alert,
                "PROCESS",
                {
                    "pid": process["pid"],
                    "process": process["name"],
                    "executable": process["executable"],
                    "username": process["username"],
                    "status": process["status"],
                },
            )

            if recorded:
                new_process_count += 1

        print(f"New processes: {new_process_count}")

        # Analyze processes using detection rules.
        for process in processes:
            alerts = analyze_process(process)

            for alert in alerts:
                recorded = record_detection(
                    alert,
                    "PROCESS",
                    {
                        "pid": process["pid"],
                        "process": process["name"],
                        "executable": process["executable"],
                    },
                )

                if recorded:
                    process_detection_count += 1

        print(f"Process rule detections: {process_detection_count}")
        print()

        # -------------------------------------------------
    else:
        print("Process monitor: DISABLED by policy")
        print()

    if POLICY["monitoring"]["monitor_network"]:
        # NETWORK MONITOR
        # -------------------------------------------------

        connections = get_network_connections()

        print("Network monitor: ACTIVE")
        print(f"Network connections detected: {len(connections)}")

        log_event(
            event_type="NETWORK_SCAN",
            severity="INFO",
            message="Network scan completed.",
            details={"connection_count": len(connections)},
        )

        for connection in connections:
            alerts = analyze_network(connection)

            for alert in alerts:
                recorded = record_detection(
                    alert,
                    "NETWORK",
                    {
                        "pid": connection["pid"],
                        "process": connection["process"],
                        "executable": connection["executable"],
                        "remote_address": connection["remote_address"],
                    },
                )

                if recorded:
                    network_detection_count += 1

        print(f"Network detections: {network_detection_count}")
        print()

        # -------------------------------------------------
    else:
        print("Network monitor: DISABLED by policy")
        print()

    if POLICY["monitoring"]["monitor_files"]:
        # FILE MONITOR
        # -------------------------------------------------

        files = monitor_directory(PROJECT_ROOT)

        print("File monitor: ACTIVE")
        print(f"Files detected: {len(files)}")

        log_event(
            event_type="FILE_SCAN",
            severity="INFO",
            message="File scan completed.",
            details={"file_count": len(files)},
        )

        # Detect files that appeared after the baseline.
        new_files = detect_new_files_from_baseline(files)

        for file_info in new_files:
            new_file_alert = {
                "severity": "INFO",
                "rule": "NEW_FILE_DETECTED",
                "reason": (
                    f"A new file appeared since the previous scan: "
                    f"{file_info['path']}"
                ),
            }

            recorded = record_detection(
                new_file_alert,
                "FILE",
                {
                    "file": file_info.get("path"),
                },
            )

            if recorded:
                new_file_count += 1

        print(f"New files: {new_file_count}")

        # Analyze files using detection rules.
        for file_info in files:
            alerts = analyze_file(file_info)

            for alert in alerts:
                recorded = record_detection(
                    alert,
                    "FILE",
                    {
                        "file": file_info.get("path"),
                    },
                )

                if recorded:
                    file_detection_count += 1

        print(f"File detections: {file_detection_count}")
        print()

        # -------------------------------------------------
    else:
        print("File monitor: DISABLED by policy")
        print()

    # SUMMARY
    # -------------------------------------------------

    total_new_events = (
        new_process_count
        + process_detection_count
        + network_detection_count
        + new_file_count
        + file_detection_count
    )

    print("-" * 50)
    print("SCAN SUMMARY")
    print("-" * 50)
    print(f"New processes:          {new_process_count}")
    print(f"Process detections:     {process_detection_count}")
    print(f"Network detections:     {network_detection_count}")
    print(f"New files:              {new_file_count}")
    print(f"File detections:        {file_detection_count}")
    print(f"Total new events:       {total_new_events}")
    print(f"Known events:           {len(seen_detections)}")
    print()


def main():
    print("=" * 50)
    print("              AI-SHIELD")
    print("        Security Monitor v0.5")
    print("=" * 50)
    print()

    print("Security engine: STARTING")

    log_event(
        event_type="SYSTEM",
        severity="INFO",
        message="AI-SHIELD security engine started.",
    )

    print("Continuous monitoring: ACTIVE")
    print(f"Scan interval: {MONITOR_INTERVAL} seconds")
    print("Process baseline: ACTIVE")
    print("File baseline: ACTIVE")
    print()

    try:
        while True:
            print("=" * 50)
            print(
                "SCAN START:",
                datetime.now().astimezone().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            )
            print("=" * 50)
            print()

            run_scan()

            print("Security engine: RUNNING")
            print(
                f"Next scan in {MONITOR_INTERVAL} seconds..."
            )
            print()

            time.sleep(MONITOR_INTERVAL)

    except KeyboardInterrupt:
        print()
        print("=" * 50)
        print("AI-SHIELD monitoring stopped by user.")
        print("=" * 50)

        log_event(
            event_type="SYSTEM",
            severity="INFO",
            message="AI-SHIELD security engine stopped by user.",
        )


if __name__ == "__main__":
    main()