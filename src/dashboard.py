import html
import json
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = ROOT / "logs" / "events.jsonl"
HOST = "127.0.0.1"
PORT = 8765


def read_events():
    events = []
    invalid_lines = 0

    if not LOG_PATH.exists():
        return events, invalid_lines

    with LOG_PATH.open("r", encoding="utf-8-sig") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
                else:
                    invalid_lines += 1
            except json.JSONDecodeError:
                invalid_lines += 1

    return events, invalid_lines


def esc(value):
    return html.escape(str(value if value is not None else "—"))


def make_page():
    events, invalid_lines = read_events()
    event_types = Counter(
        str(event.get("event_type", "UNKNOWN")).upper()
        for event in events
    )
    severities = Counter(
        str(event.get("severity", "UNKNOWN")).upper()
        for event in events
    )

    detections = [
        event for event in events
        if str(event.get("event_type", "")).upper() == "DETECTION"
    ]
    detections.reverse()
    recent = detections[:10]

    severity_cards = ""
    for severity in ("INFO", "WARNING", "HIGH", "CRITICAL", "UNKNOWN"):
        severity_cards += (
            '<div class="card"><div class="muted">'
            + esc(severity)
            + '</div><div class="number">'
            + str(severities.get(severity, 0))
            + "</div></div>"
        )

    event_rows = ""
    for name, count in event_types.most_common():
        event_rows += (
            "<tr><td>" + esc(name) + "</td><td>" + str(count) + "</td></tr>"
        )

    detection_rows = ""
    for event in recent:
        details = event.get("details")
        if not isinstance(details, dict):
            details = {}

        severity = str(event.get("severity", "UNKNOWN")).upper()
        detection_rows += (
            "<tr><td>" + esc(event.get("timestamp"))
            + '</td><td><span class="severity '
            + esc(severity.lower()) + '">'
            + esc(severity) + "</span></td><td>"
            + esc(details.get("rule", "—")) + "</td><td>"
            + esc(details.get("source", "—")) + "</td><td>"
            + esc(event.get("message", "—")) + "</td></tr>"
        )

    if not detection_rows:
        detection_rows = (
            '<tr><td colspan="5">No detection events found in the log.</td></tr>'
        )

    if not event_rows:
        event_rows = '<tr><td colspan="2">No events found.</td></tr>'

    latest_timestamp = "No timestamp available"
    if events:
        latest_timestamp = str(events[-1].get("timestamp", latest_timestamp))

    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="10">
<title>AI-SHIELD Dashboard</title>
<style>
body { font-family: Arial, sans-serif; margin: 0; background: #f3f5f8; color: #182230; }
header { background: #172554; color: white; padding: 24px; }
header h1 { margin: 0 0 8px; }
main { max-width: 1200px; margin: 24px auto; padding: 0 16px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap: 12px; }
.card, section { background: white; padding: 18px; border-radius: 10px; margin-bottom: 18px; box-shadow: 0 2px 8px #0000000b; }
.number { font-size: 28px; font-weight: bold; margin-top: 8px; }
.muted { color: #667085; font-size: 13px; }
h2 { margin-top: 0; font-size: 19px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 11px 9px; border-bottom: 1px solid #e5e7eb; overflow-wrap: anywhere; }
th { background: #f8fafc; }
.table-wrap { overflow-x: auto; }
.severity { display: inline-block; padding: 4px 7px; border-radius: 5px; font-size: 12px; font-weight: bold; }
.warning { background: #fff0c2; color: #7a4b00; }
.high, .critical { background: #fee2e2; color: #991b1b; }
.info { background: #e0f2fe; color: #075985; }
.unknown { background: #e5e7eb; color: #374151; }
.note { color: #475467; line-height: 1.5; }
footer { padding: 16px 0 28px; color: #667085; font-size: 13px; }
</style>
</head>
<body>
<header>
<h1>AI-SHIELD</h1>
<div>Local Security Monitoring Dashboard</div>
</header>
<main>
<section>
<h2>Log overview</h2>
<div class="cards">
<div class="card"><div class="muted">Total valid events</div>
<div class="number">""" + str(len(events)) + """</div></div>
<div class="card"><div class="muted">Detection events</div>
<div class="number">""" + str(len(detections)) + """</div></div>
<div class="card"><div class="muted">Invalid log lines</div>
<div class="number">""" + str(invalid_lines) + """</div></div>
</div>
<p class="note">Latest recorded event timestamp: """ + esc(latest_timestamp) + """</p>
<p class="note">These figures summarize the log file. They do not confirm that an attack occurred.</p>
</section>
<section>
<h2>Events by severity</h2>
<div class="cards">""" + severity_cards + """</div>
</section>
<section>
<h2>Events by type</h2>
<div class="table-wrap"><table><thead><tr><th>Event type</th><th>Count</th></tr></thead>
<tbody>""" + event_rows + """</tbody></table></div>
</section>
<section>
<h2>10 most recent detection records</h2>
<div class="table-wrap"><table><thead><tr>
<th>Timestamp</th><th>Severity</th><th>Rule</th><th>Source</th><th>Message</th>
</tr></thead><tbody>""" + detection_rows + """</tbody></table></div>
</section>
<p class="note">Read-only dashboard. It does not block processes, change files, or start the monitor. The page refreshes every 10 seconds.</p>
<footer>AI-SHIELD · Local dashboard · Log: logs/events.jsonl</footer>
</main>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404, "Page not found")
            return

        try:
            page = make_page().encode("utf-8")
        except OSError:
            page = (
                "<h1>AI-SHIELD Dashboard</h1>"
                "<p>Could not read the event log. Check logs/events.jsonl.</p>"
            ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, format_string, *args):
        print("[Dashboard]", format_string % args)


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print("AI-SHIELD Dashboard")
    print("Open: http://127.0.0.1:8765")
    print("Reading:", LOG_PATH)
    print("Press Ctrl+C to stop the dashboard.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
