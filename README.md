# AI-SHIELD

A Python-based Windows security monitoring and risk assessment project.

AI-SHIELD monitors selected system activity, evaluates configurable detection rules, assigns risk scores, and generates incident reports.

## Features

- Process monitoring
- Network connection monitoring
- Periodic file monitoring
- Configurable detection rules
- Risk scoring
- Voice alerts
- JSONL event logging
- Text and CSV incident reports
- Policy configuration
- Automated tests

## Requirements

- Windows
- Python 3.13 or compatible
- psutil
- pyttsx3 for voice alerts

Install dependencies:

```powershell
python -m pip install psutil pyttsx3
## Run the Monitor

From the project root:

```powershell
python src\main.py
python src\incident_report.py
python -m unittest discover -s .\tests -v
python -m compileall -q .\src .\tests
Safety and Limitations

Automatic blocking is disabled by default.

This project is a monitoring and detection tool, not a guarantee of protection against all threats or AI agents.

File monitoring is periodic, not guaranteed real-time monitoring.

Some system information may be unavailable because of Windows permissions.

Detection results may include false positives and should be reviewed.

Project Status

AI-SHIELD is under active development. Future improvements may include a dashboard, additional detection rules, and carefully controlled response features.

License

No license has been selected yet. All rights remain with the copyright holder until a license is added.
