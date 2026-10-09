from voice_alert import speak_alert


def show_alert(alert, risk, details, voice_enabled=True):
    severity = alert.get("severity", "UNKNOWN")
    risk_score = risk.get("score", 0)
    risk_level = risk.get("level", "UNKNOWN")
    rule = alert.get("rule", "UNKNOWN")
    source = details.get("source", "UNKNOWN")
    reason = alert.get("reason", "No reason provided.")

    print()
    print("=" * 60)
    print("⚠ AI-SHIELD ALERT")
    print("=" * 60)

    print(f"Severity:   {severity}")
    print(f"Risk Score: {risk_score}")
    print(f"Risk Level: {risk_level}")
    print(f"Rule:       {rule}")
    print(f"Source:     {source}")

    if details.get("process"):
        print(f"Process:    {details['process']}")

    if details.get("pid") is not None:
        print(f"PID:        {details['pid']}")

    if details.get("executable"):
        print(f"Location:   {details['executable']}")

    if details.get("file"):
        print(f"File:       {details['file']}")

    if details.get("remote_address"):
        print(f"Remote:     {details['remote_address']}")

    print()
    print(f"Reason:     {reason}")
    print("=" * 60)
    print()

    # Voice alerts are enabled for WARNING and above.
    if voice_enabled and severity.upper() in {"WARNING", "HIGH", "CRITICAL"}:
        voice_message = (
            f"AI Shield {severity.lower()}. "
            f"{reason}"
        )

        speak_alert(voice_message)