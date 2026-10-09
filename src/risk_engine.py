def calculate_event_risk(alert):
    severity = alert.get("severity", "")
    severity = severity.upper() if isinstance(severity, str) else ""

    severity_scores = {
        "INFO": 0,
        "WARNING": 25,
        "HIGH": 50,
        "CRITICAL": 75,
    }

    if severity not in severity_scores:
        return {
            "score": None,
            "level": "UNKNOWN",
        }

    score = severity_scores[severity]

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "WARNING"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
    }


def calculate_risk(alerts):
    score = 0

    for alert in alerts:
        severity = alert.get("severity", "")
        severity = severity.upper() if isinstance(severity, str) else ""

        severity_scores = {
            "INFO": 0,
            "WARNING": 25,
            "HIGH": 50,
            "CRITICAL": 75,
        }

        if severity not in severity_scores:
            return {
                "score": None,
                "level": "UNKNOWN",
            }

        score += severity_scores[severity]

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "WARNING"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
    }
