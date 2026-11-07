from scanner.scoring import calculate_score


def scan_email(sender, subject, body):
    risk_score, reasons = calculate_score(sender, subject, body)

    # Keep the folder thresholds aligned with the dashboard and README.
    if risk_score >= 70:
        status = "quarantine"
    elif risk_score >= 30:
        status = "review"
    else:
        status = "inbox"

    return {
        "risk_score": risk_score,
        "status": status,
        "reasons": reasons
    }
