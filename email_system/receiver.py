from scanner.scanner import scan_email
from database import get_language_preferences
from models import save_email


def receive_email(user_id, sender, subject, body):
    # Scan before storage so message text only needs to be decrypted for display.
    preferences = get_language_preferences(user_id)
    result = scan_email(
        sender,
        subject,
        body,
        primary_language=preferences["primary_language"],
        secondary_languages=preferences["secondary_languages"],
    )
    reasons = "; ".join(result["reasons"])

    email_id = save_email(
        user_id=user_id,
        sender=sender,
        subject=subject,
        body=body,
        risk_score=result["risk_score"],
        status=result["status"],
        reasons=reasons
    )

    return {
        "id": email_id,
        "sender": sender,
        "subject": subject,
        "risk_score": result["risk_score"],
        "status": result["status"],
        "reasons": result["reasons"]
    }
