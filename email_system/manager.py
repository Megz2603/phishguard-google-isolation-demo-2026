from models import update_email_status


def move_to_inbox(email_id):
    update_email_status(email_id, "inbox")


def move_to_review(email_id):
    update_email_status(email_id, "review")


def move_to_quarantine(email_id):
    update_email_status(email_id, "quarantine")
