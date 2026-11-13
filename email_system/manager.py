from models import update_email_status


def move_to_inbox(user_id, email_id):
    update_email_status(user_id, email_id, "inbox")


def move_to_review(user_id, email_id):
    update_email_status(user_id, email_id, "review")


def move_to_quarantine(user_id, email_id):
    update_email_status(user_id, email_id, "quarantine")
