import threading
import time
import unittest
from unittest.mock import patch

from email_system import mailbox


class MailboxSyncTests(unittest.TestCase):
    def test_gmail_message_fetches_run_concurrently(self):
        state_lock = threading.Lock()
        active = 0
        max_active = 0

        def fake_google_json(url, access_token):
            nonlocal active, max_active
            if "/messages?" in url:
                return {"messages": [{"id": str(index)} for index in range(16)]}
            if "/messages/" in url:
                with state_lock:
                    active += 1
                    max_active = max(max_active, active)
                time.sleep(0.01)
                with state_lock:
                    active -= 1
                message_id = url.split("/messages/")[1].split("?")[0]
                return {
                    "id": message_id,
                    "internalDate": "0",
                    "payload": {
                        "headers": [
                            {"name": "From", "value": "Sender <sender@example.com>"},
                            {"name": "Subject", "value": "Hello"},
                        ],
                        "mimeType": "text/plain",
                        "body": {"data": "SGVsbG8"},
                    },
                }
            self.fail(f"Unexpected Gmail API URL: {url}")

        with patch.object(mailbox, "_google_json", side_effect=fake_google_json):
            messages = list(mailbox._gmail_messages("token"))

        self.assertEqual(len(messages), 16)
        self.assertGreater(max_active, 1)
        self.assertEqual(messages[0]["sender"], "sender@example.com")

    def test_sync_inserts_and_reports_progress_in_batches(self):
        messages = [
            {
                "sender": f"sender{index}@example.com",
                "subject": "Hello",
                "body": "Good morning",
                "external_id": str(index),
                "received_at": None,
            }
            for index in range(205)
        ]
        batches = []
        progress = []
        self.assertTrue(mailbox._sync_lock.acquire(blocking=False))
        try:
            with (
                patch.object(mailbox, "_access_token", return_value="token"),
                patch.object(mailbox, "get_language_preferences", return_value={
                    "primary_language": "en",
                    "secondary_languages": [],
                }),
                patch.object(mailbox, "_gmail_messages", return_value=iter(messages)),
                patch.object(mailbox, "scan_email", return_value={
                    "risk_score": 0,
                    "status": "inbox",
                    "reasons": [],
                }),
                patch.object(mailbox, "save_emails", side_effect=lambda user_id, batch: batches.append(list(batch))),
                patch.object(mailbox, "_set_sync", side_effect=lambda user_id, status, processed=0, error=None: progress.append((status, processed))),
            ):
                mailbox._run_sync("user-a")
        finally:
            if mailbox._sync_lock.locked():
                mailbox._sync_lock.release()

        self.assertEqual([len(batch) for batch in batches], [100, 100, 5])
        self.assertEqual(progress, [
            ("running", 100),
            ("running", 200),
            ("complete", 205),
        ])


if __name__ == "__main__":
    unittest.main()
