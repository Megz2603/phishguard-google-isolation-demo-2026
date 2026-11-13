import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit
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
                return {
                    "messages": [{"id": str(index)} for index in range(16)],
                    "nextPageToken": "next-page",
                }
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
            messages, next_page = mailbox._gmail_messages("token", limit=20)

        self.assertEqual(len(messages), 16)
        self.assertEqual(next_page, "next-page")
        self.assertGreater(max_active, 1)
        self.assertEqual(messages[0]["sender"], "sender@example.com")

    def test_gmail_messages_requests_one_page_with_the_given_limit_and_cursor(self):
        requests = []

        def fake_google_json(url, access_token):
            requests.append((parse_qs(urlsplit(url).query), access_token))
            return {"messages": [], "nextPageToken": "next-page"}

        with patch.object(mailbox, "_google_json", side_effect=fake_google_json):
            messages, next_page = mailbox._gmail_messages(
                "token",
                page_token="current-page",
                limit=40,
            )

        self.assertEqual(messages, [])
        self.assertEqual(next_page, "next-page")
        self.assertEqual(requests, [({
            "maxResults": ["40"],
            "pageToken": ["current-page"],
        }, "token")])

    def test_sync_scans_20_then_40_from_saved_gmail_page_cursor(self):
        def messages(count, offset):
            return [
                {
                    "sender": f"sender{index}@example.com",
                    "subject": "Hello",
                    "body": "Good morning",
                    "external_id": str(index),
                    "received_at": None,
                }
                for index in range(offset, offset + count)
            ]
        page_states = [
            {"next_page_token": None, "batch_number": 0, "has_more": True},
            {"next_page_token": "page-2", "batch_number": 1, "has_more": True},
        ]
        fetched = []
        completed = []

        def fake_gmail_messages(access_token, page_token=None, limit=20):
            fetched.append((page_token, limit))
            if limit == 20:
                return messages(20, 0), "page-2"
            return messages(40, 20), None

        batches = []
        with (
            patch.object(mailbox, "_access_token", return_value="token"),
            patch.object(mailbox, "get_language_preferences", return_value={
                "primary_language": "en",
                "secondary_languages": [],
            }),
            patch.object(mailbox, "_sync_page_state", side_effect=page_states),
            patch.object(mailbox, "_gmail_messages", side_effect=fake_gmail_messages),
            patch.object(mailbox, "scan_email", return_value={
                "risk_score": 0,
                "status": "inbox",
                "reasons": [],
            }),
            patch.object(mailbox, "save_emails", side_effect=lambda user_id, batch: batches.append(list(batch))),
            patch.object(mailbox, "_set_sync_page", side_effect=lambda *args: completed.append(args)),
        ):
            for _ in range(2):
                self.assertTrue(mailbox._sync_lock.acquire(blocking=False))
                mailbox._run_sync("user-a")

        self.assertEqual(fetched, [(None, 20), ("page-2", 40)])
        self.assertEqual([len(batch) for batch in batches], [20, 40])
        self.assertEqual(completed, [
            ("user-a", "complete", 20, None, "page-2", 1),
            ("user-a", "complete", 40, None, None, 2),
        ])


if __name__ == "__main__":
    unittest.main()
