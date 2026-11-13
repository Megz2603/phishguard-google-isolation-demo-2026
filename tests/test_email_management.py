import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from database import get_connection, initialise_database
from email_system.mailbox import MailboxError, clear_saved_emails, _sync_lock
from models import delete_all_emails


class EmailManagementTests(unittest.TestCase):
    def test_clear_removes_emails_without_removing_settings_or_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("database.DATABASE", str(Path(directory) / "emails.db")),
                patch.dict(os.environ, {
                    "APP_DATA_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
                }),
            ):
                initialise_database()
                connection = get_connection()
                connection.executemany("""
                    INSERT INTO emails
                    (user_id, sender, subject, body, risk_score, status, reasons)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, [
                    ("user-a", "one@example.com", "One", "First", 1, "inbox", ""),
                    ("user-a", "two@example.com", "Two", "Second", 2, "review", ""),
                ])
                connection.execute(
                    "INSERT INTO app_settings (user_id, key, value) VALUES (?, ?, ?)",
                    ("user-a", "primary_language", "en"),
                )
                connection.execute("""
                    INSERT INTO mail_accounts
                    (user_id, provider, email, encrypted_token, auth_method)
                    VALUES (?, ?, ?, ?, ?)
                """, ("user-a", "google", "user@example.com", "encrypted", "oauth"))
                connection.commit()
                connection.close()

                self.assertEqual(delete_all_emails("user-a"), 2)

                connection = get_connection()
                try:
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM emails").fetchone()[0],
                        0,
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM app_settings"
                        ).fetchone()[0],
                        1,
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM mail_accounts"
                        ).fetchone()[0],
                        1,
                    )
                finally:
                    connection.close()

    def test_delete_endpoint_clears_emails_and_reports_the_count(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "emails.db")
            with (
                patch("database.DATABASE", database_path),
                patch("email_system.mailbox.unlock_oauth_credentials"),
                patch.dict(os.environ, {
                    "APP_SECRET_KEY": "test-secret-" + "x" * 40,
                    "APP_ENV": "development",
                    "APP_DATA_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
                }),
            ):
                initialise_database()
                app_module = importlib.import_module("app")
                connection = get_connection()
                connection.executemany("""
                    INSERT INTO emails
                    (user_id, sender, subject, body, risk_score, status, reasons)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, [
                    ("user-a", "one@example.com", "One", "First", 1, "inbox", ""),
                    ("user-a", "two@example.com", "Two", "Second", 2, "review", ""),
                ])
                connection.commit()
                connection.close()

                client = app_module.app.test_client()
                with client.session_transaction() as browser_session:
                    browser_session["user_id"] = "user-a"
                    browser_session["csrf_token"] = "csrf-test-token"
                self.assertTrue(_sync_lock.acquire(blocking=False))
                try:
                    response = client.delete(
                        "/emails", headers={"X-CSRF-Token": "csrf-test-token"}
                    )
                finally:
                    _sync_lock.release()
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.get_json()["code"], "sync_in_progress")

                response = client.delete(
                    "/emails", headers={"X-CSRF-Token": "csrf-test-token"}
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), {"deleted_count": 2})

    def test_clear_is_refused_while_gmail_sync_holds_the_lock(self):
        self.assertTrue(_sync_lock.acquire(blocking=False))
        try:
            with self.assertRaises(MailboxError):
                clear_saved_emails("user-a")
        finally:
            _sync_lock.release()


if __name__ == "__main__":
    unittest.main()
