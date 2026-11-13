import base64
import hashlib
import importlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from cryptography.fernet import Fernet

import database
import models
from email_system.encryption import (
    DPAPI_FIELD_PREFIX,
    FIELD_PREFIX,
    KEY_CHECK,
    EncryptionError,
    decrypt_secret,
    encrypt_field,
    encrypt_secret,
)
from email_system.mailbox import MailboxError


class AuthenticationIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.import_directory = tempfile.TemporaryDirectory()
        cls.import_database = str(Path(cls.import_directory.name) / "app-import.db")
        cls.environment_patch = patch.dict(os.environ, {
                "APP_SECRET_KEY": "test-key-" + "x" * 40,
                "APP_ENV": "development",
                "APP_DATA_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
            })
        cls.environment_patch.start()
        with patch.object(database, "DATABASE", cls.import_database), patch(
            "email_system.mailbox.unlock_oauth_credentials"
        ):
            cls.app_module = importlib.import_module("app")

    @classmethod
    def tearDownClass(cls):
        cls.environment_patch.stop()
        cls.import_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.directory.name) / "emails.db")
        self.database_patch = patch.object(database, "DATABASE", self.database_path)
        self.database_patch.start()
        database.initialise_database()
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.database_patch.stop()
        self.directory.cleanup()

    def sign_in_as(self, user_id):
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = user_id
            browser_session["user_email"] = f"{user_id}@example.com"
            browser_session["csrf_token"] = f"csrf-{user_id}"
        return {"X-CSRF-Token": f"csrf-{user_id}"}

    def test_private_routes_reject_unauthenticated_requests(self):
        requests = (
            ("get", "/emails"),
            ("get", "/emails/inbox"),
            ("get", "/emails/1"),
            ("get", "/mail/accounts"),
            ("get", "/mail/sync/google/status"),
            ("get", "/api/language-settings"),
            ("post", "/emails"),
            ("post", "/mail/sync/google"),
            ("put", "/emails/1/move"),
            ("delete", "/emails/1"),
            ("delete", "/emails"),
        )
        for method, path in requests:
            with self.subTest(method=method, path=path):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_user_cannot_read_update_or_delete_another_users_email(self):
        with (
            patch.object(models, "encrypt_field", side_effect=lambda value: value),
            patch.object(models, "decrypt_field", side_effect=lambda value: value),
        ):
            user_a_email = models.save_email(
                "user-a", "a@example.com", "A", "A body", 1, "inbox", ""
            )
            user_b_email = models.save_email(
                "user-b", "b@example.com", "B", "B body", 2, "inbox", ""
            )
            headers = self.sign_in_as("user-a")

            response = self.client.get("/emails")
            self.assertEqual([email["id"] for email in response.get_json()], [user_a_email])
            self.assertEqual(self.client.get(f"/emails/{user_b_email}").status_code, 404)
            self.assertEqual(
                self.client.put(
                    f"/emails/{user_b_email}/move",
                    json={"status": "quarantine"},
                    headers=headers,
                ).status_code,
                404,
            )
            self.assertEqual(
                self.client.delete(f"/emails/{user_b_email}", headers=headers).status_code,
                404,
            )
            response = self.client.delete("/emails", headers=headers)
            self.assertEqual(response.get_json(), {"deleted_count": 1})

        connection = database.get_connection()
        try:
            row = connection.execute(
                "SELECT user_id, status FROM emails WHERE id = ?", (user_b_email,)
            ).fetchone()
            self.assertEqual((row["user_id"], row["status"]), ("user-b", "inbox"))
        finally:
            connection.close()

    def test_mail_accounts_sync_state_and_language_settings_are_user_scoped(self):
        connection = database.get_connection()
        connection.executemany("""
            INSERT INTO mail_accounts
                (user_id, provider, email, encrypted_token, auth_method)
            VALUES (?, 'google', ?, 'token', 'oauth')
        """, [
            ("user-a", "a@example.com"),
            ("user-b", "b@example.com"),
        ])
        connection.executemany("""
            INSERT INTO mail_syncs
                (user_id, provider, status, processed)
            VALUES (?, 'google', ?, ?)
        """, [
            ("user-a", "complete", 4),
            ("user-b", "error", 9),
        ])
        connection.commit()
        connection.close()

        headers = self.sign_in_as("user-a")
        with patch("email_system.mailbox.decrypt_secret", side_effect=lambda value: value):
            accounts = self.client.get("/mail/accounts").get_json()
        self.assertEqual([account["email"] for account in accounts], ["a@example.com"])
        self.assertEqual(
            self.client.get("/mail/sync/google/status").get_json()["status"],
            "complete",
        )

        settings_payload = {
            "primary_language": "af",
            "secondary_languages": ["zu"],
        }
        self.assertEqual(
            self.client.put(
                "/api/language-settings", json=settings_payload
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.put(
                "/api/language-settings", json=settings_payload, headers=headers
            ).status_code,
            200,
        )
        self.sign_in_as("user-b")
        self.assertEqual(
            self.client.get("/api/language-settings").get_json()["primary_language"],
            "en",
        )

        self.sign_in_as("user-a")
        with patch("email_system.mailbox._sync_lock") as sync_lock:
            sync_lock.acquire.return_value = True
            response = self.client.delete("/mail/accounts/google", headers=headers)
        self.assertEqual(response.status_code, 200)
        connection = database.get_connection()
        try:
            account_users = {
                row["user_id"] for row in connection.execute(
                    "SELECT user_id FROM mail_accounts"
                )
            }
            sync_users = {
                row["user_id"] for row in connection.execute(
                    "SELECT user_id FROM mail_syncs"
                )
            }
            self.assertEqual(account_users, {"user-b"})
            self.assertEqual(sync_users, {"user-b"})
        finally:
            connection.close()

    def test_oauth_rejects_unverified_google_identity(self):
        from email_system import mailbox

        with (
            patch.object(mailbox, "_oauth_settings", return_value=("client", "secret", "https://callback")),
            patch.object(mailbox, "_form_post", return_value={"access_token": "token"}),
            patch.object(mailbox, "_google_json", return_value={
                "sub": "attacker-sub",
                "email": "owner@example.com",
                "email_verified": False,
            }),
            patch.object(mailbox, "claim_legacy_data") as claim,
        ):
            _, state = mailbox.authorization_url()
            with self.assertRaisesRegex(MailboxError, "verified"):
                mailbox.finish_authorization(state, "code")
        claim.assert_not_called()

    def test_oauth_callback_rejects_state_from_another_browser_session(self):
        with self.client.session_transaction() as browser_session:
            browser_session["oauth_state"] = "expected-state"
        with patch.object(self.app_module, "finish_authorization") as finish:
            response = self.client.get(
                "/auth/google/callback?state=attacker-state&code=code"
            )
        self.assertEqual(response.status_code, 302)
        finish.assert_not_called()
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("user_id", browser_session)

    def test_oauth_verifier_is_stored_and_consumed_once_from_database(self):
        from email_system import mailbox

        with patch.object(
            mailbox, "_oauth_settings",
            return_value=("client", "secret", "https://callback"),
        ):
            login_url, state = mailbox.authorization_url()
        encrypted = database.consume_oauth_login(state)
        self.assertTrue(encrypted)
        verifier = decrypt_secret(encrypted)
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        self.assertEqual(
            parse_qs(urlparse(login_url).query)["code_challenge"][0],
            expected_challenge,
        )
        self.assertIsNone(database.consume_oauth_login(state))

    def test_portable_encryption_round_trips_and_rejects_another_key(self):
        encryption_key = Fernet.generate_key().decode("ascii")
        with patch.dict(os.environ, {"APP_DATA_ENCRYPTION_KEY": encryption_key}):
            protected = encrypt_secret("private token")
            self.assertTrue(protected.startswith(FIELD_PREFIX))
            self.assertEqual(decrypt_secret(protected), "private token")
        with patch.dict(
            os.environ,
            {"APP_DATA_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")},
        ):
            with self.assertRaisesRegex(EncryptionError, "incorrect"):
                decrypt_secret(protected)

    @unittest.skipUnless(os.name == "nt", "DPAPI migration requires Windows")
    def test_dpapi_data_can_be_reencrypted_with_a_portable_key_on_its_original_host(self):
        database_path = str(Path(self.directory.name) / "dpapi-migration.db")
        with (
            patch.object(database, "DATABASE", database_path),
            patch.dict(os.environ, {"APP_DATA_ENCRYPTION_KEY": ""}),
        ):
            database.initialise_database()
            email_id = models.save_email(
                "owner-sub", "owner@example.com", "Subject", "Body",
                10, "review", "Reason",
            )
            connection = database.get_connection()
            connection.execute("""
                INSERT INTO mail_accounts
                    (user_id, provider, email, encrypted_token)
                VALUES (?, 'google', ?, ?)
            """, (
                "owner-sub",
                encrypt_field("owner@example.com"),
                encrypt_secret('{"access_token":"token"}'),
            ))
            connection.commit()
            connection.close()

            connection = database.get_connection()
            old_check = connection.execute(
                "SELECT value FROM encryption_metadata WHERE name = 'key_check'"
            ).fetchone()["value"]
            connection.close()
            self.assertTrue(old_check.startswith(DPAPI_FIELD_PREFIX))

        portable_key = Fernet.generate_key().decode("ascii")
        with (
            patch.object(database, "DATABASE", database_path),
            patch.dict(os.environ, {"APP_DATA_ENCRYPTION_KEY": portable_key}),
        ):
            database.initialise_database()
            connection = database.get_connection()
            try:
                account = connection.execute(
                    "SELECT email, encrypted_token FROM mail_accounts WHERE user_id = ?",
                    ("owner-sub",),
                ).fetchone()
                check = connection.execute(
                    "SELECT value FROM encryption_metadata WHERE name = 'key_check'"
                ).fetchone()["value"]
                email = models.get_email("owner-sub", email_id)
                self.assertEqual(email["subject"], "Subject")
                self.assertEqual(email["body"], "Body")
                self.assertTrue(account["email"].startswith(FIELD_PREFIX))
                self.assertEqual(decrypt_secret(account["email"]), "owner@example.com")
                self.assertTrue(account["encrypted_token"].startswith(FIELD_PREFIX))
                self.assertEqual(
                    decrypt_secret(account["encrypted_token"]),
                    '{"access_token":"token"}',
                )
                self.assertTrue(check.startswith(FIELD_PREFIX))
            finally:
                connection.close()

    def test_unassigned_legacy_data_requires_the_configured_owner_identity(self):
        connection = database.get_connection()
        connection.execute(
            "INSERT INTO app_settings (user_id, key, value) VALUES (NULL, ?, ?)",
            ("primary_language", "af"),
        )
        connection.commit()
        connection.close()

        with patch.dict(os.environ, {"LEGACY_DATA_OWNER_EMAIL": ""}):
            with self.assertRaisesRegex(ValueError, "LEGACY_DATA_OWNER_EMAIL"):
                database.claim_legacy_data("attacker-sub", "owner@example.com")

        with patch.dict(os.environ, {"LEGACY_DATA_OWNER_EMAIL": "owner@example.com"}):
            with self.assertRaisesRegex(ValueError, "reserved"):
                database.claim_legacy_data("attacker-sub", "attacker@example.com")
            connection = database.get_connection()
            try:
                self.assertIsNone(connection.execute(
                    "SELECT user_id FROM app_settings WHERE key = 'primary_language'"
                ).fetchone()["user_id"])
            finally:
                connection.close()

            database.claim_legacy_data("owner-sub", "OWNER@example.com")

        connection = database.get_connection()
        try:
            row = connection.execute(
                "SELECT user_id, value FROM app_settings WHERE key = 'primary_language'"
            ).fetchone()
            self.assertEqual((row["user_id"], row["value"]), ("owner-sub", "af"))
        finally:
            connection.close()

    def test_existing_schema_preserves_and_owner_assigns_legacy_settings_and_syncs(self):
        legacy_path = str(Path(self.directory.name) / "legacy.db")
        protected_check = encrypt_secret(KEY_CHECK.decode("utf-8"))
        protected_email = encrypt_field("owner@example.com")
        connection = sqlite3.connect(legacy_path)
        connection.executescript("""
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
                risk_score INTEGER NOT NULL, status TEXT NOT NULL, reasons TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                provider TEXT, external_id TEXT
            );
            CREATE TABLE app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO app_settings (key, value) VALUES ('primary_language', 'af');
            CREATE TABLE mail_accounts (
                provider TEXT PRIMARY KEY, email TEXT NOT NULL,
                encrypted_token TEXT NOT NULL, auth_method TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE mail_syncs (
                provider TEXT PRIMARY KEY, status TEXT NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0, error TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO mail_syncs (provider, status, processed)
            VALUES ('google', 'complete', 12);
            CREATE TABLE encryption_metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        connection.execute("""
            INSERT INTO encryption_metadata (name, value) VALUES ('key_check', ?)
        """, (protected_check,))
        connection.execute("""
            INSERT INTO emails
                (sender, subject, body, risk_score, status, reasons, provider, external_id)
            VALUES (?, ?, ?, 8, 'review', ?, 'google', 'legacy-message')
        """, (
            protected_email,
            encrypt_field("Legacy message"),
            encrypt_field("Preserved body"),
            encrypt_field("Legacy reason"),
        ))
        connection.execute("""
            INSERT INTO mail_accounts
                (provider, email, encrypted_token, auth_method)
            VALUES ('google', ?, 'preserved-token', 'oauth')
        """, (protected_email,))
        connection.commit()
        connection.close()

        with patch.object(database, "DATABASE", legacy_path):
            database.initialise_database()
            connection = database.get_connection()
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT value FROM app_settings WHERE key = 'primary_language'"
                    ).fetchone()["value"],
                    "af",
                )
                self.assertIsNone(connection.execute(
                    "SELECT user_id FROM mail_syncs WHERE provider = 'google'"
                ).fetchone()["user_id"])
            finally:
                connection.close()

            with patch.dict(os.environ, {"LEGACY_DATA_OWNER_EMAIL": "owner@example.com"}):
                with self.assertRaisesRegex(ValueError, "reserved"):
                    database.claim_legacy_data("other-sub", "other@example.com")
                database.claim_legacy_data("owner-sub", "owner@example.com")

            connection = database.get_connection()
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT user_id, value FROM app_settings WHERE key = 'primary_language'"
                    ).fetchone()[:],
                    ("owner-sub", "af"),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT user_id, status, processed FROM mail_syncs"
                    ).fetchone()[:],
                    ("owner-sub", "complete", 12),
                )
                email_row = connection.execute(
                    "SELECT * FROM emails"
                ).fetchone()
                self.assertEqual(email_row["user_id"], "owner-sub")
                self.assertEqual(models._decode_email(email_row)["subject"], "Legacy message")
                legacy_account = connection.execute(
                    "SELECT user_id, email, encrypted_token FROM mail_accounts WHERE provider = 'google' AND user_id = 'owner-sub'"
                ).fetchone()
                self.assertEqual(legacy_account["email"], protected_email)
                self.assertEqual(legacy_account["encrypted_token"], "preserved-token")
                connection.executemany("""
                    INSERT INTO mail_accounts
                        (user_id, provider, email, encrypted_token)
                    VALUES (?, 'google', ?, 'token')
                """, [
                    ("other-sub", "other@example.com"),
                ])
                connection.commit()
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM mail_accounts").fetchone()[0],
                    2,
                )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
