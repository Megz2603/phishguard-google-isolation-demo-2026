import json
import sqlite3

from email_system.encryption import migrate_email_fields
from scanner.languages import (
    DEFAULT_PRIMARY_LANGUAGE,
    DEFAULT_SECONDARY_LANGUAGES,
    normalize_language_preferences,
)


DATABASE = "emails.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    # Overwritten/deleted message content should not remain in SQLite free pages.
    connection.execute("PRAGMA secure_delete = ON")
    return connection


def initialise_database():
    connection = get_connection()
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                reasons TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                provider TEXT,
                external_id TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        _add_missing_email_columns(connection)
        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS email_provider_external_id
            ON emails (provider, external_id)
        """)
        _create_mail_tables(connection)

        # Migrate the old plaintext rows before the app can serve them.
        migrated_plaintext = migrate_email_fields(connection)
        connection.commit()
        if migrated_plaintext:
            # Rebuild the database so old plaintext cannot linger in unused pages.
            connection.execute("VACUUM")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_language_preferences():
    connection = get_connection()
    try:
        rows = dict(connection.execute("""
            SELECT key, value FROM app_settings
            WHERE key IN (
                'primary_language', 'secondary_languages', 'language_selected'
            )
        """).fetchall())
        primary_language = rows.get(
            "primary_language", DEFAULT_PRIMARY_LANGUAGE
        )
        secondary_languages = json.loads(rows.get(
            "secondary_languages",
            json.dumps(DEFAULT_SECONDARY_LANGUAGES),
        ))
        return normalize_language_preferences(
            primary_language, secondary_languages
        ) | {"language_selected": rows.get("language_selected") == "true"}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {
            "primary_language": DEFAULT_PRIMARY_LANGUAGE,
            "secondary_languages": list(DEFAULT_SECONDARY_LANGUAGES),
            "language_selected": False,
        }
    finally:
        connection.close()


def save_language_preferences(primary_language, secondary_languages):
    preferences = normalize_language_preferences(
        primary_language, secondary_languages
    )
    connection = get_connection()
    try:
        connection.executemany("""
            INSERT INTO app_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (
            ("primary_language", preferences["primary_language"]),
            (
                "secondary_languages",
                json.dumps(preferences["secondary_languages"]),
            ),
            ("language_selected", "true"),
        ))
        connection.commit()
    finally:
        connection.close()
    return preferences


def _add_missing_email_columns(connection):
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(emails)")
    }
    for column in ("provider", "external_id"):
        if column not in columns:
            connection.execute(f"ALTER TABLE emails ADD COLUMN {column} TEXT")


def _create_mail_tables(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS mail_accounts (
            provider TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            encrypted_token TEXT NOT NULL,
            auth_method TEXT NOT NULL DEFAULT 'oauth',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(mail_accounts)")
    }
    if "auth_method" not in columns:
        connection.execute(
            "ALTER TABLE mail_accounts ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'oauth'"
        )
    connection.execute("""
        CREATE TABLE IF NOT EXISTS mail_syncs (
            provider TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            processed INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
