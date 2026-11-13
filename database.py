import json
import os
import sqlite3
import time

from email_system.encryption import migrate_email_fields
from scanner.languages import (
    DEFAULT_PRIMARY_LANGUAGE,
    DEFAULT_SECONDARY_LANGUAGES,
    normalize_language_preferences,
)


DATABASE = os.environ.get("DATABASE_PATH", "emails.db")


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
        _add_user_ownership_columns(connection)
        _create_oauth_table(connection)
        _upgrade_settings_table(connection)
        _upgrade_mail_tables(connection)
        connection.execute("""
            DROP INDEX IF EXISTS email_provider_external_id
        """)
        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS email_user_provider_external_id
            ON emails (user_id, provider, external_id)
        """)

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


def get_language_preferences(user_id):
    connection = get_connection()
    try:
        rows = dict(connection.execute("""
            SELECT key, value FROM app_settings WHERE user_id = ?
            AND key IN (
                'primary_language', 'secondary_languages', 'language_selected'
            )
        """, (user_id,)).fetchall())
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


def save_language_preferences(user_id, primary_language, secondary_languages):
    preferences = normalize_language_preferences(
        primary_language, secondary_languages
    )
    connection = get_connection()
    try:
        connection.executemany("""
            INSERT INTO app_settings (user_id, key, value) VALUES (?, ?, ?)
            ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value
        """, (
            (user_id, "primary_language", preferences["primary_language"]),
            (
                user_id,
                "secondary_languages",
                json.dumps(preferences["secondary_languages"]),
            ),
            (user_id, "language_selected", "true"),
        ))
        connection.commit()
    finally:
        connection.close()
    return preferences


def _add_missing_email_columns(connection):
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(emails)")
    }
    for column in ("provider", "external_id", "user_id"):
        if column not in columns:
            connection.execute(f"ALTER TABLE emails ADD COLUMN {column} TEXT")


def _add_user_ownership_columns(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS legacy_data_ownership (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            owner_user_id TEXT NOT NULL,
            owner_email TEXT NOT NULL
        )
    """)


def _create_oauth_table(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS oauth_login_transactions (
            state TEXT PRIMARY KEY,
            encrypted_verifier TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)


def store_oauth_login(state, encrypted_verifier, expires_at):
    connection = get_connection()
    try:
        connection.execute(
            "DELETE FROM oauth_login_transactions WHERE expires_at <= ?",
            (int(time.time()),),
        )
        connection.execute("""
            INSERT INTO oauth_login_transactions (state, encrypted_verifier, expires_at)
            VALUES (?, ?, ?)
        """, (state, encrypted_verifier, expires_at))
        connection.commit()
    finally:
        connection.close()


def consume_oauth_login(state):
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("""
            SELECT encrypted_verifier, expires_at
            FROM oauth_login_transactions WHERE state = ?
        """, (state,)).fetchone()
        connection.execute(
            "DELETE FROM oauth_login_transactions WHERE state = ?", (state,)
        )
        connection.commit()
        if not row or row["expires_at"] <= time.time():
            return None
        return row["encrypted_verifier"]
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _table_columns(connection, table):
    return connection.execute(f"PRAGMA table_info({table})").fetchall()


def _upgrade_settings_table(connection):
    columns = _table_columns(connection, "app_settings")
    if "user_id" in {row["name"] for row in columns} and {
        row["name"] for row in columns if row["pk"]
    } == {"user_id", "key"}:
        return
    connection.execute("ALTER TABLE app_settings RENAME TO app_settings_legacy")
    connection.execute("""
        CREATE TABLE app_settings (
            user_id TEXT,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (user_id, key)
        )
    """)
    legacy_columns = {row["name"] for row in _table_columns(connection, "app_settings_legacy")}
    legacy_user = "user_id" if "user_id" in legacy_columns else "NULL"
    connection.execute(f"""
        INSERT INTO app_settings (user_id, key, value)
        SELECT {legacy_user}, key, value FROM app_settings_legacy
    """)
    connection.execute("DROP TABLE app_settings_legacy")


def _upgrade_mail_tables(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS mail_accounts (
            user_id TEXT,
            provider TEXT NOT NULL,
            email TEXT NOT NULL,
            encrypted_token TEXT NOT NULL,
            auth_method TEXT NOT NULL DEFAULT 'oauth',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, provider)
        )
    """)
    columns = {row["name"] for row in _table_columns(connection, "mail_accounts")}
    if "user_id" not in columns or {
        row["name"] for row in _table_columns(connection, "mail_accounts") if row["pk"]
    } != {"user_id", "provider"}:
        connection.execute("ALTER TABLE mail_accounts RENAME TO mail_accounts_legacy")
        connection.execute("""
            CREATE TABLE mail_accounts (
                user_id TEXT,
                provider TEXT NOT NULL,
                email TEXT NOT NULL,
                encrypted_token TEXT NOT NULL,
                auth_method TEXT NOT NULL DEFAULT 'oauth',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, provider)
            )
        """)
        old_columns = {row["name"] for row in _table_columns(connection, "mail_accounts_legacy")}
        old_user = "user_id" if "user_id" in old_columns else "NULL"
        old_auth_method = "auth_method" if "auth_method" in old_columns else "'oauth'"
        old_updated_at = "updated_at" if "updated_at" in old_columns else "CURRENT_TIMESTAMP"
        connection.execute(f"""
            INSERT INTO mail_accounts
                (user_id, provider, email, encrypted_token, auth_method, updated_at)
            SELECT {old_user}, provider, email, encrypted_token,
                {old_auth_method}, {old_updated_at}
            FROM mail_accounts_legacy
        """)
        connection.execute("DROP TABLE mail_accounts_legacy")
    columns = {row["name"] for row in _table_columns(connection, "mail_syncs")} if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mail_syncs'"
    ).fetchone() else set()
    if not columns:
        connection.execute("""
            CREATE TABLE mail_syncs (
                user_id TEXT,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, provider)
            )
        """)
    elif "user_id" not in columns or {
        row["name"] for row in _table_columns(connection, "mail_syncs") if row["pk"]
    } != {"user_id", "provider"}:
        connection.execute("ALTER TABLE mail_syncs RENAME TO mail_syncs_legacy")
        connection.execute("""
            CREATE TABLE mail_syncs (
                user_id TEXT,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, provider)
            )
        """)
        old_columns = {row["name"] for row in _table_columns(connection, "mail_syncs_legacy")}
        old_user = "user_id" if "user_id" in old_columns else "NULL"
        connection.execute(f"""
            INSERT INTO mail_syncs
                (user_id, provider, status, processed, error, updated_at)
            SELECT {old_user}, provider, status, processed, error, updated_at
            FROM mail_syncs_legacy
        """)
        connection.execute("DROP TABLE mail_syncs_legacy")


def claim_legacy_data(user_id, email):
    """Assign pre-account rows only to the explicitly configured Google owner."""
    email = email.strip().lower()
    configured_owner = os.environ.get("LEGACY_DATA_OWNER_EMAIL", "").strip().lower()
    connection = get_connection()
    try:
        legacy_exists = any(
            connection.execute(
                f"SELECT 1 FROM {table} WHERE user_id IS NULL LIMIT 1"
            ).fetchone()
            for table in ("emails", "app_settings", "mail_accounts", "mail_syncs")
        )
        owner = connection.execute(
            "SELECT owner_user_id, owner_email FROM legacy_data_ownership WHERE singleton = 1"
        ).fetchone()
        if legacy_exists:
            if not configured_owner:
                raise ValueError(
                    "Unassigned legacy data exists. Set LEGACY_DATA_OWNER_EMAIL to "
                    "the exact Google account that owns it, then sign in with that account."
                )
            if email != configured_owner:
                raise ValueError(
                    "Unassigned legacy data is reserved for LEGACY_DATA_OWNER_EMAIL. "
                    "Sign in with the configured owner account before using this database."
                )
            if owner and (
                owner["owner_user_id"] != user_id or owner["owner_email"] != email
            ):
                raise ValueError("Legacy data was already assigned to a different owner.")
            connection.execute("""
                INSERT OR IGNORE INTO legacy_data_ownership
                    (singleton, owner_user_id, owner_email) VALUES (1, ?, ?)
            """, (user_id, email))
            for table in ("emails", "app_settings", "mail_accounts", "mail_syncs"):
                connection.execute(
                    f"UPDATE {table} SET user_id = ? WHERE user_id IS NULL",
                    (user_id,),
                )
        connection.execute("""
            INSERT INTO users (id, email) VALUES (?, ?)
            ON CONFLICT(id) DO UPDATE SET email = excluded.email
        """, (user_id, email))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
