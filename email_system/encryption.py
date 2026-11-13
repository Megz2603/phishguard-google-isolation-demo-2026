import base64
import ctypes
import os
from ctypes import wintypes

from cryptography.fernet import Fernet, InvalidToken


FIELD_PREFIX = "encrypted:v3:"
DPAPI_FIELD_PREFIX = "encrypted:v2:"
LEGACY_FIELD_PREFIX = "encrypted:v1:"
KEY_CHECK = b"phishing-detector-email-encryption-v2"
LEGACY_KEY_CHECK = b"phishing-detector-email-encryption-v1"
PRIVATE_FIELDS = ("sender", "subject", "body", "reasons")
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class EncryptionError(ValueError):
    """Raised when the configured encryption key cannot protect private data."""


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _dpapi(data, protect):
    """Use Windows DPAPI so no separate encryption key must be managed."""
    if os.name != "nt":
        raise EncryptionError("Windows data protection is available only on Windows.")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    source_buffer = ctypes.create_string_buffer(data)
    source = _DataBlob(
        len(data),
        ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    result = _DataBlob()

    if protect:
        success = crypt32.CryptProtectData(
            ctypes.byref(source), None, None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(result),
        )
    else:
        success = crypt32.CryptUnprotectData(
            ctypes.byref(source), None, None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(result),
        )

    if not success:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        kernel32.LocalFree(result.data)


def _portable_cipher():
    key = os.environ.get("APP_DATA_ENCRYPTION_KEY")
    if not key:
        return None
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise EncryptionError(
            "APP_DATA_ENCRYPTION_KEY must be a valid Fernet key."
        ) from error


def encrypt_secret(value):
    """Encrypt private text with a configured key or Windows DPAPI."""
    try:
        plaintext = value.encode("utf-8")
        cipher = _portable_cipher()
        if cipher:
            return FIELD_PREFIX + cipher.encrypt(plaintext).decode("ascii")
        if os.name != "nt":
            raise EncryptionError(
                "Set APP_DATA_ENCRYPTION_KEY to a Fernet key for non-Windows hosting."
            )
    except (OSError, UnicodeEncodeError) as error:
        raise EncryptionError(f"Could not encrypt private data: {error}") from error
    protected = _dpapi(plaintext, protect=True)
    return DPAPI_FIELD_PREFIX + base64.urlsafe_b64encode(protected).decode("ascii")


def decrypt_secret(value):
    """Decrypt portable ciphertext or data protected by the current Windows user."""
    if value.startswith(FIELD_PREFIX):
        cipher = _portable_cipher()
        if not cipher:
            raise EncryptionError(
                "APP_DATA_ENCRYPTION_KEY is required to decrypt saved private data."
            )
        try:
            return cipher.decrypt(value[len(FIELD_PREFIX):].encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeDecodeError) as error:
            raise EncryptionError(
                "APP_DATA_ENCRYPTION_KEY is incorrect or saved data is damaged."
            ) from error
    if not value.startswith(DPAPI_FIELD_PREFIX):
        raise EncryptionError(
            "Saved credentials use an older encryption format. Reconnect the account."
        )
    try:
        protected = base64.urlsafe_b64decode(value[len(DPAPI_FIELD_PREFIX):])
        return _dpapi(protected, protect=False).decode("utf-8")
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise EncryptionError(
            "Windows could not decrypt saved data for this account. Use the original "
            "Windows profile and set APP_DATA_ENCRYPTION_KEY to migrate it before moving hosts."
        ) from error


def encrypt_field(value):
    """Encrypt one private email field while preserving NULL values."""
    if value is None:
        return None
    return encrypt_secret(str(value))


def decrypt_field(value):
    """Decrypt a private email field returned from SQLite."""
    if value is None:
        return None
    if not value.startswith((FIELD_PREFIX, DPAPI_FIELD_PREFIX)):
        raise EncryptionError(
            "An email field is not encrypted. Restart the app to migrate saved emails."
        )
    return decrypt_secret(value)


def _decrypt_legacy(value):
    """Read old Fernet data once during upgrade; never store or require its key."""
    key = os.environ.get("MAIL_TOKEN_ENCRYPTION_KEY")
    if not key:
        raise EncryptionError(
            "This database uses the old manual encryption key. Set "
            "MAIL_TOKEN_ENCRYPTION_KEY temporarily to migrate it, then remove it."
        )
    try:
        return Fernet(key.encode("ascii")).decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeEncodeError, UnicodeDecodeError) as error:
        raise EncryptionError(
            "The old encryption key is missing or incorrect; saved data cannot be migrated."
        ) from error


def _upgrade_field(value):
    if value is None or value.startswith(FIELD_PREFIX):
        if value is not None:
            decrypt_secret(value)
        return value, False
    if value.startswith(DPAPI_FIELD_PREFIX):
        plaintext = decrypt_secret(value)
        if _portable_cipher():
            return encrypt_field(plaintext), True
        return value, False
    if value.startswith(LEGACY_FIELD_PREFIX):
        value = _decrypt_legacy(value[len(LEGACY_FIELD_PREFIX):])
    return encrypt_field(value), True


def migrate_email_fields(connection):
    """Upgrade saved mail/account data to the configured encryption format."""
    connection.execute("""
        CREATE TABLE IF NOT EXISTS encryption_metadata (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    saved_check = connection.execute("""
        SELECT value FROM encryption_metadata WHERE name = 'key_check'
    """).fetchone()

    if saved_check and saved_check["value"].startswith(FIELD_PREFIX):
        if decrypt_secret(saved_check["value"]).encode("utf-8") != KEY_CHECK:
            raise EncryptionError("The database encryption check failed.")
        return False

    portable_migration = False
    legacy_encryption = False
    if saved_check and saved_check["value"].startswith(DPAPI_FIELD_PREFIX):
        if decrypt_secret(saved_check["value"]).encode("utf-8") != KEY_CHECK:
            raise EncryptionError("The database encryption check failed.")
        portable_migration = _portable_cipher() is not None
        if not portable_migration:
            return False

    # Rows from the previous release use a manually supplied Fernet key.
    # Validate that key before changing anything, then discard old IMAP logins.
    elif saved_check:
        old_check = _decrypt_legacy(saved_check["value"])
        if old_check.encode("utf-8") != LEGACY_KEY_CHECK:
            raise EncryptionError("The old database encryption check failed.")
        legacy_encryption = True

    changed = False
    rows = connection.execute(
        "SELECT id, sender, subject, body, reasons FROM emails"
    ).fetchall()
    for row in rows:
        encrypted = {field: _upgrade_field(row[field]) for field in PRIVATE_FIELDS}
        if any(did_change for _, did_change in encrypted.values()):
            changed = True
        connection.execute("""
            UPDATE emails
            SET sender = ?, subject = ?, body = ?, reasons = ?
            WHERE id = ?
        """, (
            encrypted["sender"][0],
            encrypted["subject"][0],
            encrypted["body"][0],
            encrypted["reasons"][0],
            row["id"],
        ))

    if portable_migration:
        rows = connection.execute("""
            SELECT user_id, provider, email, encrypted_token FROM mail_accounts
        """).fetchall()
        for row in rows:
            email, email_changed = _upgrade_field(row["email"])
            token = encrypt_secret(decrypt_secret(row["encrypted_token"]))
            if email_changed or token != row["encrypted_token"]:
                changed = True
            connection.execute("""
                UPDATE mail_accounts
                SET email = ?, encrypted_token = ?
                WHERE user_id IS ? AND provider = ?
            """, (email, token, row["user_id"], row["provider"]))
        rows = connection.execute("""
            SELECT state, encrypted_verifier FROM oauth_login_transactions
        """).fetchall()
        for row in rows:
            verifier = encrypt_secret(decrypt_secret(row["encrypted_verifier"]))
            connection.execute("""
                UPDATE oauth_login_transactions
                SET encrypted_verifier = ? WHERE state = ?
            """, (verifier, row["state"]))
            changed = True
    elif legacy_encryption or not saved_check:
        # Older Fernet-era mailbox credentials were App Passwords; reconnect them.
        old_accounts = connection.execute(
            "SELECT COUNT(*) AS total FROM mail_accounts"
        ).fetchone()["total"]
        if old_accounts:
            connection.execute("DELETE FROM mail_accounts")
            changed = True

    connection.execute("""
        INSERT INTO encryption_metadata (name, value)
        VALUES ('key_check', ?)
        ON CONFLICT(name) DO UPDATE SET value = excluded.value
    """, (encrypt_secret(KEY_CHECK.decode("utf-8")),))
    return changed
