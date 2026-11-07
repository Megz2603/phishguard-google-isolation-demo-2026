import base64
import getpass
import hashlib
import html
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from database import get_connection
from email_system.encryption import (
    EncryptionError,
    decrypt_secret,
    encrypt_field,
    encrypt_secret,
)
from email_system.oauth_config import (
    OAUTH_CREDENTIALS_FILE,
    OAuthConfigError,
    load_oauth_credentials,
)
from models import save_email
from scanner.scanner import scan_email


PROVIDER = "google"
GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_API = "https://gmail.googleapis.com/gmail/v1"
GOOGLE_USER_INFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_SCOPE = "openid email https://www.googleapis.com/auth/gmail.readonly"
_sync_lock = threading.Lock()
_pending_logins = {}
_oauth_settings_lock = threading.Lock()
_cached_oauth_credentials = None


class MailboxError(Exception):
    """An expected problem connecting to or syncing Gmail."""


class _TextExtractor(HTMLParser):
    """Collect readable text from HTML-only messages."""

    def __init__(self):
        super().__init__()
        self.text = []

    def handle_data(self, data):
        if data.strip():
            self.text.append(data.strip())


def _oauth_settings():
    global _cached_oauth_credentials
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if client_id or client_secret:
        if not client_id or not client_secret:
            raise MailboxError(
                "Set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or remove "
                "them to use google_oauth.enc."
            )
    elif _cached_oauth_credentials:
        client_id, client_secret = _cached_oauth_credentials
    elif OAUTH_CREDENTIALS_FILE.exists():
        raise MailboxError(
            "Gmail OAuth credentials are locked. Stop and restart the app, "
            "then enter the passphrase in its PowerShell window."
        )
    else:
        raise MailboxError(
            "Gmail OAuth is not configured. Run setup_google_oauth.py to create "
            "google_oauth.enc, or set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."
        )
    callback = os.environ.get(
        "GOOGLE_REDIRECT_URI",
        "http://127.0.0.1:5000/auth/google/callback",
    )
    return client_id, client_secret, callback


def unlock_oauth_credentials():
    """Unlock the shared OAuth file at startup, not inside a browser request."""
    global _cached_oauth_credentials
    if os.environ.get("GOOGLE_CLIENT_ID") or os.environ.get("GOOGLE_CLIENT_SECRET"):
        _oauth_settings()
        return
    if not OAUTH_CREDENTIALS_FILE.exists():
        return

    with _oauth_settings_lock:
        if _cached_oauth_credentials:
            return
        password = getpass.getpass(
            "Unlock Gmail OAuth credentials (passphrase): "
        )
        try:
            _cached_oauth_credentials = load_oauth_credentials(
                password,
                OAUTH_CREDENTIALS_FILE,
            )
        except OAuthConfigError as error:
            raise MailboxError(str(error)) from error


def _form_post(url, values):
    request = Request(
        url,
        data=urlencode(values).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise MailboxError(
            f"Google sign-in failed (HTTP {error.code}). Check the OAuth "
            "client and redirect URI."
        ) from error
    except (URLError, TimeoutError) as error:
        raise MailboxError("Could not reach Google sign-in. Check your internet connection.") from error


def _google_json(url, access_token):
    request = Request(url, headers={
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    })
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise MailboxError(
            f"Gmail rejected a read request (HTTP {error.code}). "
            "Reconnect Gmail if its permission expired."
        ) from error
    except (URLError, TimeoutError) as error:
        raise MailboxError("Could not reach Gmail. Check your internet connection.") from error


def authorization_url():
    """Start a short-lived PKCE login; OAuth state stays in process memory."""
    client_id, _, callback = _oauth_settings()
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    state = secrets.token_urlsafe(32)
    _pending_logins[state] = (verifier, time.time() + 600)

    # Discard expired states so abandoned login attempts do not accumulate.
    for old_state, (_, expires) in list(_pending_logins.items()):
        if expires < time.time():
            _pending_logins.pop(old_state, None)

    query = urlencode({
        "client_id": client_id,
        "redirect_uri": callback,
        "response_type": "code",
        "scope": GOOGLE_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return f"{GOOGLE_AUTHORIZE_URL}?{query}", state


def finish_authorization(state, code):
    """Exchange a one-use OAuth code, then save its token with Windows DPAPI."""
    login = _pending_logins.pop(state or "", None)
    if not login or login[1] < time.time():
        raise MailboxError("Sign-in expired or could not be verified. Try connecting again.")

    client_id, client_secret, callback = _oauth_settings()
    tokens = _form_post(GOOGLE_TOKEN_URL, {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "code_verifier": login[0],
        "grant_type": "authorization_code",
        "redirect_uri": callback,
    })
    access_token = tokens.get("access_token")
    if not access_token:
        raise MailboxError("Google did not return an access token.")

    profile = _google_json(GOOGLE_USER_INFO_URL, access_token)
    email_address = profile.get("email")
    if not email_address:
        raise MailboxError("Google did not return the signed-in email address.")

    tokens["email"] = email_address
    tokens["expires_at"] = int(time.time()) + int(tokens.get("expires_in", 3600))
    try:
        encrypted_token = encrypt_secret(json.dumps(tokens))
        encrypted_email = encrypt_field(email_address)
    except EncryptionError as error:
        raise MailboxError(str(error)) from error

    connection = get_connection()
    connection.execute("""
        INSERT INTO mail_accounts
            (provider, email, encrypted_token, auth_method, updated_at)
        VALUES (?, ?, ?, 'oauth', CURRENT_TIMESTAMP)
        ON CONFLICT(provider) DO UPDATE SET
            email = excluded.email,
            encrypted_token = excluded.encrypted_token,
            auth_method = 'oauth',
            updated_at = CURRENT_TIMESTAMP
    """, (PROVIDER, encrypted_email, encrypted_token))
    connection.commit()
    connection.close()


def _access_token():
    connection = get_connection()
    row = connection.execute("""
        SELECT encrypted_token FROM mail_accounts WHERE provider = ?
    """, (PROVIDER,)).fetchone()
    connection.close()
    if not row:
        raise MailboxError("Gmail is not connected.")

    try:
        tokens = json.loads(decrypt_secret(row["encrypted_token"]))
    except (EncryptionError, ValueError) as error:
        raise MailboxError(str(error)) from error

    if int(tokens.get("expires_at", 0)) > int(time.time()) + 60:
        return tokens["access_token"]
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise MailboxError("Google authorization expired. Connect Gmail again.")

    client_id, client_secret, _ = _oauth_settings()
    refreshed = _form_post(GOOGLE_TOKEN_URL, {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    })
    tokens.update(refreshed)
    tokens["expires_at"] = int(time.time()) + int(refreshed.get("expires_in", 3600))

    connection = get_connection()
    connection.execute("""
        UPDATE mail_accounts SET encrypted_token = ?, updated_at = CURRENT_TIMESTAMP
        WHERE provider = ?
    """, (encrypt_secret(json.dumps(tokens)), PROVIDER))
    connection.commit()
    connection.close()
    return tokens["access_token"]


def list_accounts():
    connection = get_connection()
    rows = connection.execute("""
        SELECT provider, email, auth_method FROM mail_accounts
        WHERE provider = ?
    """, (PROVIDER,)).fetchall()
    connection.close()
    try:
        return [
            {**dict(row), "email": decrypt_secret(row["email"])}
            for row in rows
        ]
    except EncryptionError as error:
        raise MailboxError(str(error)) from error


def disconnect_account(provider):
    if provider != PROVIDER:
        raise MailboxError("Only Gmail is supported.")
    if not _sync_lock.acquire(blocking=False):
        raise MailboxError("Wait for Gmail sync to finish before disconnecting.")
    try:
        connection = get_connection()
        connection.execute("DELETE FROM mail_accounts WHERE provider = ?", (PROVIDER,))
        connection.execute("DELETE FROM mail_syncs WHERE provider = ?", (PROVIDER,))
        connection.commit()
        connection.close()
    finally:
        _sync_lock.release()


def _decode_header(value):
    try:
        return str(make_header(decode_header(value or "")))
    except (LookupError, UnicodeDecodeError, ValueError):
        return value or ""


def _message_body(payload):
    plain_text = []
    html_text = []

    def visit(part):
        body = part.get("body", {}).get("data")
        if body:
            try:
                raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
                content = raw.decode("utf-8", errors="replace")
                if part.get("mimeType") == "text/plain":
                    plain_text.append(content)
                elif part.get("mimeType") == "text/html":
                    html_text.append(content)
            except (ValueError, TypeError):
                pass
        for child in part.get("parts", []):
            visit(child)

    visit(payload)
    if plain_text:
        return "\n".join(plain_text).strip()

    parser = _TextExtractor()
    parser.feed(html.unescape("\n".join(html_text)))
    return " ".join(parser.text)


def _gmail_messages(access_token):
    next_page = None
    while True:
        query = {"maxResults": "500"}
        if next_page:
            query["pageToken"] = next_page
        page = _google_json(
            f"{GOOGLE_API}/users/me/messages?{urlencode(query)}",
            access_token,
        )

        for item in page.get("messages", []):
            message = _google_json(
                f"{GOOGLE_API}/users/me/messages/{item['id']}?format=full",
                access_token,
            )
            headers = {
                header["name"].lower(): header["value"]
                for header in message.get("payload", {}).get("headers", [])
            }
            from_header = _decode_header(headers.get("from", ""))
            sender = parseaddr(from_header)[1] or from_header or "Unknown sender"
            received_at = None
            try:
                received_at = datetime.fromtimestamp(
                    int(message["internalDate"]) / 1000,
                    timezone.utc,
                ).strftime("%Y-%m-%d %H:%M:%S")
            except (KeyError, TypeError, ValueError, OverflowError):
                pass

            yield {
                "external_id": message["id"],
                "sender": sender,
                "subject": _decode_header(headers.get("subject", "")) or "(No subject)",
                "body": _message_body(message.get("payload", {}))
                or message.get("snippet", ""),
                "received_at": received_at,
            }

        next_page = page.get("nextPageToken")
        if not next_page:
            return


def _set_sync(status, processed=0, error=None):
    connection = get_connection()
    connection.execute("""
        INSERT INTO mail_syncs (provider, status, processed, error, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(provider) DO UPDATE SET
            status = excluded.status,
            processed = excluded.processed,
            error = excluded.error,
            updated_at = CURRENT_TIMESTAMP
    """, (PROVIDER, status, processed, error))
    connection.commit()
    connection.close()


def sync_status(provider):
    if provider != PROVIDER:
        raise MailboxError("Only Gmail sync is supported.")
    connection = get_connection()
    row = connection.execute("""
        SELECT status, processed, error, updated_at
        FROM mail_syncs WHERE provider = ?
    """, (PROVIDER,)).fetchone()
    connection.close()
    return dict(row) if row else {"status": "idle", "processed": 0, "error": None}


def _run_sync():
    processed = 0
    try:
        access_token = _access_token()
        for message in _gmail_messages(access_token):
            result = scan_email(message["sender"], message["subject"], message["body"])
            save_email(
                sender=message["sender"],
                subject=message["subject"],
                body=message["body"],
                risk_score=result["risk_score"],
                status=result["status"],
                reasons="; ".join(result["reasons"]),
                provider=PROVIDER,
                external_id=message["external_id"],
                created_at=message["received_at"],
            )
            processed += 1
            if processed % 25 == 0:
                _set_sync("running", processed)
        _set_sync("complete", processed)
    except Exception as error:
        logging.getLogger(__name__).exception("Gmail sync failed")
        _set_sync("error", processed, str(error))
    finally:
        _sync_lock.release()


def start_sync(provider):
    if provider != PROVIDER:
        raise MailboxError("Only Gmail sync is supported.")
    if not _sync_lock.acquire(blocking=False):
        raise MailboxError("Gmail mailbox sync is already running.")
    try:
        if not list_accounts():
            raise MailboxError("Gmail is not connected.")
        _set_sync("running")
        threading.Thread(target=_run_sync, daemon=True).start()
    except Exception:
        _sync_lock.release()
        raise
    return sync_status(PROVIDER)
