import base64
import json
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


OAUTH_CREDENTIALS_FILE = Path(__file__).resolve().parent.parent / "google_oauth.enc"
_FILE_VERSION = 1
_PASSWORD_MIN_LENGTH = 12


class OAuthConfigError(ValueError):
    """Raised when OAuth credentials cannot be read or saved."""


def _key_from_password(password, salt):
    if not password or len(password) < _PASSWORD_MIN_LENGTH:
        raise OAuthConfigError(
            f"Use a passphrase with at least {_PASSWORD_MIN_LENGTH} characters."
        )
    return base64.urlsafe_b64encode(
        Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
            password.encode("utf-8")
        )
    )


def save_oauth_credentials(client_id, client_secret, password, path=None):
    """Encrypt OAuth credentials into a file protected by a passphrase."""
    client_id = (client_id or "").strip()
    client_secret = (client_secret or "").strip()
    if not client_id or not client_secret:
        raise OAuthConfigError("Both the Google client ID and client secret are required.")

    salt = os.urandom(16)
    key = _key_from_password(password, salt)
    encrypted = Fernet(key).encrypt(json.dumps({
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode("utf-8"))
    payload = {
        "version": _FILE_VERSION,
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "credentials": encrypted.decode("ascii"),
    }
    target = Path(path) if path else OAUTH_CREDENTIALS_FILE
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(payload, temporary_file)
        os.replace(temporary_path, target)
    except OSError as error:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()
        raise OAuthConfigError(f"Could not save the encrypted credentials file: {error}") from error
    return target


def load_oauth_credentials(password, path=None):
    """Decrypt a credentials file after verifying its passphrase."""
    target = Path(path) if path else OAUTH_CREDENTIALS_FILE
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        if payload.get("version") != _FILE_VERSION:
            raise OAuthConfigError("The OAuth credentials file has an unsupported format.")
        salt = base64.b64decode(payload["salt"], altchars=b"-_", validate=True)
        key = _key_from_password(password, salt)
        plaintext = Fernet(key).decrypt(payload["credentials"].encode("ascii"))
        credentials = json.loads(plaintext.decode("utf-8"))
        client_id = credentials.get("client_id")
        client_secret = credentials.get("client_secret")
        if not client_id or not client_secret:
            raise OAuthConfigError("The OAuth credentials file is missing required values.")
        return client_id, client_secret
    except InvalidToken as error:
        raise OAuthConfigError(
            "The passphrase is incorrect or the OAuth credentials file is damaged."
        ) from error
    except (OSError, KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        if isinstance(error, OAuthConfigError):
            raise
        raise OAuthConfigError(
            "The OAuth credentials file is missing or invalid. Create it again with setup_google_oauth.py."
        ) from error
