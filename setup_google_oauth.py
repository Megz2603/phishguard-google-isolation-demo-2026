from getpass import getpass

from email_system.oauth_config import (
    OAUTH_CREDENTIALS_FILE,
    OAuthConfigError,
    save_oauth_credentials,
)


def main():
    if OAUTH_CREDENTIALS_FILE.exists():
        answer = input(
            f"{OAUTH_CREDENTIALS_FILE.name} already exists. Replace it? [y/N] "
        ).strip().lower()
        if answer != "y":
            print("Kept the existing credentials file.")
            return 0

    client_id = input("Google OAuth client ID: ").strip()
    client_secret = getpass("Google OAuth client secret: ").strip()
    password = getpass("Choose a passphrase (at least 12 characters): ")
    confirmation = getpass("Enter the passphrase again: ")
    if password != confirmation:
        print("The passphrases do not match.")
        return 1

    try:
        path = save_oauth_credentials(client_id, client_secret, password)
    except OAuthConfigError as error:
        print(f"Could not create credentials file: {error}")
        return 1

    print(f"Encrypted OAuth credentials saved to: {path}")
    print("Share this file only with colleagues who should be able to connect Gmail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
