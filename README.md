# Phishing Email Detector - Python Backend

A rule-based phishing email detector built with Python, Flask and SQLite. It
can scan manually submitted messages or connect to Gmail using OAuth.

## Requirements

- Python 3.10+ recommended
- Visual Studio Code

## Installation

Open the project folder in VS Code and run:

```bash
python -m pip install -r requirements.txt
```

## Email privacy and encryption

The app encrypts sender, subject, body, scan reasons, the connected account
email, and OAuth tokens before storing them in `emails.db`. On Windows it uses
Windows Data Protection (DPAPI), tied to your Windows user profile. **You do
not need an App Password or a manually generated encryption key.** The
dashboard decrypts messages when displaying them. Risk score, folder status,
received timestamp, provider, and provider message ID remain as database
metadata for filtering, sorting, and duplicate detection.

This protects the database file at rest. Anyone using your Windows account
while the app is running can still view messages in the dashboard. A
DPAPI-protected database cannot be decrypted from another Windows user
profile.

On the first start after upgrading from the old Fernet-encrypted version, the
app migrates saved messages to DPAPI. If that database has the previous
`MAIL_TOKEN_ENCRYPTION_KEY` check, provide that old key in PowerShell for this
one-time migration only. The app will not store it; remove it after migration.
Without the old key, previously encrypted data cannot be recovered. Existing
App Password connections are removed; connect Gmail again through Google.

## Connect Gmail

Gmail uses Google's OAuth sign-in and requests read-only `gmail.readonly`
access. The app never asks for your Google password or an App Password. Google
requires you to register an OAuth application:

1. Create a Google Cloud project and enable the **Gmail API**.
2. Configure the OAuth consent screen. If it is in Testing mode, add your
   Google account as a test user.
3. Create an OAuth client with application type **Web application**. Add this
   exact redirect URI: `http://127.0.0.1:5000/auth/google/callback`.
4. Create a password-protected credentials file from PowerShell:

   ```powershell
   python setup_google_oauth.py
   ```

   Enter the client ID and secret from Google when prompted. Choose a
   passphrase with at least 12 characters. The script writes only encrypted
   credentials to `google_oauth.enc`; it does not put the secret in source
   code or command history. Do not store the passphrase in the same OneDrive
   folder as the encrypted file.
5. Start the app in PowerShell:

   ```powershell
   python app.py
   ```

   Enter the credentials-file passphrase in the PowerShell window when
   prompted at startup. Keep that window open while using the app.
6. Open `http://127.0.0.1:5000` and click **Sign in with Google**. The app
   keeps the OAuth client credentials in memory until it exits, then stores
   OAuth tokens using Windows DPAPI and imports and scans messages in the
   background.

To share the app, give colleagues `google_oauth.enc` and send them the
passphrase separately. Each colleague should use their own copy of the app
folder and their own local `emails.db`; do not share a live database through
OneDrive. Anyone who has both the encrypted file and its passphrase can
recover the OAuth client secret. This passphrase protects the file against
casual disclosure, but a distributed desktop app cannot keep a shared OAuth
client secret truly confidential. For stronger security, use a desktop OAuth
client that does not require a client secret.

Sync imports regular Gmail messages (excluding Spam and Trash), including
headers and text bodies; attachments are not downloaded. Imported messages
remain in the local database after disconnecting. The app does not send, label,
move, or delete mail in Gmail. Repeated syncs do not create duplicate messages.

## Run

```bash
python app.py
```

Open the dashboard at:

http://127.0.0.1:5000

The dashboard lets you connect Gmail, sync and scan messages, submit emails
manually, filter results by status, view detection reasons, move emails
between Inbox, Review and Quarantine, or delete local copies. **Refresh**
reloads the saved email list; use **Sync mailbox** to fetch new Gmail messages.
**Clear saved emails** removes every email record from this app, but keeps
language settings and the Gmail connection. It does not delete Gmail messages;
a later sync can import them again.

## South African language scanning

On the first visit, choose a website language before opening the landing page.
The interface supports all 11 official South African languages. Choose a
primary language and any number of secondary languages in scanner settings;
the primary language gets first priority, and all 11 keyword catalogs are still
checked so an unselected South African language is not missed. Preferences are
saved locally and apply to manual scans and Gmail sync.

The landing, about, and scanner pages, scanner controls and notices, and
detection reasons are localized to the selected language. Keyword scores are
less sensitive to a single generic phrase. Credential, account, and payment
phrases carry more weight than generic urgency or prize language; multiple
high-risk keywords combined with supporting suspicious keywords receive an
additional bonus. A modest density adjustment helps distinguish short
keyword-heavy messages. URL, file, brand, and sender checks remain part of the
score. Emails in languages outside the 11 supported keyword catalogs are still
checked for structural signals, but there is no machine-learning language
detector or translation model, so text-only threats in other languages may not
be recognized.

Gmail message retrieval uses bounded concurrent requests, and local database
writes are committed in batches to reduce sync time.

## Main API endpoints

- `GET /` - Open the web dashboard
- `GET /api/health` - Check whether the backend is running
- `GET /api/language-settings` - Read the saved primary and secondary languages
- `PUT /api/language-settings` - Save language preferences
- `POST /emails` - Submit an incoming email for scanning
- `GET /emails` - View all emails
- `DELETE /emails` - Delete all locally saved emails
- `GET /emails/inbox` - View safe emails
- `GET /emails/review` - View emails needing review
- `GET /emails/quarantine` - View quarantined emails
- `GET /emails/<id>` - View one email
- `PUT /emails/<id>/move` - Move an email
- `DELETE /emails/<id>` - Delete an email

## Risk levels

- 0-29: Inbox
- 30-69: Review
- 70-100: Quarantine

The detector uses rules and risk scoring. It does not use machine learning.
Suspicious URL paths also check selected account, credential, payment, and
sign-in route names (including `account`, `billing`, `forgot-password`,
`login`, `oauth`, `payment`, `secure`, and `signin`) from
[SecLists' common web paths list](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt).
SecLists provides web-content discovery paths, not phishing-email keywords;
these terms are treated only as URL-path clues and are not proof of phishing.
SecLists is MIT-licensed (Copyright 2018 Daniel Miessler); see its
[license](https://github.com/danielmiessler/SecLists/blob/master/LICENSE).

## Test with PowerShell

With the server running, open another VS Code terminal:

```powershell
Invoke-RestMethod `
-Uri "http://127.0.0.1:5000/emails" `
-Method POST `
-ContentType "application/json" `
-Body '{
    "sender": "security@paypa1-login.com",
    "subject": "URGENT: Verify your account",
    "body": "Your account has unusual activity. Click here to verify your password: http://paypa1-login.com/login"
}'
```

A file called `emails.db` will be created automatically after the backend starts.
