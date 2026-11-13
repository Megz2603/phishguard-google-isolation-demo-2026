# Phishing Email Detector - Python Backend

A rule-based phishing email detector built with Python, Flask and SQLite. It
can scan manually submitted messages or connect to Gmail using OAuth. Google
sign-in authenticates the app, and each signed-in Google account has a private
mailbox, Gmail connection, sync state, and language preferences.

## Requirements

- Python 3.10+ recommended
- Visual Studio Code

## Installation

Open the project folder in VS Code and run:

```bash
python -m pip install -r requirements.txt
```

Screenshot scanning also requires the Tesseract OCR executable. Install
Tesseract for your operating system and make sure `tesseract` is available on
`PATH`. The Render Docker image installs it automatically.

The scanner accepts PNG, JPEG, and WebP screenshots up to 8 MB. OCR runs on the
app server without sending the image to a third-party OCR service. The screenshot
is discarded after reading; the extracted text uses the same phishing scanner
and per-user settings as manually entered and Gmail messages. Screenshot
validation accepts readable, cohesive message text even when OCR misses headers.
The OCR crop retains the email subject and sender area while excluding some
surrounding mail-client chrome, and repairs spaces inside recognized URLs.
Review the extracted text saved with the scan. OCR currently uses Tesseract's
English language model.

## App sign-in and configuration

The app requires a random Flask session secret. In PowerShell, generate one for
the current shell before starting the app:

```powershell
$env:APP_SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Keep the value private and stable while the app is running; changing it
invalidates existing sessions. The app fails at startup if it is missing or
shorter than 32 characters. Session cookies are HttpOnly and SameSite=Lax. For
production, set `APP_ENV=production` and configure an HTTPS
`GOOGLE_REDIRECT_URI`; production cookies are Secure and the app refuses an
HTTP callback. Run production behind HTTPS with a production WSGI server, not
Flask's development server.

On non-Windows hosts, also set `APP_DATA_ENCRYPTION_KEY` to a generated
Fernet key:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Save that value as a secret environment variable and keep it unchanged. The app
uses it to encrypt email contents, Gmail tokens, and OAuth transaction data.
Windows can continue using DPAPI by omitting this variable, or use the portable
key when data will be moved to a non-Windows host.

The Google OAuth flow verifies the account's Google subject and verified email
before creating the app session. OAuth state is bound to the browser session,
the PKCE verifier is stored encrypted in SQLite for cross-worker callbacks, and
API writes require a CSRF token. Gmail access remains read-only. Do not expose
the local development server directly to the internet.

Users can choose **Continue without signing in** to manually paste or upload
email screenshots. A guest receives an unpredictable workspace isolated from
all other guests; manual scans and language preferences are scoped to that
workspace. The guest session expires after eight hours. Scans remain in the
application database until deleted, even after the guest session expires, so
guests should delete scans before leaving if they want them removed. Gmail
connection, sync, and Google-account data still require Google sign-in. Guest
scans are not transferred to a Google account.

## Email privacy and encryption

The app encrypts sender, subject, body, scan reasons, the connected account
email, and OAuth tokens before storing them in `emails.db`. By default on
Windows it uses Windows Data Protection (DPAPI), tied to your Windows user
profile. With `APP_DATA_ENCRYPTION_KEY`, it uses portable Fernet encryption
instead. **You do not need an App Password.** The
dashboard decrypts messages when displaying them. Risk score, folder status,
received timestamp, provider, and provider message ID remain as database
metadata for filtering, sorting, and duplicate detection.

This protects the database file at rest. Each app user's emails, Gmail token,
sync state, and language preferences are scoped to their verified Google
identity. Anyone using your Windows account while the app is running can still
access the local database through that Windows profile. A DPAPI-protected
database cannot be decrypted from another Windows user profile.

To move an existing DPAPI database to a non-Windows host, set
`APP_DATA_ENCRYPTION_KEY` and run the upgraded app on the original Windows
profile first. That migrates the encrypted fields and tokens to the portable
key. Only then copy the database and use the exact same key on the new host.
Never upload the DPAPI database directly to a Linux host.

On the first start after upgrading from the old Fernet-encrypted version, the
app migrates saved messages to the configured encryption format (DPAPI on
Windows by default, or the portable key when `APP_DATA_ENCRYPTION_KEY` is set).
If that database has the previous `MAIL_TOKEN_ENCRYPTION_KEY` check, provide
that old key in PowerShell for this one-time migration only. The app will not
store it; remove it after migration. Without the old key, previously encrypted
data cannot be recovered. Existing App Password connections are removed;
connect Gmail again through Google.

## Configure Google sign-in and Gmail

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
   $env:APP_SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
   python app.py
   ```

   Enter the credentials-file passphrase in the PowerShell window when
   prompted at startup. Keep that window open while using the app.
6. Open `http://127.0.0.1:5000` and choose **Sign in with Google**. A verified
   Google sign-in creates the app session and connects that user's Gmail. The
   app keeps OAuth client credentials in memory and stores each user's OAuth
   token using Windows DPAPI.

Each user signs in with their own Google account. Share the OAuth client
configuration only with trusted operators; anyone who has both
`google_oauth.enc` and its passphrase can recover the client secret. A
distributed desktop app cannot keep a shared OAuth client secret truly
confidential. For stronger security, use a desktop OAuth client that does not
require a client secret.

### Existing database migration

The first launch against a pre-authentication `emails.db` adds ownership-aware
schema but leaves existing emails, settings, Gmail accounts, and sync records
unassigned and inaccessible. Before starting an upgrade, stop the app and back
up the configured database. To avoid changing an original or Downloads copy,
make a separate working copy and point `DATABASE_PATH` at that copy, for
example:

```powershell
$env:DATABASE_PATH = "C:\PhishGuard\migration-copy\emails.db"
$env:LEGACY_DATA_OWNER_EMAIL = "owner@example.com"
```

Set `LEGACY_DATA_OWNER_EMAIL` to the exact Google account that owns the old
single-user data, then sign in with that account. The callback compares the
verified Google email with this setting and assigns the unowned records
atomically to that Google subject. If the setting is missing or the wrong
account signs in, the app fails closed with an actionable error; no visitor can
claim the rows. After a successful assignment, the ownership marker remains in
the database and the environment setting can be removed. New users can then
sign in normally. Do not share the database file through OneDrive or another
live file-sync service.

### Free test hosting on Render

Render offers free Python web services for hobby testing ([plan limits](https://render.com/docs/free)).
Create a **Web Service** from this repository using the **Docker** runtime and
the root `Dockerfile`. It installs Tesseract and starts Gunicorn. If you already
created a Python-native service, change its runtime to Docker in the service
source settings so screenshot OCR is available. Do not enter separate build or
start commands; the Dockerfile provides them.

In the service's environment settings, keep/add `APP_ENV=production`,
`APP_SECRET_KEY`, `APP_DATA_ENCRYPTION_KEY`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, and
`DATABASE_PATH=/tmp/phishguard-demo.db`. The separate database path avoids
loading any existing local `emails.db` in the repository. Generate the two keys
using the commands above. After Render gives the service a URL, set the callback
to `https://<your-service>.onrender.com/auth/google/callback` and register that
exact URL in the Google OAuth client. For Google's consent screen in Testing
mode, add each test account as a test user. Public use of Gmail's restricted
read-only scope requires Google's OAuth verification before inviting general
users. Leave `LEGACY_DATA_OWNER_EMAIL` unset for a fresh demo database.

This is only for testing: Render's free service sleeps after inactivity and
its filesystem is temporary, so the SQLite database and test data can be lost
when the service sleeps, restarts, or redeploys. Do not use real or important
mail there. The app is configured for one worker process; the free service is
for a small demo, not production.

Sync imports regular Gmail messages (excluding Spam and Trash), including
headers and text bodies; attachments are not downloaded. The first Gmail
connection scans up to 20 messages. The **Scan next** button below the email list
then scans up to 40 more messages per click, until Gmail has no more pages.
Imported messages remain in the local database after disconnecting. The app
does not send, label, move, or delete mail in Gmail. Repeated syncs do not create
duplicate messages.

## Run

```bash
python app.py
```

Open the dashboard at:

http://127.0.0.1:5000

The dashboard lets you scan the signed-in user's Gmail in batches, submit emails
manually, view detection reasons, move emails between Inbox, Review and
Quarantine, or delete local copies. Select the summary cards above the email
list to filter by All emails, Inbox, Needs review, or Quarantined. The sidebar
also includes lessons on staying safe online and spotting phishing. **Refresh**
reloads the saved email list; use **Scan next** below the list to fetch the next
Gmail batch.
**Clear saved emails** removes the signed-in user's email records, but keeps
their language settings and Gmail connection. It does not delete Gmail
messages; a later sync can import them again.

## South African language scanning

After signing in, choose a website language before opening the landing page.
The interface supports all 11 official South African languages. Choose a
primary language and any number of secondary languages in scanner settings;
the primary language gets first priority, and all 11 keyword catalogs are still
checked so an unselected South African language is not missed. Preferences are
saved per Google account and apply to manual scans and Gmail sync.

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

All routes that access email, account, sync, or language data require a
Google-authenticated session. `/api/health`, `/login`, and the Google OAuth
start/callback endpoints are public.

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
