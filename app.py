import hmac
import os
import secrets
from datetime import timedelta
from functools import wraps

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge

from database import initialise_database, get_language_preferences, save_language_preferences
from email_system.image_scanner import ImageScanError, extract_email_from_image
from email_system.mailbox import (
    MailboxError,
    authorization_url,
    clear_saved_emails,
    disconnect_account,
    finish_authorization,
    list_accounts,
    start_sync,
    sync_status,
    unlock_oauth_credentials,
)
from models import (
    get_all_emails,
    get_emails_by_status,
    get_email,
    update_email_status,
    delete_email,
)
from email_system.receiver import receive_email
from scanner.languages import LANGUAGES


MAX_IMAGE_BYTES = 8 * 1024 * 1024

app = Flask(__name__)
app_secret = os.environ.get("APP_SECRET_KEY", "")
if len(app_secret) < 32:
    raise RuntimeError(
        "Set APP_SECRET_KEY to a random secret of at least 32 characters before starting the app."
    )
app.config.update(
    SECRET_KEY=app_secret,
    MAX_CONTENT_LENGTH=MAX_IMAGE_BYTES + 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("APP_ENV", "").lower() == "production",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
if os.environ.get("APP_ENV", "").lower() == "production" and not os.environ.get(
    "GOOGLE_REDIRECT_URI", ""
).startswith("https://"):
    raise RuntimeError(
        "Production requires GOOGLE_REDIRECT_URI to be an HTTPS callback URL."
    )

initialise_database()
unlock_oauth_credentials()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user_id:
            if request.path.startswith(("/api/", "/emails", "/mail/")):
                return jsonify({"error": "Sign in with Google to continue."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def workspace_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.data_user_id:
            if request.path.startswith(("/api/", "/emails")):
                return jsonify({
                    "error": "Sign in or continue as a guest to use manual scanning."
                }), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def load_user_and_check_csrf():
    g.user_id = session.get("user_id")
    g.guest_id = session.get("guest_id")
    g.data_user_id = g.user_id or g.guest_id
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and g.data_user_id:
        expected = session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(
            expected.encode("utf-8"), supplied.encode("utf-8")
        ):
            return jsonify({"error": "The request could not be verified. Reload the page and try again."}), 400


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(error):
    message = (
        "Image uploads must be 8 MB or smaller."
        if request.path == "/emails/image"
        else "The request body is too large."
    )
    return jsonify({"error": message}), 413


def render_page(template):
    return render_template(
        template,
        languages=LANGUAGES,
        language_preferences=get_language_preferences(g.data_user_id),
        csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)),
        user_email=session.get("user_email", ""),
        is_guest=bool(g.guest_id),
    )


@app.route("/login")
def login():
    if g.user_id:
        return redirect(url_for("home"))
    return render_template(
        "login.html",
        error=request.args.get("error", ""),
        csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)),
    )


@app.route("/auth/guest", methods=["POST"])
def continue_as_guest():
    if g.user_id:
        return redirect(url_for("home"))
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(
        expected.encode("utf-8"), supplied.encode("utf-8")
    ):
        return render_template(
            "login.html",
            error="The request could not be verified. Reload the page and try again.",
            csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)),
        ), 400

    session.clear()
    session.permanent = True
    session["guest_id"] = "guest:" + secrets.token_urlsafe(32)
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("home"))


@app.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@workspace_required
def home():
    if not get_language_preferences(g.data_user_id)["language_selected"]:
        return render_page("language.html")
    return render_page("index.html")


@app.route("/scanner")
@workspace_required
def scanner():
    if not get_language_preferences(g.data_user_id)["language_selected"]:
        return redirect(url_for("home"))
    return render_page("scanner.html")


@app.route("/about")
@workspace_required
def about():
    if not get_language_preferences(g.data_user_id)["language_selected"]:
        return redirect(url_for("home"))
    return render_page("about.html")


@app.route("/api/language-settings", methods=["GET", "PUT"])
@workspace_required
def language_settings():
    if request.method == "GET":
        return jsonify({
            **get_language_preferences(g.data_user_id),
            "languages": LANGUAGES,
        })

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Language settings must be a JSON object."}), 400
    try:
        preferences = save_language_preferences(
            g.data_user_id,
            data.get("primary_language"),
            data.get("secondary_languages", []),
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({**preferences, "language_selected": True})


@app.route("/api/health")
def health():
    return jsonify({
        "application": "Phishing Email Detector",
        "status": "running"
    })


@app.after_request
def prevent_private_response_caching(response):
    if request.path.startswith(("/api/", "/emails", "/mail/")) or request.path in {
        "/", "/scanner", "/about"
    }:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/auth/google")
def connect_gmail():
    try:
        session.clear()
        login_url, state = authorization_url()
        session["oauth_state"] = state
        return redirect(login_url)
    except MailboxError as error:
        return redirect(url_for("login", error=str(error)))


@app.route("/auth/google/callback")
def gmail_callback():
    if request.args.get("error"):
        return redirect(url_for("login", error="Google sign-in was canceled."))
    expected_state = session.pop("oauth_state", None)
    state = request.args.get("state", "")
    if not expected_state or not state or not hmac.compare_digest(
        expected_state.encode("utf-8"), state.encode("utf-8")
    ):
        return redirect(url_for("login", error="Sign-in could not be verified. Please try again."))
    try:
        identity = finish_authorization(state, request.args.get("code"))
        session.clear()
        session.permanent = True
        session["user_id"] = identity["id"]
        session["user_email"] = identity["email"]
        session["csrf_token"] = secrets.token_urlsafe(32)
    except MailboxError as error:
        return redirect(url_for("login", error=str(error)))
    try:
        start_sync(identity["id"], "google")
    except MailboxError as error:
        return redirect(url_for("scanner", mail_error=str(error)))
    return redirect(url_for("scanner", connected="google"))


@app.route("/mail/accounts", methods=["GET"])
@login_required
def mail_accounts():
    try:
        return jsonify(list_accounts(g.user_id))
    except MailboxError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/mail/accounts/<provider>", methods=["DELETE"])
@login_required
def remove_mail_account(provider):
    try:
        disconnect_account(g.user_id, provider)
    except MailboxError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({"message": "Email account disconnected. Imported messages remain in the local database."})


@app.route("/mail/sync/<provider>", methods=["POST"])
@login_required
def sync_mailbox(provider):
    try:
        return jsonify(start_sync(g.user_id, provider)), 202
    except MailboxError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/mail/sync/<provider>/status", methods=["GET"])
@login_required
def mail_sync_status(provider):
    try:
        return jsonify(sync_status(g.user_id, provider))
    except MailboxError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/emails", methods=["POST"])
@workspace_required
def create_email():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No email data supplied"}), 400

    sender = data.get("sender")
    subject = data.get("subject")
    body = data.get("body")
    if not sender or not subject or not body:
        return jsonify({"error": "sender, subject and body are required"}), 400

    result = receive_email(g.data_user_id, sender, subject, body)
    return jsonify(result), 201


@app.route("/emails/image", methods=["POST"])
@workspace_required
def scan_email_image():
    upload = request.files.get("image")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose an image file to scan."}), 400

    image_bytes = upload.stream.read(MAX_IMAGE_BYTES + 1)
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return jsonify({"error": "Image uploads must be 8 MB or smaller."}), 413

    try:
        email = extract_email_from_image(image_bytes)
    except ImageScanError as error:
        return jsonify({"error": str(error)}), 400

    result = receive_email(
        g.data_user_id,
        email["sender"],
        email["subject"],
        email["body"],
    )
    return jsonify(result), 201


@app.route("/emails", methods=["GET", "DELETE"])
@workspace_required
def emails():
    if request.method == "DELETE":
        try:
            deleted_count = clear_saved_emails(g.data_user_id)
        except MailboxError as error:
            return jsonify({
                "error": str(error),
                "code": "sync_in_progress",
            }), 409
        return jsonify({"deleted_count": deleted_count})
    return jsonify(get_all_emails(g.data_user_id))


@app.route("/emails/inbox", methods=["GET"])
@workspace_required
def inbox():
    return jsonify(get_emails_by_status(g.data_user_id, "inbox"))


@app.route("/emails/review", methods=["GET"])
@workspace_required
def review():
    return jsonify(get_emails_by_status(g.data_user_id, "review"))


@app.route("/emails/quarantine", methods=["GET"])
@workspace_required
def quarantine():
    return jsonify(get_emails_by_status(g.data_user_id, "quarantine"))


@app.route("/emails/<int:email_id>", methods=["GET"])
@workspace_required
def get_single_email(email_id):
    email = get_email(g.data_user_id, email_id)
    if not email:
        return jsonify({"error": "Email not found"}), 404
    return jsonify(email)


@app.route("/emails/<int:email_id>/move", methods=["PUT"])
@workspace_required
def move_email(email_id):
    data = request.get_json()
    if not data or "status" not in data:
        return jsonify({"error": "Status is required"}), 400

    new_status = data["status"]
    allowed_statuses = ["inbox", "review", "quarantine"]
    if new_status not in allowed_statuses:
        return jsonify({"error": "Invalid status"}), 400
    if not get_email(g.data_user_id, email_id):
        return jsonify({"error": "Email not found"}), 404
    update_email_status(g.data_user_id, email_id, new_status)
    return jsonify({
        "message": "Email moved successfully",
        "email_id": email_id,
        "new_status": new_status
    })


@app.route("/emails/<int:email_id>", methods=["DELETE"])
@workspace_required
def remove_email(email_id):
    if not get_email(g.data_user_id, email_id):
        return jsonify({"error": "Email not found"}), 404
    delete_email(g.data_user_id, email_id)
    return jsonify({"message": "Email deleted successfully"})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
