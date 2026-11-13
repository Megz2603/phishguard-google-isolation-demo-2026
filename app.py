from flask import Flask, jsonify, redirect, render_template, request, url_for

from database import initialise_database
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
    delete_email
)
from email_system.receiver import receive_email
from database import get_language_preferences, save_language_preferences
from scanner.languages import LANGUAGES

app = Flask(__name__)

# Verify DPAPI access and migrate any older database rows before serving requests.
initialise_database()
unlock_oauth_credentials()


# WELCOME PAGE
def render_page(template):
    return render_template(
        template,
        languages=LANGUAGES,
        language_preferences=get_language_preferences(),
    )


@app.route("/")
def home():
    if not get_language_preferences()["language_selected"]:
        return render_page("language.html")
    return render_page("index.html")


# EMAIL SCANNER DASHBOARD
@app.route("/scanner")
def scanner():
    if not get_language_preferences()["language_selected"]:
        return redirect(url_for("home"))
    return render_page("scanner.html")


# ABOUT PAGE
@app.route("/about")
def about():
    if not get_language_preferences()["language_selected"]:
        return redirect(url_for("home"))
    return render_page("about.html")


@app.route("/api/language-settings", methods=["GET", "PUT"])
def language_settings():
    if request.method == "GET":
        return jsonify({
            **get_language_preferences(),
            "languages": LANGUAGES,
        })

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Language settings must be a JSON object."}), 400
    try:
        preferences = save_language_preferences(
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
def prevent_email_caching(response):
    # API responses contain decrypted message content for the dashboard.
    if request.path.startswith(("/emails", "/mail/")):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/auth/google")
def connect_gmail():
    try:
        login_url, _ = authorization_url()
        return redirect(login_url)
    except MailboxError as error:
        return redirect(url_for("scanner", mail_error=str(error)))


@app.route("/auth/google/callback")
def gmail_callback():
    if request.args.get("error"):
        return redirect(url_for("scanner", mail_error="Google sign-in was canceled."))
    try:
        finish_authorization(request.args.get("state"), request.args.get("code"))
        start_sync("google")
        return redirect(url_for("scanner", connected="google"))
    except MailboxError as error:
        return redirect(url_for("scanner", mail_error=str(error)))


@app.route("/mail/accounts", methods=["GET"])
def mail_accounts():
    return jsonify(list_accounts())


@app.route("/mail/accounts/<provider>", methods=["DELETE"])
def remove_mail_account(provider):
    try:
        disconnect_account(provider)
    except MailboxError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({"message": "Email account disconnected. Imported messages remain in the local database."})


@app.route("/mail/sync/<provider>", methods=["POST"])
def sync_mailbox(provider):
    try:
        return jsonify(start_sync(provider)), 202
    except MailboxError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/mail/sync/<provider>/status", methods=["GET"])
def mail_sync_status(provider):
    try:
        return jsonify(sync_status(provider))
    except MailboxError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/emails", methods=["POST"])
def create_email():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No email data supplied"}), 400

    sender = data.get("sender")
    subject = data.get("subject")
    body = data.get("body")

    if not sender or not subject or not body:
        return jsonify({
            "error": "sender, subject and body are required"
        }), 400

    result = receive_email(sender, subject, body)
    return jsonify(result), 201


@app.route("/emails", methods=["GET", "DELETE"])
def emails():
    if request.method == "DELETE":
        try:
            deleted_count = clear_saved_emails()
        except MailboxError as error:
            return jsonify({
                "error": str(error),
                "code": "sync_in_progress",
            }), 409
        return jsonify({"deleted_count": deleted_count})
    return jsonify(get_all_emails())


@app.route("/emails/inbox", methods=["GET"])
def inbox():
    return jsonify(get_emails_by_status("inbox"))


@app.route("/emails/review", methods=["GET"])
def review():
    return jsonify(get_emails_by_status("review"))


@app.route("/emails/quarantine", methods=["GET"])
def quarantine():
    return jsonify(get_emails_by_status("quarantine"))


@app.route("/emails/<int:email_id>", methods=["GET"])
def get_single_email(email_id):
    email = get_email(email_id)

    if not email:
        return jsonify({"error": "Email not found"}), 404

    return jsonify(email)


@app.route("/emails/<int:email_id>/move", methods=["PUT"])
def move_email(email_id):
    data = request.get_json()

    if not data or "status" not in data:
        return jsonify({"error": "Status is required"}), 400

    new_status = data["status"]
    allowed_statuses = ["inbox", "review", "quarantine"]

    if new_status not in allowed_statuses:
        return jsonify({"error": "Invalid status"}), 400

    if not get_email(email_id):
        return jsonify({"error": "Email not found"}), 404

    update_email_status(email_id, new_status)

    return jsonify({
        "message": "Email moved successfully",
        "email_id": email_id,
        "new_status": new_status
    })


@app.route("/emails/<int:email_id>", methods=["DELETE"])
def remove_email(email_id):
    if not get_email(email_id):
        return jsonify({"error": "Email not found"}), 404

    delete_email(email_id)
    return jsonify({"message": "Email deleted successfully"})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
