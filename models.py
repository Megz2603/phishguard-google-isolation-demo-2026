from database import get_connection
from email_system.encryption import decrypt_field, encrypt_field


PRIVATE_FIELDS = ("sender", "subject", "body", "reasons")


def _decode_email(row):
    """Return a dashboard-ready email while keeping SQLite values encrypted."""
    email = dict(row)
    for field in PRIVATE_FIELDS:
        email[field] = decrypt_field(email[field])
    return email


def save_email(
    sender, subject, body, risk_score, status, reasons,
    provider=None, external_id=None, created_at=None
):
    """Scan results are stored with all message content encrypted."""
    connection = get_connection()
    content = tuple(encrypt_field(value) for value in (
        sender, subject, body, reasons
    ))

    if provider and external_id:
        connection.execute("""
            INSERT OR IGNORE INTO emails
            (sender, subject, body, risk_score, status, reasons,
             provider, external_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
        """, (
            content[0], content[1], content[2], risk_score, status,
            content[3], provider, external_id, created_at
        ))
        email_id = connection.execute("""
            SELECT id FROM emails WHERE provider = ? AND external_id = ?
        """, (provider, external_id)).fetchone()["id"]
    else:
        cursor = connection.execute("""
            INSERT INTO emails (sender, subject, body, risk_score, status, reasons)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            content[0], content[1], content[2],
            risk_score, status, content[3]
        ))
        email_id = cursor.lastrowid

    connection.commit()
    connection.close()
    return email_id


def _get_emails(query, parameters=()):
    connection = get_connection()
    rows = connection.execute(query, parameters).fetchall()
    connection.close()
    return [_decode_email(row) for row in rows]


def get_all_emails():
    return _get_emails("SELECT * FROM emails ORDER BY created_at DESC")


def get_emails_by_status(status):
    return _get_emails(
        "SELECT * FROM emails WHERE status = ? ORDER BY created_at DESC",
        (status,)
    )


def get_email(email_id):
    connection = get_connection()
    row = connection.execute(
        "SELECT * FROM emails WHERE id = ?", (email_id,)
    ).fetchone()
    connection.close()
    return _decode_email(row) if row else None


def update_email_status(email_id, status):
    connection = get_connection()
    connection.execute(
        "UPDATE emails SET status = ? WHERE id = ?", (status, email_id)
    )
    connection.commit()
    connection.close()


def delete_email(email_id):
    connection = get_connection()
    connection.execute("DELETE FROM emails WHERE id = ?", (email_id,))
    connection.commit()
    connection.close()
