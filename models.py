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
    user_id, sender, subject, body, risk_score, status, reasons,
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
            (user_id, sender, subject, body, risk_score, status, reasons,
             provider, external_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
        """, (
            user_id, content[0], content[1], content[2], risk_score, status,
            content[3], provider, external_id, created_at
        ))
        email_id = connection.execute("""
            SELECT id FROM emails
            WHERE user_id = ? AND provider = ? AND external_id = ?
        """, (user_id, provider, external_id)).fetchone()["id"]
    else:
        cursor = connection.execute("""
            INSERT INTO emails
                (user_id, sender, subject, body, risk_score, status, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, content[0], content[1], content[2],
            risk_score, status, content[3]
        ))
        email_id = cursor.lastrowid

    connection.commit()
    connection.close()
    return email_id


def save_emails(user_id, emails):
    """Encrypt and insert a mailbox batch in one transaction."""
    encrypted_rows = []
    for email in emails:
        content = tuple(encrypt_field(email[field]) for field in (
            "sender", "subject", "body", "reasons"
        ))
        encrypted_rows.append((
            content[0],
            content[1],
            content[2],
            email["risk_score"],
            email["status"],
            content[3],
            email["provider"],
            email["external_id"],
            email.get("created_at"),
        ))

    connection = get_connection()
    try:
        connection.executemany("""
            INSERT OR IGNORE INTO emails
            (user_id, sender, subject, body, risk_score, status, reasons,
             provider, external_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
        """, [(user_id, *row) for row in encrypted_rows])
        connection.commit()
    finally:
        connection.close()


def _get_emails(query, parameters=()):
    connection = get_connection()
    rows = connection.execute(query, parameters).fetchall()
    connection.close()
    return [_decode_email(row) for row in rows]


def get_all_emails(user_id):
    return _get_emails(
        "SELECT * FROM emails WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    )


def get_emails_by_status(user_id, status):
    return _get_emails(
        "SELECT * FROM emails WHERE user_id = ? AND status = ? ORDER BY created_at DESC",
        (user_id, status)
    )


def get_email(user_id, email_id):
    connection = get_connection()
    row = connection.execute(
        "SELECT * FROM emails WHERE user_id = ? AND id = ?", (user_id, email_id)
    ).fetchone()
    connection.close()
    return _decode_email(row) if row else None


def update_email_status(user_id, email_id, status):
    connection = get_connection()
    connection.execute(
        "UPDATE emails SET status = ? WHERE user_id = ? AND id = ?",
        (status, user_id, email_id)
    )
    connection.commit()
    connection.close()


def delete_email(user_id, email_id):
    connection = get_connection()
    try:
        connection.execute(
            "DELETE FROM emails WHERE user_id = ? AND id = ?", (user_id, email_id)
        )
        connection.commit()
    finally:
        connection.close()


def delete_all_emails(user_id):
    connection = get_connection()
    try:
        cursor = connection.execute("DELETE FROM emails WHERE user_id = ?", (user_id,))
        connection.commit()
        return cursor.rowcount
    finally:
        connection.close()
