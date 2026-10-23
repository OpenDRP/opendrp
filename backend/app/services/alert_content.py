"""Transport-neutral safe facts; no secret samples leave the platform."""
import html
import json
import re

from app.core.safe_errors import sanitize_external_error

_SECRET = re.compile(r"password|passwd|secret|token|authorization|cookie|credential|api.?key", re.I)


def safe_snapshot(value, key=""):
    if _SECRET.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): safe_snapshot(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [safe_snapshot(item, key) for item in value]
    if isinstance(value, str):
        return sanitize_external_error(value, limit=max(600, len(value)))
    return value


def fact_text(value):
    """One fact as a person reads it, where empty and missing are not the same.

    ``None`` is a fact nobody reported — a lookup that has not run, a column that
    has never been filled — and prints as ``N/A``. An empty string is a fact that
    *was* reported and carries nothing, and printing it as a blank made the two
    indistinguishable: a reader could not tell an empty registrar lookup from a
    field that was never looked up (AUD-015). It prints the mark the table
    renderer already uses for a value that carries nothing, with the reason.
    """
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if value is None:
        return "N/A"
    if isinstance(value, str) and not value.strip():
        return "— (empty)"
    return str(value)


def telegram_parts(notification, limit, batch_id=None):
    """Split text BEFORE escaping; every part has balanced independent markup."""
    header = f"🚨 <b>OpenDRP {html.escape(notification.label.upper())}</b>\n<b>{notification.counted()}</b>\n"
    header += "\n".join(f"<b>{html.escape(k)}:</b> {html.escape(v)}" for k, v in notification.groups)
    footer = f"\nJob <code>{html.escape(notification.job_id)}</code>"
    if notification.link:
        footer += f'\n<a href="{html.escape(notification.link, quote=True)}">Open in OpenDRP</a>'
    # At small configured limits omit the redundant summary, never a finding.
    if len(header) + len(footer) + 100 >= limit:
        header = f"🚨 <b>OpenDRP {html.escape(notification.label.upper())}</b>\n{notification.counted()}"
        footer = f"\nJob {html.escape(notification.job_id)}"
    reserve = len(header) + len(footer) + 90
    if reserve >= limit:
        raise ValueError("Telegram header exceeds message budget")
    budget = limit - reserve
    chunks = []
    for index, row in enumerate(notification.rows, 1):
        for field_index, (name, value) in enumerate(row.items()):
            text = f"{index}. {fact_text(value)}" if field_index == 0 else f"  {name}: {fact_text(value)}"
            current = ""
            for char in text:
                encoded = html.escape(char)
                if len(current) + len(encoded) > budget:
                    chunks.append(current)
                    current = ""
                current += encoded
            if current:
                chunks.append(current)
    bodies = []
    body = ""
    for chunk in chunks:
        if body and len(body) + len(chunk) + 1 > budget:
            bodies.append(body)
            body = ""
        body += ("\n" if body else "") + chunk
    bodies.append(body)
    result = []
    for index, body in enumerate(bodies, 1):
        identity = f"\nBatch {batch_id}" if batch_id else ""
        result.append(f"{header}\nPart {index}/{len(bodies)}{identity}\n{body}{footer}")
    if any(len(part) > limit for part in result):
        raise ValueError("Telegram part exceeds message budget")
    return result
