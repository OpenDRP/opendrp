"""The words a delivered alert is made of — no database, no network, no policy.

Everything here is pure: it takes the facts of one finding (already sanitized by
:mod:`app.services.alert_content`) and produces the neutral ``Notification`` that
each channel renders, or the vocabulary a subject line uses. Keeping this layer
free of I/O is what lets it be read in one sitting and tested directly, and it is
what the delivery path renders from regardless of which channel sends and which
module reported the finding.
"""

import html
from collections import Counter
from dataclasses import dataclass
from urllib.parse import quote

from app.core.config import settings
from app.services.alert_content import fact_text

#: Longest single value a delivered message prints before it is clipped. A
#: connector controls these strings, and one 4 KB "domain" must not be able to
#: push every other finding out of its own alert.
MAX_FIELD_CHARS = 160
#: The same bound for values in the breakdown, which prints several per line.
BREAKDOWN_CHARS = 80
#: How many distinct values a breakdown line counts before it counts the rest,
#: so a job that matched 400 assets does not print 400 of them.
MAX_BREAKDOWN_VALUES = 4
#: Room kept for the "… +N more findings" line. It is what explains a truncated
#: list, so it is charged to the budget the list was built against.
OMISSION_NOTE_RESERVE = 64
#: Hosts whose "link" would point at the reader's own machine rather than at
#: this installation.
# B104 is about binding a listener, not rejecting a URL host supplied as input.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # nosec B104
#: The finding list a delivered message links to, per threat type. A module
#: declared at runtime has its own page, named by its registry id.
FINDING_PATHS = {"phishing": "/phishing", "breach": "/breaches", "dns": "/dns-security", "dns_security": "/dns-security"}
#: Payload keys that are already a finding's own fact, so the generic loop below
#: must not print them a second time under the name they arrived with.
NEUTRAL_KEYS = frozenset(
    {
        "phishing_domain",
        "matched_asset",
        "detection_source",
        "breach_name",
        "matched_email",
        "matched_domain",
        "domain",
        "fields",
        "title",
    }
)
#: The payload keys a phishing message prints as columns of its own (WI-02). The
#: list is exhaustive on purpose: a phishing event also carries the rule and the
#: severity that shape the message rather than fill a column, and the raw finding
#: with the source it came from — evidence the platform stores once, for the page
#: this message links to, not for the mail. An exhaustive list is what keeps a
#: service key a later wave adds to an event from turning into a column by accident.
PHISHING_COLUMNS = frozenset({"Field", "Previous value", "Current value"})
#: The columns a breach message prints (WI-01), which is the whole set it may print.
#: Exhaustive for the same reason the phishing list is — a payload key a later wave
#: adds must not become a column of a delivered message by accident — and here it
#: also closes the defect this list was written for: the old rule
#: ("everything that is not one of the finding's own neutral facts") printed the
#: machine's own bookkeeping, so an operator opening a breach alert read an `id`, a
#: `created_at`, a truncated `description`, a JSON-encoded `data_classes` and the raw
#: `attributes` blob next to the two facts that mattered.
#:
#: What each column is: which *event* this delivery reports (a new incident, one that
#: grew, a correction), the incident, the account it matched, the vendor's domain, the
#: date, the classes of data, how many accounts the incident covers, and — only when
#: the source stated one — the verification state and whether the metadata arrived.
BREACH_COLUMNS = frozenset(
    {
        "Event",
        "Incident",
        "Account",
        "Vendor domain",
        "Breach date",
        "Data classes",
        "Accounts affected",
        "Verification",
        "Exposure",
    }
)
#: The words a message uses for the class of exposure a breach row is. A breach of an
#: account keeps no column: it is what the module always meant, and printing it would
#: add a line to every message that has nothing new to say. A paste or a stealer-log
#: site is a different kind of document, and a reader who is not told which one is
#: reading a partial statement (WI-17, WI-18).
BREACH_EXPOSURE_LABELS = {
    "paste": "Paste",
    "stealer_log": "Stealer log",
}


def breach_exposure_label(value) -> str | None:
    return BREACH_EXPOSURE_LABELS.get(str(value or "").strip().lower())


#: The change classes a breach event can carry, in the words a message uses. The
#: class is what tells a reader why this incident is in their inbox at all: the same
#: incident reported twice means two different things (it grew, or it was confirmed).
BREACH_EVENT_LABELS = {
    "new_incident": "New incident",
    "incident_grew": "Incident grew",
    "new_data_class": "New data class",
    "reappeared": "Reappeared after being resolved",
    "now_verified": "Confirmed by the source",
    "date_corrected": "Breach date corrected",
}


def breach_event_label(value) -> str:
    """The delivery's change class, in words.

    An event written before the class existed carries none, and it was a first
    sighting: ``New incident`` is what it means rather than a placeholder.
    """
    key = str(value or "").strip().lower()
    return BREACH_EVENT_LABELS.get(key, "New incident")


def declared_column(threat_type: str, name: str) -> bool:
    """Whether a payload key may become a column of a delivered message.

    The two built-in modules that were rendered from the payload of the moment the
    finding arrived (phishing, breach) keep a declared list rather than a rule — the
    keys the module says it prints and nothing else — while a module declared at
    runtime contributes the fields it declared to begin with. Phishing and breaches
    both refuse a payload key that is not in their own list, so the machine's
    bookkeeping (an id, a status, a source, a created_at, a raw attributes blob)
    cannot reach a human through a message.
    """
    if threat_type == "phishing":
        return name in PHISHING_COLUMNS
    if threat_type == "breach":
        return name in BREACH_COLUMNS
    return name not in NEUTRAL_KEYS


BADGE_CLASSES = {"phishing": "badge-phishing", "breach": "badge-breach"}


#: How the severities a module may report on a row compare. A module that sends
#: none keeps the subject it always had; DNS Security sends one per arrival.
SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2}


def highest_severity(findings: list[dict]) -> str | None:
    """The worst severity in one batch, when the module reported any at all.

    The subject is what an operator sees in a mail list or a Telegram push, so a
    batch that contains something urgent has to say so there, not only after the
    message is opened (F-01 in the DNS & TLS audit: arrivals were reported as one
    flat feed of the same weight as an expiry reminder).
    """
    ranked = [
        str(item.get("severity") or "").lower()
        for item in findings
        if str(item.get("severity") or "").lower() in SEVERITY_RANK
    ]
    if not ranked:
        return None
    return max(ranked, key=lambda value: SEVERITY_RANK[value])


def clip(value: object, limit: int = MAX_FIELD_CHARS) -> str:
    """One printable value: single line, bounded, and never a raw `None`."""
    text = " ".join(str("N/A" if value is None else value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def escaped(value: object, limit: int = MAX_FIELD_CHARS) -> str:
    """`clip`, escaped for Telegram's HTML parse mode.

    Clipping happens before escaping on purpose: escaping first would let a slice
    cut `&amp;` in half, which Telegram reads as an unknown entity and rejects.
    """
    return html.escape(clip(value, limit))


def counted(values: list[str]) -> str:
    """`a × 3, b × 1`: most frequent first, the tail counted rather than listed."""
    ordered = sorted(Counter(values).items(), key=lambda item: (-item[1], item[0]))
    shown = [f"{value} × {count}" for value, count in ordered[:MAX_BREAKDOWN_VALUES]]
    if len(ordered) > len(shown):
        shown.append(f"+{len(ordered) - len(shown)} more")
    return ", ".join(shown)


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def finding_path(threat_type: str) -> str:
    """The page a delivered message links to for this threat type."""
    if threat_type in FINDING_PATHS:
        return FINDING_PATHS[threat_type]
    if threat_type.startswith("module:"):
        module_id = threat_type.removeprefix("module:").strip()
        if module_id:
            return f"/modules/{quote(module_id, safe='')}"
    return "/dashboard"


@dataclass(frozen=True)
class Notification:
    """One queued alert batch, in the neutral shape each channel renders.

    The module decides the content — which values identify a finding, and which
    of them are worth counting — while the channel decides the layout. That split
    is what lets a source onboarded as data reach an inbox or a chat without a
    line of per-source rendering code.
    """

    label: str
    subject: str
    job_id: str
    total: int
    included: int
    rows: list[dict[str, str]]
    groups: list[tuple[str, str]]
    link: str | None

    @property
    def columns(self) -> list[str]:
        """Every fact name the findings use, in the order they named them.

        A module declares its own fields, so two findings of one batch can carry
        different keys; the table shows the union rather than the first row's.
        """
        names: list[str] = []
        for row in self.rows:
            for name in row:
                if name not in names:
                    names.append(name)
        return names

    def table(self) -> list[list[str]]:
        """Rows aligned to `columns`, with a missing field shown as missing."""
        return [[row.get(name, "—") for name in self.columns] for row in self.rows]


def telegram_finding_line(index: int, row: dict[str, str]) -> str:
    values = list(row.values())
    primary = escaped(values[0]) if values else "N/A"
    details = [escaped(value) for value in values[1:4]]
    tail = " · ".join(details)
    if len(values) > 4:
        tail += f" · +{len(values) - 4} more fields"
    return f"{index}. <code>{primary}</code>" + (f" — {tail}" if tail else "")


def telegram_text(notification: Notification) -> str:
    """Render the summary Telegram receives, inside Telegram's own limits.

    Telegram answers a message it cannot parse (unbalanced or sliced markup) or
    one it considers too long with `400`, which the delivery queue records as a
    permanent failure — an alert lost to a length check rather than to an outage.
    So this never slices markup it built: the finding list is dropped line by
    line against a budget that already reserved the footer and the note saying
    how many findings were left out.
    """
    lines = [f"🚨 <b>OpenDRP {html.escape(notification.label.upper())}</b>"]
    counted_line = f"<b>{plural(notification.total, 'new finding')}</b>"
    if notification.included < notification.total:
        counted_line += f" · showing {notification.included}"
    lines.append(counted_line)
    if notification.groups:
        lines.append("")
        lines.extend(
            f"<b>{html.escape(name)}:</b> {html.escape(summary)}"
            for name, summary in notification.groups
        )
    if notification.rows:
        lines.append("")
        lines.append("<b>Findings</b>")
    footer = [f"Job <code>{html.escape(notification.job_id)}</code>"]
    if notification.link:
        footer.append(
            f'🔗 <a href="{html.escape(notification.link, quote=True)}">Open in OpenDRP</a>'
        )
    footer_text = "\n".join(footer)
    budget = (
        settings.ALERT_MAX_TELEGRAM_MESSAGE_LENGTH
        - OMISSION_NOTE_RESERVE
        - len(footer_text)
        - 1
    )
    text = "\n".join(lines)
    kept = 0
    for index, row in enumerate(notification.rows, start=1):
        line = telegram_finding_line(index, row)
        if len(text) + 1 + len(line) > budget:
            break
        text = f"{text}\n{line}"
        kept += 1
    if kept < len(notification.rows):
        missing = len(notification.rows) - kept
        text += f"\n… +{plural(missing, 'more finding')} in OpenDRP"
    return f"{text}\n\n{footer_text}"


def plain_text(notification: Notification) -> str:
    """The `text/plain` alternative: the same facts, readable without HTML."""
    lines = [notification.subject, ""]
    lines.append(f"Job: {notification.job_id}")
    counted_line = f"Findings: {notification.total}"
    if notification.included < notification.total:
        counted_line += f" (showing the first {notification.included})"
    lines.append(counted_line)
    lines.extend(f"{name}: {summary}" for name, summary in notification.groups)
    if notification.rows:
        lines.append("")
        for index, row in enumerate(notification.rows, start=1):
            facts = "  ".join(f"{name}={fact_text(value)}" for name, value in row.items())
            lines.append(f"{index:>3}. {facts}")
    if notification.link:
        lines.extend(["", f"Open in OpenDRP: {notification.link}"])
    return "\n".join(lines)


def digest_heading(count: int, threat_type: str = "phishing") -> tuple[str, str]:
    """The label and subject of a digest batch (WI-10, WI-06).

    A digest is not an alert: it is the daily statement that the channel is alive
    and what it decided was not worth a message at 02:30. Saying so in the subject
    is what keeps an operator from reading a summary of eighty look-alikes as one
    finding — and from concluding that the alert path has gone quiet.

    The breach backlog is the same kind of message from a different reason: those
    incidents were not below a threshold, there were simply more of them in one scan
    than a channel should interrupt someone for. Naming the module keeps the two
    apart in a mail list.
    """
    if threat_type == "breach":
        label = "Breach digest"
        return label, (
            f"[OpenDRP Alert] {label}: {plural(count, 'new incident')} "
            "from one scan"
        )
    label = "Phishing digest"
    return label, f"[OpenDRP Alert] {label}: {plural(count, 'candidate')} below the alert threshold"


def breach_subject_class(findings: list[dict]) -> str | None:
    """The change class of a batch, when every finding in it names the same one.

    The subject is what an operator triages from a mail list, so the class belongs
    there as well as in the first column (WI-08). A batch that mixes classes — or
    that holds an event written before the class existed — says nothing rather than
    naming the wrong one, which is the same rule the severity suffix follows.
    """
    classes = [str(item.get("change_class") or "") for item in findings]
    if not classes or any(not value for value in classes):
        return None
    if len(set(classes)) != 1:
        return None
    return breach_event_label(classes[0])
