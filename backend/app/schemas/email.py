"""Shared email validation for every request schema.

Pydantic's ``EmailStr`` (email-validator) rejects *special-use* domains —
RFC 6761/2606 names such as ``.local``, ``.internal``, ``.onion``,
``localhost``, ``.invalid``, ``arpa`` — because they can never be reached over
the public Internet. OpenDRP is routinely deployed inside corporate networks
where operator accounts, monitored mailboxes and SMTP relays live on exactly
those names, so rejecting them makes the platform unusable in the environment
it targets.

Two deliberate design points:

* ``check_deliverability=False`` — request validation must never perform DNS
  lookups. It would add latency to every write and leak internal hostnames to
  a public resolver.
* Dotless domains (``user@localhost``) stay rejected: only the reserved-name
  rejection is relaxed, so ``a@b`` and ``not-an-email`` are still invalid.

The relaxed path re-uses email-validator's own local-part grammar by validating
the same local part against a public domain probe, and only then checks the
domain against a hostname grammar. Nothing is hand-rolled.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from email_validator import EmailNotValidError, validate_email
from pydantic import BeforeValidator

# Marker used by email-validator when the domain is a special-use/reserved name.
_SPECIAL_USE_MARKER = "special-use or reserved name"

# Zone-file style hostname: 1..63 char labels, no leading/trailing hyphen,
# at least one label, total length bounded. Accepts `localdomain.local`,
# `corp.internal`, `example.com`.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def normalize_email(value: Any) -> Any:
    """Validate and normalize an address, allowing internal domains."""
    if not isinstance(value, str):
        return value
    candidate = value.strip()
    if not candidate:
        raise ValueError("Email address must not be empty")

    try:
        info = validate_email(
            candidate, check_deliverability=False, test_environment=True
        )
        return info.normalized
    except EmailNotValidError as exc:
        message = str(exc)
        if _SPECIAL_USE_MARKER not in message:
            raise ValueError(message) from exc

    local_part, separator, domain = candidate.rpartition("@")
    if not separator or not local_part or not domain:
        raise ValueError("An email address must have an @-sign.")
    # Reuse the library's local-part rules: the probe domain is public, so a
    # bad local part still fails exactly as it would for a public address.
    try:
        validate_email(f"{local_part}@example.com", check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError(str(exc)) from exc
    if not _HOSTNAME_RE.match(domain):
        raise ValueError(
            "The part after the @-sign is not a valid hostname."
        )
    return f"{local_part}@{domain.lower()}"


EmailAddress = Annotated[str, BeforeValidator(normalize_email)]
