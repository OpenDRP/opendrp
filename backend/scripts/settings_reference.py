"""Render the settings audit table: name, default, validator, documentation.

The table is the exit criterion of step S19 in `docs/exec-plans/009-staged-audit.md`:
"does every setting have a validator, a documented default and a safe fallback?" —
a question that cannot be answered by reading the class once, because the answer
differs per field and the class grows.

It is generated rather than hand-written so that it cannot drift: the validator
column comes from the field's own metadata (`ge`/`le`, the model and field
validators listed below), the default from the field, and
`tests/test_settings_reference.py` fails when the committed table and this
renderer disagree. A new setting therefore arrives with a row — and with the
question "what validates this?" already asked and answered in the diff.

Usage::

    python -m scripts.settings_reference          # print the section
    python -m scripts.settings_reference --check   # exit 1 if the page is stale
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.services.report_service import MAX_RENDERED_REPORT_ROWS, MAX_REPORT_BYTES

#: Start and end markers of the generated section inside the page. Everything
#: between them is replaced by this script; the prose around it is not.
BEGIN = "<!-- BEGIN GENERATED SETTINGS TABLE -->"
END = "<!-- END GENERATED SETTINGS TABLE -->"

PAGE = Path(__file__).resolve().parents[2] / "docs" / "configuration.md"

#: The validator a setting runs, where the type alone does not say it. A field
#: with bounds renders them automatically; a field listed here renders this text
#: instead, and a field in neither place is reported as "type only" — which is a
#: statement about the setting, not a gap in the renderer.
_VALIDATORS: dict[str, str] = {
    # --- credentials and keys -------------------------------------------------
    "JWT_SECRET_KEY": "placeholder refused, `len >= 32`; production refuses a shipped or derived value",
    "ENCRYPTION_KEY": "must be a valid Fernet key (import-time check); production refuses a shipped value",
    "ENCRYPTION_PREVIOUS_KEYS": "comma-separated, each must be a valid Fernet key",
    "JWT_PREVIOUS_SECRET_KEYS": "comma-separated; in production each needs `len >= 32` and no placeholder",
    "AUDIT_CHAIN_KEYS": "comma-separated; production requires an explicit value (no derived fallback)",
    "AUDIT_CHAIN_PREVIOUS_KEYS": "comma-separated, verify-only",
    "METRICS_TOKEN": "empty disables the endpoint; production needs `len >= 32` and no placeholder",
    "JWT_ALGORITHM": "allowlist HS256/HS384/HS512, upper-cased",
    "AUTH_COOKIE_SECURE": "production refuses `false`",
    "OPENDRP_VERSION": "production requires a pinned semantic version",
    # --- addresses and networks ----------------------------------------------
    "DATABASE_URL": "parsed in production: the password must not be a shipped value",
    "REDIS_URL": "parsed in production: a non-loopback host must carry a password",
    "CORS_ORIGINS": "JSON array or comma list, parsed to a list",
    "TRUSTED_PROXY_IPS": "IPs/CIDRs only; refused when it covers the data or connector subnet",
    "UVICORN_FORWARDED_ALLOW_IPS": "IPs/CIDRs only; `*` is refused everywhere",
    "OPENDRP_NETWORK_SUBNET": "must parse as an IP network",
    "OPENDRP_EDGE_SUBNET": "must parse and lie inside `OPENDRP_NETWORK_SUBNET`",
    "OPENDRP_DATA_SUBNET": "must parse and lie inside `OPENDRP_NETWORK_SUBNET`",
    "OPENDRP_CONNECTOR_SUBNET": "must parse and lie inside `OPENDRP_NETWORK_SUBNET`",
    "OUTBOUND_ALLOWED_HOSTS": "comma-separated; each entry widens the outbound policy",
    "OUTBOUND_BLOCKED_CIDRS": "comma-separated CIDRs; additive to the built-in block list",
    # --- behaviour ------------------------------------------------------------
    "APP_ENV": "one of `development`/`test`/`integration`/`production` (case and whitespace normalised); an unknown value is refused. `production` switches the production-only checks on",
    "LOG_LEVEL": "one of CRITICAL/ERROR/WARNING/INFO/DEBUG, upper-cased",
    "REQUIRE_MFA_ROLES": "role names must exist (`admin`, `analyst`, `viewer`)",
    "ALERT_BREACH_NOISE_POLICY": "one of `store_only_spam`, `verified_only`, `all`",
    "ALERT_CONFIDENCE_DIGEST": "must stay below `ALERT_CONFIDENCE_DIRECT`",
    "ALERT_CONFIDENCE_DIRECT": "must stay above `ALERT_CONFIDENCE_DIGEST`",
    "HSTS_MAX_AGE": "must be positive when `HSTS_ENABLED`",
    "REPORTS_STORE_DIR": "resolved with `realpath`; every artifact read is contained by it",
    "AUDIT_ARCHIVE_DIR": "empty blocks audit retirement instead of deleting unarchived rows",
}

#: A sentence a setting's effect needs beside its bounds. The bounds are rendered
#: from the field itself; this is the part a reader cannot see in the declaration —
#: and it is derived from the constants that enforce it, so a ceiling that moves
#: moves the page with it instead of leaving a number nobody re-measures.
_NOTES: dict[str, str] = {
    "REPORT_MAX_ROWS": (
        "bounds each of the five sections, and the renderer refuses a document over "
        f"{MAX_RENDERED_REPORT_ROWS:,} rows in total (five sections at the default) or "
        f"{MAX_REPORT_BYTES // (1024 * 1024)} MiB, as `report_too_large`"
    ),
}

#: Kinds whose type *is* the validation, so the row says so instead of nothing.
_SIMPLE_TYPES: dict[Any, str] = {
    int: "type only",
    float: "type only",
    bool: "type only",
    str: "type only",
}


def _default(field) -> str:
    if field.default_factory is not None:
        return "*generated per process*"
    value = field.default
    if value == "":
        return "*(empty)*"
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if isinstance(value, str):
        return f"`{value}`"
    return f"`{value!r}`"


def _bounds(field) -> str | None:
    ge = le = None
    for meta in field.metadata:
        if getattr(meta, "ge", None) is not None:
            ge = meta.ge
        if getattr(meta, "le", None) is not None:
            le = meta.le
        if getattr(meta, "min_length", None) is not None:
            ge = f"len >= {meta.min_length}" if ge is None else ge
    if ge is None and le is None:
        return None
    # ASCII on purpose: the page is generated by a script that also prints to a
    # console, and a Windows code page cannot encode a comparison sign.
    if ge is not None and le is not None:
        return f"`{ge} <= value <= {le}`"
    if ge is not None:
        return f"`value >= {ge}`"
    return f"`value <= {le}`"


def _validator(name: str, field) -> str:
    if name in _VALIDATORS:
        return _VALIDATORS[name]
    bounds = _bounds(field)
    note = _NOTES.get(name)
    if bounds is not None:
        return f"{bounds}; {note}" if note else bounds
    if note is not None:
        return note
    annotation = field.annotation
    if annotation in _SIMPLE_TYPES:
        return _SIMPLE_TYPES[annotation]
    return "type only"


def rows() -> list[tuple[str, str, str]]:
    """`(setting, default, validator)` for every field, in declaration order."""
    return [
        (name, _default(field), _validator(name, field))
        for name, field in Settings.model_fields.items()
    ]


def render() -> str:
    """The generated section, markers included."""
    lines = [
        BEGIN,
        "",
        "| Setting | Default | Validator |",
        "|---|---|---|",
    ]
    for name, default, validator in rows():
        lines.append(f"| `{name}` | {default} | {validator} |")
    lines.append("")
    lines.append(END)
    return "\n".join(lines)


def _env_example_names() -> set[str]:
    path = Path(__file__).resolve().parents[2] / ".env.example"
    if not path.is_file():
        return set()
    return {
        line.split("=", 1)[0].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.strip().startswith("#")
    }


def env_example_gaps() -> list[str]:
    """Settings the shipped `.env` template does not name.

    Not every setting belongs there — a value with a safe default that nobody
    tunes is noise — but a value that decides *where data lives* or *whether a
    control is on* is one an operator has to be able to find.
    """
    named = _env_example_names()
    return [name for name, _, _ in rows() if name not in named]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 when the page's generated section is not what this renders",
    )
    args = parser.parse_args(argv)

    rendered = render()
    if not args.check:
        print(rendered)
        return 0

    page = PAGE.read_text(encoding="utf-8")
    if BEGIN not in page or END not in page:
        print(f"{PAGE} has no generated settings section", file=sys.stderr)
        return 1
    current = page.split(BEGIN, 1)[1].split(END, 1)[0]
    expected = rendered.split(BEGIN, 1)[1].split(END, 1)[0]
    if current.strip() != expected.strip():
        print(
            "the settings table is stale: run `python -m scripts.settings_reference` "
            "and replace the section between the markers",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
