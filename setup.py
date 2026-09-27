#!/usr/bin/env python3
"""OpenDRP setup wizard: writes a correct `.env` from `.env.example`.

Read this first: **this file is not a packaging script.** A `setup.py` at the
root of a Python project conventionally means setuptools, and this one means
"provision this installation". It imports nothing but the standard library, and
nothing else in the repository imports it.

Why it exists. The documented way to provision OpenDRP used to be `cp
.env.example .env` followed by hand-generating five secrets and editing a dozen
values. That is the first thing a new operator meets, and it is the step where
the project's own instructions are easiest to get subtly wrong:

* a password with a character that needs percent-encoding (`@`, `:`, `/`)
  produces a malformed connection URL, and Compose interpolates two of these
  passwords straight into URLs;
* an *empty* `SHODAN_API_KEY` makes Compose refuse to start at all, so "I do not
  use Shodan" must not be expressed by blanking the value;
* `ENCRYPTION_KEY` must be exactly the Fernet shape, and a value that merely
  looks random is rejected at startup — by the application, minutes later,
  inside a container;
* a subnetwork outside `OPENDRP_NETWORK_SUBNET` is refused by the application
  with a message about audit rows, which is correct and hard to connect to the
  line that was edited.

So the wizard generates every secret with `secrets` (the OS CSPRNG, never the
`random` module), checks its own output against the same rules the application
enforces at startup, and only then writes the file. It never prints a secret
value: a fingerprint is enough to confirm that one was written.

Usage
-----
    python setup.py                       # interactive, writes .env
    python setup.py --check               # audit an existing .env, change nothing
    python setup.py --repair              # fill only the gaps (placeholders, empties)
    python setup.py --force               # rotate secrets, keeping the old ones valid
    python setup.py --non-interactive --public-url https://drp.example.com --version 0.1.0

Interactive runs ask only what has no safe default: the release to run (offered
as the version this checkout declares), the public URL the UI is served from,
which connectors to enable, and whether administrator routes need a second
factor. Everything else is generated, or has one correct value.

There is one installation shape, and this writes it: a production `.env`, started
by `make up`. Nothing here can describe another one — a file that downgraded
`APP_ENV`, the refresh-cookie flag or the Compose file set would make what a
developer proved locally a different installation from the one an operator runs.
A source-mounted stack with pytest and ruff still exists as `make up-tools`; that
is a test harness, and nothing in this file or in the documented installation
path reaches it.

Exit codes: 0 success, 1 findings or refusal, 2 unusable input, 130 aborted.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_TEMPLATE = REPO_ROOT / ".env.example"
DEFAULT_TARGET = REPO_ROOT / ".env"

#: The environment every installation this wizard writes runs in. `APP_ENV=production`
#: is what makes `app.core.config` enforce its production checks — a pinned image
#: version, explicit secrets, a Secure refresh cookie, an explicit proxy allowlist
#: — and a file this wizard writes must never be the reason they are skipped.
INSTALLATION_ENV = "production"

#: The values that have no safe default. `POSTGRES_PASSWORD` and
#: `REDIS_PASSWORD` are interpolated into connection URLs, which is why they are
#: generated URL-safe rather than merely random.
GENERATED_KEYS = (
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "JWT_SECRET_KEY",
    "ENCRYPTION_KEY",
    "AUDIT_CHAIN_KEYS",
)

#: When a key is rotated, the value it replaces must stay *verifiable*: a JWT
#: signed with the old secret is still in a browser, ciphertext written with the
#: old Fernet key is still in the database, and audit rows signed with the old
#: chain key must still check out. Dropping the old value instead of listing it
#: is how a rotation turns into "every session invalidated", "settings
#: undecryptable" and "the audit trail looks tampered with".
ROTATION_PREVIOUS_KEY = {
    "JWT_SECRET_KEY": "JWT_PREVIOUS_SECRET_KEYS",
    "ENCRYPTION_KEY": "ENCRYPTION_PREVIOUS_KEYS",
    "AUDIT_CHAIN_KEYS": "AUDIT_CHAIN_PREVIOUS_KEYS",
}

#: A copy of `app.core.config._INSECURE_SECRET_MARKERS`. It cannot be imported:
#: this script runs on a host where the backend's dependencies are not
#: installed, and requiring pydantic to write a config file would be absurd.
#: `tests/test_setup_env.py` asserts the two lists are identical, so the copy
#: cannot drift away from the validator it mirrors.
INSECURE_SECRET_MARKERS = (
    "changethis",
    "change-me",
    "replace_with",
    "replace-me",
    "yourstrong",
    "password123",
    "example-secret",
)

#: Values interpolated into `postgresql+asyncpg://user:pass@host` or
#: `redis://:pass@host` must survive that trip unencoded.
URL_SAFE_RE = re.compile(r"^[A-Za-z0-9._~-]+$")

#: `KEY=value` as it appears in a dotenv file. Compose reads plain assignments;
#: entries that are commented out are documentation, not settings.
ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

#: Settings that describe *how the installation is deployed* rather than what an
#: operator chose, and that therefore have exactly one correct value. `--repair`
#: fills gaps and leaves choices alone; these are not choices — a file that keeps
#: `APP_ENV=development`, `AUTH_COOKIE_SECURE=false` or a canonical origin of
#: `http://localhost:3000` is one the application refuses to start, or one that
#: sends every visitor to their own machine.
ALWAYS_WRITTEN_KEYS = frozenset({"APP_ENV", "AUTH_COOKIE_SECURE", "CANONICAL_ORIGIN"})

#: Keys whose value must never be printed, in any mode. The `*_PREVIOUS_*` lists
#: hold the secrets a rotation just replaced, and they are live credentials until
#: the rotation is finished — the change report for a rotation is exactly where
#: they would otherwise be echoed into a terminal and a CI log.
SENSITIVE_KEYS = frozenset(GENERATED_KEYS) | frozenset(
    ROTATION_PREVIOUS_KEY.values()
)

#: Connector name -> the task type its credential is issued for. dnstwist needs
#: no account; the other two are useless without an API key, which is why the
#: wizard asks about them separately.
CONNECTORS: Dict[str, Dict[str, str]] = {
    "dnstwist": {"type": "phishing"},
    "shodan": {"type": "phishing"},
    "hibp": {"type": "breaches"},
}

#: The Compose file set an installation runs, and the only file set this wizard
#: ever checks against. The development overlay (`docker-compose.dev.yml`) is a
#: test harness: `make up-tools` layers it on for the test and lint targets, and
#: no installation path names it.
COMPOSE_FILES = ("docker-compose.yml",)

#: A pinned release version, in the shape `app.core.config` requires in production.
SEMVER_RE = re.compile(r"^[vV]?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")

#: The browser-visible origin: scheme, host, optional port, and nothing else.
#: `CORS_ORIGINS` and the frontend build both take it verbatim.
PUBLIC_URL_RE = re.compile(
    r"^(?P<scheme>https?)://(?P<host>\[[^\]]+\]|[^\s/:]+)(?::(?P<port>\d+))?$"
)

#: The only hosts allowed to be reached over plain HTTP. Browsers treat
#: `localhost` as a trustworthy origin, so a `Secure` refresh cookie still works
#: there — which is what makes `http://localhost:<port>` a usable way to check an
#: installation on the machine that runs it, and nothing more than that.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: The loopback bindings the Compose files publish by default. Named here rather
#: than spelled out at each use, because three of them appear in a prompt, in a
#: finding and in `.env.example`.
DEFAULT_BACKEND_PORT = "127.0.0.1:8000"
DEFAULT_FRONTEND_PORT = "127.0.0.1:3000"
DEFAULT_POSTGRES_PORT = "127.0.0.1:5432"
DEFAULT_REDIS_PORT = "127.0.0.1:6379"

#: A Compose port binding: a bare port, or host:port (an IPv6 host is bracketed).
BINDING_RE = re.compile(
    r"^(?:(?P<host>\[[^\]]+\]|[^\s/:]+):)?(?P<port>\d{1,5})$"
)

#: The file that declares the version of *this checkout*. `make up` builds the
#: images from this tree (`docker compose up -d --build`), and
#: `scripts/check_version_consistency.py` already treats this assignment as the
#: single source of truth for the platform version.
VERSION_FILE = REPO_ROOT / "backend" / "app" / "__init__.py"


def invalid_public_url_reason(value: str) -> Optional[str]:
    """Why `value` cannot be the browser-visible origin, or None if it can be.

    One rule, enforced in three places — the interactive prompt, the
    non-interactive check, and `--check` — so that a file cannot be accepted by
    one path and refused by another. A public URL over plain HTTP is an error
    rather than a warning: production requires `AUTH_COOKIE_SECURE=true`, so no
    browser would send the session cookie to it, and what the operator sees is a
    sign-in page that reloads forever.
    """
    raw = (value or "").strip().rstrip("/")
    if raw and is_placeholder(raw):
        # The template's `https://REPLACE_WITH_PUBLIC_HOST` parses as a URL, and a
        # wizard that accepted it would write a file whose CORS origin no browser
        # ever uses - which is the failure `--check` exists to report, arriving
        # instead as "the frontend is broken" from a user.
        return (
            "the origin users will actually reach, not the template's placeholder"
        )
    match = PUBLIC_URL_RE.match(raw)
    if not match:
        return (
            "a URL you will actually serve the UI from, e.g. https://drp.example.com "
            "(scheme, host and port only - no path)"
        )
    host = match.group("host").strip("[]").lower()
    if match.group("scheme") == "http" and host not in LOOPBACK_HOSTS:
        return (
            "https://, or http:// only for localhost: the refresh cookie is Secure, "
            "so a plain-HTTP installation refuses to start and no browser would send "
            "the cookie. Terminate TLS in front of it "
            "(docker/nginx/reverse-proxy.example.conf), or name "
            "http://localhost:<port> to check it on this machine."
        )
    return None


def invalid_binding_reason(value: str) -> Optional[str]:
    """Why `value` cannot be a published binding, or None if it can.

    A binding is `host:port` or a bare `port`. The bare form is accepted by
    Compose as "every interface", which is why the wizard normalizes it to
    loopback before validating rather than refusing it: the operator who writes
    `3000` means the port on this machine, and only an explicit host can express
    the other intention.
    """
    if not value:
        return (
            "a port, or host:port when the service must be reachable from the "
            "network"
        )
    match = BINDING_RE.match(value)
    if match is None:
        return (
            "write it as `port` or `host:port`, e.g. 127.0.0.1:8000: a path, a "
            "scheme or a URL does not belong in a Compose port binding"
        )
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        return "the port must be between 1 and 65535"
    return None


def normalize_binding(value: str) -> str:
    """A bare port becomes a loopback binding, and an explicit host is kept.

    `3000` in a Compose file binds `0.0.0.0:3000`, so an operator who meant "the
    port on this machine" would publish the platform on every interface. The
    wizard writes what was meant and prints the rewrite, while a typed host is
    left exactly as it is — that is the one form that expresses a deliberate
    wider publication.
    """
    if ":" in value or not value.isdigit():
        return value
    return f"127.0.0.1:{value}"


def published_port(value: Optional[str]) -> Optional[int]:
    """The host port a `*_PORT` entry publishes, or None when it cannot be read.

    Every form Compose accepts is understood: `127.0.0.1:3000`, `[::1]:3000`
    and a bare `3000`.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    candidate = raw.rsplit(":", 1)[-1] if ":" in raw else raw
    return int(candidate) if candidate.isdigit() else None


def checkout_version() -> Optional[str]:
    """The version this checkout declares, or None when it cannot be read.

    `backend/app/__init__.py` is where the running process reads `__version__`
    from, so it is the honest default for "the release to run": `make up` builds
    the images from this tree, and `/api/v1/health` answers that same string
    while Settings reports `OPENDRP_VERSION`. Parsed with `ast` rather than
    imported, for the same reason the validators below are duplicated: this
    script runs on a host without the application's dependencies, and importing
    `app` to read one string would require pydantic and a database URL.
    """
    try:
        tree = ast.parse(VERSION_FILE.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "__version__"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                value = node.value.value.strip()
                return value.lstrip("vV") if SEMVER_RE.match(value) else None
    return None


def suggested_frontend_binding(answers: "Answers") -> str:
    """The UI binding to offer when the operator is choosing bindings.

    Only for the shape where a browser reaches this machine directly: a loopback
    origin with a port of its own names the port the UI has to answer on there,
    and a UI published somewhere else is a UI the operator cannot open. With a
    terminator in front, the origin is not loopback and the binding is the
    proxy's target, not the browser's port — which is why this is a default in an
    already-explicit "do not keep the defaults" branch rather than an automatic
    rewrite.
    """
    match = PUBLIC_URL_RE.match((answers.public_url or "").rstrip("/"))
    if match is None or match.group("scheme") != "http":
        return answers.frontend_port
    if match.group("host").strip("[]").lower() not in LOOPBACK_HOSTS:
        return answers.frontend_port
    port = match.group("port")
    if not port or port in {"80", "443"}:
        return answers.frontend_port
    return f"127.0.0.1:{port}"


class Aborted(Exception):
    """The operator pressed Ctrl-C or closed stdin before anything was written."""


class Finding:
    """One problem found in a set of values, with the file it belongs to."""

    def __init__(self, level: str, message: str) -> None:
        self.level = level  # error | warning | note
        self.message = message

    def __str__(self) -> str:
        return f"{self.level}: {self.message}"


# ==============================================================================
# Secrets
# ==============================================================================
def generate_secret(key: str) -> str:
    """A fresh value for `key`, from the operating system's CSPRNG.

    `secrets` rather than `random`: `random` is a Mersenne Twister seeded from
    the clock, and a password it produces can be recovered from a few outputs of
    the same generator. Nothing here uses a non-cryptographic source.
    """
    if key == "ENCRYPTION_KEY":
        # Fernet's key format: 32 random bytes, urlsafe base64, 44 characters
        # including padding. Generated directly rather than through
        # `cryptography`, so the wizard needs no third-party package — and
        # verified to decode to exactly 32 bytes before it is returned.
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    if key in {"JWT_SECRET_KEY", "AUDIT_CHAIN_KEYS"}:
        # The application requires at least 32 characters for the JWT secret.
        return secrets.token_urlsafe(48)
    return secrets.token_urlsafe(32)


def generate_secrets() -> Dict[str, str]:
    return {key: generate_secret(key) for key in GENERATED_KEYS}


def fingerprint(value: str) -> str:
    """Eight hex characters identifying a value without revealing it.

    An operator needs to see *that* a secret was written, and to recognise it
    later (the same fingerprint on two files means the same secret). Printing
    the value would put it in scrollback, in a screenshot and in the CI log of
    whoever runs this on a build agent.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def is_placeholder(value: str) -> bool:
    normalized = (value or "").strip().lower()
    return not normalized or any(marker in normalized for marker in INSECURE_SECRET_MARKERS)


def is_fernet_key(value: str) -> bool:
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return False
    return len(decoded) == 32


def is_gap(key: str, value: str) -> bool:
    """Whether `key`'s current value is something `--repair` should replace.

    Empty and placeholder values, plus the two the application refuses outright
    rather than merely distrusting: a JWT secret shorter than 32 characters, and
    an `ENCRYPTION_KEY` that is not a Fernet key. Without the last two, an
    operator who hand-wrote `JWT_SECRET_KEY=REPLACE_ME` — which no marker in the
    application's list catches — would be told their file has no gaps and then
    have it refused at startup.

    A password is never a gap on these grounds however short it looks: the
    application accepts the operator's choice, and silently replacing a live
    database password would be the worst possible repair.
    """
    if is_placeholder(value):
        return True
    stripped = (value or "").strip()
    if key == "JWT_SECRET_KEY":
        return len(stripped) < 32
    if key == "ENCRYPTION_KEY":
        return not is_fernet_key(stripped)
    return False


def as_bool(value: Optional[str], default: bool = False) -> bool:
    normalized = (value or "").strip().lower()
    if not normalized:
        return default
    return normalized in {"1", "true", "yes", "on"}


# ==============================================================================
# The dotenv file, as a list of lines that keeps its comments
# ==============================================================================
@dataclass
class EnvFile:
    """A dotenv file, editable in place so that comments survive a rewrite.

    Regenerating the file from the template would discard an operator's own
    notes and any local key the template does not know about. Nothing here is
    clever: the parsed form is the line list, and `set` rewrites one line.
    """

    lines: List[str] = field(default_factory=list)
    values: Dict[str, str] = field(default_factory=dict)
    appended: List[str] = field(default_factory=list)

    @classmethod
    def parse(cls, text: str) -> "EnvFile":
        lines = text.splitlines()
        values: Dict[str, str] = {}
        for line in lines:
            match = ASSIGNMENT_RE.match(line)
            if match:
                values.setdefault(match.group(1), match.group(2).strip())
        return cls(lines=lines, values=values)

    @classmethod
    def read(cls, path: Path) -> "EnvFile":
        return cls.parse(path.read_text(encoding="utf-8", errors="replace"))

    def documented(self) -> Set[str]:
        """Every name the file mentions, including commented-out entries.

        The advanced overrides are presented as comments, and a key that is
        documented but inactive is still documented: the audit reports an
        unknown key as a probable typo, and it must not accuse an entry that the
        template mentions.
        """
        names: Set[str] = set()
        for line in self.lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                match = ASSIGNMENT_RE.match(stripped.lstrip("#").strip())
                if match:
                    names.add(match.group(1))
                continue
            match = ASSIGNMENT_RE.match(line)
            if match:
                names.add(match.group(1))
        return names

    def set(self, key: str, value: str) -> None:
        """Set `key`, rewriting its line or appending it to the file."""
        for index, line in enumerate(self.lines):
            match = ASSIGNMENT_RE.match(line)
            if match and match.group(1) == key:
                self.lines[index] = f"{key}={value}"
                self.values[key] = value
                return
        self.lines.append(f"{key}={value}")
        self.appended.append(key)
        self.values[key] = value

    def render(self) -> str:
        if self.appended:
            # Marked, because a key appended by the wizard is one the template
            # does not carry — usually a newer setting on an older .env.
            self.lines.append("")
            self.lines.append(
                "# --- Added by setup.py: not present in .env.example ---"
            )
            self.lines.extend(
                f"{key}={self.values[key]}"
                for key in self.appended
                if f"{key}={self.values[key]}" not in self.lines
            )
        return "\n".join(self.lines) + "\n"


# ==============================================================================
# Validation — the rules the application enforces at startup, checked here
# ==============================================================================
def parse_origins(value: Optional[str]) -> List[str]:
    raw = (value or "").strip()
    if not raw:
        return []
    if raw.startswith("["):
        import json

        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except ValueError:
            pass
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_network(
    value: Optional[str],
) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        return ipaddress.ip_network((value or "").strip(), strict=False)
    except ValueError:
        return None


def validate_values(values: Mapping[str, str]) -> List[Finding]:
    """Check a set of values the way `app.core.config` would.

    Every rule here mirrors one in the application. They are duplicated rather
    than imported because this script runs on a host without the application's
    dependencies — and duplicating them is only acceptable because
    `tests/test_setup_env.py` loads the file this script writes *through the
    real `Settings` model* and asserts the application accepts it. A copy that
    drifts is a failing test, not a slow discovery in production.
    """
    findings: List[Finding] = []
    production = (values.get("APP_ENV", "development").strip().lower() == "production")
    if not production:
        findings.append(
            Finding(
                "warning",
                "APP_ENV is not production. Every installation this project "
                "supports runs `APP_ENV=production`; in development the "
                "application skips the checks that protect a real deployment "
                "(a pinned image version, explicit secrets, a Secure refresh "
                "cookie, an explicit proxy allowlist). Run `python setup.py "
                "--repair` to move the file to the one shape the wizard writes.",
            )
        )

    for key in GENERATED_KEYS:
        value = values.get(key, "").strip()
        if not value:
            findings.append(Finding("error", f"{key} is empty."))
        elif is_placeholder(value):
            findings.append(
                Finding("error", f"{key} still holds a placeholder; generate a value.")
            )
        elif key == "ENCRYPTION_KEY" and not is_fernet_key(value):
            findings.append(
                Finding(
                    "error",
                    "ENCRYPTION_KEY is not a Fernet key: it must be 32 random "
                    "bytes in urlsafe base64 (44 characters). Stored secrets "
                    "cannot be decrypted with anything else.",
                )
            )

    jwt_secret = values.get("JWT_SECRET_KEY", "").strip()
    if jwt_secret and len(jwt_secret) < 32:
        findings.append(
            Finding("error", "JWT_SECRET_KEY must contain at least 32 characters.")
        )

    for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD"):
        value = values.get(key, "").strip()
        if value and not URL_SAFE_RE.match(value):
            findings.append(
                Finding(
                    "warning",
                    f"{key} contains a character that must be percent-encoded in "
                    "the connection URL it is interpolated into; a value from "
                    "`secrets.token_urlsafe` needs no encoding.",
                )
            )

    if production and not as_bool(values.get("AUTH_COOKIE_SECURE"), default=True):
        findings.append(
            Finding(
                "error",
                "AUTH_COOKIE_SECURE must be true when APP_ENV=production: the "
                "refresh cookie is otherwise sent over plain HTTP.",
            )
        )

    origins = parse_origins(values.get("CORS_ORIGINS"))
    secure_cookie = as_bool(values.get("AUTH_COOKIE_SECURE"), default=True)
    https_origin = any(origin.startswith("https://") for origin in origins)
    if origins and https_origin and not secure_cookie:
        findings.append(
            Finding(
                "warning",
                "CORS_ORIGINS names an https:// origin while AUTH_COOKIE_SECURE "
                "is false: the cookie will not be sent.",
            )
        )
    for origin in origins:
        if is_placeholder(origin):
            # Reported once, below, with the advice that fits a placeholder.
            continue
        reason = invalid_public_url_reason(origin)
        if reason is None:
            continue
        if origin.startswith("http://"):
            findings.append(
                Finding(
                    "warning",
                    f"CORS_ORIGINS names {origin}, a plain-HTTP origin. That is "
                    "the way to check an installation on this machine; anything a "
                    "user reaches needs TLS in front of it.",
                )
            )
        else:
            findings.append(
                Finding(
                    "error",
                    f"CORS_ORIGINS names {origin}, which cannot be the origin the "
                    f"browser uses: {reason}",
                )
            )

    if production:
        version = values.get("OPENDRP_VERSION", "").strip()
        if not SEMVER_RE.match(version):
            findings.append(
                Finding(
                    "error",
                    "OPENDRP_VERSION must be a pinned semantic version in production; "
                    "the moving `latest` tag is not allowed.",
                )
            )

    if production and not values.get("AUDIT_CHAIN_KEYS", "").strip():
        findings.append(
            Finding(
                "error",
                "AUDIT_CHAIN_KEYS must be set explicitly in production: a key "
                "derived from ENCRYPTION_KEY would stop verifying the moment "
                "that key was rotated, which reads exactly like tampering.",
            )
        )

    parent = parse_network(values.get("OPENDRP_NETWORK_SUBNET"))
    if values.get("OPENDRP_NETWORK_SUBNET", "").strip() and parent is None:
        findings.append(
            Finding("error", "OPENDRP_NETWORK_SUBNET is not an IP network.")
        )
    if parent is not None:
        for key in (
            "OPENDRP_EDGE_SUBNET",
            "OPENDRP_DATA_SUBNET",
            "OPENDRP_CONNECTOR_SUBNET",
        ):
            value = values.get(key, "").strip()
            if not value:
                continue
            network = parse_network(value)
            if network is None:
                findings.append(Finding("error", f"{key} is not an IP network."))
            elif not network.subnet_of(parent):
                findings.append(
                    Finding(
                        "error",
                        f"{key} ({network}) lies outside OPENDRP_NETWORK_SUBNET "
                        f"({parent}): nginx would stop being recognised as a "
                        "trusted proxy and every audit row would record the "
                        "proxy address instead of the client's.",
                    )
                )

    # Every published port belongs on loopback: the UI is reached through the TLS
    # terminator in front of it (docker/nginx/reverse-proxy.example.conf) and the
    # datastores are reached by the containers themselves. A bare port publishes on
    # every interface instead, which for the UI means an unencrypted copy of the
    # platform listening next to the encrypted one.
    for key in ("POSTGRES_PORT", "REDIS_PORT", "BACKEND_PORT", "FRONTEND_PORT"):
        value = values.get(key, "").strip()
        if value and ":" not in value:
            findings.append(
                Finding(
                    "warning",
                    f"{key}={value} publishes this service on every interface, not "
                    f"just loopback. Write it as `127.0.0.1:{value}` unless it is "
                    "meant to be reachable from the network.",
                )
            )

    # A plain-HTTP loopback origin is the "check it on this machine" shape, and
    # on this machine the UI answers on a published binding or on a proxy in
    # front of it. The wizard cannot see the proxy, so this states the choice
    # rather than asserting an error — but it is not silent either, because the
    # commonest way to arrive here is typing `http://localhost` while the UI is
    # published on 3000: nothing serves port 80, the SPA keeps working (its
    # requests go to its own origin through the frontend's `/api/` proxy, where no
    # CORS check happens), and the file ends up recording an origin nobody can
    # open.
    binding = values.get("FRONTEND_PORT", "").strip() or DEFAULT_FRONTEND_PORT
    ui_port = published_port(binding)
    for origin in origins:
        match = PUBLIC_URL_RE.match(origin.rstrip("/"))
        if match is None or match.group("scheme") != "http":
            continue
        if match.group("host").strip("[]").lower() not in LOOPBACK_HOSTS:
            continue
        named = int(match.group("port")) if match.group("port") else 80
        if ui_port is None or named == ui_port:
            continue
        findings.append(
            Finding(
                "warning",
                f"CORS_ORIGINS names {origin}, but the UI is published on "
                f"{binding} (FRONTEND_PORT), so nothing answers on port {named} "
                "unless a proxy is there. Either that port carries the TLS "
                "terminator and forwards to the UI, or the origin is really "
                f"http://{match.group('host')}:{ui_port} (`python setup.py "
                f"--repair --public-url http://{match.group('host')}:{ui_port}`). "
                f"To serve the UI itself on port {named}, publish it there "
                "instead.",
            )
        )

    # A canonical origin is where the SPA sends a browser that reached it under a
    # different origin, and the value a development build used to carry points at
    # the browser's own machine. The bundle is built from it, so this is checked
    # here for the files that predate the single installation shape.
    canonical = values.get("CANONICAL_ORIGIN", "").strip().rstrip("/")
    if canonical:
        host = re.sub(r"^[a-z]+://", "", canonical).split("/")[0].split(":")[0].lower()
        if canonical.startswith("http://") and host in LOOPBACK_HOSTS:
            findings.append(
                Finding(
                    "error",
                    f"CANONICAL_ORIGIN is {canonical}, the development default: the "
                    "bundle sends every visitor whose origin differs from it to "
                    "their own machine. Run `python setup.py --repair` to clear "
                    "it, then rebuild the frontend image.",
                )
            )
        elif invalid_public_url_reason(canonical) is not None:
            findings.append(
                Finding(
                    "error",
                    f"CANONICAL_ORIGIN is {canonical}, which is not an origin a "
                    "browser can be sent to: "
                    f"{invalid_public_url_reason(canonical)}",
                )
            )
        else:
            findings.append(
                Finding(
                    "warning",
                    f"CANONICAL_ORIGIN is set to {canonical}: the UI redirects a "
                    "browser that reached it under any other origin there. That "
                    "is only right when the same UI is deliberately served under "
                    "two origins, and it takes effect after the frontend image "
                    "is rebuilt.",
                )
            )

    for origin in origins:
        if "REPLACE_WITH" in origin.upper():
            findings.append(
                Finding(
                    "error",
                    f"CORS_ORIGINS still names the placeholder {origin}: the UI is "
                    "served from a different origin, so the browser refuses every "
                    "request and the failure looks like a broken frontend.",
                )
            )

    # The application resolves the broker and database URLs from the environment,
    # and in production it refuses a broker URL without a password: anything that
    # can reach Redis can publish a task the worker executes with the platform's
    # own database credentials. Compose builds both URLs, so this only fires for
    # a deployment that sets them itself — which is exactly when it is needed.
    if production:
        from urllib.parse import unquote, urlsplit

        for key in ("REDIS_URL", "DATABASE_URL"):
            raw = values.get(key, "").strip()
            if not raw:
                continue
            try:
                parts = urlsplit(raw)
            except ValueError:
                findings.append(Finding("error", f"{key} is not a valid URL."))
                continue
            host = (parts.hostname or "").lower()
            if host not in {"localhost", "127.0.0.1", "::1", ""} and not unquote(
                parts.password or ""
            ):
                findings.append(
                    Finding(
                        "error",
                        f"{key} carries no password in production. Compose "
                        "constructs both URLs from the passwords above; a URL set "
                        "here must carry the same one.",
                    )
                )

    # A deployment can pass every syntax check and still exhaust PostgreSQL or
    # the host. Keep this as a warning: the wizard cannot know the database's
    # max_connections, but it can show the operator the calculated budget.
    try:
        workers = max(1, int(values.get("UVICORN_WORKERS", "1") or "1"))
        pool = max(1, int(values.get("DB_POOL_SIZE", "20") or "20"))
        overflow = max(0, int(values.get("DB_MAX_OVERFLOW", "10") or "10"))
        worker_pool = max(1, int(values.get("CELERY_DB_POOL_SIZE", "10") or "10"))
        worker_overflow = max(0, int(values.get("CELERY_DB_MAX_OVERFLOW", "5") or "5"))
        connection_budget = workers * (pool + overflow) + worker_pool + worker_overflow + 12
        if connection_budget > 80:
            findings.append(
                Finding(
                    "warning",
                    f"the configured database connection budget is approximately "
                    f"{connection_budget}; keep it below PostgreSQL max_connections "
                    "with migration, backup and admin headroom.",
                )
            )
    except ValueError:
        findings.append(Finding("error", "database pool and worker values must be integers."))

    # `make up` builds the images from this checkout (`docker compose up -d
    # --build`), and an installation reports its version from two places:
    # `/api/v1/health` answers `__version__` of the code that runs, Settings
    # reports `OPENDRP_VERSION` of the file. A file pinning something else shows
    # an operator two versions of one installation, which is the drift
    # `scripts/check_version_consistency.py` exists to prevent between the
    # repository's own files. A note rather than a warning: `make pull-prod`
    # pulls a release tag deliberately, and that is the one case where the two
    # differ on purpose.
    declared = checkout_version()
    pinned = values.get("OPENDRP_VERSION", "").strip().lstrip("vV")
    if declared and pinned and SEMVER_RE.match(pinned) and pinned != declared:
        findings.append(
            Finding(
                "note",
                f"OPENDRP_VERSION is {pinned} while this checkout declares "
                f"{declared}: `make up` builds these images from this tree, so "
                f"the UI would report both. Keep the difference only when "
                "`make pull-prod` is pulling that release on purpose.",
            )
        )

    return findings


def host_resource_findings() -> List[Finding]:
    """Best-effort host sizing warnings that work without third-party packages.

    Reported on every run: every run produces an installation meant to serve
    other people, so the host it will run on is exactly what is being prepared.
    """
    findings: List[Finding] = []
    cpu_count = os.cpu_count() or 0
    if cpu_count and cpu_count < 4:
        findings.append(Finding("warning", f"host reports {cpu_count} CPU(s); production guidance recommends at least 4."))
    try:
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            memory_gib = pages * page_size / (1024 ** 3)
            if memory_gib < 8:
                findings.append(Finding("warning", f"host reports approximately {memory_gib:.1f} GiB RAM; production guidance recommends at least 8 GiB."))
    except (OSError, ValueError, TypeError):
        pass
    try:
        free_gib = shutil.disk_usage(REPO_ROOT).free / (1024 ** 3)
        if free_gib < 40:
            findings.append(Finding("warning", f"only {free_gib:.1f} GiB is free on the checkout volume; production guidance recommends at least 40 GiB."))
    except OSError:
        pass
    return findings


# ==============================================================================
# The wizard's answers, and the values they produce
# ==============================================================================
@dataclass
class Answers:
    public_url: str = ""
    backend_port: str = DEFAULT_BACKEND_PORT
    #: Loopback by default, like the API: the UI is reached through the TLS
    #: terminator in front of it. Publishing it on every interface puts an
    #: unencrypted copy of the platform next to the encrypted one.
    frontend_port: str = DEFAULT_FRONTEND_PORT
    postgres_port: str = DEFAULT_POSTGRES_PORT
    redis_port: str = DEFAULT_REDIS_PORT
    release_version: str = ""
    connectors: Tuple[str, ...] = ("dnstwist",)
    api_keys: Dict[str, str] = field(default_factory=dict)
    require_mfa: bool = False
    keep_defaults: bool = True
    #: Keys the operator named on the command line. In `--repair` mode these are
    #: applied even when a value already exists, because an explicit flag is an
    #: instruction rather than a gap being filled.
    explicit: Set[str] = field(default_factory=set)


def frontend_origin(answers: Answers) -> str:
    """The browser-visible origin of the UI: the one the operator named.

    It used to be derived from the published port, which is how a loopback
    installation ended up with a canonical origin: the port a browser can reach
    on this host says nothing about the origin a user reaches.
    """
    return answers.public_url.rstrip("/")


def installation_values(answers: Answers) -> Dict[str, str]:
    """The values that describe the installation, as opposed to its secrets."""
    origin = frontend_origin(answers)
    host = re.sub(r"^[a-z]+://", "", origin).split("/")[0].split(":")[0]
    values: Dict[str, str] = {
        "APP_ENV": INSTALLATION_ENV,
        "CORS_ORIGINS": f'["{origin}"]',
        # Empty on purpose. A canonical origin makes the SPA send a visitor to
        # another origin, and the development build used to carry
        # `http://localhost:3000` here - which redirects every real visitor to
        # their own machine. An installation has exactly one browser origin (the
        # public URL above), so there is nothing to redirect *from*; set it only
        # when the same UI is deliberately served under two origins.
        "CANONICAL_ORIGIN": "",
        # The validator refuses `false` in production, so writing anything else
        # would produce a file the application declines to load.
        "AUTH_COOKIE_SECURE": "true",
        "MFA_ISSUER": host or "OpenDRP",
        "BACKEND_PORT": answers.backend_port,
        "FRONTEND_PORT": answers.frontend_port,
        "POSTGRES_PORT": answers.postgres_port,
        "REDIS_PORT": answers.redis_port,
        "REQUIRE_MFA_FOR_ADMINS": "true" if answers.require_mfa else "false",
        **({"OPENDRP_VERSION": answers.release_version} if answers.release_version else {}),
    }
    return values


def plan_writes(answers: Answers) -> Dict[str, str]:
    """Every value this run intends to write, before the mode decides what to keep.

    Secrets are always generated, including in `--repair`: the mode filters this
    mapping down to the gaps, and a value that does not survive the filter is
    simply discarded. Generating only when a gap is known to exist would mean
    knowing the gap before reading the file — the same thing, in the wrong order.
    """
    values = installation_values(answers)
    values.update(generate_secrets())
    for name, api_key in answers.api_keys.items():
        if api_key:
            values[name] = api_key
    return values


def rotated_previous_values(existing: Mapping[str, str]) -> Dict[str, str]:
    """The `*_PREVIOUS_*` lists a rotation has to write.

    Newest first, deduplicated: the replaced value stays accepted for
    verification, so a rotation does not invalidate live sessions, stored
    ciphertext or signed audit history.
    """
    migrated: Dict[str, str] = {}
    for key, previous_key in ROTATION_PREVIOUS_KEY.items():
        old = (existing.get(key) or "").strip()
        if not old or is_placeholder(old):
            continue
        migrated[previous_key] = ",".join(
            part for part in [old, (existing.get(previous_key) or "").strip()] if part
        )
    return migrated


def already_populated_message(target: Path) -> str:
    return (
        f"{target} already holds secrets. Re-running would write new ones, and "
        "some of them cost more than an edit to undo:\n"
        "  a new POSTGRES_PASSWORD leaves the database volume on the old one;\n"
        "  a new ENCRYPTION_KEY makes stored secrets unreadable until "
        "`scripts.rotate_keys rewrap` has run.\n"
        "Use --repair to fill only the gaps, or --force to rotate (the replaced "
        "keys are kept so that existing sessions, ciphertext and audit rows still "
        "verify)."
    )


def rotation_warning() -> str:
    return (
        "Rotating keeps the replaced JWT, Fernet and audit-chain keys in the "
        "matching *_PREVIOUS_* lists, so what they signed or encrypted stays "
        "readable and verifiable. POSTGRES_PASSWORD is the exception: the volume "
        "keeps the password it was initialised with, so a rotation there needs "
        "`ALTER ROLE` against the live database - it does not take effect by "
        "editing this file."
    )


# ==============================================================================
# Interactive prompts
# ==============================================================================
def _input(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt) as exc:  # pragma: no cover - terminal only
        raise Aborted() from exc


def ask_text(
    prompt: str,
    default: str = "",
    validate=None,
    hint: str = "",
    normalize=None,
) -> str:
    """Ask one question, and return a value that has already passed its rules.

    Three things can accompany a question, and they are deliberately not the
    same thing:

    ``default``
        A value Enter accepts. Only for a setting with one right answer — the
        release this checkout declares is one; the public URL is not, because a
        guessed origin is a UI that refuses every request.
    ``hint``
        An example that is printed and never accepted, which is what a prompt
        with no safe default still owes the operator: the shape of an answer.
        Suppressed when a default is shown, because the default is the example.
    ``normalize``
        A rewrite applied before validation, reported when it changes anything.
        This is how a bare port becomes a loopback binding instead of being
        accepted as "publish on every interface".
    """
    suffix = f" [{default}]" if default else ""
    aside = f" ({hint})" if hint and not default else ""
    while True:
        answer = _input(f"{prompt}{aside}{suffix}: ").strip()
        if not answer:
            answer = default
        if normalize is not None:
            normalized = normalize(answer)
            if normalized != answer:
                print(f"  - using {normalized}")
            answer = normalized
        if validate is not None:
            problem = validate(answer)
            if problem:
                print(f"  ! {problem}")
                continue
        return answer


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        answer = _input(f"{prompt} [{hint}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("  ! answer y or n")


def ask_choice(prompt: str, options: Sequence[Tuple[str, str]], default: str) -> str:
    print(prompt)
    for index, (value, label) in enumerate(options, start=1):
        marker = " (default)" if value == default else ""
        print(f"  {index}) {label}{marker}")
    while True:
        answer = _input("> ").strip()
        if not answer:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]
        if any(value == answer for value, _ in options):
            return answer
        print("  ! pick one of the numbers listed")


def wizard(answers: Answers) -> Answers:
    # Printed output stays ASCII: this runs on Windows consoles whose code page
    # is not UTF-8, where a typographic dash arrives as a replacement character.
    print("OpenDRP setup: writes .env from .env.example. Secrets are generated")
    print("with the operating system's CSPRNG and never printed.")
    print()

    # The installation shape is not a question. It used to be, and the answer a
    # developer naturally gave - "local development" - wrote a file the
    # application then started with weaker checks than a real installation, so
    # what was being tested was not what was being shipped.
    #
    # An installation runs one release; this is the image tag every service is
    # built or pulled as, not a choice between versions installed side by side.
    # It is offered as the version this checkout declares, because `make up`
    # builds the images from this tree and because `/api/v1/health` answers
    # `__version__` while Settings reports `OPENDRP_VERSION`: a file that pins
    # anything else has the installation reporting two versions of itself.
    answers.release_version = ask_text(
        "OpenDRP release to run (the image tag for every service)",
        answers.release_version or checkout_version() or "",
        validate=lambda value: (
            None
            if SEMVER_RE.match(value)
            else "use a pinned semantic version such as 0.1.0; `latest` is not allowed"
        ),
        hint="e.g. 0.1.0",
    ).lstrip("vV")
    answers.explicit.add("OPENDRP_VERSION")

    if not answers.public_url:
        # No suggested default: a guessed origin is worse than none, because the
        # UI would be served from the real host and every request refused by CORS.
        # The example is printed instead, which is all an operator needs to see
        # the shape of an answer without the wizard inventing a value.
        answers.public_url = ask_text(
            "Public URL the UI is served from",
            "",
            validate=invalid_public_url_reason,
            hint="e.g. https://drp.example.com",
        ).rstrip("/")

    print()
    # These four are where the containers are published on this host, not the
    # ports a browser uses: the UI is reached through whatever terminates TLS in
    # front of it (`docker/nginx/reverse-proxy.example.conf` forwards to the UI
    # binding), and the datastores are reached by the containers themselves.
    if not ask_yes_no(
        "Keep the default loopback bindings on this host "
        f"(API {DEFAULT_BACKEND_PORT}, UI {DEFAULT_FRONTEND_PORT}, "
        f"PostgreSQL {DEFAULT_POSTGRES_PORT}, Redis {DEFAULT_REDIS_PORT})?",
        True,
    ):
        answers.backend_port = ask_text(
            "   API binding this host publishes",
            answers.backend_port,
            validate=invalid_binding_reason,
            normalize=normalize_binding,
        )
        answers.frontend_port = ask_text(
            "   UI binding the TLS terminator forwards to",
            suggested_frontend_binding(answers),
            validate=invalid_binding_reason,
            normalize=normalize_binding,
        )
        answers.postgres_port = ask_text(
            "   PostgreSQL binding this host publishes",
            answers.postgres_port,
            validate=invalid_binding_reason,
            normalize=normalize_binding,
        )
        answers.redis_port = ask_text(
            "   Redis binding this host publishes",
            answers.redis_port,
            validate=invalid_binding_reason,
            normalize=normalize_binding,
        )

    print()
    print("Connectors. Each scans one external source, and each gets its own")
    print("credential from the core. dnstwist needs no account; Shodan and HIBP")
    print("need an API key, and can also be enabled later.")
    if not ask_yes_no("   Enable Shodan (phishing search engine)?", False):
        answers.connectors = tuple(
            name for name in answers.connectors if name != "shodan"
        )
    else:
        answers.connectors = tuple(
            sorted(set(answers.connectors) | {"shodan"})
        )
        answers.api_keys["SHODAN_API_KEY"] = ask_text(
            "   Shodan API key",
            hint=(
                "Membership tier or higher for the SSL-text and favicon "
                "searches; leave empty to set it later"
            ),
        )
    if not ask_yes_no("   Enable HIBP (breach data)?", False):
        answers.connectors = tuple(name for name in answers.connectors if name != "hibp")
    else:
        answers.connectors = tuple(sorted(set(answers.connectors) | {"hibp"}))
        answers.api_keys["HIBP_API_KEY"] = ask_text(
            "   HIBP API key",
            hint=(
                "00000000000000000000000000000000 is HIBP's integration key "
                "for a test installation; leave empty to set it later"
            ),
        )

    print()
    # Required by default, because an administrator route is a route into the
    # audit trail and the settings that hold the alert credentials. The prompt
    # still offers the choice: an installation must not be able to lock its own
    # administrator out, and `manage_admin mfa-reset` is the recovery path.
    mfa_default = (
        answers.require_mfa
        if "REQUIRE_MFA_FOR_ADMINS" in answers.explicit
        else True
    )
    answers.require_mfa = ask_yes_no(
        "Require a second factor for administrator routes? Recovery is a person "
        "with host access (`manage_admin mfa-reset`).",
        mfa_default,
    )
    answers.explicit.add("REQUIRE_MFA_FOR_ADMINS")

    print()
    if not ask_yes_no("Keep the default retention windows and database limits?", True):
        answers.keep_defaults = False

    return answers


# ==============================================================================
# Writing
# ==============================================================================
def git_ignored(path: Path) -> Optional[bool]:
    """True when git ignores `path`, False when it does not, None when unknown.

    Unknown (no git, or not a checkout) is not a failure: the check exists for
    the one case where it matters — a fork whose `.gitignore` lost the `.env`
    rule, where the next `git add -A` publishes every secret in the file.
    """
    git = shutil.which("git")
    if git is None:
        return None
    try:
        result = subprocess.run(
            [git, "check-ignore", "-q", str(path)],
            cwd=str(path.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def write_env_file(target: Path, text: str) -> None:
    """Write `text` to `target` atomically, with owner-only permissions.

    A partially written `.env` is worse than none: Compose would start with some
    secrets and not others. The temporary file lands in the same directory so the
    final `os.replace` is atomic on every platform, and the mode is set before
    the rename so the file is never briefly world-readable.
    """
    handle, temp_name = tempfile.mkstemp(
        prefix=".env.setup-", dir=str(target.parent)
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass  # Windows: the ACLs, not the mode bits, are what apply.
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def backup_path(target: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return target.with_name(f"{target.name}.backup-{stamp}")


def compose_command(names: Sequence[str]) -> str:
    """The command an operator copies, for the one file set an installation runs."""
    files = " ".join(f"-f {name}" for name in COMPOSE_FILES)
    suffix = f" {' '.join(names)}" if names else ""
    return f"docker compose {files}{suffix}"


def next_steps(answers: Answers, target: Path) -> List[str]:
    """The commands that finish the installation.

    This block is the last thing the wizard prints and the first thing an
    operator acts on, so it states the whole step rather than only its heading.
    Two omissions were worth fixing: the connector containers exit until they
    hold a credential (the README was the only place that said so), and a value
    pasted into `.env` reaches a container only when that container is
    *recreated* -- `docker compose restart` reuses the environment it was
    created with, which is the trap the connector's own error message invited.

    Steps are numbered here instead of being written out, so a run with
    nothing to provision does not print a sequence with a hole in it.
    """
    ui_url = frontend_origin(answers)
    api_port = answers.backend_port.rsplit(":", 1)[-1]
    api_url = f"http://localhost:{api_port}/api/v1/health"
    has_make = shutil.which("make") is not None
    compose = compose_command(())

    steps: List[List[str]] = []

    if has_make:
        launch = "make up"
    else:
        launch = f"{compose} up -d --build"
    start = [f"Start the stack:  {launch}"]
    start.append(
        "     This is the installation: the production Compose shape, with no "
        "source mounts and no test tooling in the image."
    )
    if answers.connectors:
        start.append(
            "     (the connector containers exit with `Missing required "
            "environment variables: CONNECTOR_TOKEN` until they are given a "
            "credential below - that is expected)"
        )
    steps.append(start)

    steps.append(
        [
            f"Put TLS in front of the UI. It is published on "
            f"{answers.frontend_port} as plain HTTP, and nothing in the stack",
            "     terminates TLS: that is the proxy or load balancer in front of "
            "the host. Its `proxy_pass` must name that binding, or it answers "
            "for a",
            "     UI that is not there - change one and change the other. "
            "`docs/deployment.md` walks through the nginx config shipped as",
            "     `docker/nginx/reverse-proxy.example.conf`, a self-signed "
            "certificate included for an internal installation. HSTS stays off",
            "     (`HSTS_ENABLED=false`) until that certificate is one browsers "
            "already trust: enabling it early issues a promise you cannot take",
            "     back for HSTS_MAX_AGE seconds, and a self-signed certificate is "
            "replaced more often than that.",
        ]
    )

    if answers.connectors:
        issue = ["Issue a credential per connector (each token is shown once):"]
        for name in answers.connectors:
            if has_make:
                issue.append(
                    f"     make connector-token NAME={name} "
                    f"TYPE={CONNECTORS[name]['type']}"
                )
            else:
                issue.append(
                    f"     {compose} exec -T backend python -m "
                    f"scripts.manage_connector_tokens issue {name} "
                    f"--type {CONNECTORS[name]['type']} "
                    f"--env CONNECTOR_TOKEN_{name.upper()}"
                )
        skipped = [name for name in CONNECTORS if name not in answers.connectors]
        if skipped:
            issue.append(
                f"     (not enabled: {', '.join(skipped)} - start those containers "
                "once you add an API key)"
            )
        if not has_make:
            workers = " ".join(f"connector-{name}" for name in answers.connectors)
            issue.append("")
            issue.append(
                "     Each command prints `CONNECTOR_TOKEN_<NAME>=<token>` once. "
                f"Paste it into {target.name} in place of that variable's "
                "placeholder, then recreate the workers so they read it:"
            )
            issue.append(f"     {compose} up -d {workers}")
            issue.append(
                "     `up -d` is what applies it, not `docker compose restart`: a "
                "container keeps the environment it was created with, so a restart "
                "leaves the placeholder in place."
            )
        steps.append(issue)

    steps.append(
        [
            "Create the first administrator (replace the password with your own,",
            "     keeping the double quotes: cmd.exe does not treat single quotes as",
            "     quoting):",
            f"     {compose_command(('exec', 'backend'))} "
            "python -m scripts.manage_admin create --email admin@example.com "
            '--password "ChangeMeAdminPass123!"',
            "     That password is temporary on purpose: whoever runs this command knows",
            "     it, and so does the shell history it was typed into. The first sign-in",
            "     asks for a password of your own, and the platform stays closed until",
            "     it is set.",
        ]
    )
    steps.append(
        [
            f"Open {ui_url} and sign in with admin@example.com and the temporary",
            "     password, then choose your own on the page that appears",
            f"     (API health: {api_url})",
        ]
    )

    lines: List[str] = []
    for number, block in enumerate(steps, start=1):
        lines.append(f"{number}. {block[0]}")
        lines.extend(block[1:])

    lines.append("")
    lines.append(
        "Re-run `python setup.py --check` at any time to audit the file that was "
        "written."
    )
    if not answers.keep_defaults:
        lines.append(
            "The retention windows and database limits are at their defaults; "
            "edit AUDIT_RETENTION_DAYS, REPORT_RETENTION_DAYS, RETENTION_BATCH_SIZE,"
            f" RETENTION_MAX_BATCHES_PER_RUN, DB_STATEMENT_TIMEOUT_MS, "
            f"DB_LOCK_TIMEOUT_MS, DB_IDLE_IN_TRANSACTION_TIMEOUT_MS or "
            f"DB_COMMAND_TIMEOUT_SECONDS in {target.name} when you need to."
        )
    return lines


def describe_changes(
    before: Mapping[str, str], after: Mapping[str, str]
) -> List[str]:
    """A masked report of what is about to change, or what changed.

    Secret values are never printed, only a fingerprint: enough to confirm the
    write and to recognise the same secret on a later run, useless to anyone
    reading a CI log. A value that is absent or still a placeholder is named as
    such, because a fingerprint of `REPLACE_WITH_...` is noise.
    """
    lines: List[str] = []
    for key in sorted(after):
        new_value = after[key]
        old_value = (before.get(key) or "").strip()
        if old_value == new_value:
            continue
        if key in SENSITIVE_KEYS:
            if not old_value:
                was = "unset"
            elif is_placeholder(old_value):
                was = "placeholder"
            else:
                was = fingerprint(old_value)
            lines.append(f"  {key:<34} {was} -> {fingerprint(new_value)} (secret)")
        else:
            lines.append(f"  {key:<34} {old_value or 'unset'} -> {new_value}")
    return lines


# ==============================================================================
# Modes
# ==============================================================================
def run_check(
    target: Path, template: EnvFile, quiet: bool = False
) -> int:
    if not target.is_file():
        print(
            f"no such file: {target}. Create it with `python setup.py`, or point\n"
            "--target at the file you want audited.",
            file=sys.stderr,
        )
        return 2

    env = EnvFile.read(target)
    findings: List[Finding] = []
    template_active = {
        line.split("=", 1)[0]
        for line in template.lines
        if ASSIGNMENT_RE.match(line)
    }
    documented = template.documented()

    missing = sorted(
        key
        for key in template_active
        if key not in env.values and key not in {"DATABASE_URL", "REDIS_URL"}
    )
    if missing:
        findings.append(
            Finding(
                "note",
                "the template defines settings this file does not mention "
                f"(each has a default): {', '.join(missing)}",
            )
        )

    unknown = sorted(
        key
        for key in env.values
        if key not in documented and not key.startswith("COMPOSE_")
    )
    for key in unknown:
        findings.append(
            Finding(
                "error",
                f"{key} is not documented in {DEFAULT_TEMPLATE.name}: if that is a "
                "typo, the intended setting is silently at its default.",
            )
        )

    findings.extend(validate_values(env.values))

    ignored = git_ignored(target)
    if ignored is False:
        findings.append(
            Finding(
                "error",
                f"{target.name} is not ignored by git: a secret file that git will "
                "commit is one `git add -A` away from being published. Add it to "
                ".gitignore.",
            )
        )

    if not quiet:
        print(f"Auditing {target}")
        if not findings:
            print("  no findings: the file is usable as it stands.")
        for finding in findings:
            print(f"  {finding}")
    errors = [f for f in findings if f.level == "error"]
    if errors:
        print(f"{len(errors)} error(s): the application would refuse to start.")
        return 1
    return 0


def compose_config_check(target: Path) -> None:
    """Ask Compose to resolve the file, which is the cheapest real proof.

    `docker compose config` interpolates every `${...}` and reports a missing
    required value, so it catches the mistakes a text check cannot — an unset
    variable Compose demands. It is client-side and needs no daemon.
    """
    docker = shutil.which("docker")
    if docker is None:
        print("Not checked against Compose: `docker` is not on PATH.")
        return
    command = [docker, "compose", "--env-file", str(target)]
    for name in COMPOSE_FILES:
        command += ["-f", str(REPO_ROOT / name)]
    command += ["config", "--quiet"]
    try:
        result = subprocess.run(
            command, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Not checked against Compose: {exc}")
        return
    if result.returncode == 0:
        print(f"Compose resolves {target.name} for the installation file set.")
    else:
        print(
            "Compose rejects the file set - the first thing to check is a value "
            "Compose requires:\n"
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write a valid OpenDRP .env from .env.example.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--template", default=None, help="template file to read")
    parser.add_argument("--target", default=None, help="file to write (default: .env)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="audit an existing file and change nothing",
    )
    parser.add_argument(
        "--repair",
        action="store_true",
        help="fill only empty and placeholder values; never overwrite a secret",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="rotate the secrets, keeping the replaced ones valid (see --help notes)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the changes, write nothing"
    )
    parser.add_argument(
        "--non-interactive",
        "--yes",
        dest="non_interactive",
        action="store_true",
        help="ask nothing; use the flags and the defaults",
    )
    parser.add_argument("--public-url", default=None, help="https://drp.example.com")
    parser.add_argument("--backend-port", default=None)
    parser.add_argument("--frontend-port", default=None)
    parser.add_argument("--postgres-port", default=None)
    parser.add_argument("--redis-port", default=None)
    parser.add_argument(
        "--version",
        dest="release_version",
        default=None,
        help="pinned production release version, for example 0.1.0",
    )
    parser.add_argument(
        "--connectors",
        default=None,
        help="comma-separated subset of dnstwist,shodan,hibp (default: dnstwist)",
    )
    parser.add_argument("--shodan-api-key", default=None)
    parser.add_argument("--hibp-api-key", default=None)
    parser.add_argument(
        "--mfa",
        dest="mfa",
        action="store_true",
        default=None,
        help="require a second factor for administrator routes",
    )
    parser.add_argument("--no-mfa", dest="mfa", action="store_false")
    parser.add_argument(
        "--no-compose-check",
        action="store_true",
        help="skip the `docker compose config` verification of the written file",
    )
    return parser.parse_args(argv)


def answers_from_args(args: argparse.Namespace) -> Answers:
    answers = Answers()
    if args.public_url:
        answers.public_url = args.public_url.rstrip("/")
        answers.explicit.update({"CORS_ORIGINS", "MFA_ISSUER"})
    for field_name, key in (
        ("backend_port", "BACKEND_PORT"),
        ("frontend_port", "FRONTEND_PORT"),
        ("postgres_port", "POSTGRES_PORT"),
        ("redis_port", "REDIS_PORT"),
    ):
        value = getattr(args, field_name)
        if value:
            setattr(answers, field_name, value)
            answers.explicit.add(key)
    if args.release_version:
        answers.release_version = args.release_version.lstrip("vV")
        answers.explicit.add("OPENDRP_VERSION")
    if args.connectors is not None:
        answers.connectors = tuple(
            name.strip() for name in args.connectors.split(",") if name.strip()
        )
    if args.shodan_api_key:
        answers.api_keys["SHODAN_API_KEY"] = args.shodan_api_key
    if args.hibp_api_key:
        answers.api_keys["HIBP_API_KEY"] = args.hibp_api_key
    if args.mfa is not None:
        answers.require_mfa = bool(args.mfa)
        answers.explicit.add("REQUIRE_MFA_FOR_ADMINS")
    return answers


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    template_path = Path(args.template).resolve() if args.template else DEFAULT_TEMPLATE
    target = Path(args.target).resolve() if args.target else DEFAULT_TARGET

    if not template_path.is_file():
        print(f"no such template: {template_path}", file=sys.stderr)
        return 2

    template = EnvFile.read(template_path)

    if args.check:
        return run_check(target, template)

    if args.repair and args.force:
        print("--repair and --force contradict each other.", file=sys.stderr)
        return 2

    existing = EnvFile.read(target) if target.is_file() else None
    populated = bool(existing) and any(
        existing.values.get(key) and not is_placeholder(existing.values[key])
        for key in GENERATED_KEYS
    )

    # An explicit flag decides the mode by itself; the file's state only decides
    # what happens when neither was given, because a file that already holds
    # secrets must not be silently rewritten by a plain re-run.
    mode = "rotate" if args.force else ("repair" if args.repair else "fresh")
    if mode == "fresh" and existing is not None and populated:
        if args.non_interactive:
            print(already_populated_message(target), file=sys.stderr)
            return 1
        print(f"{target} already holds secrets.")
        choice = ask_choice(
            "What would you like to do?",
            [
                ("repair", "Fill only the empty and placeholder values"),
                ("rotate", "Rotate the generated secrets (a backup is written)"),
                ("abort", "Change nothing"),
            ],
            "repair",
        )
        if choice == "abort":
            print("Nothing written.")
            return 0
        mode = "rotate" if choice == "rotate" else "repair"

    try:
        answers = answers_from_args(args)
        if not args.non_interactive:
            answers = wizard(answers)
    except Aborted:
        print("\nAborted; nothing was written.", file=sys.stderr)
        return 130

    # A re-run against a file that already describes an installation does not need
    # the two values repeated: they are in the file, and asking for them again is
    # how `--repair` becomes a shell script quoting someone else's URL back at it.
    if existing is not None:
        if not answers.public_url:
            saved = parse_origins(existing.values.get("CORS_ORIGINS"))
            if len(saved) == 1 and invalid_public_url_reason(saved[0]) is None:
                answers.public_url = saved[0]
        if not answers.release_version:
            saved_version = existing.values.get("OPENDRP_VERSION", "").strip()
            if SEMVER_RE.match(saved_version):
                answers.release_version = saved_version.lstrip("vV")

    # The last resort, and the same default the interactive prompt offers: the
    # version this checkout declares. `--version` is therefore optional rather
    # than required — not because the release stops mattering, but because `make
    # up` builds these images from this tree, so "the version here" is the answer
    # an operator has to type only when they mean a different one.
    if not answers.release_version:
        answers.release_version = checkout_version() or ""

    url_problem = invalid_public_url_reason(answers.public_url)
    if url_problem is not None:
        print(
            "An installation file needs --public-url: CORS_ORIGINS is what tells "
            "the browser\nwhich origin may call the API, and a guessed value breaks "
            "the UI silently. It is\nthe origin users reach over https:// - or "
            "http://localhost:<port> to check the\ninstallation on the machine that "
            "runs it.\n"
            f"  {answers.public_url or '--public-url was not given'}: {url_problem}",
            file=sys.stderr,
        )
        return 2
    if not answers.release_version:
        print(
            "An installation file needs --version: images are pinned to a release "
            "and the\nmoving `latest` tag is not allowed. The version this "
            "checkout declares could\nnot be read from backend/app/__init__.py, so "
            "name one here.",
            file=sys.stderr,
        )
        return 2

    planned = plan_writes(answers)
    if mode == "repair":
        # Only gaps: a usable existing value survives, unless the operator named
        # the key on the command line (an instruction rather than a gap), or the
        # key describes the installation shape itself - those have exactly one
        # correct value, and a file still carrying the old development one is
        # repaired by `--repair` rather than accepted. See `is_gap` for the rest.
        planned = {
            key: value
            for key, value in planned.items()
            if is_gap(key, existing.values.get(key, "") if existing else "")
            or key in answers.explicit
            or key in ALWAYS_WRITTEN_KEYS
        }
    if mode == "rotate" and existing is not None:
        planned.update(rotated_previous_values(existing.values))

    # On a fresh run the baseline is the template, not nothing: an operator who
    # copied the template needs to see which placeholders are replaced, and which
    # settings the wizard sets for the installation.
    changes = describe_changes(
        existing.values if existing is not None else template.values, planned
    )
    kept_lines = list(existing.lines if existing else template.lines)

    if args.dry_run:
        print(f"Would write {target} ({len(changes)} change(s)):")
        for line in changes:
            print(line)
        if not changes:
            print("  nothing to do.")
        return 0

    if not changes:
        print(
            f"Nothing to write: {target} has a value for every setting this mode "
            "would fill."
        )
        print("Run `python setup.py --check` to audit the file as it stands.")
        return 0

    # Refuse to write a file git would publish. This is checked before the write,
    # not after, because "the file is already on disk" is the moment the advice
    # stops being useful.
    if git_ignored(target) is False:
        print(
            f"{target} is not ignored by git - refusing to write secrets into a "
            "file that would be committed. Add it to .gitignore (this repository "
            "ships a rule for .env) and run this again.",
            file=sys.stderr,
        )
        return 1

    print(f"About to write {target} ({len(changes)} change(s)):")
    for line in changes:
        print(line)
    if mode == "rotate":
        print()
        print(rotation_warning())

    if not args.non_interactive and not ask_yes_no("Proceed?", True):
        print("Nothing written.")
        return 0

    # A file this wizard writes is the installation's configuration, not a copy of
    # the template: a line nothing reads is a line an operator has to ask about.
    updated = EnvFile(
        lines=kept_lines,
        values=dict(existing.values) if existing else {},
    )
    for key, value in planned.items():
        updated.set(key, value)

    text = updated.render()
    written = EnvFile.parse(text)

    if populated:
        # Only a file that already holds live secrets is worth preserving; a
        # fresh copy of the template has nothing in it to lose.
        keep = backup_path(target)
        shutil.copy2(target, keep)
        print(f"Previous {target.name} kept as {keep.name}")

    write_env_file(target, text)
    print(f"Wrote {target}.")

    problems = [f for f in validate_values(written.values) if f.level == "error"]
    if problems:
        print()
        print("The file was written, but it would be refused at startup:")
        for problem in problems:
            print(f"  {problem}")
        return 1

    for warning in (
        finding for finding in validate_values(written.values) if finding.level != "error"
    ):
        print(f"  {warning}")
    for warning in host_resource_findings():
        print(f"  {warning}")

    if not args.no_compose_check:
        print()
        compose_config_check(target)

    print()
    print("Next:")
    for line in next_steps(answers, target):
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
