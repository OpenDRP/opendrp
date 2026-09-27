#!/usr/bin/env python3
"""Fail when .env.example stops describing the configuration that exists.

`.env.example` is the only configuration reference this project ships: the
README points at it, `docs/upgrading.md` tells an operator to diff it after an
upgrade, and the documented procedure for provisioning an installation starts by
copying it to `.env`. That makes two failure modes costly, and both are silent
at runtime:

1. **A variable Compose reads but the template never mentions.** It works, and
   nobody can find the knob. The operator who needs to raise a retention window
   or point at an internal DNS resolver has no documented way in.

2. **A variable the template documents but Compose never passes into a
   container.** This is the worse one, because it *looks* like a control. The
   value sits in `.env`, the operator edits it — as the template's own comment
   instructs, e.g. raising the statement timeout for a large inventory — and the
   container keeps running with the code default. Nothing warns, because nothing
   is wrong: the setting is simply not connected.

There is a third, cheaper check in the same pass: every entry the template
defines should be *read* by something — a Compose interpolation, an application
setting, or a reference in the source that consumes it. A knob nobody reads is
either a leftover or a typo, and both are worth failing on before an operator
spends an evening on it.

Hence three rules:

* rule 1 — every variable a Compose file interpolates is documented in the
  template (a commented-out entry counts) or is listed in ``INTERNAL_VARS``
  with a reason;
* rule 2 — every entry the template defines is consumed somewhere real: a
  Compose interpolation, a ``Settings`` field, or a textual reference in
  ``backend/app``, ``connectors``, ``frontend/src``, ``scripts``, ``docker`` or
  the ``Makefile``;
* rule 3 — every template entry that *is* a ``Settings`` field is passed by at
  least one Compose file, or is listed in ``HOST_ONLY_VARS`` with a reason;
* rule 4 — no Compose file sets a template entry to a literal value, which
  shadows it: the container gets the literal and the entry in ``.env`` is
  decoration. This is the same defect as rule 3 seen from the other side, and
  the one that hides best, because the container *is* configured — just not by
  the operator;
* rule 5 — a setting a connector reads, and nothing else does, is namespaced
  after that connector. `.env` is one namespace shared by every service in the
  file set, so a bare ``SCAN_SSL_TEXT`` reads like a platform-wide knob and
  becomes a collision the moment a second connector wants the same word. It was
  also the only connector-scoped entry in this template without a prefix, which
  is how the rule was found. ``CONNECTOR_SHARED_VARS`` exists for the entry that
  is deliberately not namespaced, with a reason.

Rule 2 deliberately ignores the test suite, the CI workflows and the
documentation when it looks for a consumer. A knob referenced only by a test is
not wired into anything: the test is asserting the default, not an operator's
ability to change it.

Comment lines are stripped from the Compose files before scanning. This file
documents the ``${VAR:?...}`` idiom in prose, and a scanner that cannot tell a
comment from a directive reports a variable that does not exist — which is
exactly how the healthcheck scanner in this directory was fixed once already.

Deliberately stdlib-only, with no YAML parser, for the same reason as its
neighbour: the repository-hygiene CI job installs nothing, and the shape of
files this project owns is known.

Usage:  python scripts/check_env_template.py [--root DIR] [--template PATH]
                                             [compose files...]

Exit codes: 0 clean, 1 findings, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set

#: Variables a Compose file interpolates on purpose without the template
#: documenting them. Each entry needs a reason, because the alternative reading
#: — "we forgot" — is what this gate exists to catch. Keep it empty when you can.
INTERNAL_VARS: Dict[str, str] = {}

#: Template entries that are application settings, described to an operator, but
#: not passed by Compose because Compose *builds* them itself. Editing them in
#: `.env` is meaningful only when the application runs outside Compose.
HOST_ONLY_VARS: Dict[str, str] = {
    "REDIS_URL": (
        "Every Compose service receives REDIS_URL built from REDIS_PASSWORD, so "
        "the URL cannot drift from the password the broker was started with. The "
        "template entry is documentation for running the API outside Compose."
    ),
}

#: Template entries a connector reads that are deliberately *not* prefixed with
#: that connector's name. Each needs a reason, because the alternative reading —
#: "we forgot" — is what rule 5 exists to catch. Keep it as short as you can.
CONNECTOR_SHARED_VARS: Dict[str, str] = {
    "DNS_NAMESERVERS": (
        "a resolver list, not a capability: the name says what it does, no "
        "connector owns the `DNS_` namespace, and the connector-specific "
        "settings next to it in the template are prefixed (`DNSTWIST_*`)."
    ),
}

#: Prefixes the platform owns rather than any connector: the connector protocol
#: itself (``CONNECTOR_*``, ``CORE_*``) and Compose's own namespace. A name under
#: one of these is not a capability setting, so rule 5 leaves it alone.
CONNECTOR_PROTOCOL_PREFIXES = ("CONNECTOR_", "CORE_", "COMPOSE_")

#: The directory that holds the connector plugins. A name under it is a
#: namespace for rule 5, and its contents are the only place a connector-scoped
#: variable can be read from.
CONNECTOR_ROOT = "connectors"

#: Connector machinery that is not a connector: the SDK they build on.
CONNECTOR_ROOT_SKIPS = {"base", "__pycache__"}

DEFAULT_COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.dev.yml",
    "docker-compose.replicas.yml",
)

#: Directories scanned when looking for a consumer of a template entry.
SOURCE_ROOTS = ("backend/app", "connectors", "frontend/src", "scripts", "docker")

#: Files scanned in addition to the directories above.
SOURCE_FILES = ("Makefile",)

SOURCE_SUFFIXES = {
    "",
    ".conf",
    ".css",
    ".js",
    ".jsx",
    ".py",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}

SKIP_DIRECTORIES = {"__pycache__", "node_modules", ".git", ".mypy_cache", ".ruff_cache"}

COMPOSE_VAR_RE = re.compile(r"\$\$?\{([A-Za-z_][A-Za-z0-9_]*)")
#: A SCREAMING_CASE key in a Compose file — an environment variable, since the
#: services, networks and volumes in these files are lowercase.
COMPOSE_LITERAL_RE = re.compile(r"^\s+([A-Z][A-Z0-9_]*)\s*:\s*(.+)$")
ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
SETTINGS_FIELD_RE = re.compile(
    r"^\s{4}([A-Z][A-Z0-9_]*)\s*:.*?=\s*Field\(", re.MULTILINE
)


class Finding:
    """One rule violation, with the rule number and a way out of it."""

    def __init__(self, rule: int, variable: str, message: str) -> None:
        self.rule = rule
        self.variable = variable
        self.message = message

    def __str__(self) -> str:
        return self.message


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _without_comment_lines(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def compose_variables(compose_files: Sequence[Path]) -> Dict[str, Set[str]]:
    """Map each interpolated variable name to the Compose files that use it.

    Both ``${NAME}`` and ``$${NAME}`` are collected: the second form is what a
    ``command:`` block uses to forward a host value into a shell inside the
    container, and for the purpose of this gate it is the same variable.
    """
    found: Dict[str, Set[str]] = {}
    for path in compose_files:
        text = _without_comment_lines(_read(path))
        for name in COMPOSE_VAR_RE.findall(text):
            found.setdefault(name, set()).add(path.name)
    return found


def template_entries(template: Path) -> tuple[Dict[str, str], Set[str]]:
    """Return the active entries of the template and every name it documents.

    A commented-out entry counts as documentation — that is how the optional
    overrides are presented — but it is not an *active* setting, so the rules
    that reason about values apply only to uncommented lines.
    """
    active: Dict[str, str] = {}
    documented: Set[str] = set()
    for line in _read(template).splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()
            match = ASSIGNMENT_RE.match(candidate)
            if match:
                documented.add(match.group(1))
            continue
        match = ASSIGNMENT_RE.match(line)
        if match:
            name, value = match.group(1), match.group(2)
            active.setdefault(name, value.strip())
            documented.add(name)
    return active, documented


def settings_fields(settings_file: Path) -> Set[str]:
    """Field names declared by the application's ``Settings`` model."""
    if not settings_file.is_file():
        return set()
    text = _without_comment_lines(_read(settings_file))
    return set(SETTINGS_FIELD_RE.findall(text))


def connector_scope(roots: Iterable[Path]) -> tuple[Set[str], str]:
    """The connector namespaces and the source text of every connector.

    Two shapes have to be recognised, because both are real: the documented
    invocation points the scanner at the `connectors` directory itself (the
    namespaces are its subdirectories), and a fixture points it at one connector
    (the namespace is the directory after `connectors`).
    """
    namespaces: Set[str] = set()
    chunks: List[str] = []
    for root in roots:
        parts = Path(root).parts
        if CONNECTOR_ROOT not in parts:
            continue
        index = parts.index(CONNECTOR_ROOT)
        path = Path(root)
        if index + 1 < len(parts):
            namespaces.add(parts[index + 1].upper())
        elif path.is_dir():
            namespaces.update(
                child.name.upper()
                for child in path.iterdir()
                if child.is_dir() and child.name not in CONNECTOR_ROOT_SKIPS
            )
        chunks.append(_source_text([path]))
    return namespaces, "\n".join(chunks)


def _source_text(roots: Iterable[Path]) -> str:
    chunks: List[str] = []
    for root in roots:
        if root.is_file():
            chunks.append(_read(root))
            continue
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRECTORIES for part in path.parts):
                continue
            if path.suffix not in SOURCE_SUFFIXES:
                continue
            chunks.append(_read(path))
    return "\n".join(chunks)


def analyse(
    template: Path,
    compose_files: Sequence[Path],
    source_roots: Sequence[Path],
    settings_file: Path | None = None,
) -> List[Finding]:
    """Apply the three rules and return the findings, in rule order."""
    active, documented = template_entries(template)
    compose = compose_variables(compose_files)
    settings = settings_fields(settings_file) if settings_file else set()
    source_by_root = {str(root): _source_text([root]) for root in source_roots}
    source = "\n".join(source_by_root.values())
    connector_namespaces, connector_source = connector_scope(source_roots)
    platform_source = "\n".join(
        text
        for root, text in source_by_root.items()
        if CONNECTOR_ROOT not in Path(root).parts
    )

    findings: List[Finding] = []

    # Rule 1 — Compose reads it, the template does not document it.
    for name in sorted(compose):
        if name in documented or name in INTERNAL_VARS:
            continue
        files = ", ".join(sorted(compose[name]))
        findings.append(
            Finding(
                1,
                name,
                f"rule 1: {files} reads ${{{name}}}, but .env.example does not "
                f"document it.\n"
                f"        Add it to .env.example (a commented-out entry counts) or "
                f"list it in INTERNAL_VARS in this script with a reason.",
            )
        )

    # Rule 4 — Compose sets it itself, so the template's value cannot arrive.
    for path in compose_files:
        for line in _without_comment_lines(_read(path)).splitlines():
            match = COMPOSE_LITERAL_RE.match(line)
            if not match:
                continue
            name, value = match.group(1), match.group(2)
            if name not in active or f"${{{name}" in value:
                continue
            findings.append(
                Finding(
                    4,
                    name,
                    f"rule 4: {path.name} sets {name} to a literal value, so the "
                    f".env.example entry is\n"
                    f"        shadowed — the container gets that literal, never the "
                    f"operator's value. Interpolate\n"
                    f"        it (`{name}: ${{{name}:-{value[:32]}}}`) or delete it "
                    f"from .env.example.",
                )
            )

    for name in sorted(active):
        # Rule 2 — the template defines it, nothing consumes it.
        consumed = name in compose or name in settings or re.search(
            rf"\b{re.escape(name)}\b", source
        )
        if not consumed:
            findings.append(
                Finding(
                    2,
                    name,
                    f"rule 2: .env.example defines {name}, but nothing reads it: not "
                    f"a Compose\n"
                    f"        interpolation, not a Settings field, and not "
                    f"referenced anywhere in\n"
                    f"        {' , '.join(SOURCE_ROOTS)} or the Makefile. Either wire "
                    f"it up or delete it.",
                )
            )
            continue

        # Rule 3 — it is an application setting, and no Compose file passes it.
        if name in settings and name not in compose and name not in HOST_ONLY_VARS:
            findings.append(
                Finding(
                    3,
                    name,
                    f"rule 3: .env.example documents {name}, which is an application "
                    f"setting that no\n"
                    f"        Compose file passes into a container — setting it in "
                    f".env would do nothing.\n"
                    f"        Pass it through, e.g. `{name}: ${{{name}:-<default>}}`, "
                    f"or add it to\n"
                    f"        HOST_ONLY_VARS in this script with a reason.",
                )
            )

    # Rule 5 — a connector-scoped setting has to be namespaced.
    for name in sorted(documented):
        if name in CONNECTOR_SHARED_VARS or name.startswith(CONNECTOR_PROTOCOL_PREFIXES):
            continue
        if not re.search(rf"\b{re.escape(name)}\b", connector_source):
            continue
        if re.search(rf"\b{re.escape(name)}\b", platform_source):
            # The platform reads it too, so it is a setting a connector honours
            # rather than a connector-scoped one.
            continue
        if any(name.startswith(f"{prefix}_") for prefix in connector_namespaces):
            continue
        known = ", ".join(sorted(connector_namespaces)) or "no connector was found"
        findings.append(
            Finding(
                5,
                name,
                f"rule 5: {name} is read by a connector and by nothing else, but "
                f"its name is not\n"
                f"        namespaced after it (known connectors: {known}).\n"
                f"        Rename it to <CONNECTOR>_{name} in .env.example, the Compose "
                f"file that reads it and the\n"
                f"        connector itself, or list it in CONNECTOR_SHARED_VARS in "
                f"this script with a reason.",
            )
        )

    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        default=None,
        help="repository root (default: the parent of the directory holding this script)",
    )
    parser.add_argument(
        "--template",
        default=None,
        help="template to check (default: <root>/.env.example)",
    )
    parser.add_argument(
        "--settings",
        default=None,
        help="Settings model to read field names from "
        "(default: <root>/backend/app/core/config.py)",
    )
    parser.add_argument(
        "compose",
        nargs="*",
        default=None,
        help=f"Compose files to scan (default: {' '.join(DEFAULT_COMPOSE_FILES)})",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    template = Path(args.template).resolve() if args.template else root / ".env.example"
    settings_file = (
        Path(args.settings).resolve()
        if args.settings
        else root / "backend/app/core/config.py"
    )
    compose_files = [
        (root / name if not Path(name).is_absolute() else Path(name))
        for name in (args.compose or DEFAULT_COMPOSE_FILES)
    ]

    missing = [p for p in [template, *compose_files] if not p.is_file()]
    if missing:
        for path in missing:
            print(f"unreadable input: {path}", file=sys.stderr)
        return 2

    findings = analyse(template, compose_files, [root / p for p in SOURCE_ROOTS], settings_file)

    if not findings:
        print(
            f".env.example agrees with {len(compose_files)} Compose files and with "
            f"the application settings."
        )
        return 0

    for finding in findings:
        print(f"{finding}\n")
    print(f"{len(findings)} finding(s) in {template}.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
