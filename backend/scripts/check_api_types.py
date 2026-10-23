"""The SPA's request paths and response types must be what the API serves (AUD-060, plan 015).

`frontend/src/lib/api.ts` reads 101 responses. Until this gate existed, 56 of
them were `any`: the request was checked (method, path, query, body, all pinned
by `endpoints.test.ts`) and the answer was not, so a field renamed or removed on
the server compiled cleanly and failed in the browser — the one class of drift
the TypeScript compiler is expected to catch, switched off on more than half the
client.

Three rules, all cheap and all able to fail:

1. **Every helper names its response type.** A call without a generic is a
   payload the compiler cannot see. A route that answers no body names `void`,
   which is a statement too.
2. **A field the SPA reads is a field the response model sends.** Each interface
   in `SCHEMA_PAIRS` is compared with its OpenAPI schema: a property declared in
   TypeScript and absent from the model is exactly the removal this gate exists
   for. A model field the SPA does not read is not a failure — a client is
   allowed to model the half of a payload it uses, and forcing it to mirror
   every column would make this gate a second schema nobody maintains.
3. **Every path the SPA asks for is a route the API serves.** Both sides already
   had their own check — `endpoints.test.ts` pins the client's method, path and
   body, and `docs/api.md` is compared with the schema in both directions — and
   nothing compared the two, so a route renamed in `app/api/v1/routers/` left the
   helper calling a 404 that no build noticed. This was the readiness page's
   limitation 5 ("the client's path literals are still unchecked") and the reason
   two dead helpers survived an audit. The rule reads every `api.<verb>` call
   under `frontend/src` (not just `lib/api.ts`: eight calls live in four other
   files), normalises `{...}` and `${...}` to the same parameter slot, and
   compares verb against verb. What it does not claim: a route that exists but
   answers the wrong *shape* is rule 2's business, and a route nobody calls is
   not a defect at all. The client is still hand-written — generating it from
   `/openapi.json` would remove the class rather than the instance, and is not
   this gate.

`MINIMUM_CALLS` keeps rule 3 honest. A scanner that stops recognising a call
style would otherwise check fewer paths and still print OK, which is the class of
gate this repository has spent an audit removing.

4. **A route whose response describes no row is named, once.** Rule 2 can only
   compare what both sides describe, and a route that answers a `dict` describes
   nothing: the client declares an interface, the server declares nothing, and a
   field renamed there compiles. The question is asked of the **rows** — a bare
   model, `list[Model]`, and a paginated envelope whose `items` are `Model` all
   count; `PaginatedResponse[dict]` and `PaginatedResponse[Any]` do not, because the
   envelope's five counters are not what a page renders (plan 035). `UNMODELLED`
   lists the routes that fail it with the interface read from each, so the hole is an
   inventory rather than a sentence in this docstring. The rule fails in both
   directions: a typed read of a route that is not listed is a new unchecked
   response, and an entry whose route gained a row model is stale and has to go. The
   list can therefore only shrink, and each entry is a unit of the work that closes
   it. Plan 034 emptied it of routes with no model at all; asking about rows brought
   three back, and plan 035 closed one of them.

The gate runs where the OpenAPI document can be built — the backend job, after
the mypy ratchet — because the document is produced by importing the FastAPI
application. The frontend job still runs `tsc -b` over the same types, so the
two halves meet: this gate proves the declarations match the server, and the
compiler proves the pages match the declarations.

Usage:
    python scripts/check_api_types.py [--root PATH]
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

#: Interfaces compared field-for-field with the response model they describe.
#:
#: Only schema-backed payloads are here. A route that answers an undeclared dict
#: has no schema to compare with; the helper is typed against its own interface and
#: the compiler still checks every page that consumes it, but a server-side field
#: rename there is not visible to this gate until the route declares a model — which
#: is what rule 4's inventory, now empty, counted.
SCHEMA_PAIRS: Mapping[str, str] = {
    "Asset": "AssetResponse",
    "User": "UserResponse",
    "Job": "JobResponse",
    "Breach": "BreachResponse",
    "PhishingThreat": "PhishingThreatResponse",
    "Report": "ReportResponse",
    "SystemSettings": "SystemSettingsResponse",
    "Connector": "ConnectorOut",
    "CleanupResult": "CleanupResponse",
    "TestEmailResult": "TestEmailResponse",
    "TestTelegramResult": "TestTelegramResponse",
    "TelegramChatValidationResponse": "TelegramValidationResponse",
    "RuntimeConfiguration": "RuntimeConfigurationResponse",
    "UserBrief": "UserBriefResponse",
    "CertificateScopeException": "CertificateScopeExceptionResponse",
    "ScanStartResult": "ScanStartResponse",
    "PromotedAsset": "PromotedAssetResponse",
    "AssetFindingsResponse": "AssetFindingsResponse",
    "SourceAccount": "SourceAccountOut",
    "ConnectorHealth": "ConnectorHealth",
    "ConnectorHealthResponse": "ConnectorHealthResponse",
    "ConnectorModuleEntry": "ConnectorModuleEntry",
    "ConnectorModulesResponse": "ConnectorModulesResponse",
    "BreachKpi": "BreachKpi",
    "PlatformStatus": "PlatformStatus",
    "DashboardStats": "DashboardStats",
    "DashboardOverview": "DashboardOverview",
    "AlertDeliverySummary": "AlertDeliverySummary",
    "AlertChannelHealth": "AlertChannelHealth",
    "AlertChannelsHealthResponse": "AlertChannelsHealthResponse",
    "AuditActionsCatalog": "AuditActionsCatalog",
    "AuditIntegrity": "AuditIntegrity",
    "AlertQueueSummary": "AlertQueueSummary",
    "ExposureObservation": "ExposureObservationResponse",
    "ExposureTriageResult": "ExposureTriageResponse",
    "PhishingEvidence": "PhishingEvidenceItem",
    "AuditLogRow": "AuditLogRowResponse",
    "DNSObservation": "DNSObservationResponse",
    "TLSCertificate": "TLSCertificateResponse",
    "TLSCertificateSighting": "TLSCertificateSightingResponse",
    "RevokedSessions": "RevokedSessionsResponse",
    "UserInvite": "UserInviteResponse",
    "UserBulkResult": "UserBulkResponse",
    "MfaRecoveryCodes": "MfaRecoveryCodesResponse",
    "SourceAccountCreated": "SourceAccountCreated",
    "SourceAccountPolicyUpdated": "SourceAccountPolicyUpdated",
    "SourceAccountApiKey": "SourceAccountApiKeyState",
    "ReportQueued": "ReportQueued",
    "InvitationAccepted": "InvitationAccepted",
    "BreachDomainVerificationStarted": "BreachDomainVerificationStarted",
    "TLSSightingReview": "TLSSightingReview",
}

#: Routes whose successful response describes no row, and the interface the SPA
#: reads from each. Rule 4 keeps this list exact in both directions, so it is the
#: measured size of the remaining hole rather than a note: every entry is a payload
#: whose field names only the client checks.
#:
#: **Empty as of plan 037.** It held the routes whose response described no row —
#: first those with no model at all (plan 034), then, once the question was asked of
#: the rows, those whose page held `dict`s (plans 035–037). The mapping stays because
#: it is the rule's other half, not the work: a typed read of a route that answers an
#: undescribed row is still reported here, and an entry added back with a reason is a
#: decision written down. Removing one is the procedure that emptied it: declare a row
#: model (and a page whose `items` is one) on the route, add the pair above when the
#: interface is schema-backed, and the rule reports the entry as stale until it is
#: deleted.
UNMODELLED: Mapping[str, str] = {}

_INTERFACE_START = re.compile(r"^export interface (?P<name>\w+)(?:[^{]*)\{", re.M)
_PROPERTY = re.compile(r"^  (?P<name>[A-Za-z_]\w*)\??:")
_REQUEST = re.compile(r"api\.(get|post|put|patch|delete)\s*(<)?\(")

#: The prefix the client's `baseURL` carries, so its literals are relative to it.
#: `frontend/src/lib/api.ts` falls back to `/api/v1` and every shipped build sets
#: it (`frontend/Dockerfile`, `docker-compose.yml`, the release workflow).
API_PREFIX = "/api/v1"

#: Request calls this gate must find under `frontend/src`. A floor rather than a
#: count: a helper added raises it, and a call style the scanner stopped reading
#: fails here instead of shrinking the corpus silently.
MINIMUM_CALLS = 100

_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
_VERB_CALL = re.compile(r"api\s*\.\s*(?P<verb>get|post|put|patch|delete)\b")
_STRING_QUOTES = "\"'`"
_PATH_PARAMETER = re.compile(r"\$\{[^}]*\}|\{[^}]*\}")


@dataclass(frozen=True)
class Call:
    """One `api.<verb>(...)` in the client, and the path it asks for.

    `line` is where the path is written — the line a reader has to open — not
    where `api` is, because this client writes most calls chained one line down.
    `path` is ``None`` when the first argument is not a string literal: a path
    the scanner cannot read is a path the rule cannot check, and skipping it is
    how a gate stops meaning anything.
    """

    source: str
    line: int
    verb: str
    path: str | None
    response: str | None = None


def _on_the_opening_line(tail: str) -> tuple[set[str], bool]:
    """The properties written after the opening brace, and whether the body closed.

    Two declarations need this. `interface Page extends Paginated<Row> {}` opens and
    closes on one line: the block walk below would start on the *next* line and run
    to the next `}` alone, so it read the body as the following interface's fields
    and made that interface invisible to every rule — which is how a typed read of a
    route with no response model (`ExposureTriageResult`) was in neither the
    inventory nor its failures. And a body whose first member shares the opening
    line (`{ id: string;`) lost that member, because the walk skipped the line that
    opened it.

    Braces are counted, so a nested object's own members are not mistaken for the
    interface's; a name is one the body's own depth introduces followed by `:` or
    `?:`.
    """
    names: set[str] = set()
    depth = 1
    index = 0
    while index < len(tail) and depth > 0:
        char = tail[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif depth == 1 and (char.isalpha() or char == "_"):
            start = index
            while index < len(tail) and (tail[index].isalnum() or tail[index] == "_"):
                index += 1
            rest = tail[index:].lstrip()
            if rest.startswith("?"):
                rest = rest[1:].lstrip()
            if rest.startswith(":"):
                names.add(tail[start:index])
            continue
        index += 1
    return names, depth == 0


def parse_interfaces(text: str) -> dict[str, set[str]]:
    """``interface -> declared property names`` for one TypeScript file.

    Only top-level properties count: a nested object's keys sit at four spaces
    or deeper, and its closing brace is indented, so the walk stops at the first
    line that is exactly ``}``. Union members and comments are skipped because
    they do not match the property pattern. Whatever shares the opening line is
    read separately (:func:`_on_the_opening_line`), because a body that opened and
    closed there used to end the walk in the wrong place.
    """
    interfaces: dict[str, set[str]] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = _INTERFACE_START.match(lines[index])
        if match is None:
            index += 1
            continue
        fields, closed = _on_the_opening_line(lines[index][match.end() :])
        index += 1
        if not closed:
            while index < len(lines) and lines[index].rstrip() != "}":
                prop = _PROPERTY.match(lines[index])
                if prop is not None:
                    fields.add(prop.group("name"))
                index += 1
            index += 1
        interfaces[match.group("name")] = fields
    return interfaces


def untyped_helpers(api_text: str) -> list[str]:
    """Helpers under ``endpoints`` that call the API without a response generic."""
    start = api_text.find("export const endpoints")
    if start == -1:
        return ["export const endpoints was not found"]
    block = api_text[start:]
    entries = re.split(r"\n  (?=\w+: )", block)[1:]
    failures: list[str] = []
    for entry in entries:
        name = entry.split(":", 1)[0].strip()
        for verb, generic in _REQUEST.findall(entry):
            if not generic:
                failures.append(
                    f"{name}: `api.{verb}(...)` declares no response type; "
                    f"add `api.{verb}<T>(...)` (use `<void>` when the route sends no body)"
                )
    return failures


def _skip_generic(text: str, start: int) -> int | None:
    """Index just past the `>` closing the generic that begins at `start`.

    The client's generics carry object types (`<{ codes: string[] }>`), nested
    types and string literal members, so counting brackets is the only reading
    that survives them. A `=>` inside one is an arrow function rather than a
    closing bracket. ``None`` means the generic never closed, which the caller
    reports instead of guessing at the path behind it.
    """
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if char in _STRING_QUOTES:
            closing = text.find(char, index + 1)
            if closing == -1:
                return None
            index = closing + 1
            continue
        if char == "<":
            depth += 1
        elif char == ">":
            if index and text[index - 1] == "=":
                index += 1
                continue
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _read_literal(text: str, start: int) -> str | None:
    """The body of the string or template literal opening at `start`."""
    quote = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return text[start + 1 : index]
        index += 1
    return None


def calls_in(source: str, text: str) -> list[Call]:
    """Every request in one TypeScript source file, in the order it is written.

    A chained call (`api` on one line, `.post<T>(` on the next) is as much a
    request as an inline one, and 16 of the 101 calls in `lib/api.ts` are written
    that way.
    """
    calls: list[Call] = []
    for match in _VERB_CALL.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        verb = match.group("verb").upper()
        index = match.end()
        while index < len(text) and text[index].isspace():
            index += 1
        response: str | None = None
        if index < len(text) and text[index] == "<":
            after = _skip_generic(text, index)
            if after is None:
                calls.append(Call(source, line, verb, None))
                continue
            response = text[index + 1 : after - 1].strip()
            index = after
            while index < len(text) and text[index].isspace():
                index += 1
        if index >= len(text) or text[index] != "(":
            # A method read rather than a request (`api.getInterceptors`, or the
            # verb passed as a value): nothing is asked for on this line.
            continue
        index += 1
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or text[index] not in _STRING_QUOTES:
            calls.append(Call(source, line, verb, None, response))
            continue
        calls.append(
            Call(
                source,
                text.count("\n", 0, index) + 1,
                verb,
                _read_literal(text, index),
                response,
            )
        )
    return calls


def collect_calls(root: Path) -> list[Call]:
    """Every request call under the SPA's source tree, tests excluded.

    `lib/api.ts` holds 101 of them and four other files hold the rest; scanning
    only the endpoints object would leave those eight paths unchecked, and a
    page that calls `api` directly is exactly what the gate is for.
    """
    calls: list[Call] = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in (".ts", ".tsx") or not path.is_file():
            continue
        if ".test." in path.name or path.name.endswith(".d.ts"):
            continue
        calls.extend(
            calls_in(path.relative_to(root).as_posix(), path.read_text(encoding="utf-8"))
        )
    return calls


def _shape(path: str) -> str:
    """The path with every parameter slot spelled the same way."""
    return _PATH_PARAMETER.sub("{param}", path)


def check_calls(
    calls: Sequence[Call],
    paths: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Every request whose path or verb the route table does not serve."""
    served: dict[str, list[tuple[str, str]]] = {}
    for spec_path, operations in paths.items():
        for method in operations:
            if method.lower() in _METHODS:
                served.setdefault(_shape(spec_path), []).append((method.upper(), spec_path))

    failures: list[str] = []
    for call in calls:
        where = f"{call.source}:{call.line}"
        if call.path is None:
            failures.append(
                f"{where}: {call.verb} — the path is not a string literal, so this gate "
                "cannot check it"
            )
            continue
        # `params` is how the client sends a filter; a literal carrying a query is
        # still asking for the route in front of it, and the route is what exists.
        path = call.path.split("?", 1)[0]
        if path == API_PREFIX or path.startswith(API_PREFIX + "/"):
            failures.append(
                f"{where}: {call.verb} {path} — the client path is relative to "
                f"`{API_PREFIX}`, which would be asked for twice"
            )
            continue
        full = API_PREFIX + (path if path.startswith("/") else f"/{path}")
        routes = served.get(_shape(full))
        if not routes:
            failures.append(
                f"{where}: {call.verb} {full} — no route the API serves has that path"
            )
            continue
        if not any(verb == call.verb for verb, _ in routes):
            offered = ", ".join(sorted({verb for verb, _ in routes}))
            failures.append(f"{where}: {call.verb} {full} — {routes[0][1]} serves {offered}")
    return failures


def _served_routes(
    paths: Mapping[str, Mapping[str, Any]],
) -> dict[str, tuple[str, Mapping[str, Any]]]:
    """``shape -> (the spec's spelling, its operations)`` for every published route."""
    routes: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for spec_path, operations in paths.items():
        routes.setdefault(_shape(spec_path), (spec_path, operations))
    return routes


def _success_schema(operation: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The JSON schema of the route's first successful response, if it has one."""
    for code, response in (operation.get("responses") or {}).items():
        if not str(code).startswith("2"):
            continue
        for media, body in (response.get("content") or {}).items():
            if "json" in media:
                return body.get("schema") or {}
    return None


def declares_schema(
    schema: Mapping[str, Any] | None, schemas: Mapping[str, Any]
) -> bool:
    """Whether a response schema says what one **row** of the payload holds.

    The question used to be "does the response carry a `$ref`", which a paginated
    envelope satisfies on its own: `PaginatedResponse[dict]` and
    `PaginatedResponse[Any]` published five described counters and an `items` array
    of nothing, and three routes the SPA reads an interface from counted as declared
    (plan 035). A route that returns a `dict` publishes `{}` — present, describing
    nothing — and so does one whose page holds dicts.

    A model is a promise about fields, and the fields a page renders are the row's,
    so the walk resolves `$ref`, `allOf`, an array, and a paginated envelope's
    `items` before asking. A payload that is itself a map of records (the module
    inventory is one) has properties and is described.
    """
    return _describes(schema, schemas)


def _describes(
    schema: Mapping[str, Any] | None, schemas: Mapping[str, Any], depth: int = 0
) -> bool:
    """The row question, through the wrappers a response schema may wear."""
    if not isinstance(schema, Mapping) or depth > 6:
        return False
    reference = schema.get("$ref")
    if isinstance(reference, str):
        return _describes(schemas.get(reference.rsplit("/", 1)[-1]), schemas, depth + 1)
    if schema.get("type") == "array":
        return _describes(schema.get("items"), schemas, depth + 1)
    alternatives = schema.get("allOf")
    if isinstance(alternatives, Sequence):
        return any(_describes(part, schemas, depth + 1) for part in alternatives)
    properties = schema.get("properties")
    if not isinstance(properties, Mapping) or not properties:
        return False
    items = properties.get("items")
    if isinstance(items, Mapping) and items.get("type") == "array":
        # The paginated envelope: the five counters are not what the operator reads
        # row by row, so the answer is the answer about `items`.
        return _describes(items.get("items"), schemas, depth + 1)
    return True


def _named_interface(response: str | None, interfaces: Mapping[str, Any]) -> str | None:
    """The interface a response generic names, when it names one the SPA declares.

    `{ id: string }` is a literal and `Blob`/`void` are not interfaces at all; only a
    bare declared name, `Name[]`, or the `Name` inside `Paginated<Name>` is rule 4's
    business. The container is unwrapped because the **row** is what a page renders:
    until plan 035 only a bare name or `Name[]` was read, so every paginated read in
    the client — most of its list helpers — was invisible to the rule whatever the
    server declared.
    """
    text = (response or "").strip()
    paginated = re.fullmatch(r"Paginated<([A-Za-z_]\w*)>", text)
    if paginated is not None:
        text = paginated.group(1)
    match = re.fullmatch(r"([A-Za-z_]\w*)(\[\])?", text)
    if match is None or match.group(1) not in interfaces:
        return None
    return match.group(1)


def check_unmodelled(
    calls: Sequence[Call],
    paths: Mapping[str, Mapping[str, Any]],
    schemas: Mapping[str, Any],
    interfaces: Mapping[str, Any],
    unmodelled: Mapping[str, str],
) -> list[str]:
    """Every typed read of an undeclared row shape, against the inventory of them."""
    routes = _served_routes(paths)
    found: dict[str, str] = {}
    failures: list[str] = []
    for call in calls:
        interface = _named_interface(call.response, interfaces)
        if interface is None or call.path is None:
            continue
        hit = routes.get(_shape(API_PREFIX + call.path.split("?", 1)[0]))
        if hit is None:
            continue
        spec_path, operations = hit
        if declares_schema(_success_schema(operations.get(call.verb.lower()) or {}), schemas):
            continue
        key = f"{call.verb} {spec_path}"
        found[key] = interface
        if key not in unmodelled:
            failures.append(
                f"{call.source}:{call.line}: {interface} — {key} answers no declared row "
                "shape, so its fields are unchecked; declare a model (or a page whose "
                "`items` is one) on the route, or add "
                f"`{key}` to UNMODELLED with the reason"
            )
    for key in unmodelled:
        if key not in found:
            failures.append(
                f"UNMODELLED: `{key}` no longer names a route the SPA reads an undeclared "
                "response from; remove the entry (and the pair it made unnecessary)"
            )
    return failures


def corpus_floor(total: int) -> str | None:
    """A failure when the scanner found fewer calls than the client is known to hold."""
    if total >= MINIMUM_CALLS:
        return None
    return (
        f"only {total} request calls were found in frontend/src, and the client has at "
        f"least {MINIMUM_CALLS}: a call style this gate cannot read is hiding paths from it"
    )


def check_text(
    *,
    api_text: str,
    types_text: str,
    schemas: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Every failure the two rules find in one pair of files."""
    failures = untyped_helpers(api_text)
    interfaces = parse_interfaces(types_text)
    for interface, schema_name in SCHEMA_PAIRS.items():
        # Interface first: a pair whose two sides are both gone is two failures
        # in one change, and reporting only the schema half would hide the other.
        declared = interfaces.get(interface)
        if declared is None:
            failures.append(f"{interface}: the interface this gate watches is gone")
        schema = schemas.get(schema_name)
        if schema is None:
            failures.append(
                f"{schema_name}: named by {interface} but missing from the OpenAPI document"
            )
            continue
        if declared is None:
            continue
        properties = set((schema.get("properties") or {}).keys())
        # A name starts with a capital letter in this file only because it is
        # exported; an interface that vanished is as much a drift as a field.
        missing = sorted(declared - properties)
        for field in missing:
            failures.append(
                f"{interface}.{field}: the SPA reads this field, {schema_name} no longer sends it"
            )
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare the SPA's typed responses with the OpenAPI document."
    )
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[2]),
        help="repository root (default: the one this script lives in)",
    )
    args = parser.parse_args(argv)
    root = Path(args.root)

    api_path = root / "frontend" / "src" / "lib" / "api.ts"
    types_path = root / "frontend" / "src" / "types" / "api.ts"
    try:
        api_text = api_path.read_text(encoding="utf-8")
        types_text = types_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"api types gate: FAILED — cannot read {exc.filename}: {exc.strerror}")
        return 2

    # Running as `python scripts/check_api_types.py` puts `scripts/`, not the
    # backend directory, on the path; the application package lives beside it.
    backend_dir = str(Path(__file__).resolve().parents[1])
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    from app.main import app

    document = app.openapi()
    schemas = document.get("components", {}).get("schemas", {})
    calls = collect_calls(root / "frontend" / "src")
    paths = document.get("paths", {})
    floor = corpus_floor(len(calls))
    failures = [floor] if floor else []
    failures += check_text(api_text=api_text, types_text=types_text, schemas=schemas)
    failures += check_calls(calls, paths)
    failures += check_unmodelled(
        calls, paths, schemas, parse_interfaces(types_text), UNMODELLED
    )

    if failures:
        print(f"api types gate: FAILED — {len(failures)} disagreement(s):")
        for failure in failures:
            print(f"  {failure}")
        return 1

    inventory = (
        "the routes that answer no declared row shape are the ones listed in "
        f"UNMODELLED ({len(UNMODELLED)})"
        if UNMODELLED
        else "every route the SPA reads an interface from declares the rows it sends"
    )
    print(
        "api types gate: OK — every request helper names its response type, the "
        f"{len(SCHEMA_PAIRS)} interfaces it compares declare only fields their response "
        f"models send, all {len(calls)} request calls name a route the API serves, and "
        f"{inventory}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
