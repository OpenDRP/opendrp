#!/usr/bin/env python3
"""Prove that the API is stateless, by using two replicas against each other.

"Stateless, so it scales horizontally" is a claim that has to be demonstrated,
not asserted, and the demonstration is specific: a session created on one replica
must be usable on another, and the record of what happened must be visible from
both. If any of it lived in process memory, everything below would still work in
a single-replica deployment — which is exactly why it needs two.

Runs inside `make verify-replicas` (a `python:3.12-slim` container on the Compose
network) and uses only the standard library, so it adds no dependency to the
project. Every check prints PASS or FAIL with the reason, and the process exits
non-zero if any failed — a check that cannot fail the run is a check nobody acts
on.

Checks, in order:

1. **Both replicas are up and identical.** `/health` on each, same version.
2. **An access token crosses replicas.** Sign in against replica A, present the
   token to replica B. This fails if a replica signs with its own secret.
3. **A refresh family crosses replicas.** The refresh cookie issued by A is
   presented to B, which must be able to rotate it. This fails if refresh state
   lives in memory.
4. **CSRF is enforced on the replica that did not issue the cookie.** The same
   refresh, without the `X-CSRF-Token` header, must be refused.
5. **The audit trail is shared, and correlation survives the hop.** The login
   against A is found in the audit listing served by both A and B, located by the
   `X-Request-ID` the client sent — which also proves the request id propagates
   into the audit record rather than only into the log line.

Environment: REPLICA_HOST (default `backend`), REPLICA_PORT (default 8000),
ADMIN_EMAIL, ADMIN_PASSWORD.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
import uuid

REPLICA_HOST = os.environ.get("REPLICA_HOST", "backend")
REPLICA_PORT = int(os.environ.get("REPLICA_PORT", "8000"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
TIMEOUT_SECONDS = 20

_REFRESH_COOKIE = "opendrp_refresh"
_CSRF_COOKIE = "opendrp_csrf"

_failures: list[str] = []


def _report(ok: bool, name: str, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}{' — ' + detail if detail else ''}", flush=True)
    if not ok:
        _failures.append(name)


def _addresses() -> list[str]:
    """Every distinct address the API service resolves to.

    Docker's embedded DNS returns one record per replica for the service name, so
    this is how the script finds both of them without being told which container
    is which.
    """
    infos = socket.getaddrinfo(REPLICA_HOST, REPLICA_PORT, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def call(
    ip: str,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict | None = None,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
):
    """One HTTP request, returning ``(status, body_text, response_headers)``.

    Cookies are passed explicitly rather than through a cookie jar: the point of
    several checks is to hand replica B a cookie that replica A issued, and a jar
    keyed by host would quietly refuse to do that.
    """
    url = f"http://{ip}:{REPLICA_PORT}/api/v1{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if cookies:
        request.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    for key, value in (headers or {}).items():
        request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, response.read().decode("utf-8", errors="replace"), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), exc.headers
    except urllib.error.URLError as exc:
        return 0, str(exc.reason), {}


def set_cookies(headers, wanted: set[str]) -> dict[str, str]:
    """Extract ``name=value`` for the requested cookies from ``Set-Cookie``."""
    found: dict[str, str] = {}
    for raw in headers.get_all("Set-Cookie") or []:
        pair = raw.split(";", 1)[0]
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        if name.strip() in wanted:
            found[name.strip()] = value.strip()
    return found


def json_body(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def main() -> int:
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print("FAIL  configuration — ADMIN_EMAIL and ADMIN_PASSWORD are required", flush=True)
        return 2

    try:
        ips = _addresses()
    except OSError as exc:
        print(f"FAIL  discovery — cannot resolve {REPLICA_HOST}: {exc}", flush=True)
        return 2

    if len(ips) < 2:
        print(
            f"FAIL  discovery — {REPLICA_HOST} resolved to {len(ips)} address(es) "
            f"({', '.join(ips) or 'none'}); two replicas are required for this proof",
            flush=True,
        )
        return 1
    print(f"[replicas] {REPLICA_HOST} -> {', '.join(ips)}", flush=True)
    first, second = ips[0], ips[1]

    # 1. Both replicas answer, and they are the same release.
    versions: dict[str, str | None] = {}
    for ip in (first, second):
        status, text, _ = call(ip, "GET", "/health")
        payload = json_body(text) or {}
        versions[ip] = payload.get("version")
        _report(
            status == 200,
            f"health: {ip} answers /health",
            f"HTTP {status}",
        )
    _report(
        len(set(versions.values())) == 1 and None not in versions.values(),
        "health: replicas report the same version",
        f"{versions}",
    )

    # 2. Sign in against the first replica, use the token on the second.
    correlation = f"replica-check-{uuid.uuid4().hex[:12]}"
    status, text, headers = call(
        first,
        "POST",
        "/auth/login",
        body={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"X-Request-ID": correlation},
    )
    login = json_body(text) or {}
    token = login.get("access_token")
    if status != 200 or not token:
        _report(False, "login: sign in against the first replica", f"HTTP {status}: {text[:200]}")
        return 1
    _report(True, "login: sign in against the first replica")

    status, text, _ = call(second, "GET", "/auth/me", token=token)
    me = json_body(text) or {}
    _report(
        status == 200 and me.get("email") == ADMIN_EMAIL,
        "session: access token issued by one replica is accepted by the other",
        f"HTTP {status}: {text[:200]}" if status != 200 else "",
    )

    cookies = set_cookies(headers, {_REFRESH_COOKIE, _CSRF_COOKIE})
    if _REFRESH_COOKIE not in cookies or _CSRF_COOKIE not in cookies:
        _report(False, "cookies: login returned the refresh and CSRF cookies", f"got {sorted(cookies)}")
        return 1

    # 3. Refresh on the other replica: the family lives in PostgreSQL, not memory.
    status, text, refreshed_headers = call(
        second,
        "POST",
        "/auth/refresh",
        cookies=cookies,
        headers={"X-CSRF-Token": cookies[_CSRF_COOKIE]},
    )
    refreshed = json_body(text) or {}
    _report(
        status == 200 and bool(refreshed.get("access_token")),
        "session: refresh family issued by one replica rotates on the other",
        f"HTTP {status}: {text[:200]}" if status != 200 else "",
    )

    # 4. The CSRF check is real on the replica that never issued the cookie.
    status, text, _ = call(second, "POST", "/auth/refresh", cookies=cookies)
    _report(
        status == 401,
        "session: refresh without the CSRF header is refused on the other replica",
        f"HTTP {status}" if status != 401 else "",
    )

    # 5. The audit trail is shared, and the correlation id travelled with it.
    admin_token = refreshed.get("access_token") or token
    for ip in (first, second):
        status, text, _ = call(
            ip,
            "GET",
            "/audit/logs?action=auth.login.success&size=50",
            token=admin_token,
        )
        payload = json_body(text) or {}
        items = payload.get("items") or []
        correlated = [
            item
            for item in items
            if (item.get("details") or {}).get("request_id") == correlation
        ]
        _report(
            status == 200 and bool(correlated),
            f"audit: login performed on {first} is visible from {ip} with its request id",
            f"HTTP {status}, {len(items)} row(s), none carrying {correlation}" if not correlated else "",
        )

    print("", flush=True)
    if _failures:
        print(f"RESULT: FAIL — {len(_failures)} check(s) failed: {', '.join(_failures)}", flush=True)
        return 1
    print(
        "RESULT: PASS — sessions, refresh families, CSRF and the audit trail all "
        "survive a hop between replicas; the API holds no state of its own.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
