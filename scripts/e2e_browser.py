#!/usr/bin/env python3
"""The browser half of the end-to-end check: does an operator's own browser end up in the state the platform intends?

`scripts/e2e_smoke.py` drives the *documented interfaces* -- the operator API, the
connector protocol, the metrics scrape -- and its docstring is explicit about what
that cannot reach: a `urllib` request has no rendering, no DOM and no cookie jar, so
the SPA's shell can be served byte-for-byte while the application behind it never
reaches the screen. This script covers exactly that gap. It drives a real browser
down the path an operator takes, and it asserts the properties only a browser can
show:

1. **the sign-in screen is reachable and the form signs somebody in.** A stranger
   who opens the root is sent to the form rather than to a blank page or a
   spinner, and the session is created by that form's own submission -- against the
   API, through the reverse proxy, in a browser.
2. **the session lives where the design says it does.** The refresh token is in an
   ``HttpOnly`` cookie, so page scripts cannot read it (one injected script does not
   end in a stolen long-lived session); the CSRF value beside it *is* readable by
   scripts, because that is how the SPA sends it back; and no access token is left
   in ``localStorage`` or ``sessionStorage``.
3. **what the platform stored is what the operator sees**, and **signing out ends
   the session on both sides**: the newest finding the API lists renders as a row in
   the Phishing table, the table states which zone its timestamps are in, and after
   signing out the browser is back at the form *and* the refresh token it held is
   refused by the API.

What this deliberately is not
-----------------------------

* **Not a replacement for the smoke.** It creates nothing. The finding it asserts
  is one the platform already has, so run it against a stack where the smoke (or a
  real scan) has run and the two together are the journey. Run on its own against
  an installation with no findings it *fails* rather than passing vacuously: an
  empty table is not evidence that a table renders.
* **Not a visual or accessibility review.** It asserts structure -- roles, headings
  and text the operator can see -- not layout, colour or contrast.
* **Not every page.** One collection page, one freshly loaded router state, one
  sign-out. The claim is that the assembled product works in a browser; per-page
  behaviour is what the frontend suite and each page's own tests are for.
* **Not a cross-engine check.** It drives Chromium, which is what the CI job
  installs. ``E2E_BROWSER_CHANNEL`` exists so a person on a machine that already
  has Edge or Chrome can run the same check against that build.

Configuration (environment)
---------------------------

``E2E_FRONTEND_URL``      The SPA's origin, e.g. ``http://127.0.0.1:3000``.
                          Required. The API is reached through this same origin,
                          because that is the reverse proxy a browser talks to.
``E2E_ADMIN_EMAIL``       Administrator to sign in as. Required.
``E2E_ADMIN_PASSWORD``    That administrator's password. Required.
``E2E_ADMIN_TOTP_SECRET`` Base32 secret of that account's authenticator, for an
                          account that has a second factor: the form then asks for
                          the current code and this is what supplies it. Optional.
``E2E_EXPECTED_DOMAIN``   The finding the Phishing page must show. Optional: by
                          default the newest finding the API lists is used, which
                          is the one a smoke run has just written. It has to be
                          among the newest findings, because the page renders the
                          first page of that listing.
``E2E_BROWSER_CHANNEL``   A browser build to drive instead of Playwright's own
                          Chromium: ``msedge`` or ``chrome``. Optional.
``E2E_BROWSER_HEADLESS``  ``false`` opens a window you can watch. Default ``true``.
``E2E_TIMEOUT_SECONDS``   Time for one navigation, action or assertion. Default 30.
``E2E_ARTIFACT_DIR``      Where a failing run writes ``failure-page.png`` and
                          ``failure-full-page.png``, for a person rather than for
                          CI's log. Optional; without it the report is the page's
                          own text plus the browser's console.

Playwright is deliberately *not* a runtime dependency of the platform: this script
needs ``pip install playwright`` and ``playwright install chromium`` and says so
when they are missing. Everything else it uses is the standard library.

Exit codes: 0 when every step held, 1 when a step did not (the report names the
step, what the page was showing and what the browser logged), 2 when the run could
not start at all.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time

FRONTEND = os.environ.get("E2E_FRONTEND_URL", "").rstrip("/")
ADMIN_EMAIL = os.environ.get("E2E_ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("E2E_ADMIN_PASSWORD", "")
TOTP_SECRET = os.environ.get("E2E_ADMIN_TOTP_SECRET", "")
EXPECTED_DOMAIN = os.environ.get("E2E_EXPECTED_DOMAIN", "")
CHANNEL = os.environ.get("E2E_BROWSER_CHANNEL", "").strip()
HEADLESS = os.environ.get("E2E_BROWSER_HEADLESS", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
TIMEOUT_SECONDS = float(os.environ.get("E2E_TIMEOUT_SECONDS", "30"))
TIMEOUT_MS = TIMEOUT_SECONDS * 1000
ARTIFACT_DIR = os.environ.get("E2E_ARTIFACT_DIR", "")

#: The two cookies a browser session is built from. The split is the property under
#: test: the refresh token must be unreadable by page scripts, the CSRF value must
#: be readable by them. Both names are the ones the API sets, and this check is
#: allowed to know them -- a check that imported them would follow the product's
#: own rename and stop noticing that the name, path or flag had moved.
REFRESH_COOKIE = "opendrp_refresh"
CSRF_COOKIE = "opendrp_csrf"

#: The first characters of every JWT (base64url of ``{"alg":...``). Web storage may
#: hold anything an operator's browser put there; a token it must not.
JWT_PREFIX = "eyJ"

#: Chromium's own noise, not the application's: a resize notification delivered
#: outside a frame, which every virtualised table can emit on a busy machine. It is
#: named here so that the check below can still fail on a real uncaught exception.
BENIGN_PAGE_ERROR = "ResizeObserver loop"

#: Where each step is expected to land.
SIGN_IN_URL = re.compile(r"/login")
DASHBOARD_URL = re.compile(r"/dashboard")
PHISHING_URL = re.compile(r"/phishing")

#: The step a failure is reported against. Held here rather than threaded through
#: every call, so the report can name the step even when the browser itself threw.
CURRENT = {"step": "(not started)"}


class CheckFailure(RuntimeError):
    """A step that did not hold, with what the browser was showing."""


for _stream in (sys.stdout, sys.stderr):
    # A Windows console is often cp1251, and a message copied out of a failing page
    # can hold a character it cannot encode. A check that dies with
    # UnicodeEncodeError instead of printing what it saw is worse than a `?`.
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")


def step(name: str) -> None:
    CURRENT["step"] = name
    print(f"[e2e-browser] {name}", flush=True)


def totp_code(secret: str) -> str:
    """The code an authenticator app shows for this secret, right now.

    Thirty-second steps and SHA-1, as RFC 6238 defines them for TOTP, computed here
    rather than taken from a dependency: the run then needs nothing but Playwright,
    and no test helper, on the machine that drives the browser.
    """
    key = base64.b32decode(secret.strip().upper() + "=" * (-len(secret.strip()) % 8))
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % 1_000_000:06d}"


class Recorder:
    """What the page said while it was driven: console output, errors, bad answers.

    A browser check that only asserts on the DOM can pass while the application
    throws on every render and a React error boundary hides it, so the browser's own
    accounts of the run are collected here and reported with a failure.
    """

    def __init__(self, page) -> None:
        self.console: list[str] = []
        self.errors: list[str] = []
        self.responses: list[str] = []
        page.on("console", self._on_console)
        page.on("pageerror", self._on_error)
        page.on("response", self._on_response)

    def _on_console(self, message) -> None:
        if message.type in {"error", "warning"}:
            self.console.append(f"{message.type}: {message.text}")

    def _on_error(self, error) -> None:
        self.errors.append(str(error))

    def _on_response(self, response) -> None:
        if response.status >= 400:
            self.responses.append(f"{response.status} {response.url}")


def mfa_hint() -> str:
    """Why a run cannot sign in, and the two ways out of it."""
    return (
        "this installation does not allow administrators without a second factor "
        f"(REQUIRE_MFA_FOR_ADMINS) and {ADMIN_EMAIL} has none: enrol one and pass its "
        "base32 secret as E2E_ADMIN_TOTP_SECRET, or run against a stack whose policy "
        "is off (REQUIRE_MFA_FOR_ADMINS=false)"
    )


@contextlib.contextmanager
def api_context(playwright_ctx):
    """Playwright's API client, closed however the step that opened it ends.

    Its own cookie jar, separate from the browser's: a sign-in through this client
    establishes the *API* half of a check and must not be the thing that created
    the session the browser is being tested for.
    """
    client = playwright_ctx.request.new_context(base_url=FRONTEND)
    try:
        yield client
    finally:
        client.dispose()


def finding_to_render(playwright_ctx) -> tuple[str, str, int]:
    """The finding the page must show, as the API lists it.

    Read through the SPA's origin, so the browser's own reverse-proxy path is what
    is exercised.
    """
    with api_context(playwright_ctx) as client:
        body = {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        if TOTP_SECRET:
            body["totp_code"] = totp_code(TOTP_SECRET)
        session = client.post(
            "/api/v1/auth/login",
            data=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        if not session.ok:
            answer = session.text()[:300]
            if "mfa" in answer.lower():
                raise CheckFailure(mfa_hint())
            raise CheckFailure(f"POST /api/v1/auth/login answered {session.status}: {answer}")
        token = (session.json() or {}).get("access_token")
        if not token:
            raise CheckFailure(f"the sign-in returned no access_token: {session.text()[:200]}")

        listing = client.get(
            "/api/v1/phishing/threats?size=50",
            headers={"Authorization": f"Bearer {token}"},
        )
        if not listing.ok:
            answer = listing.text()[:300]
            if "mfa_required" in answer:
                raise CheckFailure(mfa_hint())
            raise CheckFailure(
                f"GET /api/v1/phishing/threats answered {listing.status}: {answer}"
            )
        payload = listing.json() or {}
        rows = payload.get("items") or []
        if not rows:
            raise CheckFailure(
                "this installation lists no phishing findings, so the browser half has "
                "nothing to render and would pass without checking anything: run "
                "scripts/e2e_smoke.py against this stack first (it writes one), or point "
                "E2E_FRONTEND_URL at an installation that has findings"
            )
        wanted = EXPECTED_DOMAIN or (rows[0].get("phishing_domain") or "")
        row = next((item for item in rows if item.get("phishing_domain") == wanted), None)
        if row is None:
            raise CheckFailure(
                f"E2E_EXPECTED_DOMAIN={wanted!r} is not among the {len(rows)} newest "
                "findings the API lists, and the page renders that first page"
            )
        return wanted, (row.get("matched_asset") or ""), int(payload.get("total") or 0)


def wait_for_sign_in(page) -> str:
    """Wait for the form's submission to land, and say where it landed.

    Three outcomes need different handling: the dashboard (signed in), the
    second-factor field (the API verified the password and wants a code -- the SPA
    reveals it only then, so this also asserts that ordering), and the onboarding
    page (the deployment's policy refuses this account until it enrols a factor).
    """
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if "/dashboard" in page.url:
            return "dashboard"
        if "/onboarding" in page.url:
            return "onboarding"
        code_field = page.locator("#mfa-code")
        if code_field.count() and code_field.is_visible():
            return "mfa"
        time.sleep(0.2)
    return "unknown"


def journey(playwright_ctx, page, expect) -> None:
    """Drive one browser down the operator's path, or fail with what it showed.

    Assertions go through two small helpers so that every one of them waits for this
    run's timeout (``E2E_TIMEOUT_SECONDS``) instead of Playwright's five-second
    default: on a busy runner the first paint after a sign-in can take longer than
    that, and a check that fails for being impatient teaches the wrong lesson.
    """

    def shown(locator) -> None:
        expect(locator).to_be_visible(timeout=TIMEOUT_MS)

    def at(url_pattern) -> None:
        expect(page).to_have_url(url_pattern, timeout=TIMEOUT_MS)

    step(f"the platform has a finding for the browser to render ({FRONTEND})")
    domain, matched_asset, total = finding_to_render(playwright_ctx)
    print(f"      phishing threats total = {total}, newest = {domain}")

    step("a stranger who opens the root is sent to the sign-in screen")
    page.goto(FRONTEND + "/", wait_until="load")
    at(SIGN_IN_URL)
    shown(page.get_by_role("heading", name="Sign in"))
    shown(page.get_by_label("Email", exact=True))
    shown(page.get_by_label("Password", exact=True))
    print(f"      landed on {page.url}")

    step(f"the form signs {ADMIN_EMAIL} in")
    page.get_by_label("Email", exact=True).fill(ADMIN_EMAIL)
    page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Sign in", exact=True).click()
    outcome = wait_for_sign_in(page)

    if outcome == "mfa":
        if not TOTP_SECRET:
            raise CheckFailure(
                f"{ADMIN_EMAIL} has a second factor enrolled, so the form asks for a "
                "code from it: set E2E_ADMIN_TOTP_SECRET to that factor's base32 secret"
            )
        step("the second factor the form asks for is supplied")
        page.locator("#mfa-code").fill(totp_code(TOTP_SECRET))
        page.get_by_role("button", name="Sign in", exact=True).click()
        outcome = wait_for_sign_in(page)
    if outcome == "onboarding":
        raise CheckFailure(mfa_hint())
    if outcome != "dashboard":
        raise CheckFailure(f"the form did not sign in: the browser is still on {page.url}")

    step("a session was created, in the cookies the design puts it in")
    cookies = {cookie["name"]: cookie for cookie in page.context.cookies()}
    refresh = cookies.get(REFRESH_COOKIE)
    csrf = cookies.get(CSRF_COOKIE)
    if refresh is None or csrf is None:
        raise CheckFailure(
            f"the session cookies are not both present after signing in: "
            f"{sorted(cookies)} (expected {REFRESH_COOKIE} and {CSRF_COOKIE})"
        )
    if not refresh["httpOnly"]:
        raise CheckFailure(
            f"{REFRESH_COOKIE} is readable by page scripts (httpOnly=False), so one "
            "injected script is enough to steal the long-lived session"
        )
    if csrf["httpOnly"]:
        raise CheckFailure(
            f"{CSRF_COOKIE} is HttpOnly, so the SPA cannot read the value it has to "
            "send back and the session breaks on the next refresh"
        )
    readable = page.evaluate("() => document.cookie")
    if REFRESH_COOKIE in readable:
        raise CheckFailure(f"document.cookie exposes {REFRESH_COOKIE}: {readable[:200]}")
    if CSRF_COOKIE not in readable:
        raise CheckFailure(
            f"document.cookie cannot see {CSRF_COOKIE}, which the SPA must read: "
            f"{readable[:200]}"
        )
    # Web storage outlives the tab and every script on the origin can read it, so a
    # token there is a token that leaks. The SPA keeps its access token in memory.
    stored = page.evaluate(
        "() => JSON.stringify(Object.entries({ ...localStorage, ...sessionStorage }))"
    )
    if JWT_PREFIX in stored:
        raise CheckFailure(
            "a token was written to web storage, where any script on the page can read "
            f"it and where it survives the tab: {stored[:200]}"
        )
    print(
        f"      {REFRESH_COOKIE} httpOnly=True sameSite={refresh['sameSite']}, "
        f"{CSRF_COOKIE} readable by scripts, no token in web storage"
    )

    step("the shell rendered for the account that signed in")
    at(DASHBOARD_URL)
    shown(page.get_by_role("heading", name="Dashboard"))
    shown(page.get_by_role("button", name=ADMIN_EMAIL))
    shown(page.locator('a[href="/phishing"]').first)

    step(f"the newest finding renders as a row on the Phishing page ({domain})")
    page.locator('a[href="/phishing"]').first.click()
    at(PHISHING_URL)
    expect(page).to_have_title(re.compile("Phishing"), timeout=TIMEOUT_MS)
    shown(page.get_by_role("heading", name="Phishing Threats"))
    shown(page.get_by_text("All times are UTC").first)
    rows = page.locator("table tbody tr")
    shown(rows.first)
    rendered = rows.filter(has_text=domain)
    shown(rendered.first)
    if matched_asset:
        # The column that says which of the operator's assets the finding is about:
        # a row that renders the domain but not the attribution is a half-answer.
        shown(rendered.filter(has_text=matched_asset).first)
    print(
        f"      {rendered.count()} row(s) for the newest finding "
        f"({total} finding(s) in the API)"
    )

    step("signing out ends the session in the browser and at the API")
    refresh_value = refresh["value"]
    csrf_value = csrf["value"]
    page.get_by_role("button", name=ADMIN_EMAIL).click()
    page.get_by_role("menuitem", name="Logout").click()
    at(SIGN_IN_URL)
    shown(page.get_by_role("button", name="Sign in", exact=True))
    # A route guard that still believed the in-memory session would render the
    # dashboard here, which is what makes this the second half of the assertion.
    page.goto(FRONTEND + "/dashboard", wait_until="load")
    at(SIGN_IN_URL)
    remaining = {cookie["name"] for cookie in page.context.cookies()}
    if REFRESH_COOKIE in remaining:
        raise CheckFailure(f"{REFRESH_COOKIE} survived the sign-out")
    # The cookie is gone from the jar; the value it held has to be dead server-side
    # too, or a copy taken before the sign-out would still mint sessions.
    with api_context(playwright_ctx) as client:
        refused = client.post(
            "/api/v1/auth/refresh",
            headers={
                "Cookie": f"{REFRESH_COOKIE}={refresh_value}; {CSRF_COOKIE}={csrf_value}",
                "X-CSRF-Token": csrf_value,
            },
        )
        if refused.status != 401:
            raise CheckFailure(
                f"the refresh token this browser held answered {refused.status} after "
                f"the sign-out (expected 401), so signing out did not revoke it: "
                f"{refused.text()[:200]}"
            )
    print("      back at the sign-in form, cookie cleared, and the API refuses the old token")


def report(failure: Exception, page, recorder: Recorder | None) -> None:
    """Everything a person needs to tell a broken product from a broken check."""
    print(f"\n[e2e-browser] FAILED during: {CURRENT['step']}", file=sys.stderr)
    print(f"[e2e-browser] {failure}", file=sys.stderr)
    if page is not None:
        with contextlib.suppress(Exception):
            # A page that cannot be read is not the failure being reported, so a
            # problem in this block must not replace the message above.
            print(f"[e2e-browser] page: {page.url}", file=sys.stderr)
            print("[e2e-browser] what the page was showing:", file=sys.stderr)
            print(page.inner_text("body")[:1500], file=sys.stderr)
    if recorder is not None:
        for error in recorder.errors[:10]:
            print(f"[e2e-browser] uncaught in the page: {error}", file=sys.stderr)
        for line in recorder.console[:10]:
            print(f"[e2e-browser] console: {line}", file=sys.stderr)
        for line in recorder.responses[:10]:
            print(f"[e2e-browser] http: {line}", file=sys.stderr)
    if ARTIFACT_DIR and page is not None:
        with contextlib.suppress(Exception):
            os.makedirs(ARTIFACT_DIR, exist_ok=True)
            for name, full_page in (("failure-page.png", False), ("failure-full-page.png", True)):
                path = os.path.join(ARTIFACT_DIR, name)
                page.screenshot(path=path, full_page=full_page)
                print(f"[e2e-browser] wrote {path}", file=sys.stderr)


def main() -> int:
    missing = [
        name
        for name, value in (
            ("E2E_FRONTEND_URL", FRONTEND),
            ("E2E_ADMIN_EMAIL", ADMIN_EMAIL),
            ("E2E_ADMIN_PASSWORD", ADMIN_PASSWORD),
        )
        if not value
    ]
    if missing:
        print(
            "missing required environment: " + ", ".join(missing) + "\n"
            "see the module docstring for what each one is for",
            file=sys.stderr,
        )
        return 2

    try:
        from playwright.sync_api import expect, sync_playwright
    except ImportError:
        # Deliberately an installation step of its own rather than a dependency of
        # the platform: the browser is needed to run this check, not to run OpenDRP.
        print(
            "[e2e-browser] Playwright is not installed, and this check drives a real "
            "browser.\n"
            "  python -m pip install playwright\n"
            "  python -m playwright install chromium\n"
            "Both are needed once per machine; the CI job installs them for its own run.",
            file=sys.stderr,
        )
        return 2

    launch_options: dict[str, object] = {"headless": HEADLESS}
    if CHANNEL:
        launch_options["channel"] = CHANNEL

    with sync_playwright() as playwright_ctx:
        browser = playwright_ctx.chromium.launch(**launch_options)
        # A context of its own, with no storage state: this run signs in as a person
        # who has never been here, which is the state the first assertion is about.
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.set_default_timeout(TIMEOUT_MS)
        recorder = Recorder(page)
        failure: Exception | None = None
        try:
            journey(playwright_ctx, page, expect)
            # The steps all held; what the browser logged while they did still counts.
            raised = [error for error in recorder.errors if BENIGN_PAGE_ERROR not in error]
            if raised:
                raise CheckFailure(f"the page raised an uncaught error: {raised[0]}")
        except Exception as error:  # noqa: BLE001 - every failure is the report's input
            # Not a swallowed error: the run is a check, so a thrown step is reported
            # with the page it was thrown on and the process exits non-zero. The
            # report comes before the browser is closed, because it reads the page.
            failure = error
            report(error, page, recorder)
        finally:
            context.close()
            browser.close()

    if failure is not None:
        return 1
    print(
        "\n[e2e-browser] PASSED: sign-in form  ->  session cookies  ->  finding on screen  ->  sign-out"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
