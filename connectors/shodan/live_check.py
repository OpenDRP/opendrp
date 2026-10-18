"""Operator-run spike for the Shodan questions the budget-and-filters wave adds.

Not part of the test suite and never run by CI: it spends real query credits. It
exists to *confirm* the vendor's documented names against the account this
installation actually pays with, because the two questions this wave depends on
are exactly the ones a misnamed filter answers with a silent zero:

* the certificate-name filter the connector builds for a look-alike
  (``ssl.cert.subject.cn``), and whether the organisation variant
  (``ssl.cert.subject.O``) is accepted at all — the vendor's filter reference
  lists the ``.cn`` form and no ``.O`` form, so the second is a question, not a
  given, and the capability that would use it stays off until an operator has
  answered it here;
* which of the free fields ``/shodan/host/{ip}`` returns on *this* account —
  ``http.html_hash`` is computed by Shodan's own crawlers (no published
  algorithm, so the platform can never compute it itself), and the favicon,
  JARM and certificate fields are the enrichment the free lookup is for.

Reads the key from the environment only (``SHODAN_API_KEY``), makes at most
``--max-requests`` physical requests (hard ceiling 4, retries included — one
per question), and prints counters: never the key, a request URL or a response
body.

    SHODAN_API_KEY=... python live_check.py --question cert_subject --value look-alike.example
    SHODAN_API_KEY=... python live_check.py --question cert_subject_org --value "ACME Corp."
    SHODAN_API_KEY=... python live_check.py --question count --value example.com
    SHODAN_API_KEY=... python live_check.py --question host --value 203.0.113.10
    SHODAN_API_KEY=... python live_check.py --question html_hash --value 1234567890

Record what each answer confirmed in ``connectors/README.md`` beside the Shodan
capability table before a capability is relied on. A filter the grammar refuses
comes back in ``errors=`` rather than as ``matches=0``; the two are different
answers and this script is where they are told apart.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

import httpx

API = "https://api.shodan.io"
HARD_CEILING = 4
#: Shodan's documented general API rate is one request per second; the spike is
#: run by hand and paced the same way the connector paces itself.
MIN_INTERVAL = 1.0
PAGE_SIZE = 100

QUESTIONS = (
    "cert_subject",
    "cert_subject_org",
    "count",
    "host",
    "html_hash",
)


def _quote(value: str) -> str:
    """A quoted provider phrase.

    The spike types the operator's value into the same grammar the connector
    builds, and a value carrying a quote or a control character has no escape
    there — refusing it here keeps this script from demonstrating a query the
    connector would never send.
    """
    stripped = value.strip()
    if not stripped or any(character in stripped for character in '"\\') or any(
        ord(character) < 0x20 for character in stripped
    ):
        raise ValueError("value cannot be quoted into a Shodan phrase")
    return f'"{stripped}"'


class Spike:
    """One explored account: a key, a request ceiling, and a pace."""

    def __init__(self, key: str, max_requests: int) -> None:
        self.key = key
        self.max_requests = max_requests
        self.requests = 0
        self._last = 0.0

    async def get(self, path: str, **params) -> dict:
        if self.requests >= self.max_requests:
            raise RuntimeError("request ceiling reached")
        elapsed = time.monotonic() - self._last
        if elapsed < MIN_INTERVAL:
            await asyncio.sleep(MIN_INTERVAL - elapsed)
        self._last = time.monotonic()
        self.requests += 1
        timeout = httpx.Timeout(30.0, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"{API}{path}",
                params={"key": self.key, **params},
                headers={"User-Agent": "OpenDRP-Connector-live-check/1.0"},
            )
        if response.status_code != 200:
            # The status is the answer for a refused query; the body may quote
            # the query, and this script prints neither.
            raise RuntimeError(f"http_{response.status_code}")
        return response.json()


async def ask(spike: Spike, question: str, value: str) -> str:
    """One question, one documented call, counters as the answer."""
    if question in {"cert_subject", "cert_subject_org"}:
        field = "ssl.cert.subject.cn" if question == "cert_subject" else "ssl.cert.subject.O"
        payload = await spike.get(
            "/shodan/host/search/tokens", query=f"{field}:{_quote(value)}"
        )
        filters = payload.get("filters")
        errors = payload.get("errors")
        return (
            f"filters={sorted(filters) if isinstance(filters, list) else 'missing'} "
            f"errors={len(errors) if isinstance(errors, list) else 'missing'}"
        )
    if question == "count":
        payload = await spike.get(
            "/shodan/host/count", query=_quote(value), minify=True
        )
        return f"total={payload.get('total', 'missing')} page_size={PAGE_SIZE}"
    if question == "host":
        payload = await spike.get(f"/shodan/host/{value}", minify=True)
        http = payload.get("http") if isinstance(payload.get("http"), dict) else {}
        favicon = http.get("favicon") if isinstance(http.get("favicon"), dict) else {}
        ssl = payload.get("ssl") if isinstance(payload.get("ssl"), dict) else {}
        cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
        subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
        return (
            f"asn={'yes' if payload.get('asn') else 'no'} "
            f"org={'yes' if payload.get('org') else 'no'} "
            f"title={'yes' if http.get('title') else 'no'} "
            f"favicon_hash={'yes' if favicon.get('hash') else 'no'} "
            f"jarm={'yes' if ssl.get('jarm') else 'no'} "
            f"cert_subject_cn={'yes' if subject.get('CN') else 'no'} "
            f"html_hash={'yes' if http.get('html_hash') else 'no'}"
        )
    if question == "html_hash":
        payload = await spike.get(
            "/shodan/host/search", query=f"http.html_hash:{int(value)}", minify=True
        )
        matches = payload.get("matches")
        return (
            f"matches={len(matches) if isinstance(matches, list) else 'missing'} "
            f"total={payload.get('total', 'missing')}"
        )
    raise ValueError("unsupported question")


async def run(question: str, value: str, max_requests: int) -> int:
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        print("SHODAN_API_KEY is not set in the environment; nothing was sent.")
        return 2
    spike = Spike(key, max_requests)
    try:
        answer = await ask(spike, question, value)
    except (RuntimeError, ValueError, httpx.HTTPError) as exc:
        print(f"question={question} requests={spike.requests} status=error code={exc}")
        return 1
    print(f"question={question} requests={spike.requests} status=ok {answer}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--question", choices=QUESTIONS, required=True)
    parser.add_argument(
        "--value",
        required=True,
        help="a look-alike name, an organisation, a domain, an IP or a numeric html hash",
    )
    parser.add_argument("--max-requests", type=int, default=1)
    args = parser.parse_args(argv)
    if not 1 <= args.max_requests <= HARD_CEILING:
        parser.error(f"--max-requests must be between 1 and {HARD_CEILING}")
    return asyncio.run(run(args.question, args.value, args.max_requests))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
