"""Operator-run spike for the Netlas questions the breadth wave adds.

Not part of the test suite and never run by CI: it spends real provider quota. It
exists to *confirm* what the vendor documents against the account this installation
actually pays with, because the query shapes here — a brand in a certificate, a
fuzzy favicon match, the WHOIS collection, the ``mx:*`` existence test, the count
route — are the ones a misnamed field would silently answer with "nothing
matched".

Reads the key from the environment only (``NETLAS_API_TOKEN``), makes at most
``--max-requests`` physical requests (hard ceiling 6, retries included), and prints
counters: never the key, a request URL or a response body.

    NETLAS_API_TOKEN=... python live_check.py --question brand --value "ACME Corp."
    NETLAS_API_TOKEN=... python live_check.py --question own_hashes --value example.com
    NETLAS_API_TOKEN=... python live_check.py --question favicon --value <sha256>

Record what each answer confirmed in ``docs/source-intelligence.md`` before the
capability is relied on: a field that arrives under another name is refused rather
than searched for, so a wrong name shows up as an empty result here and as a skip
reason in the scan summary.
"""

import argparse
import asyncio
import os
import sys

from providers import (
    Adapter,
    KEYS,
    ProviderError,
    brand_certificate_expression,
    host,
    mail_facts,
    query,
    whois_facts,
)

HARD_CEILING = 6

QUESTIONS = (
    "brand",
    "count",
    "body",
    "own_hashes",
    "favicon",
    "favicon_similar",
    "whois",
    "mx",
)


async def ask(adapter, question, value):
    """One question, one documented call, counters as the answer."""
    if question == "brand":
        rows = await adapter.search_brand_certificates(
            value, max_pages=1, max_results=20
        )
        return (
            f"expression_ok certificates={len(rows)} "
            f"names={sum(len(row.get('names') or []) for row in rows)}"
        )
    if question == "count":
        count = await adapter.count_responses(brand_certificate_expression(value))
        return f"count={count}"
    if question == "body":
        # SPIKE-04: the page-body question WI-24 rests on. The count is asked first,
        # exactly as a scan asks it, and one page is read only when the expression is
        # small enough to be about a brand rather than about the internet.
        expression = query("netlas", "body", value)
        count = await adapter.count_responses(expression, bucket="search")
        rows = await adapter.search("body", value, max_pages=1, max_results=20)
        return f"count={count} rows={len(rows)}"
    if question == "own_hashes":
        hashes = await adapter.own_favicon_hashes(value, max_results=20)
        return (
            f"sha256={'yes' if hashes.get('sha256') else 'no'} "
            f"perceptual={'yes' if hashes.get('perceptual') else 'no'}"
        )
    if question in {"favicon", "favicon_similar"}:
        algorithm = "sha256" if question == "favicon" else "perceptual"
        rows = await adapter.search_favicon(
            algorithm, value, max_pages=1, max_results=20
        )
        return f"responses={len(rows)}"
    if question == "whois":
        rows = await adapter.search_whois(value, max_pages=1, max_results=20)
        facts = whois_facts(rows, adapter)
        return (
            f"rows={len(rows)} registrar={'yes' if facts.get('registrar') else 'no'} "
            f"created={'yes' if facts.get('created') else 'no'}"
        )
    if question == "mx":
        rows = await adapter.search_mail_records(value, max_pages=1, max_results=20)
        facts = mail_facts(rows, adapter)
        return f"rows={len(rows)} mail_capable={facts['mail_capable']}"
    raise ProviderError("unsupported_capability")


async def run(question, value, max_requests):
    key = os.environ.get(KEYS["netlas"], "")
    if not key.strip():
        print(f"{KEYS['netlas']} is not set in the environment; nothing was sent.")
        return 2

    async def reserve(bucket):
        # No core, no quota account: this is an operator's one-off check, and the
        # request ceiling below is what bounds what it can spend.
        return None

    adapter = Adapter("netlas", {KEYS["netlas"]: key}, reserve)
    adapter.max_requests = max_requests
    try:
        # A brand, a count or a body expression is a *phrase* the query builder
        # quotes; only the questions that name an endpoint take a host. Normalising
        # "ACME Corp." as a host would refuse every documented brand example.
        target = (
            host(value)
            if question in {"own_hashes", "whois", "mx"}
            else value
        )
        answer = await ask(adapter, question, target)
    except ProviderError as exc:
        print(
            f"question={question} requests={adapter.requests} status=error code={exc}"
        )
        return 1
    print(f"question={question} requests={adapter.requests} status=ok {answer}")
    if adapter.record_errors:
        print(f"unreadable_records={adapter.record_errors} codes="
              f"{sorted(set(adapter.record_error_codes))}")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--question", choices=QUESTIONS, required=True)
    parser.add_argument(
        "--value",
        required=True,
        help="a brand, a domain, or a favicon hash for the favicon questions",
    )
    parser.add_argument("--max-requests", type=int, default=1)
    args = parser.parse_args(argv)
    if not 1 <= args.max_requests <= HARD_CEILING:
        parser.error(f"--max-requests must be between 1 and {HARD_CEILING}")
    return asyncio.run(run(args.question, args.value, args.max_requests))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
