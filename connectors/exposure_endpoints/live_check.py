"""Operator-run live check of a provider endpoint lookup, with a hard request budget.

Not part of the test suite and never run by CI: it spends real provider quota.
It reads the key from the environment only (``NETLAS_API_TOKEN`` or
``SHODAN_API_KEY``), makes at most ``--max-requests`` physical requests (hard
ceiling 5, retries included), and prints counts and ports. It never prints the
key, the request URL or a response body.

    NETLAS_API_TOKEN=... python live_check.py --provider netlas --target 192.0.2.1
"""

import argparse
import asyncio
import ipaddress
import os
import sys

from endpoint_providers import KEY_ENV, EndpointClient, ProviderError, host

HARD_CEILING = 5


async def run(provider, target, max_requests):
    key = os.environ.get(KEY_ENV[provider], "")
    if not key.strip():
        print(f"{KEY_ENV[provider]} is not set in the environment; nothing was sent.")
        return 2

    async def reserve(bucket):
        return None

    client = EndpointClient(provider, key, reserve, max_requests=max_requests)
    try:
        try:
            ipaddress.ip_address(target)
            value = target
        except ValueError:
            value = host(target)
        records = await client.host_ports(value)
    except ProviderError as exc:
        print(f"provider={provider} requests={client.requests} status=error code={exc}")
        return 1
    ports = sorted({(r["port"], r["transport"]) for r in records})
    print(
        f"provider={provider} requests={client.requests} status=ok "
        f"endpoints={len(records)} ports={[f'{p}/{t}' for p, t in ports]}"
    )
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--provider", choices=sorted(KEY_ENV), required=True)
    parser.add_argument("--target", required=True, help="one IP or domain")
    parser.add_argument("--max-requests", type=int, default=2)
    args = parser.parse_args(argv)
    if not 1 <= args.max_requests <= HARD_CEILING:
        parser.error(f"--max-requests must be between 1 and {HARD_CEILING}")
    return asyncio.run(run(args.provider, args.target, args.max_requests))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
