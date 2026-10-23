#!/usr/bin/env python3
"""Check the frontend Nginx rules that keep client-side routes canonical.

The SPA has a real ``assets/`` directory for hashed JavaScript and CSS files.
Using ``try_files $uri $uri/ /index.html`` in the catch-all location makes the
client route ``/assets`` collide with that directory: Nginx redirects it to
``/assets/`` before React can render the Assets page. The redirect can also use
Nginx's listening port instead of the public UI port.

This is intentionally a small standard-library gate. It checks the shipped
configuration rather than relying on a browser test that may never exercise the
one route whose name collides with a build directory.

Usage:  python scripts/check_frontend_spa.py [--root DIR]

Exit codes: 0 clean, 1 findings, 2 unreadable input.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

CONFIG = Path("docker/nginx/default.conf")
EXPECTED_FALLBACK = "try_files $uri /index.html;"
FORBIDDEN_FALLBACK = "try_files $uri $uri/ /index.html;"


def check(root: Path) -> list[str]:
    """The rules `docker/nginx/default.conf` has to keep, under `root`.

    The configuration is read from the root it is given rather than from a fixed
    relative path: a gate whose input depends on the caller's working directory
    cannot be pointed at a fixture, and this one had no test until it could.
    """
    text = (root / CONFIG).read_text(encoding="utf-8")

    failures: list[str] = []
    if FORBIDDEN_FALLBACK in text:
        # One message for one defect: the forbidden form also fails the rule
        # below, and reporting both would read as two mistakes to fix.
        failures.append(
            "the SPA fallback must not contain `$uri/`: `/assets` is also the "
            "static build directory and would receive a filesystem slash redirect"
        )
    elif EXPECTED_FALLBACK not in text:
        failures.append(
            "the SPA location must use `try_files $uri /index.html;` so a route "
            "cannot resolve to a real build directory"
        )
    if "port_in_redirect off;" not in text:
        failures.append(
            "`port_in_redirect off;` is required so an unavoidable Nginx redirect "
            "does not expose the internal listening port"
        )
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the frontend Nginx rules that keep client routes canonical."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="checkout to scan (default: the working directory)",
    )
    args = parser.parse_args(argv)
    root = Path(args.root)

    try:
        failures = check(root)
    except OSError as exc:
        print(f"frontend SPA gate: FAILED — cannot read {CONFIG}: {exc}")
        return 2
    except UnicodeDecodeError as exc:
        print(f"frontend SPA gate: FAILED — {CONFIG} is not UTF-8: {exc}")
        return 2

    if failures:
        print("frontend SPA gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "frontend SPA gate: OK — application routes use the index fallback and "
        "redirects do not expose the internal port"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
