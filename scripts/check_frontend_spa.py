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
"""

from __future__ import annotations

from pathlib import Path


CONFIG = Path("docker/nginx/default.conf")
EXPECTED_FALLBACK = "try_files $uri /index.html;"


def main() -> int:
    try:
        text = CONFIG.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"frontend SPA gate: FAILED — cannot read {CONFIG}: {exc}")
        return 2

    failures: list[str] = []
    if EXPECTED_FALLBACK not in text:
        failures.append(
            "the SPA location must use `try_files $uri /index.html;` so a route "
            "cannot resolve to a real build directory"
        )
    if "try_files $uri $uri/ /index.html;" in text:
        failures.append(
            "the SPA fallback must not contain `$uri/`: `/assets` is also the "
            "static build directory and would receive a filesystem slash redirect"
        )
    if "port_in_redirect off;" not in text:
        failures.append(
            "`port_in_redirect off;` is required so an unavoidable Nginx redirect "
            "does not expose the internal listening port"
        )

    if failures:
        print("frontend SPA gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("frontend SPA gate: OK — application routes use the index fallback and redirects do not expose the internal port")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
