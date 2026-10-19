"""An executable `nginx` stub, on a filesystem that will actually execute it.

`docker/nginx/hsts.sh` and `docker/nginx/realip.sh` both end with an optional
`nginx -t`, run when one is found on `PATH`. Two test files render those fragments,
and both stub that binary for the same two reasons:

* a runner that has a real `nginx` installed must not make the assertion depend on
  that machine's configuration or permissions;
* the stub has to be **executable**, which is not the same property as writable.

The second one is not theoretical. The platform's own Compose hardening mounts
`/tmp` as `rw,noexec,nosuid,size=64m` on the API and web containers
(`docker-compose.yml`), the tooling container this suite runs in inherits it
(`docker-compose.dev.yml` does not remove it), and pytest's `tmp_path` lives
there — so a stub written beside the render input answered `nginx: Permission
denied` (exit 126) and ten correct tests failed over an environment property that
says nothing about the scripts under test.

The directory is therefore chosen by capability rather than by guesswork: a
candidate is accepted only after the stub written into it runs and reports
success, with `/var/tmp` and the home directory as the fallbacks a portable shell
script would also reach for. It is created once per process and removed at exit.
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

#: Accepts nothing but `nginx -t`, which is all the fragments under test ask of it.
STUB_SOURCE = '#!/bin/sh\n[ "$#" -eq 1 ] && [ "$1" = "-t" ] || exit 2\n'

_DIRECTORY: Path | None = None


def _can_execute(candidate: Path) -> Path | None:
    """A directory under `candidate` holding an `nginx` that runs, or `None`.

    The probe goes through `sh`, the way the fragments invoke the binary: on a
    POSIX system that is the same `execve`, and on Windows the shell is what reads
    the stub's `#!` line, so probing the file directly would report a capability
    the tests do not need and, on Windows, one they do not lack.
    """
    directory = Path(tempfile.mkdtemp(prefix="opendrp-nginx-stub-", dir=candidate))
    stub = directory / "nginx"
    stub.write_text(STUB_SOURCE, encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join((str(directory), env.get("PATH", "")))
    try:
        probe = subprocess.run(
            ["sh", "-c", "nginx -t"], capture_output=True, text=True, env=env, timeout=30
        )
    except OSError:  # pragma: no cover - no `sh` at all: nothing here can help
        shutil.rmtree(directory, ignore_errors=True)
        return None
    if probe.returncode == 0:
        return directory
    shutil.rmtree(directory, ignore_errors=True)
    return None


def directory() -> Path:
    """A directory that holds an executable `nginx`, created once per process."""
    global _DIRECTORY
    if _DIRECTORY is not None:
        return _DIRECTORY

    home = Path.home()
    for candidate in (Path(tempfile.gettempdir()), Path("/var/tmp"), home):
        if not candidate.is_dir() or not os.access(candidate, os.W_OK | os.X_OK):
            continue
        found = _can_execute(candidate)
        if found is not None:
            _DIRECTORY = found
            atexit.register(shutil.rmtree, found, True)
            return found

    raise RuntimeError(
        "no writable filesystem here executes a file — tried "
        f"{tempfile.gettempdir()}, /var/tmp and {home} — so the nginx stub these "
        "tests need cannot be provided"
    )


def path() -> str:
    """`PATH` with the stub's directory first, as the fragments must see it."""
    return os.pathsep.join((str(directory()), os.environ.get("PATH", "")))
