"""The backup has two halves, and the gate only ever proved one of them.

`scripts/backup.sh` writes a dump and, beside it, an archive of the report store.
`scripts/verify_restore.sh` — the step `make backup-verify` runs and CI runs on
every push — restored the dump into a scratch database and read three values back,
and never opened the archive. The store half of a backup therefore had no proof at
all: an empty, truncated or wrongly-rooted `reports-*.tgz` passed every gate the
repository has, and the runbook's own warning ("a restore that stops at the
database ... reads like a permissions problem rather than an unfinished restore")
described the outcome, not a check.

These tests drive the two shipped scripts the way the container does — a POSIX
shell with `pg_dump`, `pg_restore` and `psql` replaced by stubs that record what
they were asked to do — so they assert the scripts' decisions rather than a copy of
them. `tar` is the host's real one: the archive layout is the fact under test.

What each guard pins:

* the store is archived when it is there, with the members the runbook tells an
  operator to extract (`reports/…`, the basename of `REPORTS_DIR`), and the pass
  fails when the archive it just wrote cannot be read back;
* a store that is not there is *named* in the output instead of passing as a clean
  backup, because the run's success line is what an operator reads before trusting
  it;
* the verification opens the archive beside the dump, fails on one that cannot be
  listed, reports the file it read back, and — under `REQUIRE_REPORT_ARCHIVE=1`,
  which is what CI sets — fails when a backup that should carry the store does not;
* the database half still decides the result on its own, so a green run cannot be
  bought by a good archive.

The shell is the reason this file skips at all: there is no way to run a `sh` script
without one, and the run is skipped (and inventoried) rather than failing on a
Windows host that has no Git for Windows on `PATH`.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_BACKUP = _ROOT / "scripts" / "backup.sh"
_VERIFY = _ROOT / "scripts" / "verify_restore.sh"

_SHELL = shutil.which("sh")

pytestmark = pytest.mark.skipif(
    _SHELL is None,
    reason="running the backup scripts needs a POSIX shell",
)

_STAMP = "20260101T000000Z"
_DUMP_NAME = f"opendrp-{_STAMP}.dump"
_ARCHIVE_NAME = f"reports-{_STAMP}.tgz"

#: Writes the file it was told to write and succeeds: the dump's own content is not
#: what these tests are about, only that the script treats it as a dump.
_PG_DUMP = """\
for arg in "$@"; do
    case "$arg" in
        --file=*) printf 'PGDMP fixture' > "${arg#--file=}" ;;
    esac
done
exit 0
"""

_PG_RESTORE = """\
if [ -n "${PG_RESTORE_FAILS:-}" ]; then
    echo "pg_restore: error: fixture" >&2
    exit 1
fi
exit 0
"""

#: `psql` answers the read-back query and nothing else. The three values are the
#: shape the script parses: tables, modules, revision rows.
_PSQL = """\
if [ -n "${PSQL_SILENT:-}" ]; then
    exit 0
fi
for arg in "$@"; do
    case "$arg" in
        *information_schema*) printf '12|2|1\\n' ;;
    esac
done
exit 0
"""

#: A `tar` that writes something for `-czf` and refuses to list it, which is the
#: only way to reach the "an archive I cannot read back is not a backup" branch.
_BAD_TAR = """\
case "$1" in
    -czf)
        printf 'not a tar archive' > "$2"
        exit 0
        ;;
    *)
        echo "tar: not a tar archive" >&2
        exit 1
        ;;
esac
"""


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _tools(directory: Path, *, tar: str | None = None) -> Path:
    """Stub executables for one run, first on `PATH`."""
    directory.mkdir(parents=True, exist_ok=True)
    _stub(directory, "pg_dump", _PG_DUMP)
    _stub(directory, "pg_restore", _PG_RESTORE)
    _stub(directory, "psql", _PSQL)
    if tar is not None:
        _stub(directory, "tar", tar)
    return directory


def _store(directory: Path, *names: str) -> Path:
    """A report store with one generated PDF per name."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_bytes(b"%PDF-1.4 fixture report\n")
    return directory


def _archive(path: Path, store_name: str, files: dict[str, bytes]) -> Path:
    """An archive laid out the way `backup.sh` writes one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"{store_name}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def _run(
    script: Path,
    tools: Path,
    *,
    cwd: Path,
    variables: dict[str, str] | None,
    args: list[str] | None = None,
):
    """Run one script from the directory it was given relative paths for.

    The paths are relative on purpose. `tar -f` reads a `C:/…` argument as a
    *remote* archive (`Cannot connect to C:`), so a run driven with Windows-style
    absolute paths never reaches the archive branch at all — the test would pass
    for the wrong reason on the one host it cannot be reasoned about. A working
    directory and relative names sidestep the question: the shipped container is
    POSIX, and these runs exercise the script's decisions rather than its paths.
    """
    environment = dict(os.environ)
    environment["PATH"] = os.pathsep.join([tools.as_posix(), environment.get("PATH", "")])
    for name, value in (variables or {}).items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    return subprocess.run(
        [_SHELL, script.as_posix(), *(args or [])],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        cwd=cwd.as_posix(),
        timeout=120,
    )


def _newest(directory: Path, pattern: str) -> Path | None:
    """The file the pass wrote, named with the stamp it chose for itself."""
    matches = sorted(directory.glob(pattern))
    return matches[-1] if matches else None


def _backup(tmp_path: Path, *, store: str, tar: str | None = None, reports: str = "1"):
    backups = tmp_path / "backups"
    backups.mkdir()
    tools = _tools(tmp_path / "tools", tar=tar)
    result = _run(
        _BACKUP,
        tools,
        cwd=tmp_path,
        variables={
            "BACKUP_DIR": "backups",
            "BACKUP_ONCE": "1",
            "BACKUP_REPORTS": reports,
            "BACKUP_KEEP": "5",
            "REPORTS_DIR": store,
            "PGUSER": "opendrp",
            "PGPASSWORD": "fixture",
            "PGDATABASE": "opendrp",
            "PGHOST": "127.0.0.1",
        },
    )
    return result, backups


def _verify(
    tmp_path: Path,
    *,
    archive_name: str | None = _ARCHIVE_NAME,
    dump_name: str = _DUMP_NAME,
    **overrides,
):
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / dump_name).write_bytes(b"PGDMP fixture")
    if archive_name is not None:
        _archive(backups / archive_name, "reports", {"report.pdf": b"%PDF-1.4\n"})
    tools = _tools(tmp_path / "tools")
    variables = {
        "BACKUP_DIR": "backups",
        "REPORTS_DIR": "reports",
        "PGUSER": "opendrp",
        "PGPASSWORD": "fixture",
        "PGHOST": "127.0.0.1",
        "REQUIRE_REPORT_ARCHIVE": None,
    }
    variables.update(overrides)
    result = _run(
        _VERIFY,
        tools,
        cwd=tmp_path,
        variables=variables,
        args=[f"backups/{dump_name}"],
    )
    return result, backups


# ==============================================================================
# Taking the backup
# ==============================================================================
def test_the_report_store_is_archived_under_the_entry_the_runbook_names(tmp_path: Path) -> None:
    _store(tmp_path / "reports", "report.pdf")

    result, backups = _backup(tmp_path, store="reports")

    assert result.returncode == 0, result.stdout + result.stderr
    archive = _newest(backups, "reports-*.tgz")
    assert archive is not None, sorted(path.name for path in backups.iterdir())
    with tarfile.open(archive) as tar:
        names = tar.getnames()
    # `REPORTS_DIR` is `/reports` in both Compose file sets, so the archive's single
    # top-level entry is `reports`; the runbook's extraction instructions depend on
    # that name and used to state it wrongly.
    assert names[0] == "reports", names
    assert "reports/report.pdf" in names, names


def test_a_store_that_is_not_mounted_is_named_in_the_run(tmp_path: Path) -> None:
    """The dump is still good, but the run must not read as a full backup."""
    result, backups = _backup(tmp_path, store="not-mounted")

    assert result.returncode == 0, result.stdout + result.stderr
    assert _newest(backups, "opendrp-*.dump") is not None
    assert _newest(backups, "reports-*.tgz") is None
    output = result.stdout + result.stderr
    assert "report store is NOT in this backup" in output, output
    assert "docs/backup-restore.md" in output, output


def test_a_report_archive_that_cannot_be_read_back_fails_the_pass(tmp_path: Path) -> None:
    """Symmetric with the dump's own `pg_restore --list` check."""
    _store(tmp_path / "reports", "report.pdf")

    result, _ = _backup(tmp_path, store="reports", tar=_BAD_TAR)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "report store" in (result.stdout + result.stderr)


def test_the_store_can_be_left_out_on_purpose(tmp_path: Path) -> None:
    """`BACKUP_REPORTS=0` is a database-only backup, not a warning."""
    _store(tmp_path / "reports", "report.pdf")

    result, backups = _backup(tmp_path, store="reports", reports="0")

    assert result.returncode == 0, result.stdout + result.stderr
    assert _newest(backups, "reports-*.tgz") is None
    assert "NOT in this backup" not in result.stdout + result.stderr


# ==============================================================================
# Proving the backup restores
# ==============================================================================
def test_the_verification_opens_the_archive_beside_the_dump(tmp_path: Path) -> None:
    result, _ = _verify(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert _ARCHIVE_NAME in output, output
    assert "report store" in output.lower(), output


def test_a_corrupt_report_archive_fails_the_verification(tmp_path: Path) -> None:
    _verify(tmp_path, archive_name=None)
    # A file with the right name and the wrong content: what a truncated copy off
    # the end of a full disk looks like.
    (tmp_path / "backups" / _ARCHIVE_NAME).write_bytes(b"PGDMP truncated archive")

    result = _run(
        _VERIFY,
        tmp_path / "tools",
        cwd=tmp_path,
        variables={
            "BACKUP_DIR": "backups",
            "REPORTS_DIR": "reports",
            "PGUSER": "opendrp",
            "PGPASSWORD": "fixture",
            "PGHOST": "127.0.0.1",
        },
        args=[f"backups/{_DUMP_NAME}"],
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert _ARCHIVE_NAME in (result.stdout + result.stderr)


def test_an_archive_rooted_elsewhere_than_the_store_is_refused(tmp_path: Path) -> None:
    """The runbook used to promise a `reports_store/` entry; extracting that leaves
    the PDFs beside the store instead of in it, so the verification has to notice."""
    result, backups = _verify(tmp_path, archive_name=None)
    _archive(backups / _ARCHIVE_NAME, "reports_store", {"report.pdf": b"%PDF-1.4\n"})

    result = _run(
        _VERIFY,
        tmp_path / "tools",
        cwd=tmp_path,
        variables={
            "BACKUP_DIR": "backups",
            "REPORTS_DIR": "reports",
            "PGUSER": "opendrp",
            "PGPASSWORD": "fixture",
            "PGHOST": "127.0.0.1",
        },
        args=[f"backups/{_DUMP_NAME}"],
    )

    assert result.returncode == 1, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert "reports_store" in output and "reports" in output, output


def test_a_database_only_backup_says_the_store_was_not_in_it(tmp_path: Path) -> None:
    result, _ = _verify(tmp_path, archive_name=None)

    assert result.returncode == 0, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert "database only" in output, output


def test_requiring_the_archive_fails_when_a_backup_has_none(tmp_path: Path) -> None:
    """What CI sets, so a job that gains no archive cannot pass quietly."""
    result, _ = _verify(tmp_path, archive_name=None, REQUIRE_REPORT_ARCHIVE="1")

    assert result.returncode == 1, result.stdout + result.stderr
    assert "REQUIRE_REPORT_ARCHIVE" in (result.stdout + result.stderr)


def test_the_archive_is_found_beside_latest_dump(tmp_path: Path) -> None:
    """`make backup-verify` passes no argument, so the dump is `latest.dump`."""
    result, _ = _verify(tmp_path, dump_name="latest.dump")

    assert result.returncode == 0, result.stdout + result.stderr
    assert _ARCHIVE_NAME in result.stdout + result.stderr


def test_the_database_checks_still_decide_the_result(tmp_path: Path) -> None:
    """A good archive cannot make an unrestorable dump pass."""
    result, _ = _verify(tmp_path, PSQL_SILENT="1")

    assert result.returncode == 1, result.stdout + result.stderr
    assert "schema is incomplete" in (result.stdout + result.stderr)
