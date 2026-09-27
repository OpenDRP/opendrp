"""The setup wizard has one job, and one way to fail it badly.

The job: turn `.env.example` into a `.env` that the application starts with. The
failure is the interesting part — a wizard that writes a plausible-looking file
which the production validators reject is *worse* than the hand-editing it
replaces, because the mistake now arrives with a tool's authority and surfaces
inside a container minutes later. So the central test here loads the wizard's
output through the real `Settings` model, and the rest of the file pins the
properties that make the output trustworthy: secrets from a CSPRNG in the shapes
the validators demand, no secret ever printed, comments preserved, `--repair`
that cannot overwrite a live secret, and a rotation that keeps the replaced keys
verifiable.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import re
import sys
from pathlib import Path
from typing import Dict, Optional

import pytest
from pydantic import ValidationError

from app.core.config import _INSECURE_SECRET_MARKERS, Settings

_ROOT = Path(__file__).resolve().parents[2]
_SETUP = _ROOT / "setup.py"
TEMPLATE = _ROOT / ".env.example"

if not _SETUP.is_file() or not TEMPLATE.is_file():
    # `make test-backend` mounts the repository's setup.py and template read-only
    # at the paths this suite resolves; a trimmed checkout cannot answer the
    # question, and a hard error would look like a wizard failure.
    pytest.skip(
        f"{_SETUP} is not present: run this suite from a repository checkout",
        allow_module_level=True,
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


setup_wizard = _load(_SETUP, "opendrp_test_setup")


# ==============================================================================
# Helpers
# ==============================================================================
def _values(path: Path) -> Dict[str, str]:
    return dict(
        re.findall(r"^([A-Z_][A-Z0-9_]*)=(.*)$", path.read_text(encoding="utf-8"), re.M)
    )


def _fresh_copy(tmp_path: Path, name: str = ".env") -> Path:
    """Exactly what the README used to tell an operator to do."""
    target = tmp_path / name
    target.write_text(TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def _run(target: Path, *args: str) -> int:
    return setup_wizard.main(
        [
            "--non-interactive",
            "--no-compose-check",
            "--template",
            str(TEMPLATE),
            "--target",
            str(target),
            *args,
        ]
    )


def _public_args() -> list:
    """The values an installation cannot be given a default for.

    No flag selects a shape, so the helper supplies exactly what `parse_args`
    cannot guess: the public URL and the release version.
    """
    return [
        "--public-url",
        "https://drp.example.com",
        "--version",
        "0.1.1",
        "--connectors",
        "dnstwist",
    ]


#: Kept as an alias so the many call sites below read as "a complete run".
_production_args = _public_args


# ==============================================================================
# The secrets
# ==============================================================================
def test_every_secret_is_generated_long_enough_and_url_safe() -> None:
    secrets_ = setup_wizard.generate_secrets()

    assert set(secrets_) == set(setup_wizard.GENERATED_KEYS)
    for key, value in secrets_.items():
        assert len(value) >= 32, key
        if key == "ENCRYPTION_KEY":
            # Fernet's own shape: 32 bytes in urlsafe base64, so nothing else can
            # be substituted without the application refusing to decrypt.
            assert len(base64.urlsafe_b64decode(value)) == 32
        else:
            assert re.fullmatch(r"[A-Za-z0-9_-]+", value), key


def test_two_runs_do_not_produce_the_same_secrets() -> None:
    first = setup_wizard.generate_secrets()
    second = setup_wizard.generate_secrets()

    assert first != second
    assert len({value for value in first.values()}) == len(first)


def test_the_placeholder_list_matches_the_applications_own() -> None:
    """The wizard cannot import the app's markers, so it copies them.

    A copy that drifts is a wizard that writes a value the application rejects,
    which is exactly the failure this suite exists to prevent — so the copy is
    asserted here rather than trusted.
    """
    assert tuple(setup_wizard.INSECURE_SECRET_MARKERS) == tuple(_INSECURE_SECRET_MARKERS)


def test_generated_secrets_avoid_every_shipped_placeholder_marker() -> None:
    for value in setup_wizard.generate_secrets().values():
        assert not setup_wizard.is_placeholder(value)
        lowered = value.lower()
        for marker in _INSECURE_SECRET_MARKERS:
            assert marker not in lowered


def test_the_fernet_check_rejects_a_key_of_the_wrong_shape() -> None:
    assert setup_wizard.is_fernet_key(setup_wizard.generate_secret("ENCRYPTION_KEY"))
    assert not setup_wizard.is_fernet_key(base64.urlsafe_b64encode(b"short").decode())
    assert not setup_wizard.is_fernet_key("REPLACE_WITH_A_GENERATED_FERNET_KEY")


# ==============================================================================
# The file the application has to accept
# ==============================================================================
def test_a_production_file_is_accepted_by_the_settings_model(tmp_path: Path) -> None:
    """The contract that matters: production validators pass on the output.

    The file's own values are handed to `Settings` as keyword arguments so that
    the environment of the test run cannot decide what is being tested — a CI
    runner that exports `APP_ENV=test` must not turn the production validator
    into dead code. `DATABASE_URL` and `REDIS_URL` are supplied the way Compose
    builds them, because that is how the application receives them in a real
    deployment; neither is in the file (`.env.example` documents them as built by
    Compose).
    """
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0

    values = _values(target)
    assert values["APP_ENV"] == "production"
    password = values["POSTGRES_PASSWORD"]

    settings = Settings(
        _env_file=None,
        DATABASE_URL=f"postgresql+asyncpg://opendrp:{password}@postgres:5432/opendrp",
        REDIS_URL=f"redis://:{values['REDIS_PASSWORD']}@redis:6379/0",
        **{
            key: value
            for key, value in values.items()
            if key
            in {
                "APP_ENV",
                "OPENDRP_VERSION",
                "JWT_SECRET_KEY",
                "ENCRYPTION_KEY",
                "JWT_ALGORITHM",
                "AUTH_COOKIE_SECURE",
                "AUTHENTICATED_RATE_LIMIT_PER_MINUTE",
                "AUDIT_CHAIN_KEYS",
                "AUDIT_CHAIN_PREVIOUS_KEYS",
                "CORS_ORIGINS",
                "LOG_LEVEL",
                "TRUSTED_PROXY_IPS",
                "OPENDRP_NETWORK_SUBNET",
                "OPENDRP_EDGE_SUBNET",
                "OPENDRP_DATA_SUBNET",
                "OPENDRP_CONNECTOR_SUBNET",
                "REQUIRE_MFA_FOR_ADMINS",
                "MFA_ISSUER",
            }
        },
    )

    assert settings.APP_ENV == "production"
    assert settings.CORS_ORIGINS == ["https://drp.example.com"]
    assert settings.AUTH_COOKIE_SECURE is True
    assert settings.audit_chain_keys


def test_the_same_values_without_an_audit_chain_key_are_rejected(tmp_path: Path) -> None:
    """The control for the test above: the validator is genuinely reached.

    Without this, a `Settings(...)` that ignored `APP_ENV` would let the previous
    test pass while asserting nothing about production.
    """
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    values = _values(target)

    with pytest.raises(ValidationError) as caught:
        Settings(
            _env_file=None,
            APP_ENV="production",
            OPENDRP_VERSION=values["OPENDRP_VERSION"],
            JWT_SECRET_KEY=values["JWT_SECRET_KEY"],
            ENCRYPTION_KEY=values["ENCRYPTION_KEY"],
            AUDIT_CHAIN_KEYS="",
            AUTH_COOKIE_SECURE=True,
            CORS_ORIGINS=["https://drp.example.com"],
            DATABASE_URL=(
                f"postgresql+asyncpg://opendrp:{values['POSTGRES_PASSWORD']}"
                "@postgres:5432/opendrp"
            ),
        )

    assert "AUDIT_CHAIN_KEYS" in str(caught.value)


def test_no_secret_value_reaches_stdout_or_stderr(tmp_path: Path, capsys) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    captured = capsys.readouterr()

    for key in setup_wizard.GENERATED_KEYS:
        value = _values(target)[key]
        assert value not in captured.out
        assert value not in captured.err
    # Only the fingerprint is printed, so the operator can still confirm the write.
    assert setup_wizard.fingerprint(_values(target)["JWT_SECRET_KEY"]) in captured.out


def test_the_printed_output_is_ascii(tmp_path: Path, capsys) -> None:
    """Windows consoles are not UTF-8; a typographic dash arrives as garbage."""
    assert _run(_fresh_copy(tmp_path), *_production_args()) == 0
    captured = capsys.readouterr()

    captured.out.encode("ascii")
    captured.err.encode("ascii")


# ==============================================================================
# Writing
# ==============================================================================
def test_comments_and_local_keys_survive_a_rewrite(tmp_path: Path) -> None:
    target = _fresh_copy(tmp_path)
    text = target.read_text(encoding="utf-8")
    text += "\n# our own note\nOUR_PRIVATE_FLAG=1\n"
    target.write_text(text, encoding="utf-8")

    assert _run(target, *_production_args()) == 0

    written = target.read_text(encoding="utf-8")
    assert "# our own note" in written
    assert "OUR_PRIVATE_FLAG=1" in written
    # The shipped explanations survive too: they are the reason the template is
    # the configuration reference, and a rewrite that dropped them would make the
    # file it wrote the only file that explains nothing.
    assert "# Key for the audit hash chain" in written
    assert written.count("#") >= TEMPLATE.read_text(encoding="utf-8").count("#")


def test_the_written_file_uses_lf_and_is_not_world_readable(tmp_path: Path) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0

    raw = target.read_bytes()
    assert b"\r\n" not in raw
    assert not raw.startswith(b"\xef\xbb\xbf")  # no BOM
    if os.name == "posix":
        assert target.stat().st_mode & 0o077 == 0


def test_a_key_the_template_does_not_carry_is_appended_and_marked(tmp_path: Path) -> None:
    """An older .env gains a newer setting, with a note saying where it came from."""
    target = tmp_path / ".env"
    target.write_text(
        "APP_ENV=production\nOPENDRP_VERSION=0.1.1\n"
        "JWT_SECRET_KEY=REPLACE_ME\nCORS_ORIGINS=[\"http://localhost:3000\"]\n",
        encoding="utf-8",
    )

    assert _run(target, "--repair") == 0

    written = target.read_text(encoding="utf-8")
    assert "Added by setup.py" in written
    assert "AUDIT_CHAIN_KEYS=" in written


# ==============================================================================
# Modes
# ==============================================================================
def test_repair_fills_the_gaps_and_leaves_a_working_value_alone(tmp_path: Path) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    before = _values(target)

    # Break one secret by putting the shipped placeholder back, as a copy of a
    # newer template over an older file would: what is present and usable must
    # survive the repair.
    text = target.read_text(encoding="utf-8")
    text = re.sub(
        r"^REDIS_PASSWORD=.*$",
        "REDIS_PASSWORD=REPLACE_WITH_A_GENERATED_REDIS_PASSWORD",
        text,
        flags=re.M,
    )
    target.write_text(text, encoding="utf-8")

    assert _run(target, "--repair") == 0
    after = _values(target)

    assert after["REDIS_PASSWORD"] not in {
        "REPLACE_ME",
        "REPLACE_WITH_A_GENERATED_REDIS_PASSWORD",
    }
    assert after["JWT_SECRET_KEY"] == before["JWT_SECRET_KEY"]
    assert after["ENCRYPTION_KEY"] == before["ENCRYPTION_KEY"]
    assert after["APP_ENV"] == before["APP_ENV"]


def test_repair_replaces_a_secret_the_application_would_refuse(tmp_path: Path) -> None:
    """`JWT_SECRET_KEY=REPLACE_ME` is not in the application's placeholder list.

    Its marker list does not catch that spelling and no length rule applies to a
    password, so a hand-written file can be full of values that are not
    placeholders yet cannot start. Repair fills exactly those two.
    """
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    text = target.read_text(encoding="utf-8")
    text = re.sub(r"^JWT_SECRET_KEY=.*$", "JWT_SECRET_KEY=REPLACE_ME", text, flags=re.M)
    target.write_text(text, encoding="utf-8")

    assert _run(target, "--repair") == 0

    assert len(_values(target)["JWT_SECRET_KEY"]) >= 32


def test_repair_leaves_a_password_the_operator_chose_alone(tmp_path: Path) -> None:
    """A short password is legal to the application.

    Quietly replacing it would be the worst repair available: the database volume
    keeps the password it was initialised with, so the file would stop matching
    the installation it describes.
    """
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    text = target.read_text(encoding="utf-8")
    text = re.sub(r"^POSTGRES_PASSWORD=.*$", "POSTGRES_PASSWORD=short", text, flags=re.M)
    target.write_text(text, encoding="utf-8")

    assert _run(target, "--repair") == 0

    assert _values(target)["POSTGRES_PASSWORD"] == "short"


def test_repair_never_rewrites_a_file_that_already_holds_secrets(tmp_path: Path) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    before = target.read_text(encoding="utf-8")

    assert _run(target, "--repair") == 0

    assert target.read_text(encoding="utf-8") == before


def test_a_plain_re_run_refuses_to_overwrite_an_installation(tmp_path: Path, capsys) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    before = target.read_text(encoding="utf-8")

    assert _run(target) == 1

    assert target.read_text(encoding="utf-8") == before
    assert "--repair" in capsys.readouterr().err


def test_rotation_keeps_the_replaced_keys_verifiable(tmp_path: Path) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    before = _values(target)

    assert _run(target, "--force", *_production_args()) == 0
    after = _values(target)

    assert after["JWT_SECRET_KEY"] != before["JWT_SECRET_KEY"]
    assert before["JWT_SECRET_KEY"] in after["JWT_PREVIOUS_SECRET_KEYS"].split(",")
    assert before["ENCRYPTION_KEY"] in after["ENCRYPTION_PREVIOUS_KEYS"].split(",")
    assert before["AUDIT_CHAIN_KEYS"] in after["AUDIT_CHAIN_PREVIOUS_KEYS"].split(",")
    # A backup is taken before any overwrite: the file may hold the only copy of a
    # live database password.
    assert list(tmp_path.glob(f"{target.name}.backup-*"))


def test_rotation_reports_the_replaced_secrets_mask_only(tmp_path: Path, capsys) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    before = _values(target)

    assert _run(target, "--force", *_production_args()) == 0
    captured = capsys.readouterr()

    assert before["JWT_SECRET_KEY"] not in captured.out
    assert setup_wizard.fingerprint(before["JWT_SECRET_KEY"]) in captured.out


def test_a_dry_run_writes_nothing(tmp_path: Path) -> None:
    target = _fresh_copy(tmp_path)
    before = target.read_text(encoding="utf-8")

    assert _run(target, "--dry-run", *_production_args()) == 0

    assert target.read_text(encoding="utf-8") == before


def test_a_run_without_a_public_url_is_refused(tmp_path: Path) -> None:
    """Nothing is guessed: a wrong origin is a UI that refuses every request."""
    assert _run(_fresh_copy(tmp_path), "--version", "0.1.1") == 2


def test_the_wizard_writes_the_one_installation_shape(tmp_path: Path) -> None:
    """There is no profile to choose, so the file cannot describe another one.

    A file that said `APP_ENV=development` would start the application with its
    production checks disabled — what the wizard wrote would not be what the
    installation ran.
    """
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    values = _values(target)

    assert values["APP_ENV"] == "production"
    assert values["AUTH_COOKIE_SECURE"] == "true"
    assert values["OPENDRP_VERSION"] == "0.1.1"
    # Empty, not a development origin. A canonical origin sends a browser that
    # reached the SPA under some other origin to that one - and a release built
    # with `http://localhost:3000` sends every real user to their own machine.
    assert values["CANONICAL_ORIGIN"] == ""
    # Loopback, like the API: the UI is reached through the terminator in front of
    # this host, and a bare port publishes a plaintext copy of it on every
    # interface as well.
    assert values["FRONTEND_PORT"].startswith("127.0.0.1:")


def test_a_localhost_public_url_is_accepted_and_a_public_http_one_is_refused(
    tmp_path: Path, capsys
) -> None:
    """The exception for `localhost` is deliberate, and only for `localhost`.

    Production requires `AUTH_COOKIE_SECURE=true`, so a public plain-HTTP origin
    is an installation whose users can never stay signed in. `localhost` is
    different: browsers treat it as a trustworthy origin, so the Secure cookie
    works there, and it is how the operator checks the installation on the
    machine that runs it.
    """
    local = tmp_path / "local.env"
    local.write_text(TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
    assert _run(local, "--public-url", "http://localhost:3000", "--version", "0.1.1") == 0
    assert _values(local)["CORS_ORIGINS"] == '["http://localhost:3000"]'

    public = tmp_path / "public.env"
    public.write_text(TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
    assert (
        _run(public, "--public-url", "http://drp.example.com", "--version", "0.1.1") == 2
    )
    # The refusal names the way forward, and leaves the target untouched: a
    # rejected run must not write half an installation.
    assert "https://" in capsys.readouterr().err
    assert _values(public)["CORS_ORIGINS"] == '["https://REPLACE_WITH_PUBLIC_HOST"]'


def test_a_flag_that_selects_a_shape_is_not_accepted(tmp_path: Path, capsys) -> None:
    """Nothing selects a shape, so nothing may look like it does.

    argparse exits with code 2 on an unrecognised argument, which is the same
    code the wizard uses for unusable input.
    """
    target = _fresh_copy(tmp_path)
    with pytest.raises(SystemExit) as refused:
        _run(target, "--profile", "dev")

    assert refused.value.code == 2
    assert "--profile" in capsys.readouterr().err
    # Refused before anything was written: a rejected run leaves no half file.
    assert _values(target)["APP_ENV"] == "production"


def test_repair_moves_a_development_file_to_the_installation_shape(
    tmp_path: Path,
) -> None:
    """A file the old wizard wrote is repaired into the only shape that exists.

    `APP_ENV`, `AUTH_COOKIE_SECURE` and `CANONICAL_ORIGIN` describe the
    installation rather than an operator's choice, so `--repair` rewrites them
    even though a value is present - while still leaving the ports, the MFA policy
    and every secret alone.
    """
    target = tmp_path / ".env"
    target.write_text(
        "APP_ENV=development\n"
        "OPENDRP_VERSION=0.1.1\n"
        "AUTH_COOKIE_SECURE=false\n"
        'CORS_ORIGINS=["https://drp.example.com"]\n'
        "CANONICAL_ORIGIN=http://localhost:3000\n"
        "FRONTEND_PORT=3000\n",
        encoding="utf-8",
    )

    assert _run(target, "--repair") == 0
    values = _values(target)

    assert values["APP_ENV"] == "production"
    assert values["AUTH_COOKIE_SECURE"] == "true"
    assert values["CANONICAL_ORIGIN"] == ""
    # The operator's own choice survives, and is reported rather than rewritten.
    assert values["FRONTEND_PORT"] == "3000"


def test_a_re_run_recovers_the_public_url_and_version_from_the_file(
    tmp_path: Path,
) -> None:
    """`--repair` must not make the operator repeat what the file already says."""
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    before = _values(target)

    assert _run(target, "--repair") == 0
    after = _values(target)

    assert after["CORS_ORIGINS"] == before["CORS_ORIGINS"]
    assert after["OPENDRP_VERSION"] == before["OPENDRP_VERSION"]


def test_the_wizard_refuses_a_file_git_would_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _fresh_copy(tmp_path)
    before = target.read_text(encoding="utf-8")
    monkeypatch.setattr(setup_wizard, "git_ignored", lambda path: False)

    assert _run(target, *_production_args()) == 1

    assert target.read_text(encoding="utf-8") == before


def test_git_ignored_answers_unknown_outside_a_repository(tmp_path: Path) -> None:
    """Unknown is not a refusal: the check exists for a checkout that lost a rule."""
    assert setup_wizard.git_ignored(tmp_path / ".env") is None


# ==============================================================================
# The audit
# ==============================================================================
def test_check_passes_the_file_the_wizard_wrote(tmp_path: Path, capsys) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0

    code = setup_wizard.main(["--check", "--target", str(target)])

    assert code == 0
    assert "no findings" in capsys.readouterr().out


@pytest.mark.parametrize(
    "replacement, expected",
    [
        (("JWT_SECRET_KEY", "REPLACE_WITH_AT_LEAST_32_RANDOM_CHARACTERS"), "JWT_SECRET_KEY"),
        (("ENCRYPTION_KEY", "not-a-fernet-key"), "ENCRYPTION_KEY"),
        (("AUTH_COOKIE_SECURE", "false"), "AUTH_COOKIE_SECURE"),
        (("OPENDRP_DATA_SUBNET", "10.1.0.0/24"), "OPENDRP_DATA_SUBNET"),
        (("CORS_ORIGINS", '["https://REPLACE_WITH_PUBLIC_HOST"]'), "CORS_ORIGINS"),
        # The value a development build used to carry, which sends every visitor
        # to their own machine. It is an error rather than a warning because the
        # bundle is built from it, so a file that keeps it ships that behaviour.
        (("CANONICAL_ORIGIN", "http://localhost:3000"), "CANONICAL_ORIGIN"),
        (("AUDIT_CHAIN_KEYS", ""), "AUDIT_CHAIN_KEYS"),
        (("REDIS_URL", "redis://redis:6379/0"), "REDIS_URL"),
    ],
)
def test_check_names_each_class_of_problem(
    tmp_path: Path, capsys, replacement: tuple, expected: str
) -> None:
    """Each rule the application enforces at startup is also visible here."""
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    key, value = replacement
    text = target.read_text(encoding="utf-8")
    if re.search(rf"^{key}=", text, flags=re.M):
        text = re.sub(rf"^{key}=.*$", f"{key}={value}", text, flags=re.M)
    else:
        text += f"\n{key}={value}\n"
    target.write_text(text, encoding="utf-8")

    code = setup_wizard.main(["--check", "--target", str(target)])
    output = capsys.readouterr().out

    assert code == 1, f"{key} should be reported"
    assert expected in output


def test_check_reports_a_typo_as_unknown(tmp_path: Path, capsys) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    with target.open("a", encoding="utf-8") as stream:
        stream.write("\nJWT_SECRETKEY=leftover\n")

    code = setup_wizard.main(["--check", "--target", str(target)])
    output = capsys.readouterr().out

    assert code == 1
    assert "JWT_SECRETKEY" in output
    assert "not documented" in output


def test_check_reports_the_settings_a_newer_template_added(tmp_path: Path, capsys) -> None:
    """The upgrade path: `docs/upgrading.md` tells an operator to diff the template."""
    target = tmp_path / ".env"
    target.write_text("APP_ENV=development\n", encoding="utf-8")

    setup_wizard.main(["--check", "--target", str(target)])
    output = capsys.readouterr().out

    assert "the template defines settings this file does not mention" in output


def test_check_on_a_missing_file_is_an_input_error(tmp_path: Path) -> None:
    assert setup_wizard.main(["--check", "--target", str(tmp_path / "absent")]) == 2


def test_validate_mirrors_the_configuration_validators() -> None:
    """A compact statement of the rules, so a change to them is a deliberate edit."""
    good: Dict[str, Optional[str]] = {
        "APP_ENV": "production",
        "OPENDRP_VERSION": "0.1.1",
        "POSTGRES_PASSWORD": setup_wizard.generate_secret("POSTGRES_PASSWORD"),
        "REDIS_PASSWORD": setup_wizard.generate_secret("REDIS_PASSWORD"),
        "JWT_SECRET_KEY": setup_wizard.generate_secret("JWT_SECRET_KEY"),
        "ENCRYPTION_KEY": setup_wizard.generate_secret("ENCRYPTION_KEY"),
        "AUDIT_CHAIN_KEYS": setup_wizard.generate_secret("AUDIT_CHAIN_KEYS"),
        "AUTH_COOKIE_SECURE": "true",
        "CORS_ORIGINS": '["https://drp.example.com"]',
        "OPENDRP_NETWORK_SUBNET": "172.18.0.0/16",
        "OPENDRP_EDGE_SUBNET": "172.18.10.0/24",
        "OPENDRP_DATA_SUBNET": "172.18.20.0/24",
        "OPENDRP_CONNECTOR_SUBNET": "172.18.30.0/24",
    }
    assert [f for f in setup_wizard.validate_values(good) if f.level == "error"] == []

    broken = dict(good, OPENDRP_CONNECTOR_SUBNET="10.9.0.0/24")
    errors = [f for f in setup_wizard.validate_values(broken) if f.level == "error"]
    assert any("OPENDRP_CONNECTOR_SUBNET" in str(finding) for finding in errors)


# ==============================================================================
# The closing block: what the operator is told to do next
# ==============================================================================
def _next_steps(monkeypatch: pytest.MonkeyPatch, has_make: bool, **kwargs) -> str:
    """The wizard's final block, flattened. `shutil.which` picks the branch."""
    monkeypatch.setattr(
        setup_wizard.shutil, "which", lambda name: "/usr/bin/make" if has_make else None
    )
    answers = setup_wizard.Answers(**kwargs)
    return "\n".join(setup_wizard.next_steps(answers, Path(".env")))


def test_next_steps_name_the_variable_and_the_recreate_command(monkeypatch) -> None:
    """Without `make` these lines are the whole instruction, so they must be whole.

    The defect this pins: the block printed the `issue` command and stopped. An
    operator following only the wizard was left holding a token, with nothing
    saying it belongs in `.env` and nothing saying which command makes the
    worker read it.
    """
    out = _next_steps(
        monkeypatch, has_make=False, connectors=("dnstwist",)
    )

    assert "CONNECTOR_TOKEN_DNSTWIST" in out
    assert "Paste it into .env" in out
    assert "up -d connector-dnstwist" in out
    # The verb is the point: a restart keeps the environment the container was
    # created with, so it would leave the placeholder in place and re-fail.
    assert "not `docker compose restart`" in out


def test_next_steps_delegate_to_make_when_it_is_available(monkeypatch) -> None:
    out = _next_steps(
        monkeypatch, has_make=True, connectors=("dnstwist",)
    )

    assert "make connector-token NAME=dnstwist TYPE=phishing" in out
    # The installation, not a development stack: this is the command the operator
    # types, and it has to be the shape their users reach.
    assert "make up" in out
    assert "make up-prod" not in out
    # The Makefile writes `.env` and prints the recreate command itself, so the
    # wizard must not repeat either.
    assert "manage_connector_tokens issue" not in out
    assert "up -d connector-dnstwist" not in out


def test_next_steps_explain_why_the_connectors_are_down(monkeypatch) -> None:
    """Otherwise a crash-looping worker looks like a broken installation."""
    out = _next_steps(
        monkeypatch, has_make=True, connectors=("dnstwist",)
    )
    assert "Missing required environment variables: CONNECTOR_TOKEN" in out


def test_next_steps_drop_the_connector_step_when_none_is_selected(monkeypatch) -> None:
    out = _next_steps(monkeypatch, has_make=False, connectors=())

    assert "CONNECTOR_TOKEN" not in out
    # The numbering is generated, so a run with nothing to provision does not
    # print a sequence with a hole in it.
    numbered = [line for line in out.splitlines() if re.match(r"^\d+\. ", line)]
    assert [line.split(".", 1)[0] for line in numbered] == [
        str(position) for position in range(1, len(numbered) + 1)
    ]


def test_next_steps_keep_every_command_on_one_line(monkeypatch) -> None:
    """A wrapped command cannot be pasted on Windows, so the block must not wrap.

    `scripts/check_portable_commands.py` enforces this over files; the wizard
    *prints* its instructions, so the same rule is applied here to what an
    operator actually receives. `cmd.exe` reads a caret and PowerShell a backtick
    as the continuation, and neither reads a backslash.
    """
    continuations = (chr(92), "`", "^")

    for has_make in (True, False):
        out = _next_steps(
            monkeypatch,
            has_make=has_make,
            connectors=("dnstwist", "shodan"),
        )
        for line in out.splitlines():
            assert not line.rstrip().endswith(continuations), (has_make, line)


def test_next_steps_quote_the_password_the_way_every_shell_strips(
    monkeypatch,
) -> None:
    """`cmd.exe` does not treat single quotes as quoting, and eats `<` and `>`."""
    out = _next_steps(
        monkeypatch, has_make=False, connectors=("dnstwist",)
    )

    assert '--password "ChangeMeAdminPass123!"' in out
    assert "'<" not in out


def test_next_steps_say_the_administrator_password_is_temporary(monkeypatch) -> None:
    """The first sign-in surprises an operator unless this is stated where it happens.

    The wizard prints the command that creates the administrator, so it is the
    last place an operator reads before typing a password somebody else will
    replace. Without the note, the first sign-in looks like a refusal — the
    platform answers `403` for everything except the onboarding page — and the
    question it raises ("why is the password I just set not working?") arrives as
    a support ticket rather than as a sentence on screen.
    """
    for has_make in (True, False):
        out = _next_steps(monkeypatch, has_make=has_make, connectors=())
        assert "temporary on purpose" in out
        assert "asks for a password of your own" in out
        # The destination is named, so "then choose your own on the page that
        # appears" is actionable rather than vague.
        assert "choose your own" in out


# ==============================================================================
# The questions: what they offer, and what they refuse
# ==============================================================================
def _scripted(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> list[str]:
    """Answer the wizard from a list, and return the prompts it printed.

    `input` is the whole seam of the interactive path, so this is exactly what
    an operator would have seen and typed.
    """
    prompts: list[str] = []
    queue = list(answers)

    def fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        return queue.pop(0) if queue else ""

    monkeypatch.setattr("builtins.input", fake_input)
    return prompts


def test_the_public_url_prompt_shows_the_shape_of_an_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prompt with no default still owes the operator an example.

    It has no default on purpose (a guessed origin is a UI that refuses every
    request), and the mistake it invites is seen the first time it is met: the
    example used to appear only *after* the answer was refused.
    """
    prompts = _scripted(
        monkeypatch,
        [
            "",  # the release: accept the version this checkout declares
            "",  # the public URL: empty is refused, and the example is already on screen
            "https://drp.example.com",
            "",  # keep the default loopback bindings
            "n",  # no Shodan
            "n",  # no HIBP
            "",  # require MFA (the default)
            "",  # keep the default retention windows
        ],
    )

    answers = setup_wizard.wizard(setup_wizard.Answers())
    public = [prompt for prompt in prompts if prompt.startswith("Public URL")]

    assert len(public) == 2, "the empty answer should have been asked again"
    assert all("e.g. https://drp.example.com" in prompt for prompt in public)
    assert answers.public_url == "https://drp.example.com"


def test_the_version_the_checkout_declares_is_the_offered_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`make up` builds the images from this tree, so this is the honest default."""
    declared = setup_wizard.checkout_version()
    assert declared is not None, "this checkout should declare a version"
    prompts = _scripted(
        monkeypatch,
        [
            "",  # the release
            "https://drp.example.com",
            "",
            "n",
            "n",
            "",
            "",
        ],
    )

    answers = setup_wizard.wizard(setup_wizard.Answers())
    release = [prompt for prompt in prompts if prompt.startswith("OpenDRP release")]

    assert len(release) == 1
    assert f"[{declared}]" in release[0]
    assert answers.release_version == declared


def test_a_run_without_a_version_uses_the_checkout_default(tmp_path: Path) -> None:
    """`--version` stops being a required flag, because there is an answer.

    A target that does not exist yet is the case that has neither the flag nor a
    value to recover from a file, so the version this checkout declares is what
    the run writes.
    """
    target = tmp_path / ".env"

    assert _run(target, "--public-url", "https://drp.example.com") == 0
    assert _values(target)["OPENDRP_VERSION"] == setup_wizard.checkout_version()


def test_an_unreadable_checkout_version_is_refused_rather_than_guessed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """Nothing to read and nothing to recover: a file must state a real release.

    The two sources the wizard falls back to are the version in an existing file
    (a re-run does not need the flag repeated) and the one this checkout
    declares. With neither, the run has to stop rather than write `latest`.
    """
    monkeypatch.setattr(setup_wizard, "checkout_version", lambda: None)
    target = tmp_path / ".env"

    assert _run(target, "--public-url", "https://drp.example.com") == 2

    assert "--version" in capsys.readouterr().err
    # Refused before the write: no half-provisioned installation is left behind.
    assert not target.exists()


def test_the_version_in_an_existing_file_is_preferred_to_the_checkout_default(
    tmp_path: Path,
) -> None:
    """A re-run must not silently move an installation to another release."""
    target = _fresh_copy(tmp_path)
    text = target.read_text(encoding="utf-8")
    target.write_text(
        re.sub(r"^OPENDRP_VERSION=.*$", "OPENDRP_VERSION=0.0.9", text, flags=re.M),
        encoding="utf-8",
    )

    assert _run(target, "--public-url", "https://drp.example.com") == 0
    assert _values(target)["OPENDRP_VERSION"] == "0.0.9"


def test_a_loopback_origin_no_binding_serves_is_reported(tmp_path: Path, capsys) -> None:
    """The mistake the two prompts invite: an origin for a port nothing serves.

    `http://localhost` implies port 80, while the UI is published on 3000. It is
    a warning, not an error: a proxy on that port is a legitimate reading, and
    the SPA's own requests go to its own origin through the frontend's `/api/`
    proxy, where no CORS check happens. What is wrong is the record the file
    keeps.
    """
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    text = target.read_text(encoding="utf-8")
    target.write_text(
        re.sub(
            r"^CORS_ORIGINS=.*$",
            'CORS_ORIGINS=["http://localhost"]',
            text,
            flags=re.M,
        ),
        encoding="utf-8",
    )

    code = setup_wizard.main(["--check", "--target", str(target)])
    output = capsys.readouterr().out

    assert "CORS_ORIGINS names http://localhost" in output
    assert "nothing answers on port 80" in output
    # A warning leaves the file usable: the application starts with it.
    assert code == 0


def test_the_same_origin_and_binding_pass_quietly(tmp_path: Path, capsys) -> None:
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    text = target.read_text(encoding="utf-8")
    text = re.sub(
        r"^CORS_ORIGINS=.*$", 'CORS_ORIGINS=["http://localhost:3000"]', text, flags=re.M
    )
    target.write_text(text, encoding="utf-8")

    assert setup_wizard.main(["--check", "--target", str(target)]) == 0

    assert "nothing answers on port" not in capsys.readouterr().out


def test_a_version_that_differs_from_the_checkout_is_reported_as_a_note(
    tmp_path: Path, capsys
) -> None:
    """One installation must not report two versions.

    `/api/v1/health` answers the running code's `__version__`, Settings reports
    `OPENDRP_VERSION`. A note rather than a warning, because `make pull-prod`
    pulls a release tag deliberately.
    """
    target = _fresh_copy(tmp_path)
    assert _run(target, *_production_args()) == 0
    text = target.read_text(encoding="utf-8")
    target.write_text(
        re.sub(r"^OPENDRP_VERSION=.*$", "OPENDRP_VERSION=0.0.1", text, flags=re.M),
        encoding="utf-8",
    )

    code = setup_wizard.main(["--check", "--target", str(target)])
    output = capsys.readouterr().out

    assert "OPENDRP_VERSION is 0.0.1" in output
    assert "make pull-prod" in output
    assert code == 0


def test_a_bare_port_is_read_as_the_port_on_this_machine() -> None:
    """Compose reads `3000` as `0.0.0.0:3000`; the wizard writes what was meant."""
    assert setup_wizard.normalize_binding("3000") == "127.0.0.1:3000"
    # An explicit host is the one form that expresses publishing wider.
    assert setup_wizard.normalize_binding("10.0.0.10:3000") == "10.0.0.10:3000"
    # Left for the validator, which names the problem instead of guessing.
    assert setup_wizard.normalize_binding("http://drp.example.com") == (
        "http://drp.example.com"
    )

    assert setup_wizard.invalid_binding_reason("127.0.0.1:8000") is None
    assert setup_wizard.invalid_binding_reason("[::1]:8000") is None
    assert setup_wizard.invalid_binding_reason("70000") is not None
    assert setup_wizard.invalid_binding_reason("0") is not None
    assert setup_wizard.invalid_binding_reason("localhost:8000/api") is not None


def test_the_ui_binding_follows_a_loopback_origin_that_names_a_port() -> None:
    """Offered, not imposed: a proxy on that port is a legitimate other reading."""
    answers = setup_wizard.Answers()
    answers.public_url = "http://127.0.0.1:5555"
    assert setup_wizard.suggested_frontend_binding(answers) == "127.0.0.1:5555"

    answers.public_url = "http://localhost"
    assert setup_wizard.suggested_frontend_binding(answers) == "127.0.0.1:3000"

    answers.public_url = "https://drp.example.com:8443"
    assert setup_wizard.suggested_frontend_binding(answers) == "127.0.0.1:3000"
