# Contributing to OpenDRP

Thanks for taking the time to help. This document describes how the project is
developed, what a change is expected to contain, and how to get it reviewed.

The short version: **write the test that fails first, keep the change small, and
never let a security-relevant action happen without an audit record.** The rest
of this file explains what those mean in practice.

## Getting set up

Everything runs in Docker Compose; there is no supported "install the
dependencies on the host" path, because the point of the project is that the
stack is reproducible.

```bash
git clone https://github.com/OpenDRP/opendrp.git
cd opendrp
python setup.py           # writes .env, generating every secret
make up                   # the installation: base compose file, no source mounts
make up-tools             # source-mounted stack with pytest/ruff/mypy, for the test targets
```

There is one deployment shape, and `make up` is it. The overlay you develop
against is tooling rather than a second way to deploy, which is the point: what
you test in `make up-tools` is the code you just edited, and what you check in
`make up` is the artifact an operator runs.

`make help` lists every target. The ones you will use most:

| Command | What it does |
|---|---|
| `make up` / `make up-tools` | The installation / the tooling stack the test and lint targets need |
| `make logs` | Tail every container |
| `make test-backend` | Backend suite (unit + API) |
| `make test-backend-integration` | Real PostgreSQL and Redis boundary tests, inside Compose |
| `make lint-backend`, `make mypy-backend` | Ruff, and the mypy ratchet gate |
| `make test-backend-critical-coverage` | Per-module coverage floors for the security-critical modules |
| `make check-backend-migrations` | Single Alembic head, intact ancestry, reversible downgrades |
| `make check-compose` | Fails if a Compose service loses its healthcheck or log bound |
| `make backup`, `make backup-verify` | Take a backup, and prove it restores |

The frontend is exercised from `frontend/`:

```bash
npm ci
npm run test:coverage
npm run build          # typecheck + production build
```

CI runs these gates and both test suites on every push and pull request, with two
exceptions: `make seed-demo` and `make verify-replicas` are local diagnostics, and
the `compose` job validates the two-replica file set's shape without starting it.
Running the rest locally first is the fastest way to get a change merged, and it
is the only way to see the failures that CI reports as a fenced log block.

## Make targets

`make` with no argument prints the same list. There are two shapes and they are
alternatives: `make up` is the installation (`docker-compose.yml` alone, no source
mounts), and `make up-tools` is the tooling stack that the test and lint targets
exec into (`docker-compose.yml` + `docker-compose.dev.yml`). The test, lint
and type-check targets run inside the tooling stack and say so when it is
missing; `make migrate` and `make check-backend-migrations` instead exec into a
running backend container, so they need *a* stack up — the installation is
enough — rather than nothing at all.

```bash
make setup             # Write .env from .env.example, generating every secret
make check-env         # Fail if .env.example and the Compose files disagree
make check-commands    # Fail if a documented command is not one line for every shell
make check-docs        # Fail if a link, an unreachable page or a migration reference in the docs tree is wrong
make up                # Build and start the installation (production shape)
make up-tools          # Optional: source-mounted stack with pytest/ruff/mypy
make down              # Stop services and keep volumes
make restart           # Stop and start all services
make build             # Build images only
make ps                # Show service status
make health            # Show services and API health
make logs              # Follow container logs
make migrate           # Apply Alembic migrations
make test-backend      # Run the backend test suite
make test-backend-fast # Run the backend suite without integration tests
make test-backend-integration  # Run real PostgreSQL/Redis boundary tests in Compose
make test-backend-critical-coverage  # Enforce per-module coverage thresholds
make lint-backend      # Run ruff over the backend app, scripts, and tests
make mypy-backend      # Run the mypy ratchet gate
make check-backend-migrations  # Verify the Alembic graph and that the schema it builds matches the ORM
make typecheck-backend # Compile backend app, scripts, and tests
make seed-demo         # Load demo data
make clean             # Remove local caches and coverage artifacts (__pycache__, .pytest_cache,
                       # .mypy_cache, .ruff_cache, htmlcov, .coverage, *.pyc, *.pyo, *.tsbuildinfo)
make destroy           # Stop services and delete all Compose volumes
```

`make destroy` is destructive: it permanently removes the PostgreSQL, Redis and
report-store volumes. `make restore` is destructive too, and refuses without
`CONFIRM_RESTORE=yes`.

Backend targets run pytest with `COVERAGE_CORE=sysmon`; running pytest by hand
without it mis-attributes coverage in async handlers and understates the result.

A few tests need a live service: Redis for the scheduler's `SET NX` dispatch guard
and the provider-quota Lua script, PostgreSQL for the row locks and the migrated
schema. Inside the tooling stack they run; run by hand without that service they
skip with the reason in the report — `live_redis` in `backend/tests/conftest.py`
for the broker, `INTEGRATION_*` for PostgreSQL — and
`make test-backend-integration` is where they are executed for real. Setting
`REQUIRE_INTEGRATION=1`, as CI's `production-integration` job does, turns a missing
service back into a failure, so a job that was given one cannot pass on tests that
never ran.

A test you add that opens a broker connection takes the `live_redis` fixture rather
than reading `REDIS_URL` itself, and `backend/tests/test_broker_suites_gate.py`
fails the build when one does not — including a test that reaches the client
through a helper instead of calling it. PostgreSQL tests gate themselves the same
way, on `INTEGRATION_DATABASE_URL`.

### Every target

| Target | What it does | Needs `make up-tools`? |
|---|---|---:|
| `make help` | Print the list of targets (the default goal) | no |
| `make setup` | Write `.env` from `.env.example`, generating every secret; `python setup.py --check` audits an existing file, `--repair` fills gaps, `--force` rotates | no |
| `make check-env` | Fail if `.env.example` and the Compose files disagree about a setting | no |
| `make check-commands` | Fail if a documented command needs a shell-specific line continuation | no |
| `make check-deps` | Fail if dependency declarations drift apart from `requirements*.txt` | no |
| `make check-providers` | Fail if a withdrawn provider reappears in source or in the documentation | no |
| `make check-docs` | Fail if a relative link, an unreachable page or a migration reference in the documentation tree is wrong | no |
| `make check-compose` | Fail if a service loses its healthcheck, log bound or network split | no |
| `make check-frontend-spa` | Fail if Nginx can redirect an SPA route to a static directory | no |
| `make check-backend-migrations` | Single Alembic head, intact ancestry, and the schema the chain builds matches the ORM models | no |
| `make up` | Build and start the installation (base compose file, no source mounts) | no |
| `make up-tools` | Start the tooling stack: source mounts plus pytest/ruff/mypy. Not an installation | — |
| `make pull-prod` | Pull the pinned images instead of building them | no |
| `make down` | Stop services and keep volumes | no |
| `make destroy` | Stop services and delete all Compose volumes — `postgres_data`, `redis_data`, `reports_store` (destructive) | no |
| `make logs` | Follow every container's log (`--tail=200`) | no |
| `make build` | Build images only | no |
| `make ps` | List services and their status | no |
| `make health` | `docker compose ps`, then the API healthcheck over HTTP | no |
| `make restart` | `down` followed by `up` | no |
| `make migrate` | Apply pending Alembic revisions (`alembic upgrade head`) | no |
| `make seed-demo` | Populate the database with demo users, assets, threats and breaches | no |
| `make shell-backend`, `make shell-frontend` | Open a shell inside the backend / frontend container | no |
| `make connector-token NAME=<c> TYPE=<m>` | Issue a connector credential and record it in `.env` | no |
| `make connector-token-rotate NAME=<c>` | Rotate that credential (the previous one stops working) | no |
| `make connector-tokens` | List the connectors and whether a credential is registered | no |
| `make backup` | One pass: `pg_dump` plus the report store, into `./backups` | no |
| `make backup-verify` | Restore the newest dump into a throwaway database and check it | no |
| `make restore FILE=<dump>` | Restore a dump over the live database (destructive) | no |
| `make verify-audit-chain` | Verify the audit hash chain (`FULL=1` for a full pass, `FILE=<ndjson>` to check an exported stream) | no |
| `make verify-replicas` | Start two API replicas and prove they share state | no |
| `make clean` | Remove `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `htmlcov`, `.coverage`, `coverage-critical.json`, `*.pyc`, `*.pyo`, `*.tsbuildinfo` and stale `celerybeat-schedule*` files | no |
| `make tools-check` | Internal prerequisite of the targets below: fail if the tooling stack is not running | — |
| `make test-backend` | Backend suite (unit + API) | yes |
| `make test-backend-fast` | Backend suite without the `integration` marker | yes |
| `make test-backend-integration` | Real PostgreSQL and Redis boundary tests, inside Compose | yes |
| `make test-backend-critical-coverage` | Per-module coverage floors for the security- and connector-critical modules | yes |
| `make lint-backend` | Ruff over `app`, `alembic`, `scripts`, `tests` and the connector tree | yes |
| `make mypy-backend` | The mypy ratchet gate (`scripts/check_mypy_baseline.py`) | yes |
| `make typecheck-backend` | Compile-time bytecode check (`compileall` over `app`, `scripts`, `tests`) | yes |

### Running the same things without make

`make` is a convenience wrapper; nothing depends on it. The targets used most
often map to Compose commands directly.

In the table below, `docker compose` means
`docker compose -f docker-compose.yml` — the installation, and the only shape
there is. The test and lint targets are the exception: they exec into the tooling
container, so their equivalents start with
`docker compose -f docker-compose.yml -f docker-compose.dev.yml` and need
`make up-tools` (or that `-f` pair with `up -d`) first.

| Target | Equivalent command |
|---|---|
| `make setup` | `python setup.py` |
| `make check-env` | `python scripts/check_env_template.py` |
| `make check-commands` | `python scripts/check_portable_commands.py` |
| `make check-deps` | `python scripts/check_dependency_sources.py` |
| `make check-providers` | `python scripts/check_withdrawn_providers.py .` |
| `make check-docs` | `python scripts/check_docs_consistency.py` |
| `make check-frontend-spa` | `python scripts/check_frontend_spa.py` |
| `make up` | `docker compose up -d --build` |
| `make down` | `docker compose down` |
| `make restart` | `docker compose down && docker compose up -d --build` |
| `make build` | `docker compose build` |
| `make ps` | `docker compose ps` |
| `make logs` | `docker compose logs -f --tail=200` |
| `make health` | `docker compose ps` then `curl -f http://localhost:8000/api/v1/health` |
| `make migrate` | `docker compose exec -T backend alembic upgrade head` |
| `make seed-demo` | `docker compose exec -T backend python -m scripts.seed_data all --yes` |
| `make shell-backend` | `docker compose exec backend /bin/bash` |
| `make connector-tokens` | `docker compose exec -T backend python -m scripts.manage_connector_tokens list` |
| `make up-tools` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build` (tooling, not an installation) |
| `make lint-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend ruff check app alembic scripts tests ../connectors ../scripts ../setup.py` |
| `make typecheck-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend python -m compileall -q app scripts tests` |
| `make mypy-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend python scripts/check_mypy_baseline.py` |
| `make check-backend-migrations` | `docker compose exec -T backend sh -c 'python scripts/check_migrations.py && python -m scripts.check_schema_drift'` |
| `make test-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend sh -c 'COVERAGE_CORE=sysmon python -m pytest -v tests/'` |
| `make test-backend-fast` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend sh -c 'COVERAGE_CORE=sysmon python -m pytest -q -m "not integration" tests/'` |
| `make destroy` | `docker compose down -v` (deletes the data volumes) |
| `make backup` | `docker compose run --rm -e BACKUP_ONCE=1 backup` |
| `make backup-verify` | `docker compose run --rm backup sh /backup-scripts/verify_restore.sh` |
| `make check-compose` | `python scripts/check_compose_healthchecks.py docker-compose.yml` |
| `make verify-replicas` | `docker compose -f docker-compose.yml -f docker-compose.replicas.yml up -d --build`, then that same file set with `--profile verify run --rm replica-check` |

The coverage and integration targets are the same commands with extra flags; read
them from the `Makefile` if you need the exact form.

## What a change should look like

**Tests come with the code, not after it.** The suite is the specification here:
a bug fix starts with a test that reproduces the bug, a new endpoint starts with
a test that pins its authorization behaviour and its audit record. Backend tests
live in `backend/tests/`, frontend tests next to the component they cover
(`*.test.tsx`).

**Match the surrounding code.** Comments in this repository explain *why* a
non-obvious decision was made, usually naming the failure it prevents. A comment
that restates what the next line does is noise; a comment that records "this
looks redundant and is not, because X" saves the next reader from deleting it.
Keep that style.

**Keep the diff focused.** Unrelated reformatting makes a security-sensitive
change hard to review, which is exactly the change that needs review most.

**Do not weaken a gate to make CI pass.** Coverage floors, the mypy baseline,
dependency audits and the compose healthcheck check are all ratchets. If one of
them blocks you, the correct move is to fix the cause, or to discuss raising the
floor deliberately in the pull request. Adding an `--ignore-vuln` to the audit
step is acceptable only with a comment naming the advisory and the reason there
is no fix yet.

**Write prose for one version of the platform.** `README.md` and this file are the
two documents `backend/tests/test_no_legacy_surface.py` reads, and it fails the
suite on wording that promises a state earlier than the release: the platform has
one wire format, one finding shape and one installation shape, so prose that
explains what something is being kept for describes a build nobody runs. The
rejected patterns are listed as `_COMPAT_VOCABULARY` in that test; the habit it
wants is to name the mechanism the code has now, never to contrast it with a state
that never shipped.

## Security rules (non-negotiable)

These come from the project's own threat model and are enforced in review:

1. **No secrets in the repository.** Keys, tokens and passwords are read from the
   environment. `.env`, `backups/`, generated reports and databases are ignored;
   `scripts/check_tracked_sources.py` fails the build if an ignore rule would drop
   source files from a clone. CI also scans the diff and the whole history for
   credentials (`.gitleaks.toml`), so a secret that was committed and then
   removed is still a finding: rotate it rather than rewriting history.
2. **No string-built SQL.** Use the ORM or bound parameters — always.
3. **Validate everything that crosses a trust boundary** — user input, connector
   payloads, and third-party API responses (Shodan, HIBP). Pydantic models with
   `extra="forbid"` and explicit allowlists are the house style.
4. **Audit every security-relevant action.** Actions are allowlisted in
   `backend/app/core/audit.py`; a new action must be added there or it is
   reported as unrecognized. The five top-level fields (`timestamp`, `user_id`,
   `action`, `ip_address`, `details`) are a published contract — new context goes
   inside `details`, never beside it.
5. **Keep the containers hardened.** Non-root users, `cap_drop: ALL`,
   `no-new-privileges`, read-only root filesystems for connectors. A change that
   needs a capability should explain why in the pull request.
6. **Fail closed in production.** If a value cannot be trusted, refuse to start
   rather than falling back to a development default.

Found a vulnerability? Do not open a public issue — follow
[`SECURITY.md`](SECURITY.md).

## Commits and pull requests

- Write commit messages that describe **why** the change exists. "Fix bug" is not
  a message; "Reject refresh tokens whose family was revoked" is.
- One logical change per commit. If a change touches documentation and behaviour,
  the documentation belongs in the same commit — a doc that describes behaviour
  the code does not have is a bug, and this repository has been bitten by it
  before.
- Pull requests run CI in full. A green run is the expected state before review;
  reviewers will ask for one if it is red or missing.
- If your change affects operators — configuration, migrations, upgrade steps,
  backup format, log shape — update `README.md`, which carries the platform's
  description, together with the specialist runbook under `docs/` in the same pull
  request. `docs/production-readiness.md` is the live statement of what is
  production-ready; treat it as a claim that must stay true.

## Licensing of contributions

OpenDRP is licensed under the AGPL-3.0 (see [`LICENSE`](LICENSE)). By submitting a
pull request you agree that your contribution is provided under the same licence.

## Code of conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md). In short:
be decent, critique the change rather than the person, and assume the other
person is also trying to protect someone's infrastructure.
