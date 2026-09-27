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

CI runs all of the above on every push and pull request. Running them locally
first is the fastest way to get a change merged, and it is the only way to see
the failures that CI reports as a fenced log block.

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

## Security rules (non-negotiable)

These come from the project's own threat model and are enforced in review:

1. **No secrets in the repository.** Keys, tokens and passwords are read from the
   environment. `.env`, `backups/`, generated reports and databases are ignored;
   `scripts/check_tracked_sources.py` fails the build if an ignore rule would drop
   source files from a clone.
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
  backup format, log shape — update the relevant file under `docs/` in the same
  pull request. `docs/production-readiness.md` is the live statement of what is
  production-ready; treat it as a claim that must stay true.

## Licensing of contributions

OpenDRP is licensed under the AGPL-3.0 (see [`LICENSE`](LICENSE)). By submitting a
pull request you agree that your contribution is provided under the same licence.

## Code of conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md). In short:
be decent, critique the change rather than the person, and assume the other
person is also trying to protect someone's infrastructure.
