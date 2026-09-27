<!--
Keep this short; the diff is the detail. The questions that matter most in this
repository are the last four: data safety, audit, docs and the security gates.
-->

## What and why

<!-- What changes, and what failure or need does it address? -->

## How it was verified

<!-- Which tests were added or run? What did you run locally? -->

## Checklist

- [ ] Tests were added or updated, and they fail without the change.
- [ ] `make lint-backend`, `make mypy-backend` and the relevant test target are green.
- [ ] No secrets, real customer domains or personal data appear in the diff, tests or fixtures.
- [ ] Containers stay hardened (non-root, dropped capabilities, read-only where applicable), or the PR explains why not.

## Data safety

<!-- Required if this touches the schema, storage or generated files. -->

- [ ] Not applicable.
- [ ] The Alembic migration has an intact ancestry, a single head, and a real `downgrade()`.
- [ ] No migration in this PR is destructive, or the change is called out in `docs/upgrading.md`.

Notes:

## Audit and observability

<!-- Required if this adds or changes a security-relevant action, a log line or a metric. -->

- [ ] Not applicable.
- [ ] New audit actions are added to `AUDIT_ALLOWED_ACTIONS` and emitted with the five documented fields
      (context goes inside `details`, never beside it).
- [ ] Log output stays one JSON object per line on stdout, so a collector can ship it unchanged.

Notes:

## Documentation

- [ ] Not applicable.
- [ ] `docs/` (and `README.md` where relevant) describe the new behaviour in this PR.
- [ ] `CHANGELOG.md` has an entry under `Unreleased`.

## Compatibility

<!-- Configuration keys, API routes, connector protocol, log shape, backup format. -->

<!-- 0.1.0 is the first release: there is no earlier format to support, and this
     project does not carry compatibility branches for one. -->

- [ ] This change introduces no compatibility branch for an earlier format (no `legacy` handling, no default that exists only for a previous release).
- [ ] If this change alters a wire shape (connector protocol, API route, job type, column), the release note in `CHANGELOG.md` says so, and the affected component is versioned with it.
