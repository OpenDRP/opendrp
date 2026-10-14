# Security policy

OpenDRP is a security product: it holds an asset inventory, credentials for
third-party providers, and an audit trail that is meant to be trustworthy. If
you find a way to break any of those guarantees, please report it privately.

## Reporting a vulnerability

Use GitHub's private channel — **Security → Report a vulnerability** on
<https://github.com/OpenDRP/opendrp> (GitHub Security Advisories). This
keeps the report visible only to the maintainers until a fix is published.

Please do **not** open a public issue, and do not include working exploits in
public discussions.

A useful report contains:

- the affected version or commit SHA;
- the deployment shape (Docker Compose is the supported one) and whether the
  stack was reached through Nginx or directly on the API port;
- what the attacker can already do (anonymous, `viewer`, `analyst`, `admin`, or
  a registered connector);
- a minimal reproduction, and the impact you believe it has;
- any suggested fix, if you have one.

## What we consider in scope

- Authentication and session handling: login, refresh-token rotation and reuse
  detection, cookie flags, CSRF, rate limiting and lockout.
- Authorization: role boundaries (`admin` / `analyst` / `viewer`), connector
  credentials, and the "last active administrator" guard.
- The connector boundary: anything that lets a connector write outside its own
  module, impersonate another connector, or reach a route reserved for users.
- Injection of any kind, including through validated fields, report generation
  and the audit pipeline.
- Disclosure of secrets: `.env`, the encrypted `system_settings` columns, the
  provider API key stored with a source account (`source_accounts.api_key_encrypted`),
  TOTP secrets, connector token storage (only digests are stored), logs, and API
  error messages.
- Server-side request forgery and data exfiltration through connector
  configuration or monitored asset values.
- Integrity of the audit trail: anything that lets a security-relevant action
  happen without a corresponding audit record, or forge one.

## Out of scope

- Findings that a monitored asset appears in a third-party data set. Those are
  the product's output, not a vulnerability.
- Missing hardening headers on endpoints that are not meant to be browser-facing
  (the connector protocol uses its own credential, not cookies).
- Denial of service through ordinary high request volume from an authenticated
  account: the platform bounds this by design (per-account request limits,
  bounded outbound probes, connection pooling). A bypass of those bounds *is* in
  scope.
- Vulnerabilities in third-party dependencies that are already published and
  tracked by Dependabot; report those upstream, but tell us if a shipped
  dependency is affected in a way Dependabot cannot see.
- Anything that requires an administrator to run untrusted code on the host.

## Supported versions

The current checkout declares `0.2.0`; this local version bump is not a
published release. `main` is the supported development branch. Fixes are
published on `main`, and reports against older commits may be answered with
"please retry on `main`".

## What to expect

- Acknowledgement of the report: within 3 business days.
- An initial assessment (in scope, severity, planned fix): within 10 business days.
- A fix or a documented mitigation: target 30 days for high severity, longer for
  lower severity, and we will tell you when a fix ships so you can coordinate
  disclosure.

We are happy to credit reporters in the advisory and in the repository, unless
you prefer to stay anonymous.

## If you find a leaked credential

The repository ignores `.env`, generated reports, databases, caches and local
Compose overrides (see `.gitignore`). If a real credential — provider API key,
JWT or Fernet key, connector token, PostgreSQL password — is ever exposed, treat
it as compromised: report it privately as above, and rotate it.

Rotation is a documented procedure rather than an emergency, in
[`docs/upgrading.md`](docs/upgrading.md#rotating-secrets):

- `ENCRYPTION_KEY` — the key protects the four alert columns it encrypts in
  `system_settings`, the provider API key of every source account
  (`source_accounts.api_key_encrypted`) and the TOTP secret of every enrolled
  account (`users.totp_secret`). Put the new key first, list the old one in
  `ENCRYPTION_PREVIOUS_KEYS`, then re-encrypt and verify with
  `python -m scripts.rotate_keys rewrap` / `status`. Those two cover all three
  families, the enrolled authenticators included, so `status` is what tells you
  whether a previous key can still be withdrawn. Dropping a key a value was
  written with makes that value undecryptable — a second factor is then refused
  rather than silently accepted, and `manage_admin mfa-off` plus a fresh
  enrolment is the way back.
- `JWT_SECRET_KEY` — list the old secret in `JWT_PREVIOUS_SECRET_KEYS` so
  existing sessions survive, and remove it to withdraw the tokens signed with it.
- Connector tokens — one connector at a time, through
  `python -m scripts.manage_connector_tokens rotate <name>`.

## Base images and dependency pins

Two different things are pinned here, and it is worth being precise about which.

**Python and npm dependencies are pinned exactly and verified by hash.**
`backend/requirements.txt` and the connector manifests carry `name==version` for
every direct *and* transitive dependency, each with the `--hash=sha256:` digests
of every artifact the index publishes for that version; the images install them
with `pip install --require-hashes`, so a substituted package fails the build
instead of being installed quietly. The frontend is locked by
`frontend/package-lock.json` and built with `npm ci`. Regenerate a lock with
`python scripts/lock_requirements.py <file>`, check one without writing it with
`--check`, and note that `scripts/check_dependency_sources.py` fails a shipped
pin that carries no hash — `backend/requirements-dev.txt` is pinned to exact
versions and deliberately carries no digests, because no image installs it.

**Base images are moving tags, deliberately.** The Dockerfiles use
`python:3.12-slim`, `node:20-alpine` and `nginx:1.29.8-alpine3.23`, and
`docker-compose.yml` names `postgres:17-alpine` and `redis:7-alpine`. A `-slim`
or `-alpine` tag moves when upstream republishes it, so rebuilding from the same
commit can pick up a new upstream patch. What compensates for that:

- the `security` job fails the build on a known vulnerability in the shipped
  dependency sets (`pip-audit`, `npm audit --omit=dev`);
- Dependabot raises base-image updates for the Dockerfiles (`docker` for
  `/backend`, `/frontend` and five of the six connectors —
  `connectors/exposure_endpoints/Dockerfile` is the one it does not watch, so that
  base image is refreshed by hand);
- an image scan sees the packages the image really contains, which is why pip's
  vendored SBOM is removed from the runtime image.

Dependabot's `docker` ecosystem reads Dockerfiles, not Compose files, so the two
images Compose names directly are refreshed by hand:

```text
docker pull postgres:17-alpine
docker inspect --format '{{index .RepoDigests 0}}' postgres:17-alpine
```

To pin an image to a digest instead of a tag — the trade is a manual step on
every upstream patch — replace the tag with the digest that command prints, in
every file that names the image; a tag and a digest for the same release drift
apart otherwise.
