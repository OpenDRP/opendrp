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
- Disclosure of secrets: `.env`, encrypted `system_settings` columns, connector
  token storage (only digests are stored), logs, and API error messages.
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

The initial public source snapshot is `v0.1.0`; the `v0.1.1` patch is being
prepared and is not yet a published release. `main` is the supported development
branch. Fixes are published on `main`, and reports against older commits may be
answered with "please retry on `main`".

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

- `ENCRYPTION_KEY` — put the new key first, list the old one in
  `ENCRYPTION_PREVIOUS_KEYS`, then re-encrypt and verify with
  `python -m scripts.rotate_keys rewrap` / `status`. Nothing becomes unreadable in
  the meantime.
- `JWT_SECRET_KEY` — list the old secret in `JWT_PREVIOUS_SECRET_KEYS` so
  existing sessions survive, and remove it to withdraw the tokens signed with it.
- Connector tokens — one connector at a time, through
  `python -m scripts.manage_connector_tokens rotate <name>`.
