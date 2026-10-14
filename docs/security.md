# Security model

What this page is for: to state the trust boundary once, so that a control is never
described as stronger than it is. The deployment's secret store is the `.env` file on
the Docker host — nothing else holds a secret, and anything that can read that file
has already won. Everything inside the Compose file set is **one** trust domain:
`docker compose exec` into any container reaches the same network as the API, and the
database credentials in the API's environment are the platform's. Connector containers
are the exception by design, and they are the reason the network is split: a connector
is code this platform did not write, and it is given a token, not a database login.

Layers of configuration — which setting lives in `.env`, in the UI, or in a connector's
own `.env` — are in [configuration.md](configuration.md). The deployment procedure that
turns this page into a running installation is in [deployment.md](deployment.md).

## Enforced by default

**Containers run with the kernel's help, not with root privileges.** The services that
run the platform's own code (API, worker, scheduler, connectors, archiver) carry
`security_opt: no-new-privileges`, `cap_drop: [ALL]` and, where they do not need to
write to their own filesystem, `read_only: true` with explicit `tmpfs` mounts for the
paths each one writes (nginx's cache and pid file, the rendered HSTS include, the
connector liveness file). The datastores and the web server carry the same
`no-new-privileges`/`cap_drop` treatment, and the web server is read-only as well.
`docker-compose.yml` is the source of truth for which service carries which of these —
read the service block before assuming a control is on, because a missing line is
invisible at runtime.

**Images are not root.** The API, the worker, the scheduler and the connectors run as
an unprivileged user (`opendrp`, and uid `10001` in the connector images). Generated
report PDFs land in a shared `reports_store` volume created with mode `0700` and owned
by that user, so one container's rendering cannot be read by another service that has
no business reading it.

**The network is split three ways, and the split is the connector sandbox.**
`opendrp-edge` carries the browser-facing nginx and the API. `opendrp-net` carries
PostgreSQL, Redis and the processes that use them. `opendrp-connectors` carries only
the connectors and the API — a connector has no route to a datastore, whatever it does
with the token it was issued. The four subnets are named in `.env`, and the application
refuses to start if a network lies outside the parent range: the failure that would
otherwise be silent is every audit row recording nginx's address instead of the
client's.

**Redis is authenticated, because it is not "just a cache".** It holds the Celery
broker, the rate-limit counters and the scan leases, so a process that can reach it can
push work the worker executes with the platform's own database credentials. The broker
password is required by the Compose configuration, and `scripts/check_compose_healthchecks.py`
fails a build whose `REDIS_URL` has no password — a password no client sends is
decoration.

**Secrets live in the environment, and only there.** Provider API keys are never
stored in the core settings table; they are read from the connector-scoped names in
`.env` (`SHODAN_*`, `HIBP_*`, `DNSTWIST_*`, the intelligence providers). Secrets an
operator enters in the UI (SMTP password, Telegram token) are encrypted at rest with
`ENCRYPTION_KEY` via `MultiFernet`, and sender and recipient addresses are masked in
API responses. Rotation is a three-step, reversible procedure — new key first, old key
in `ENCRYPTION_PREVIOUS_KEYS`, `python -m scripts.rotate_keys rewrap`, then drop the old
key once `status` reports nothing depends on it ([upgrading.md](upgrading.md)). A value
that is not a valid Fernet key is a startup failure in every environment: a derived key
cannot read what the real key wrote, and tolerating the typo turns "the stored secrets
became unreadable" into a mystery.

**Connector credentials are digests.** A connector token is issued by the core and
stored only as a digest; the connector name reported back is a diagnostic hint, and
only the stored digest authorizes anything. The core logs every refusal, which is what
makes a mis-keyed connector findable:

```bash
docker compose logs --tail=50 backend | grep connector_credential_rejected
```

**Sessions are cookie-bound and MFA is available.** `AUTH_COOKIE_SECURE=true` is
required in production, the refresh cookie is not sent over plain HTTP, and
`REQUIRE_MFA_FOR_ADMINS` turns the second factor from a feature into a gate
(`MFA_ISSUER` names the enrolment key so two installations are distinguishable).

**Every important event is auditable, and the audit trail is tamper-evident.** Audit
rows are written as JSON with the five fields the SIEM contract names (`timestamp`,
`user_id`, `action`, `ip_address`, `details`) to both stdout and `drp_audit_logs`, and
each row is chained with HMAC keys from `AUDIT_CHAIN_KEYS`. `make verify-audit-chain`
re-verifies the chain, and the chain is *detect-only*: it makes tampering evident, it
does not prevent it — see the accepted risks below.

**Rate limiting has three layers, and the outermost one is in this repository.** Login
attempts are bounded per IP (`app/core/rate_limit.py`), manual actions per user and
scope (`app/core/manual_rate_limit.py`, from `users.rate_limit_minutes`), and
authenticated request volume per account (`app/core/request_rate_limit.py`, from
`AUTHENTICATED_RATE_LIMIT_PER_MINUTE`). All three are **fail-open** on a Redis outage,
by their own design, on the grounds that locking every operator out is worse than
losing the throttle for the duration; that is why the nginx edge limits in
`docker/nginx/` exist as the bound that does not depend on Redis. The values are
recorded in [configuration.md](configuration.md).

**HSTS is off until an operator turns it on.** Both the API and the UI's nginx read the
same `HSTS_ENABLED` / `HSTS_MAX_AGE` / `HSTS_INCLUDE_SUBDOMAINS`, so the header cannot
disagree with itself depending on which service answered. The default is off because
the promise cannot be withdrawn early: an internal installation with a self-signed
certificate would become unreachable for every browser that had already seen it.

**Container logs are bounded.** The `x-logging` anchor in `docker-compose.yml` caps
each container at 10 MB × 5 files. That bound is a debugging convenience, not a
retention policy — durable audit history belongs in the collector and the SIEM
([observability.md](observability.md)).

## What the operator must verify after deploying

The repository ships the controls above; it cannot ship the ones that depend on the
host around it. Check these before considering an installation production-ready.

1. **A TLS terminator, and its address in `TRUSTED_PROXY_IPS`.** The API resolves the
   client address itself, walking `X-Forwarded-For` from the right and believing only
   addresses in `TRUSTED_PROXY_IPS`. Compose appends this deployment's own subnet
   automatically; add any *additional* proxy range by hand. A proxy that sets no such
   header — or one whose address is not listed — gives every audit row the proxy's
   address instead of the user's, which is a quiet, permanent loss of evidence.
   `docker/nginx/reverse-proxy.example.conf` is a working configuration for that role.
2. **Ports published on loopback** unless a proxy on another host has to reach them.
   `FRONTEND_PORT`, `BACKEND_PORT`, `POSTGRES_PORT` and `REDIS_PORT` are the *host*
   bindings; the browser origin is `CORS_ORIGINS`, which is the terminator.
3. **`HSTS_ENABLED=true` only once the certificate in front of the host is one your
   users' browsers already trust**, and never while the installation is still served
   under two origins.
4. **Alert secrets entered in Settings, provider keys only in `.env`.** Neither belongs
   in the other place: a provider key in the settings table is a key the UI can be made
   to reveal, and an SMTP password in `.env` is one the UI cannot rotate.
5. **One connector token per connector and module** (`make connector-token NAME=… TYPE=…`).
   A token pasted into the wrong `CONNECTOR_TOKEN_*` variable looks exactly like a
   connector that is not running.
6. **`make verify-audit-chain`, with stdout shipped to the SIEM.** The SIEM's copy of
   that stream is the independent witness: `verify_audit_chain --ndjson FILE=` re-checks
   an exported stream against the chain, which is why the two belong in different
   accounts ([README.md](../README.md#operations)).
7. **Backups: run, verify, copy off the host, and encrypt them at rest.** Encryption is
   the operator's responsibility and the archive contains the audit table and the
   encrypted settings ([backup-restore.md](backup-restore.md)).
8. **Key rotation on a schedule** — `JWT_SECRET_KEY`, `ENCRYPTION_KEY` and
   `AUDIT_CHAIN_KEYS` each keep previous values so that rotation is reversible.
9. **No placeholders left.** `python setup.py --check` reports a documented key your
   file lacks, a key your file has that the template never documents, a leftover
   `REPLACE_WITH_…`, and the production rules the application enforces at startup.
10. **Resource limits against the set you enabled.** The limits in
    `docker-compose.yml` are per service and are *caps*; the sum across the services and
    profiles you actually run is the number that has to fit on the host
    ([configuration.md](configuration.md)).

## Accepted risks, and what bounds each one

| Risk | What bounds it |
|---|---|
| Rate limits fail open when Redis is unavailable. | The nginx edge limits in `docker/nginx/` do not depend on Redis, and every block is recorded in the audit trail (the first rejection of each window, so the audit write cannot itself become the amplification). |
| Secrets are visible to anything that can run `docker inspect`. Docker secrets are deliberately not used. | The host `.env` file and access to the Docker socket *are* the trust boundary; the residual is stated rather than hidden, and the Compose comments say so where the secret is declared. |
| The audit chain is detect-only. | Verification (`make verify-audit-chain`) plus the SIEM's copy of the stdout stream in a different account. It makes an insider with database access pay for tampering; it does not stop one. |
| One Redis holds the broker, the counters and the scan leases, and persistence is deliberately disabled. | A restart loses in-flight tasks and counters rather than restoring a half-written queue; findings are durable in PostgreSQL *before* delivery, and the scheduler re-creates the periodic work, so the backlog is delivered once Redis, `celery-beat` and `celery-worker-alerts` are back. |
| `dnstwist` is a distribution package whose CLI the connector parses (JSON fields, fuzzer vocabulary, resolved-address dictionary). | The package is pinned to an exact Debian version in `connectors/dnstwist/Dockerfile`, and to the same one in `backend/Dockerfile`, so a base image whose archive serves another release fails the build. The connector also checks `dnstwist --version` at startup and exits non-zero — with both versions and the fix in the line — if it is not the release it was written against (`_EXPECTED_DNSTWIST_VERSION`; `backend/tests/test_dnstwist_cli_version.py`). A version change is therefore a deliberate edit in this repository rather than something that arrives silently and shows up as fewer findings. |
| No WAF, no external load balancer, no HA: single PostgreSQL, single Redis, one scheduler, a local report store. | Documented as limitations with dates in [production-readiness.md](production-readiness.md), and the exposed surface is bounded by the terminator, the loopback bindings and the edge limits. An installation that needs HA replaces those components rather than scaling containers. |

## Where the numbers live

- Resource limits and the database connection budget: [configuration.md](configuration.md).
- Log sinks, the audit line contract and SIEM delivery: [observability.md](observability.md).
- What to do when a service will not become healthy: [README.md](../README.md#operations).
- Backup, restore and retention: [backup-restore.md](backup-restore.md).
- Upgrades, key rotation and the two-replica proof: [upgrading.md](upgrading.md).
