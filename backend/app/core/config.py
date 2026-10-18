import base64
import secrets
from typing import Any, List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_JWT_SECRET = "change-me-in-production-please-very-long-key"
_DEFAULT_ENCRYPTION_KEY = "Z0FBQUFBQm1hbmRvbV9rZXlfZm9yX2ZlbmNyeXB0aW9uXzMyYnl0ZXM="
# Algorithms the platform will sign and accept. Symmetric HS* only: the same
# ``JWT_SECRET_KEY`` verifies the token, so nothing outside this set may ever be
# honoured (``none`` would accept unsigned tokens; an asymmetric identifier
# would let a public key be used as an HMAC secret).
JWT_ALGORITHMS_ALLOWED = frozenset({"HS256", "HS384", "HS512"})

#: What ``ALERT_BREACH_NOISE_POLICY`` accepts, as one list rather than a rule in two
#: places. It lives here instead of beside :mod:`app.services.alert_policy` because
#: the schema below validates it while this module is still importing, and a module
#: that reads ``settings`` cannot be imported from that point; the policy module
#: imports this name the other way round.
BREACH_NOISE_POLICIES: tuple[str, ...] = ("store_only_spam", "verified_only", "all")

_INSECURE_SECRET_MARKERS = (
    "changethis",
    "change-me",
    "replace_with",
    "replace-me",
    "yourstrong",
    "password123",
    "example-secret",
)


def _looks_like_shipped_secret(value: str | None) -> bool:
    normalized = (value or "").strip().lower()
    return not normalized or any(marker in normalized for marker in _INSECURE_SECRET_MARKERS)


def _is_production_env() -> bool:
    import os
    return os.environ.get("APP_ENV", "development").lower() == "production"


def _parse_cors_origins(v: Any) -> List[str]:
    import json

    if v is None:
        return ["http://localhost:3000"]
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]

    if isinstance(v, tuple):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return ["http://localhost:3000"]
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
            if isinstance(parsed, str):
                s = parsed.strip()
        except Exception:
            pass
        return [i.strip() for i in s.split(",") if i.strip()]
    return ["http://localhost:3000"]


def _development_jwt_secret() -> str:
    return secrets.token_urlsafe(48)


def _development_encryption_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    DATABASE_URL: str = Field(
        default="postgresql://opendrp:opendrp@localhost:5432/opendrp"
    )
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    # Development defaults are generated per process rather than compiled into
    # the repository. Production still requires an explicit environment value.
    JWT_SECRET_KEY: str = Field(default_factory=_development_jwt_secret)
    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15)
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=3)
    # Always true for an installation. A browser only sends a Secure cookie over
    # HTTPS, and the one exception - `localhost`, which every browser treats as a
    # trustworthy origin - is what keeps http://localhost:3000 usable for checking
    # a deployment on the machine that runs it.
    AUTH_COOKIE_SECURE: bool = Field(default=True)
    #: `Strict-Transport-Security`, in the three pieces an operator can reason
    #: about. Off by default, and that default is the point: the header is a
    #: promise a browser keeps for HSTS_MAX_AGE seconds and cannot be withdrawn
    #: early - withdrawing it needs an HTTPS response, which is exactly what is
    #: unavailable while a certificate is expired or replaced by a self-signed
    #: one. The installations that need it off most (internal, self-signed,
    #: certificate replaced more often than a year) are therefore the ones that
    #: must not get it by accident. Both this API and the frontend's nginx read
    #: these values, so the header cannot disagree with itself depending on which
    #: of them answered the request.
    HSTS_ENABLED: bool = Field(default=False)
    #: One year, the value preload lists require.
    HSTS_MAX_AGE: int = Field(default=31536000)
    #: Also applies the header to subdomains, which is a promise about hosts this
    #: deployment does not control.
    HSTS_INCLUDE_SUBDOMAINS: bool = Field(default=False)
    # Bound on how many authenticated requests one account may make per minute.
    # Generous for a human driving the UI (a page view costs a handful of
    # requests) while still bounding a runaway client, which is what protects
    # the audit pipeline from amplifying one credential. 0 disables the check.
    # See app/core/request_rate_limit.py.
    AUTHENTICATED_RATE_LIMIT_PER_MINUTE: int = Field(default=600, ge=0)
    APP_ENV: str = Field(default="development")
    # Pinned image/release identifier. Production deployments must provide a
    # semantic version rather than the moving `latest` tag.
    OPENDRP_VERSION: str = Field(default="")
    DNS_EXPIRY_MAX_AGE_HOURS: int = Field(default=48, ge=1, le=720)
    #: Minimum level for platform log records. Audit events ignore it: they are
    #: records rather than diagnostics, and no level setting may be able to stop
    #: the platform recording who deleted an asset. See core/logging_config.py.
    LOG_LEVEL: str = Field(default="INFO")
    CORS_ORIGINS: Any = Field(default_factory=lambda: ["http://localhost:3000"])
    ENCRYPTION_KEY: str = Field(default_factory=_development_encryption_key)
    # The `issuer` shown next to the account label in an authenticator app. Set it
    # when one person manages several deployments, so that the entries are not two
    # identical-looking code generators.
    MFA_ISSUER: str = Field(default="OpenDRP")
    # Whether an administrator must have a second factor before reaching admin
    # routes. Off by default: an installation must not be able to lock its own
    # administrator out because a phone was lost, and the account-recovery path
    # is a person with CLI access, not a self-service reset.
    #
    # Enrolled-but-optional is not the same control as required. With the default
    # a stolen administrator password is still sufficient for every admin route,
    # because the attacker simply does not present the code they have not got;
    # this setting is what turns the factor from a feature into a gate. The gate
    # is applied by ``require_admin`` (app/api/deps.py), which refuses admin
    # routes only — ``/auth/mfa/*`` stays reachable so the administrator can fix
    # their own situation, and each refusal is audited as ``auth.mfa.required``.
    REQUIRE_MFA_FOR_ADMINS: bool = Field(default=False)
    # The same policy expressed as a list of roles, because "which accounts owe a
    # factor" is a deployment decision and "administrators only" was only ever one
    # answer to it. Comma-separated role names; an empty value with the flag above
    # false means the factor stays optional for everybody. Both settings are read:
    # the roles here plus `admin` when the flag is set (app/core/mfa_policy.py is
    # the single reader), so enabling the list never silently disables the flag an
    # installation already relies on.
    REQUIRE_MFA_ROLES: str = Field(default="")
    # Keys that may still *decrypt* stored values but no longer encrypt:
    # comma-separated, newest first, and empty outside a rotation. Together with
    # `scripts/rotate_keys` they make replacing `ENCRYPTION_KEY` a procedure that
    # can be completed (and undone) instead of an all-or-nothing event. See
    # docs/upgrading.md, "Rotating secrets".
    ENCRYPTION_PREVIOUS_KEYS: str = Field(default="")
    # The same idea for JWTs, which are signed rather than encrypted. Rotating
    # `JWT_SECRET_KEY` invalidates every issued access and refresh token; listing
    # the old secret here lets existing sessions keep working while the old key is
    # phased out. Remove it once `JWT_REFRESH_TOKEN_EXPIRE_DAYS` has passed and no
    # token signed with it can still be presented.
    JWT_PREVIOUS_SECRET_KEYS: str = Field(default="")
    REPORTS_STORE_DIR: str = Field(default="/workspace/reports_store")

    # Connectors authenticate with per-connector credentials issued by an
    # operator and stored as digests (see services/connector_credentials.py).
    # There is deliberately no platform-wide connector secret: such a value
    # could be replayed as any connector and could not be revoked for one of
    # them alone.
    CONNECTOR_HEALTH_STALE_AFTER_SECONDS: int = Field(default=120, ge=30, le=86400)
    CONNECTOR_JOB_LEASE_SECONDS: int = Field(default=180, ge=30, le=86400)
    CONNECTOR_JOB_MAX_ATTEMPTS: int = Field(default=3, ge=1, le=20)
    ALERT_HEALTH_CHECK_TIMEOUT_SECONDS: int = Field(default=15, ge=1, le=60)
    # How long a channel's probe result is reused before the next health request
    # dials again. The question changes on the scale of minutes, and every miss
    # is a real SMTP handshake held from a pool of four; ``0`` answers every
    # request with a probe, which is what the endpoint did before the cache.
    ALERT_HEALTH_CACHE_SECONDS: int = Field(default=60, ge=0, le=3600)
    # One wall-clock budget for a single provider delivery attempt. It applies
    # consistently to SMTP and Telegram; retries are bounded separately.
    ALERT_DELIVERY_TIMEOUT_SECONDS: float = Field(default=20, ge=1, le=300)
    ALERT_DELIVERY_MAX_ATTEMPTS: int = Field(default=3, ge=1, le=10)
    ALERT_DELIVERY_RETRY_BASE_SECONDS: float = Field(default=2, ge=0.1, le=60)
    # Findings from one connector job wait briefly in the durable queue so the
    # worker can send one summary instead of one message per finding.
    ALERT_RECIPIENT_INTERVAL_SECONDS: float = Field(default=1, ge=0, le=3600)
    # How long a recipient stays held after a delivery whose outcome is unknown
    # (a worker died mid-send, or an SMTP thread timed out). A timed-out thread
    # may still have delivered, so retrying immediately would duplicate the
    # notification; holding forever would silence that recipient for good, which
    # is the failure this setting exists to bound. An operator may end the hold
    # early from the alerts view once they have reconciled the ambiguity.
    ALERT_RECIPIENT_HOLD_SECONDS: int = Field(default=900, ge=60, le=86400)
    AUDIT_ARCHIVE_DIR: str = ""
    AUDIT_RETENTION_HOLD: bool = False
    ALERT_HISTORY_RETENTION_DAYS: int = Field(default=90, ge=0, le=3650)
    #: How long a certificate identity or sighting is kept after it was last observed.
    #: The sighting tables grow with every scan and every provider read, so they need
    #: the same bound the alert history has; 0 disables the sweep.
    TLS_CERTIFICATE_RETENTION_DAYS: int = Field(default=365, ge=0, le=3650)
    ALERT_AGGREGATION_DELAY_SECONDS: int = Field(default=10, ge=0, le=300)
    # The phishing module's alert budget (WI-07): a candidate's confidence score
    # decides how loudly the channel reports it. At or above the direct threshold
    # the candidate alerts as soon as its signals are known; between the two it
    # waits for the daily digest; below the digest threshold it is list-only, which
    # is where most lookalikes belong. The score itself is `Σ weights` computed by
    # app/services/phishing_score_service.py from the facts a candidate was observed
    # with, and the thresholds are settings because how noisy a channel may be is a
    # deployment's policy rather than a fact about a lookalike.
    ALERT_CONFIDENCE_DIRECT: int = Field(default=60, ge=1, le=100)
    ALERT_CONFIDENCE_DIGEST: int = Field(default=30, ge=0, le=99)
    # The daily digest is the middle band's channel: a candidate that is not worth
    # interrupting someone for is still reported once a day, so the channel is
    # neither silent nor noisy. Turning it off makes the budget binary — only
    # candidates at or above the direct threshold are ever delivered, and
    # everything below is list-only — which is a legitimate choice for an
    # installation that wants the safest possible signal in its inbox.
    ALERT_PHISHING_DIGEST_ENABLED: bool = True
    #: The UTC hour the digest runs at, and the only knob that moves it. 06:15 is
    #: deliberately after the default scan slots (02:30 and 03:30) so one message
    #: carries the night's candidates rather than half of them; the quarter hour is
    #: after the 05:30 DNS sweep as well, because both alerts share one queue.
    ALERT_PHISHING_DIGEST_HOUR_UTC: int = Field(default=6, ge=0, le=23)
    # A notification no configured channel can receive is *held*, not consumed:
    # an installation is pointed at a mail server at some point, and the finding
    # recorded before that is still worth reporting then. This is how long the
    # drain waits before it tries such a row again, which is also what keeps a
    # deployment with no channel from re-walking its whole backlog on every pass;
    # the save that makes delivery possible reports what was held as one digest
    # rather than waiting this window out. ``0`` holds nothing — a notification no
    # channel can receive is consumed where it stands, which is what the platform
    # did before this window existed.
    ALERT_NO_CHANNEL_RETRY_HOURS: int = Field(default=24, ge=0, le=8760)
    # A candidate is reported when it is first seen; whether a *revision* of one
    # already reported is a second message is a deployment's choice. On, the
    # channel says so when the thing moves to another address, publishes another
    # port or is re-attributed to another brand — the four fields a connector
    # actually revises on a live candidate (WI-03). Off, the row is still updated
    # and the change is still visible in the list and its evidence; only the
    # message is withheld, which is what an installation whose lookalikes flap on
    # a shared host has asked for.
    ALERT_CANDIDATE_CHANGE_NOTIFICATIONS: bool = True
    # Credential breaches are the one module whose source classifies its own
    # incidents, and two of those classes are not evidence a credential leaked:
    # ``IsSpamList`` and ``IsFabricated`` are the provider saying so itself. This
    # decides what the channel does with them. ``store_only_spam`` (the default)
    # keeps the row - it is still visible in the list, with its flag - and sends no
    # message; ``verified_only`` also silences an incident the source has not
    # confirmed; ``all`` reports everything, which is what the platform did before
    # this decision existed. Silence always needs a positive flag to act on: an
    # incident whose flags never arrived is reported rather than assumed clean.
    ALERT_BREACH_NOISE_POLICY: str = "store_only_spam"
    # A scan that finds a hundred new incidents is a backlog, not a report: past
    # this many new incidents in one scan, the scan's remaining notifications wait
    # for the daily digest instead of arriving as separate messages. The hour is
    # the phishing digest's (``ALERT_PHISHING_DIGEST_HOUR_UTC``), so an
    # installation has one "summary hour" rather than two. ``0`` switches the
    # deferral off and restores one message per scan.
    ALERT_BREACH_DIGEST_THRESHOLD: int = Field(default=20, ge=0, le=500)
    # An incident that was already reported is reported again only when it says
    # something new (WI-08): the classes of data grew, the row came back after being
    # resolved, or the number of affected accounts rose by at least this much. The
    # floor exists because a source re-publishes an incident's count as it refines
    # it - a correction of three accounts out of ten million is not news, and an
    # installation that alerted on every such edit would be alerting on the source's
    # bookkeeping.
    ALERT_BREACH_GROWTH_FLOOR: int = Field(default=1, ge=1, le=1000000000)
    ALERT_MAX_FINDINGS_PER_MESSAGE: int = Field(default=50, ge=1, le=500)
    ALERT_MAX_TELEGRAM_MESSAGE_LENGTH: int = Field(default=3800, ge=500, le=4096)
    OUTBOUND_DNS_TIMEOUT_SECONDS: float = Field(default=3.0, ge=1, le=30)
    REPORT_MAX_ROWS: int = Field(default=5000, ge=100, le=50000)
    REPORT_GENERATION_TIMEOUT_SECONDS: int = Field(default=120, ge=10, le=1800)
    REPORT_QUEUE_MAX_PENDING: int = Field(default=100, ge=1, le=10000)
    REPORT_ENQUEUE_MAX_RETRIES: int = Field(default=2, ge=0, le=10)
    REPORT_WORKER_CONCURRENCY: int = Field(default=2, ge=1, le=32)

    # Data retention. An audit table that receives a row per read is the fastest
    # growing object in the schema, and generated reports accumulate on disk
    # next to it. Both are swept nightly by ``purge_expired_data``
    # (app/tasks/retention_tasks.py).
    #
    # The audit trail is evidence, so the default keeps a year rather than the
    # shortest defensible window. ``0`` disables the sweep and keeps history
    # forever — legitimate for an append-only archive, but it must be a
    # deliberate choice: it is the setting that eventually fills the volume.
    # Retention applies to the *database* copy only. What reaches the log
    # pipeline is governed by the collector, not by this process.
    AUDIT_RETENTION_DAYS: int = Field(default=365, ge=0, le=3650)
    REPORT_RETENTION_DAYS: int = Field(default=365, ge=0, le=3650)
    # Bounded work per run: the sweep deletes in batches so a multi-million-row
    # table does not hold one long transaction (which would block vacuum and
    # bloat the WAL). The caps keep a nightly run predictable in duration.
    RETENTION_BATCH_SIZE: int = Field(default=5000, ge=100, le=100000)
    RETENTION_MAX_BATCHES_PER_RUN: int = Field(default=200, ge=1, le=100000)

    DB_POOL_SIZE: int = Field(default=20, ge=1, le=200)
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0, le=100)
    DB_POOL_RECYCLE_SECONDS: int = Field(default=1800, ge=60, le=86400)
    DB_POOL_TIMEOUT_SECONDS: int = Field(default=30, ge=5, le=300)
    DB_POOL_USE_LIFO: bool = Field(default=True)

    # --- Statement limits ---------------------------------------------------------
    # The pool is bounded (DB_POOL_SIZE + DB_MAX_OVERFLOW), so an unbounded query
    # does not slow one request down: it removes a connection from everyone else
    # until it finishes. One authenticated account could therefore take the whole
    # platform down with a handful of requests against a large inventory — and
    # would do it accidentally, with a filter that stops matching an index.
    #
    # PostgreSQL enforces these server-side, per connection:
    #
    # * ``statement_timeout`` — a single statement may not run longer than this.
    #   0 disables the bound; raise it for a large inventory rather than removing
    #   it, and note that report generation is the statement most likely to need it.
    # * ``lock_timeout`` — a statement waiting on a lock gives up instead of
    #   queueing every later writer behind it (what an operator's migration looks
    #   like from inside the application).
    # * ``idle_in_transaction_session_timeout`` — a connection left inside an open
    #   transaction stops holding its snapshot and its locks.
    DB_STATEMENT_TIMEOUT_MS: int = Field(default=30000, ge=0, le=3600000)
    DB_LOCK_TIMEOUT_MS: int = Field(default=5000, ge=0, le=3600000)
    DB_IDLE_IN_TRANSACTION_TIMEOUT_MS: int = Field(default=60000, ge=0, le=86400000)
    #: Client-side bound on one command round trip, deliberately *above*
    #: ``DB_STATEMENT_TIMEOUT_MS``: the server should be the one to cancel a slow
    #: statement, because a Postgres cancellation is an error the application can
    #: report as a busy database, while a client-side timeout is an abrupt
    #: disconnect that looks like a network fault.
    DB_COMMAND_TIMEOUT_SECONDS: float = Field(default=45, ge=0, le=3600)
    #: Shows up in ``pg_stat_activity``, which is how an operator finds out which
    #: container is holding the pool when the API is slow.
    DB_APPLICATION_NAME: str = Field(default="opendrp")

    # --- Limits a schema migration runs under -------------------------------------
    # A migration is the one process that changes the schema while the platform is
    # still serving, so it is also the one most likely to wait on a lock: an
    # ``ALTER TABLE`` behind an open transaction, or the baseline's index builds,
    # which wait for every writer to finish. Without a bound that wait is invisible
    # — the API container is simply unhealthy while `scripts.migrate` blocks, and
    # the log names nothing — which is what these two settings close.
    #
    # They are deliberately *not* ``DB_LOCK_TIMEOUT_MS``/``DB_STATEMENT_TIMEOUT_MS``:
    # the application's 5s lock bound is right for a request and wrong for an
    # upgrade, and its 30s statement bound would fail the documented maintenance
    # window on a populated database, where building the index families is the
    # longest statement this platform ever runs.
    #: How long a migration waits for a lock before failing with PostgreSQL's
    #: ``lock_timeout`` error, which names the wait instead of looking like a hang.
    #: 0 waits forever, which is what the bound exists to replace.
    MIGRATION_LOCK_TIMEOUT_MS: int = Field(default=30000, ge=0, le=3600000)
    #: How long one migration statement may run. 0 (the default) leaves it
    #: unbounded on purpose: the index build in `docs/upgrading.md`'s maintenance
    #: window is legitimate work, and an operator who wants it bounded sets this.
    MIGRATION_STATEMENT_TIMEOUT_MS: int = Field(default=0, ge=0, le=86400000)

    # --- Metrics -------------------------------------------------------------------
    # The scrape token for `GET /api/v1/metrics`, presented as `X-Metrics-Token`.
    # Empty — the default — means the endpoint does not exist: it answers 404, and
    # nothing about the installation's backlog, connectors or audit position is
    # published to whoever asks. Set it to enable scraping; the value is a
    # credential like any other, which is why the production validator below
    # refuses a short or placeholder one. Generate with:
    #   python -c "import secrets; print(secrets.token_urlsafe(32))"
    METRICS_TOKEN: str = Field(default="")

    UVICORN_WORKERS: int = Field(default=1, ge=1, le=32)
    # Never trust forwarded headers from arbitrary clients. In deployments with
    # a reverse proxy, set this to the proxy IP/CIDR explicitly.
    UVICORN_FORWARDED_ALLOW_IPS: str = Field(default="127.0.0.1")
    TRUSTED_PROXY_IPS: str = Field(default="127.0.0.1,::1")

    # --- Deployment address space -------------------------------------------------
    # The Compose stack defines three networks (edge, data, connectors) inside one
    # parent range. Two things depend on these values being consistent: the proxy
    # trust above, which names the parent range so that an audit row records the
    # real client rather than nginx's container address; and the outbound guard,
    # which refuses to dial back into the deployment from an operator-supplied
    # destination such as an SMTP host. The validator below rejects a
    # mis-configuration at startup rather than letting it show up as proxy
    # addresses in the audit trail.
    OPENDRP_NETWORK_SUBNET: str = Field(default="172.18.0.0/16")
    OPENDRP_EDGE_SUBNET: str = Field(default="172.18.10.0/24")
    OPENDRP_DATA_SUBNET: str = Field(default="172.18.20.0/24")
    OPENDRP_CONNECTOR_SUBNET: str = Field(default="172.18.30.0/24")

    # --- Outbound destination policy ------------------------------------------------
    # Comma-separated hostnames or CIDRs that may be connected to even when the
    # destination is inside a blocked range. The default block list (see
    # app/core/outbound.py) covers loopback, link-local/cloud-metadata, multicast
    # and *this deployment's own networks*, while leaving ordinary private ranges
    # usable — an internal mail relay at 10.x is the normal case for a small
    # company, and a guard that breaks alert email is a guard that gets disabled.
    # Use this list for the exceptions: a relay on the deployment network, an
    # on-prem WHOIS server.
    OUTBOUND_ALLOWED_HOSTS: str = Field(default="")
    # Extra ranges to refuse, on top of the built-in ones. Only ever additive: an
    # entry here cannot widen the policy, which is what keeps the built-in list
    # from being edited away by a deployment that meant to add one range.
    OUTBOUND_BLOCKED_CIDRS: str = Field(default="")

    # --- Audit tamper-evidence ------------------------------------------------------
    # The audit trail is hash-chained: every row carries an HMAC over its own five
    # fields plus the previous row's hash, so an edit, a deletion or an insertion
    # anywhere in the history is detectable by recomputing the chain. The key is
    # the difference between "hard to change without noticing" and "easy to
    # recompute after changing": it lives in the environment, not in the database
    # the chain protects.
    #
    # Comma-separated, newest first — the first entry signs, the rest only verify,
    # exactly like ENCRYPTION_KEY / ENCRYPTION_PREVIOUS_KEYS. Without a key here a
    # development deployment derives one from ENCRYPTION_KEY so that the chain is
    # always on; production requires an explicit value (see the validator below),
    # because a derived key silently stops verifying the moment ENCRYPTION_KEY is
    # rotated. Generate one with:
    #   python -c "import secrets; print(secrets.token_urlsafe(48))"
    AUDIT_CHAIN_KEYS: str = Field(default="")
    #: Keys that may still verify older entries but never sign new ones.
    AUDIT_CHAIN_PREVIOUS_KEYS: str = Field(default="")

    def encryption_previous_keys(self) -> List[str]:
        """The rotation-era keys, parsed once per call and stripped of blanks."""
        return [item.strip() for item in (self.ENCRYPTION_PREVIOUS_KEYS or "").split(",") if item.strip()]

    def jwt_verification_keys(self) -> List[str]:
        """Secrets a presented token may be verified against, newest first.

        Ordering matters only for which key is *tried* first; all of them are
        accepted. Empty entries are dropped so a stray trailing comma cannot
        become a verification attempt against "".
        """
        keys = [self.JWT_SECRET_KEY]
        keys.extend(
            item.strip()
            for item in (self.JWT_PREVIOUS_SECRET_KEYS or "").split(",")
            if item.strip()
        )
        return keys

    @field_validator("REQUIRE_MFA_ROLES")
    @classmethod
    def _validate_mfa_roles(cls, value: str) -> str:
        """Refuse a role name this platform does not have.

        A typo here is silent in the worst direction: the policy would require
        nothing, every account would sail past the gate, and the operator would
        believe the deployment demands a second factor. The names are the members
        of ``UserRole`` (``app/models/user.py``); they are repeated here because
        that module imports this one, and ``tests/test_mfa.py`` keeps the two in
        step by requiring every member to be accepted.
        """
        known = {"admin", "analyst", "viewer"}
        names = [item.strip().lower() for item in (value or "").split(",") if item.strip()]
        unknown = sorted({name for name in names if name not in known})
        if unknown:
            raise ValueError(
                f"REQUIRE_MFA_ROLES names unknown roles: {', '.join(unknown)} "
                f"(known: {', '.join(sorted(known))})"
            )
        return ",".join(names)

    @field_validator("TRUSTED_PROXY_IPS", "UVICORN_FORWARDED_ALLOW_IPS")
    @classmethod
    def _validate_proxy_allowlist(cls, value: str, info) -> str:
        import ipaddress

        raw = str(value or "").strip()
        if not raw:
            return raw
        if info.field_name == "UVICORN_FORWARDED_ALLOW_IPS" and raw == "*":
            raise ValueError("forwarded proxy allowlist must not be '*'")
        for item in raw.split(","):
            candidate = item.strip()
            if not candidate:
                raise ValueError(f"{info.field_name} contains an empty entry")
            if candidate == "*":
                raise ValueError(f"{info.field_name} must contain only IPs or CIDRs")
            try:
                ipaddress.ip_network(candidate, strict=False)
            except ValueError as exc:
                raise ValueError(f"{info.field_name} contains invalid IP/CIDR: {candidate}") from exc
        return raw

    @model_validator(mode="after")
    def _validate_alert_confidence_bands(self):
        """A digest threshold at or above the direct one leaves no middle band.

        `ALERT_CONFIDENCE_DIGEST = ALERT_CONFIDENCE_DIRECT` reads as "digest
        everything from 60 up", and is indistinguishable from switching the digest
        off: every score that would have been digested alerts immediately instead,
        so the feature looks configured while doing nothing. Clamping one value to
        the other would decide for the operator which of the two they meant; the
        pair is refused at startup instead, which names the setting to fix.
        """
        if self.ALERT_CONFIDENCE_DIGEST >= self.ALERT_CONFIDENCE_DIRECT:
            raise ValueError(
                "ALERT_CONFIDENCE_DIGEST must be below ALERT_CONFIDENCE_DIRECT: "
                f"got {self.ALERT_CONFIDENCE_DIGEST} and "
                f"{self.ALERT_CONFIDENCE_DIRECT}, which leaves no digest band"
            )
        return self

    @model_validator(mode="after")
    def _validate_breach_noise_policy(self):
        """An unrecognised policy would silently mean "report everything".

        The value decides whether a spam or fabricated incident reaches the channel,
        so a typo has to fail at startup rather than fall through to the loudest
        branch: an operator who wrote ``store-only-spam`` asked for silence and must
        not get the opposite while the setting looks configured.
        """
        if self.ALERT_BREACH_NOISE_POLICY not in BREACH_NOISE_POLICIES:
            raise ValueError(
                "ALERT_BREACH_NOISE_POLICY must be one of "
                f"{', '.join(BREACH_NOISE_POLICIES)}: got {self.ALERT_BREACH_NOISE_POLICY!r}"
            )
        return self

    @model_validator(mode="after")
    def _validate_hsts(self):
        """`HSTS_ENABLED=true` with a zero interval is a contradiction, not a policy.

        `max-age=0` is how a server tells a browser to *forget* HSTS, so a header
        with that interval does the opposite of what the setting that produced it
        is called. Clamping it to a default would decide for the operator which of
        the two they meant; refusing it at startup says which line to look at.
        """
        if self.HSTS_ENABLED and self.HSTS_MAX_AGE <= 0:
            raise ValueError(
                "HSTS_MAX_AGE must be a positive number of seconds when "
                "HSTS_ENABLED is true (max-age=0 means 'forget HSTS'); set "
                "HSTS_ENABLED=false to send no header at all"
            )
        return self

    @property
    def hsts_header_value(self) -> str:
        """The `Strict-Transport-Security` value, or an empty string when off.

        One place builds it, so the API's middleware and anything else that needs
        the header cannot produce a second spelling of the same promise.
        """
        if not self.HSTS_ENABLED:
            return ""
        value = f"max-age={self.HSTS_MAX_AGE}"
        if self.HSTS_INCLUDE_SUBDOMAINS:
            value = f"{value}; includeSubDomains"
        return value

    @property
    def audit_chain_keys(self) -> List[str]:
        """Signing keys for the audit chain, newest first.

        A development deployment with nothing configured derives one from
        ``ENCRYPTION_KEY`` so that the chain is exercised everywhere rather than
        being a feature only production sees — a code path that never runs in the
        test suite is a code path nobody has looked at. Production refuses to
        start without an explicit key, so the derivation can never be the thing
        protecting real audit history.
        """
        import hashlib
        import hmac as _hmac

        configured = [
            part.strip()
            for part in f"{self.AUDIT_CHAIN_KEYS},{self.AUDIT_CHAIN_PREVIOUS_KEYS}".split(",")
            if part.strip()
        ]
        if configured:
            return configured
        derived = _hmac.new(
            (self.ENCRYPTION_KEY or "development").encode("utf-8"),
            b"opendrp-audit-chain-v1",
            hashlib.sha256,
        ).hexdigest()
        return [derived]

    @property
    def deployment_networks(self) -> tuple:
        """Address ranges that belong to this deployment, as ``ip_network`` values.

        Read by the outbound guard. A value the validator could not parse is
        skipped here rather than raising: the validator is what rejects it, with a
        message naming the setting.
        """
        import ipaddress

        networks = []
        for value in (
            self.OPENDRP_NETWORK_SUBNET,
            self.OPENDRP_EDGE_SUBNET,
            self.OPENDRP_DATA_SUBNET,
            self.OPENDRP_CONNECTOR_SUBNET,
        ):
            candidate = str(value or "").strip()
            if not candidate:
                continue
            try:
                networks.append(ipaddress.ip_network(candidate, strict=False))
            except ValueError:
                continue
        return tuple(networks)

    @model_validator(mode="after")
    def _validate_network_ranges(self):
        """The three network subnets must lie inside the parent range.

        Checked in every environment: a development stack whose audit rows name
        the proxy instead of the client is a development stack whose audit trail
        nobody can read, and the check costs one comparison at startup.
        """
        import ipaddress

        try:
            parent = ipaddress.ip_network(self.OPENDRP_NETWORK_SUBNET.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"OPENDRP_NETWORK_SUBNET is not an IP network: {exc}") from exc

        for field_name, value in (
            ("OPENDRP_EDGE_SUBNET", self.OPENDRP_EDGE_SUBNET),
            ("OPENDRP_DATA_SUBNET", self.OPENDRP_DATA_SUBNET),
            ("OPENDRP_CONNECTOR_SUBNET", self.OPENDRP_CONNECTOR_SUBNET),
        ):
            try:
                subnet = ipaddress.ip_network(str(value).strip(), strict=False)
            except ValueError as exc:
                raise ValueError(f"{field_name} is not an IP network: {exc}") from exc
            if not subnet.subnet_of(parent):
                raise ValueError(
                    f"{field_name} ({subnet}) is outside OPENDRP_NETWORK_SUBNET "
                    f"({parent}): nginx would stop being recognised as a trusted "
                    f"proxy and every audit row would record the proxy address. "
                    f"Set OPENDRP_NETWORK_SUBNET and the three subnet variables to "
                    f"one consistent set (see .env.example and docker-compose.yml)."
                )

        # Trusting a network means believing the addresses it puts in
        # ``X-Forwarded-For``, so the trust list may name the edge — the only hop
        # in front of the API — and nothing else of the deployment's own space.
        # The connector network exists precisely to hold code this platform did
        # not write (see docker-compose.yml), and the data network holds the API's
        # own siblings; either one trusted means a container in it can attribute
        # its actions to any address it likes. The parent range is refused for the
        # same reason and because naming it is how the connector subnet starts
        # being trusted by accident, which is the defect this check closes.
        internal: list[tuple[str, object]] = []
        for field_name, value in (
            ("OPENDRP_DATA_SUBNET", self.OPENDRP_DATA_SUBNET),
            ("OPENDRP_CONNECTOR_SUBNET", self.OPENDRP_CONNECTOR_SUBNET),
        ):
            try:
                internal.append(
                    (field_name, ipaddress.ip_network(str(value).strip(), strict=False))
                )
            except ValueError:
                continue  # already reported by the loop above

        for item in str(self.TRUSTED_PROXY_IPS).split(","):
            entry = item.strip()
            if not entry:
                continue
            try:
                trusted = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue  # a single address, or a value `extract_ip` ignores
            for field_name, network in internal:
                try:
                    overlapped = trusted.overlaps(network)  # type: ignore[arg-type]
                except TypeError:  # an IPv4 entry beside an IPv6 range
                    overlapped = False
                if overlapped:
                    raise ValueError(
                        f"TRUSTED_PROXY_IPS contains {trusted}, which covers "
                        f"{field_name} ({network}): a container in that network "
                        f"could then write any address it liked into the audit "
                        f"trail. Trust loopback and OPENDRP_EDGE_SUBNET only."
                    )
            # The parent range is refused when an entry *contains* it. Overlap is
            # the wrong question here: the edge subnet lives inside the parent by
            # design, so the shipped value overlaps it and trusting the edge is
            # the intended configuration.
            try:
                too_broad = trusted.supernet_of(parent)  # type: ignore[arg-type]
            except TypeError:
                too_broad = False
            if too_broad:
                raise ValueError(
                    f"TRUSTED_PROXY_IPS contains {trusted}, which spans "
                    f"OPENDRP_NETWORK_SUBNET ({parent}) and therefore every "
                    f"container in the deployment, connectors included: a "
                    f"container in any of those networks could then write any "
                    f"address it liked into the audit trail. Trust loopback and "
                    f"OPENDRP_EDGE_SUBNET only."
                )
        return self

    @model_validator(mode="after")
    def _validate_production_configuration(self):
        """Fail closed for credentials and proxy settings in production."""
        if self.APP_ENV.lower() != "production":
            return self

        import os
        import re

        # `TESTING` is not a deployment setting: it exists for the test suite and
        # switches two controls off — scan admission (`scan_admission._testing_mode`)
        # and the Redis-backed login lockout and rate limits (`core.rate_limit`).
        # A copied test `.env` or a debugging export would otherwise remove both in
        # production, silently, and nothing in the configuration would say so.
        testing = os.environ.get("TESTING", "").strip().lower()
        if testing and testing not in {"0", "false", "no", "off"}:
            raise ValueError(
                "TESTING must not be set in production: it disables scan admission "
                "and the Redis-backed login lockout, so a leaked test environment "
                "would remove two controls without saying so. Unset TESTING in the "
                "deployment environment, or set it to 0."
            )

        secret_fields = ("JWT_SECRET_KEY", "ENCRYPTION_KEY")
        for field_name in secret_fields:
            value = getattr(self, field_name, None)
            if value in {_DEFAULT_JWT_SECRET, _DEFAULT_ENCRYPTION_KEY} or _looks_like_shipped_secret(value):
                raise ValueError(f"{field_name} must be explicitly configured with a random secret in production")

        # POSTGRES_PASSWORD is not a Settings field; inspect only the parsed
        # password component of the URL and never log it.
        from urllib.parse import unquote, urlsplit

        try:
            database_password = unquote(urlsplit(self.DATABASE_URL).password or "")
        except ValueError as exc:
            raise ValueError("DATABASE_URL is invalid") from exc
        if _looks_like_shipped_secret(database_password) or database_password.lower() == "opendrp":
            raise ValueError("POSTGRES_PASSWORD must be explicitly configured in production")

        if len(self.JWT_SECRET_KEY) < 32:
            raise ValueError("JWT_SECRET_KEY must contain at least 32 characters")

        # A previous key is a live credential for as long as it is listed, so it
        # must meet the same bar as the current one. It is also the value most
        # likely to be pasted in by hand during a rotation, which is why the
        # placeholder check applies here too rather than only to JWT_SECRET_KEY.
        for previous in self.jwt_verification_keys()[1:]:
            if len(previous) < 32:
                raise ValueError(
                    "every key in JWT_PREVIOUS_SECRET_KEYS must contain at least 32 characters"
                )
            if _looks_like_shipped_secret(previous):
                raise ValueError(
                    "JWT_PREVIOUS_SECRET_KEYS must not contain a placeholder value"
                )
        # The broker is not a cache that can be rebuilt: it carries the task
        # payloads and the rate-limit counters, and a process that can publish to
        # it can hand the worker a task to execute with this process's own
        # database credentials. A password that Compose requires but the
        # application never sends would be exactly the kind of protection that
        # exists only in a comment, so the URL is inspected here.
        try:
            redis_parts = urlsplit(self.REDIS_URL or "")
            redis_password = unquote(redis_parts.password or "")
            redis_host = (redis_parts.hostname or "").lower()
        except ValueError as exc:
            raise ValueError("REDIS_URL is invalid") from exc
        if redis_host not in {"localhost", "127.0.0.1", "::1", ""} and not redis_password:
            raise ValueError(
                "REDIS_URL must carry a password in production: the Celery broker "
                "accepts unauthenticated task injection from anything that can "
                "reach it. Set REDIS_PASSWORD in .env and put it in REDIS_URL as "
                "redis://:$(REDIS_PASSWORD)@redis:6379/0"
            )
        # The chain key must be explicit rather than derived. A derived key is
        # fine in development and wrong in production: rotating ENCRYPTION_KEY
        # would silently change it, and every existing entry would then look
        # tampered with (or, worse, a real edit would look like a rotation).
        if not self.AUDIT_CHAIN_KEYS.strip():
            raise ValueError(
                "AUDIT_CHAIN_KEYS must be explicitly configured in production, so "
                "that the audit hash chain is not keyed by a value derived from "
                "another secret. Generate one with: python -c \"import secrets; "
                "print(secrets.token_urlsafe(48))\""
            )
        if not re.match(r"^[vV]?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$", self.OPENDRP_VERSION.strip()):
            raise ValueError(
                "OPENDRP_VERSION must be a pinned semantic version in production; "
                "the moving latest tag is not allowed"
            )
        if not self.AUTH_COOKIE_SECURE:
            raise ValueError("AUTH_COOKIE_SECURE must be true in production")
        # Metrics are optional: an installation that does not scrape them leaves
        # the token empty and the endpoint absent. A token that *is* set is a
        # shared credential with read access to the platform's operational
        # picture, so it is held to the same bar as the other secrets here.
        if self.METRICS_TOKEN:
            if len(self.METRICS_TOKEN) < 32:
                raise ValueError("METRICS_TOKEN must contain at least 32 characters")
            if _looks_like_shipped_secret(self.METRICS_TOKEN):
                raise ValueError("METRICS_TOKEN must not be a placeholder value")
        if not self.TRUSTED_PROXY_IPS.strip():
            raise ValueError("TRUSTED_PROXY_IPS must be explicit in production")
        if self.UVICORN_FORWARDED_ALLOW_IPS.strip() == "*":
            raise ValueError("UVICORN_FORWARDED_ALLOW_IPS must not be '*' in production")
        return self

    @field_validator("LOG_LEVEL")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        """Reject an unusable level instead of silently falling back to INFO.

        ``getattr(logging, value, INFO)`` would hide a typo such as ``WARN`` or
        ``verbose``, and an operator who believes they raised the level while
        the platform quietly ignored it is worse off than one who gets an error
        at startup.
        """
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        normalized = str(v or "").strip().upper()
        if normalized not in allowed:
            raise ValueError(
                f"LOG_LEVEL must be one of {sorted(allowed)}, got {v!r}"
            )
        return normalized

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def _validate_jwt_algorithm(cls, v: str) -> str:
        """Reject any signing algorithm outside the allowlist.

        Enforced in every environment, not only production: a development
        deployment that accepts ``none`` still issues tokens that a
        production instance would accept, so the check must be unconditional.
        """
        normalized = str(v or "").strip().upper()
        if normalized not in JWT_ALGORITHMS_ALLOWED:
            raise ValueError(
                "JWT_ALGORITHM must be one of "
                f"{sorted(JWT_ALGORITHMS_ALLOWED)}, got {v!r}"
            )
        return normalized

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def _warn_default_jwt_secret(cls, v: str) -> str:
        import warnings

        if v == _DEFAULT_JWT_SECRET or _looks_like_shipped_secret(v):
            if _is_production_env():
                raise ValueError("JWT_SECRET_KEY must be explicitly configured in production")
            warnings.warn(
                "SECURITY WARNING: JWT_SECRET_KEY looks like a shipped development value!",
                stacklevel=2,
            )
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY must contain at least 32 characters")
        return v

    @field_validator("ENCRYPTION_KEY")
    @classmethod
    def _warn_default_encryption_key(cls, v: str) -> str:
        import warnings

        if v == _DEFAULT_ENCRYPTION_KEY or _looks_like_shipped_secret(v):
            if _is_production_env():
                raise ValueError("ENCRYPTION_KEY must be explicitly configured in production")
            warnings.warn(
                "SECURITY WARNING: ENCRYPTION_KEY looks like a shipped development value!",
                stacklevel=2,
            )
        return v

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[str]:
        return _parse_cors_origins(v)

    @property
    def DATABASE_URL_ASYNCPG(self) -> str:
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url


settings = Settings()
