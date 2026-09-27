from datetime import datetime
from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class ConnectorStatus:
    """String-enum for connector lifecycle states (kept plain for JSON ease)."""

    ENABLED = "enabled"
    DISABLED = "disabled"

    ALL = {ENABLED, DISABLED}


class Connector(Base, UUIDMixin, TimestampMixin):
    """A registered data-source connector (OpenCTI-style).

    Connectors are separate containers that register with the core, long-poll
    for scan work, execute it against their external data source, and submit
    normalized findings back to the core ingestion API. The core owns all DB
    writes, dedup, jobs, audit and alert fan-out.
    """

    __tablename__ = "drp_connectors"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    # Module the connector feeds. The module set is data (see
    # app/services/module_registry.py), so this is any registered module id —
    # including one an operator declared at runtime. Registration rejects an id
    # that is unknown or disabled.
    connector_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # "enabled" | "disabled". A disabled connector never receives work.
    status: Mapped[str] = mapped_column(String(32), default=ConnectorStatus.ENABLED, nullable=False)
    # Self-declared connector protocol/implementation version. Required by the
    # registration API (the SDK always sends it), informational here: it says
    # which build a row was last written by, not what it may claim.
    api_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Job type the connector declares for itself; the core accepts any
    # namespaced value (see app/services/connector_manifest.py) so a new
    # connector never needs a core change. It is required and uniquely owned:
    # it is what hands work to this connector, so two connectors can never share
    # one and none can be left claiming everything.
    default_job_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Self-declared manifest: module, job_type, finding_kind, asset_types and
    # the operator-editable config_schema. Registration always writes one; the
    # read path normalises it (connector_manifest.resolve_manifest) against the
    # module registry, which is why a row without one is still resolvable rather
    # than a coin flip.
    manifest: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Per-connector configuration delivered to the connector with every scan.
    # Validated against the connector's own manifest config_schema.
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    # Info block reported at registration (python version, hostname, etc.).
    info: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Per-connector credential. Only the SHA-256 digest is stored; the plaintext
    # is shown once at issuance (see services/connector_credentials.py). A NULL
    # digest means the connector cannot authenticate yet.
    token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )
    #: First characters of the token, so an operator can tell which credential is
    #: in use without being able to reconstruct it.
    token_prefix: Mapped[str | None] = mapped_column(String(16), nullable=True)
    token_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    token_last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @property
    def has_token(self) -> bool:
        return bool(self.token_hash)

    @property
    def is_enabled(self) -> bool:
        return self.status == ConnectorStatus.ENABLED

    def touch(self) -> None:
        from datetime import datetime, timezone

        self.last_seen_at = datetime.now(timezone.utc)
