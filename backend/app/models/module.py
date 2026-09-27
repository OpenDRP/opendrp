from sqlalchemy import JSON, Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin


class Module(Base, TimestampMixin):
    """A module the platform can collect and store findings for.

    Modules are **data, not code**: the row declares the module's label, the
    finding kind its connectors submit, the fields that payload carries, how
    those findings are deduplicated and (for modules the core has no built-in
    table for) that they are stored generically. Adding a module therefore means
    inserting a row plus writing a connector — no core release.

    ``storage`` selects the write adapter:

    * ``{"kind": "table", "table": "drp_phishing_domains", "adapter": "phishing"}``
      — a built-in adapter that owns domain-specific enrichment and alert
      rendering (the two modules this platform started with);
    * ``{"kind": "generic", "adapter": "generic"}`` — the generic writer, which
      stores the validated payload as JSON in ``drp_findings``.

    A native module can be re-declared on generic storage once its enriched
    behaviour is no longer wanted, so the closed-set problem the registry removes
    does not come back through the storage choice.
    """

    __tablename__ = "drp_modules"

    #: Stable slug used by connectors in ``CONNECTOR_TYPE`` and by the API.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Wire name of the finding kind this module's connectors submit.
    finding_kind: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    #: Asset-inventory sections the module works with (informational + UI).
    asset_types: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    #: Declared finding fields: ``{name: {type, label, required}}``. Native
    #: modules keep their code-defined schema; a declared module is validated
    #: against exactly this specification.
    fields: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    #: Declared field names that identify a finding (dedup key), in order.
    dedup_fields: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    #: Declared field shown as the finding's title in lists and alerts.
    title_field: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Write-adapter selector (see the class docstring): never a table name the
    #: caller controls at ingestion time.
    storage: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    #: Disabled modules reject new registrations and cannot claim work.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Set for the modules shipped with the platform; they cannot be deleted and
    #: their finding kind/fields are owned by core code.
    builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
