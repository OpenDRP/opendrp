import uuid
from collections.abc import Sequence
from typing import Any, Optional

from sqlalchemy import and_, asc, delete, desc, exists, func, literal, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.exceptions import BadRequestException, ConflictException
from app.models.asset import Asset
from app.schemas.asset import (
    AssetCreate,
    AssetFindingSummary,
    AssetUpdate,
    validate_and_normalize_asset_value,
)
from app.schemas.user import AssetType
from app.services.asset_matching import (
    IP_ASSET_TYPE,
    RELATED_FINDING_MODULES,
    asset_key_variants,
    asset_sql_key,
    cidr_search_values,
    domain_asset_variants,
    email_domain_join_predicate,
    email_domain_variants,
    email_domain_key,
    email_suffix_predicate,
    key_variants,
    keys_predicate,
    related_finding_observed_at,
    related_finding_value_columns,
    sql_key,
)

#: The columns ``GET /assets`` orders by, keyed by the literal ``sort`` values
#: ``app.schemas.asset.AssetSortField`` declares. Caller input is looked up here
#: and never rendered into the statement, so a sort parameter cannot become an
#: injection point (WI-16). ``asset_value`` orders by the canonical value the
#: table matches on — ``asset_value`` and ``normalized_value`` hold the same
#: canonical text, and the coalesce covers a row that stored only
#: ``asset_value`` and left ``normalized_value`` NULL.
ASSET_SORT_COLUMNS: dict[str, Any] = {
    "created_at": Asset.created_at,
    "updated_at": Asset.updated_at,
    "asset_value": func.coalesce(Asset.normalized_value, Asset.asset_value),
    "asset_type": Asset.asset_type,
    "criticality": Asset.criticality,
    "is_active": Asset.is_active,
}

#: The fields an audit entry describes, in the order they are reported.
ASSET_AUDIT_FIELDS = ("asset_type", "asset_value", "criticality", "is_active")


def asset_type_value(asset_type) -> str:
    """An asset type as the plain string the API and the audit trail publish.

    The column is a SQLAlchemy ``Enum``, so a loaded row hands back an enum
    member whose ``str()`` is ``AssetType.domain``. That repr used to reach the
    audit details of ``asset.create`` while ``dns_security.asset.promoted`` wrote
    ``domain`` for the same fact, which makes the two incomparable in a SIEM.
    """
    return str(getattr(asset_type, "value", asset_type))


def asset_audit_snapshot(asset: Asset) -> dict:
    """The auditable facts of one asset, as flat JSON-native values."""
    return {
        "asset_type": asset_type_value(asset.asset_type),
        "asset_value": str(asset.asset_value),
        "criticality": str(asset.criticality),
        "is_active": bool(asset.is_active),
    }


def diff_audit_snapshots(before: dict, after: dict) -> dict[str, dict]:
    """Field-level ``from``/``to`` for what actually changed in one update.

    Built from the row rather than from the request body: the stored value is
    canonicalized on every write, so a caller that toggles only ``criticality``
    can still change ``asset_value`` (a row whose ``normalized_value`` is NULL
    receives the canonical spelling), and
    an audit that listed the request's keys would report the one change that did
    not happen and stay silent about the one that did.
    """
    return {
        field: {"from": before[field], "to": after[field]}
        for field in ASSET_AUDIT_FIELDS
        if field in before and field in after and before[field] != after[field]
    }


def _batched(values: Sequence[Any], size: int) -> list[list[Any]]:
    """``values`` split into batches of at most ``size`` (never empty batches).

    A statement that names thousands of keys is refused by both databases, and an
    empty batch would make ``or_()`` render nothing at all — so the split is what
    keeps an involvement lookup bounded in both directions.
    """
    return [list(values[start : start + size]) for start in range(0, len(values), size)]


class AssetService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_assets(
        self,
        *,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[str] = None,
        is_active: Optional[bool] = None,
        has_findings: Optional[bool] = None,
        search: Optional[str] = None,
        sort: str = "created_at",
        order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Asset], int]:
        conditions = []
        if asset_type is not None:
            conditions.append(Asset.asset_type == asset_type)
        if criticality is not None:
            conditions.append(Asset.criticality == criticality)
        if is_active is not None:
            conditions.append(Asset.is_active.is_(is_active))
        if has_findings is not None:
            # "Is this asset involved in anything" is answered under the display
            # policy: an inactive asset still owns the findings recorded about it,
            # so deactivating one does not make its evidence disappear from this
            # filter (WI-20). The set is read the same way the row counters are
            # (see ``related_finding_summaries`` for why not per row), and it is
            # one statement of the inventory's own keys, so the filter and the
            # counters cannot answer the question differently.
            involved = await self.asset_ids_with_findings()
            ids = sorted(involved)
            chunks = [
                Asset.id.in_(ids[start : start + self.MATCHING_KEY_BATCH_SIZE])
                for start in range(0, len(ids), self.MATCHING_KEY_BATCH_SIZE)
            ] or [Asset.id.in_([])]
            matching = or_(*chunks)
            conditions.append(matching if has_findings else ~matching)
        if search:
            raw_search = search.strip()[:100]
            try:
                subnet = cidr_search_values(raw_search)
            except ValueError as exc:
                # A subnet too large to answer exactly is refused, not truncated
                # to whatever fitted (WI-16).
                raise BadRequestException(str(exc)) from exc
            if subnet is not None:
                # A subnet is a question about monitored addresses, so it stays
                # inside `ip_address`: a keyword asset that happens to read like
                # an address is not in anybody's network.
                conditions.append(Asset.asset_type == IP_ASSET_TYPE)
                conditions.append(Asset.normalized_value.in_(sorted(subnet)))
            else:
                escaped = (
                    raw_search.replace("\\", "\\\\")
                    .replace("%", r"\%")
                    .replace("_", r"\_")
                )
                pattern = f"%{escaped.lower()}%"
                conditions.append(
                    or_(
                        Asset.normalized_value.ilike(pattern, escape="\\"),
                        Asset.asset_value.ilike(f"%{escaped}%", escape="\\"),
                    )
                )

        if sort not in ASSET_SORT_COLUMNS:
            # The API validates `sort` before this point; the check is what keeps
            # that promise when the service is called from anywhere else.
            raise BadRequestException(f"Unsupported sort field: {sort}")
        if order not in ("asc", "desc"):
            raise BadRequestException(f"Unsupported sort direction: {order}")
        direction = desc if order == "desc" else asc
        # `id` breaks ties, so a row cannot appear on two pages of the same
        # listing (or be skipped between them) when the sort column repeats.
        # Annotated because `asc`/`desc` are generic over the column they wrap.
        ordering: tuple[Any, ...] = (
            direction(ASSET_SORT_COLUMNS[sort]),
            direction(Asset.id),
        )

        # The page and its total travel in one statement, so they come from one
        # snapshot: two statements under READ COMMITTED can disagree while an
        # operator scrolls, and a `total` that changes between pages of the same
        # query reads as a defect in the list rather than as a concurrent write
        # (WI-16/AST-09).
        stmt = (
            select(Asset, func.count().over().label("filtered_total"))
            .where(*conditions)
            .order_by(*ordering)
            .offset(skip)
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        items = [row[0] for row in rows]
        if rows:
            total = int(rows[0][1])
        else:
            # A page past the end carries no row to read the window count from —
            # and an empty page is the one case where a second statement cannot
            # disagree with what the caller is shown.
            total = int(
                (
                    await self.db.execute(
                        select(func.count(Asset.id)).select_from(Asset).where(*conditions)
                    )
                ).scalar()
                or 0
            )
        return (items, total)

    #: How many keys one involvement lookup may carry. A page over a large
    #: inventory asks one question per module per batch, and a statement with tens
    #: of thousands of bind parameters is refused by both databases. The same bound
    #: covers the monitored domains of the email-to-domain branch: that lookup is an
    #: indexed equality on the address's domain part, so a batch is a statement
    #: size, not an extra scan.
    MATCHING_KEY_BATCH_SIZE = 5000

    @staticmethod
    def _key_owners(
        assets: Sequence[Asset],
    ) -> tuple[dict[str, set[uuid.UUID]], dict[str, set[uuid.UUID]]]:
        """Asset ids behind every key spelling, and the domain-only subset.

        This map is what turns "a module holds a row about key *K*" into "that row
        belongs to these assets": the keys come from the one matching rule
        (WI-08), so the involvement a row reports is the same involvement the
        cascade would act on. A key can be shared — a mailbox asset and the
        domain asset derived from it both answer to the domain — which is why the
        value is a set.
        """
        owners: dict[str, set[uuid.UUID]] = {}
        domain_owners: dict[str, set[uuid.UUID]] = {}
        for asset in assets:
            stored = asset.normalized_value or asset.asset_value
            for key in asset_key_variants(asset.asset_type, stored):
                owners.setdefault(key, set()).add(asset.id)
            for key in domain_asset_variants(asset.asset_type, stored):
                domain_owners.setdefault(key, set()).add(asset.id)
        return owners, domain_owners

    async def _involvement(
        self, assets: Sequence[Asset]
    ) -> tuple[dict[uuid.UUID, dict[str, int]], dict[uuid.UUID, dict[str, Any]]]:
        """Per-asset, per-module finding counts and latest moments (WI-20).

        The rows are found by asking each module which of the assets' key
        spellings it holds (one grouped statement per module, batched), not by
        running the per-asset predicates once per row. The per-asset form has to
        evaluate a correlated existence test per inventory row — the list reads
        its ``total`` from the same statement, so every row is read — and the
        mailbox-at-a-domain branch of the breach rule cannot use an index, which
        turns it into one scan of the breaches table per asset. Measured on 2000
        assets and 100k breaches, that form took 7.6 s for a page of 20 rows
        (19 s for 50) and exceeded ``statement_timeout`` when used as a filter;
        this one is a handful of index-driven lookups over the page's own keys.

        Every row is counted once per owning asset. The equality and suffix
        passes cannot overlap — the second excludes rows the first already took —
        and within one pass a row is attributed through the union of the assets
        its keys answer to, so a breach that names both a domain and a mailbox at
        it is not counted twice for the domain asset.
        """
        columns = related_finding_value_columns()
        observed = related_finding_observed_at()
        owners, domain_owners = self._key_owners(assets)
        all_keys = sorted(owners)
        batches = self.MATCHING_KEY_BATCH_SIZE
        counts = {
            asset.id: dict.fromkeys(RELATED_FINDING_MODULES, 0) for asset in assets
        }
        moments: dict[uuid.UUID, dict[str, Any]] = {
            asset.id: dict.fromkeys(RELATED_FINDING_MODULES) for asset in assets
        }

        def _record(asset_id: uuid.UUID, module: str, rows: Any, latest: Any) -> None:
            counts[asset_id][module] += int(rows or 0)
            previous = moments[asset_id][module]
            if latest is not None and (previous is None or latest > previous):
                moments[asset_id][module] = latest

        for module, module_columns in columns.items():
            expressions = [sql_key(column) for column in module_columns]
            labels = [expression.label(f"key{index}") for index, expression in enumerate(expressions)]
            # Pass 1: rows whose own identifier is one of the page's keys.
            for chunk in _batched(all_keys, batches):
                statement = (
                    select(
                        *labels,
                        func.count().label("rows"),
                        func.max(observed[module]).label("latest"),
                    )
                    .where(or_(*[expression.in_(chunk) for expression in expressions]))
                    .group_by(*labels)
                )
                for row in (await self.db.execute(statement)).all():
                    owned: set[uuid.UUID] = set()
                    for key in row[: len(expressions)]:
                        owned |= owners.get(str(key), set())
                    for asset_id in owned:
                        _record(asset_id, module, row[-2], row[-1])
            # Pass 2 (breaches only): rows about a mailbox at a *monitored
            # domain*. They name no asset themselves, so they are grouped by the
            # domain they are at and attributed to that domain's asset. The
            # domain is an expression the plan can index (migration 0009), not a
            # `LIKE '%@domain'`: with a page of domains the wildcard form scanned
            # the breaches table once per request, and answering it for the whole
            # inventory instead of a page took 37 s on the measured dataset.
            if module == "breaches" and domain_owners:
                # A row is "already taken" when one of its own keys is one the
                # page answers to. The keys are coalesced because a NULL key
                # makes `NOT taken` unknown rather than true, and a breach about
                # an address at a monitored domain has no matched domain at all.
                taken = or_(
                    *[
                        func.coalesce(expression, literal("")).in_(chunk)
                        for expression in expressions
                        for chunk in _batched(all_keys, batches)
                    ]
                )
                matched_domain = email_domain_key(module_columns[1]).label("matched_domain")
                for chunk in _batched(sorted(domain_owners), batches):
                    suffix = email_suffix_predicate(module_columns[1], chunk)
                    if suffix is None:
                        continue
                    statement = (
                        select(
                            matched_domain,
                            func.count().label("rows"),
                            func.max(observed[module]).label("latest"),
                        )
                        .where(and_(suffix, ~taken))
                        .group_by(matched_domain)
                    )
                    for domain, rows, latest in (await self.db.execute(statement)).all():
                        for asset_id in domain_owners.get(str(domain), set()):
                            _record(asset_id, module, rows, latest)
        return counts, moments

    async def related_finding_summaries(
        self, assets: Sequence[Asset]
    ) -> dict[uuid.UUID, AssetFindingSummary]:
        """How much the platform holds about each of these assets (WI-20).

        The list shows a counter per row so "present in the table" and "actually
        monitored" are different things at a glance, and each counter has to agree
        with the asset page and with what a cascade delete would remove. Both read
        the same matching rule (``app/services/asset_matching.py``); the asset page
        asks it one asset at a time, this asks it for a whole page in a few
        grouped statements.
        """
        counts, moments = await self._involvement(assets)
        summaries: dict[uuid.UUID, AssetFindingSummary] = {}
        for asset in assets:
            summaries[asset.id] = AssetFindingSummary(
                **counts[asset.id],
                total=sum(counts[asset.id].values()),
                last_seen={
                    module: (moment.isoformat() if moment is not None else None)
                    for module, moment in moments[asset.id].items()
                },
            )
        return summaries

    async def asset_ids_with_findings(self) -> set[uuid.UUID]:
        """The assets the platform holds findings about (WI-20).

        The ``has_findings`` filter needs this for the whole inventory before the
        page is chosen, so it is read through the same counters rather than by a
        per-row existence test (which is what made filtering the inventory cost
        one scan of the breaches table per asset).
        """
        assets = (await self.db.execute(select(Asset))).scalars().all()
        summaries = await self.related_finding_summaries(assets)
        return {
            asset_id for asset_id, summary in summaries.items() if summary.total > 0
        }

    async def asset_exists(self, asset_type: object, normalized_value: str) -> bool:
        """Whether this canonical value is already monitored under this type.

        The one implementation of the duplicate rule, shared by ``create_asset``
        and the read-only import preview (WI-18): a preview that asked the
        question differently would answer a different one.
        """
        found = (
            await self.db.execute(
                select(Asset.id)
                .where(
                    Asset.asset_type == asset_type,
                    Asset.normalized_value == normalized_value,
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        return found is not None

    async def get_asset(self, asset_id: uuid.UUID) -> Optional[Asset]:
        result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
        return result.scalar_one_or_none()

    async def create_asset(self, data: AssetCreate, *, commit: bool = True) -> Asset:
        """Create one asset.

        ``commit=False`` leaves the INSERT flushed inside the caller's
        transaction, so a route can put its audit row and this mutation into one
        commit — the mutation must not be durable without the record of it. The
        unique index is still what closes the duplicate race either way: the
        statement runs here and a conflict surfaces now, not at the caller's
        commit.
        """
        try:
            values = data.model_dump()
            values["asset_value"] = validate_and_normalize_asset_value(
                values["asset_type"], values["asset_value"]
            )
            values["normalized_value"] = values["asset_value"]
            if await self.asset_exists(values["asset_type"], values["normalized_value"]):
                raise ConflictException("Asset with this value already exists")
            asset = Asset(**values)
            self.db.add(asset)
            if commit:
                await self.db.commit()
                await self.db.refresh(asset)
            else:
                await self.db.flush()
        except IntegrityError as exc:
            await self.db.rollback()
            raise ConflictException("Asset with this value already exists") from exc
        except ValueError as exc:
            await self.db.rollback()
            raise BadRequestException(str(exc)) from exc
        return asset

    async def update_asset(
        self, asset: Asset, data: AssetUpdate, *, commit: bool = True
    ) -> Asset:
        update_dict = data.model_dump(exclude_unset=True)
        final_type = asset_type_value(update_dict.get("asset_type", asset.asset_type))
        original_type = asset_type_value(asset.asset_type)
        # A type change is only meaningful together with a value that is valid
        # *for the new type*. Without one the row's existing value would be
        # re-interpreted under another type — a domain read as a keyword, which
        # drops it out of DNS and breach matching and hands the scanners a
        # different inventory — and the per-type rules would not have run at all,
        # because `AssetUpdate.validate_asset_value` only sees the value that the
        # payload carries. This is that same rule for the payload that carries
        # the type alone.
        if final_type != asset_type_value(asset.asset_type) and "asset_value" not in update_dict:
            raise BadRequestException(
                "Changing an asset's type requires the new asset_value for that type"
            )
        identity_changed = (
            "asset_value" in update_dict
            or final_type != original_type
        )
        if identity_changed:
            final_value = update_dict.get("asset_value", asset.asset_value)
            try:
                normalized = validate_and_normalize_asset_value(final_type, final_value)
            except ValueError as exc:
                raise BadRequestException(str(exc)) from exc
            duplicate = (
                await self.db.execute(
                    select(Asset.id).where(
                        Asset.asset_type == final_type,
                        Asset.normalized_value == normalized,
                        Asset.id != asset.id,
                    ).limit(1)
                )
            ).scalar_one_or_none()
            if duplicate is not None:
                raise ConflictException("Asset with this value already exists")
            # (The update path keeps its own query because it must exclude the row
            # being changed; ``asset_exists`` is the create-side rule.)
            # A PATCH to unrelated fields must not silently rewrite an identity
            # (e.g. its original spelling or NULL normalized_value).
            # Canonicalize only when the caller explicitly changes the identity;
            # that change is then visible in the before/after audit diff.
            update_dict["asset_value"] = normalized
            update_dict["normalized_value"] = normalized
        if "asset_type" in update_dict:
            # Stored as the plain string, not the enum member: the column accepts
            # either, and the string is what the API and the audit trail publish.
            update_dict["asset_type"] = final_type
        # Keep a stable, canonical identity for all matching paths when the
        # identity was explicitly changed; unrelated PATCH fields leave it intact.
        for key, value in update_dict.items():
            setattr(asset, key, value)
        try:
            if commit:
                await self.db.commit()
                await self.db.refresh(asset)
            else:
                await self.db.flush()
        except IntegrityError as exc:
            await self.db.rollback()
            raise ConflictException("Asset with this value already exists") from exc
        return asset

    async def delete_asset(
        self, asset: Asset, *, cascade_findings: bool = False, commit: bool = True
    ) -> tuple[int, int, int]:
        """Delete an asset and optionally its linked findings.

        Finding tables intentionally keep denormalized matched values rather
        than foreign keys, because connector findings can outlive an asset
        configuration change. Related findings are removed only when the
        caller explicitly requests the destructive cascade.
        """
        phishing_deleted = breach_deleted = generic_deleted = 0
        if cascade_findings:
            from app.models.breach import Breach
            from app.models.finding import Finding
            from app.models.phishing import PhishingDomain

            # One rule for all three modules (WI-08): the cascade removes exactly
            # the findings that depend on this asset's *value*, under the shared
            # canonicalization — the old byte-for-byte comparison missed findings
            # the breach list happily displayed next to the same asset.
            keys = key_variants(asset.asset_value)
            phishing_deleted = await self._delete_in_batches(
                PhishingDomain,
                PhishingDomain.id,
                keys_predicate(PhishingDomain.matched_asset, keys),
            )
            breach_conditions = [
                keys_predicate(Breach.matched_domain, keys),
                keys_predicate(Breach.matched_email, keys),
            ]
            # Deleting a monitored *domain* also removes the breach findings about
            # mailboxes at that domain; deleting one mailbox does not touch its
            # domain. ``email_suffix_predicate`` ignores keys that are not
            # hostnames, so an email or keyword key can never widen the cascade.
            by_email_domain = email_suffix_predicate(Breach.matched_email, keys)
            if by_email_domain is not None:
                breach_conditions.append(by_email_domain)
            breach_deleted = await self._delete_in_batches(
                Breach, Breach.id, or_(*breach_conditions)
            )
            generic_deleted = await self._delete_in_batches(
                Finding,
                Finding.id,
                keys_predicate(Finding.matched_asset, keys),
            )

        await self.db.delete(asset)
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return phishing_deleted, breach_deleted, generic_deleted


    #: Findings are removed in bounded batches so one DELETE over a large table
    #: cannot hold locks past the installation's ``lock_timeout``.
    FINDING_BATCH_SIZE = 1000

    async def _delete_in_batches(self, model, id_column, predicate) -> int:
        """``DELETE`` the rows matching ``predicate``, ``FINDING_BATCH_SIZE`` at a time."""
        deleted = 0
        while True:
            ids = list(
                (
                    await self.db.execute(
                        select(id_column)
                        .where(predicate)
                        .order_by(id_column)
                        .limit(self.FINDING_BATCH_SIZE)
                    )
                ).scalars()
            )
            if not ids:
                return deleted
            result = await self.db.execute(delete(model).where(id_column.in_(ids)))
            deleted += result.rowcount or 0
            if len(ids) < self.FINDING_BATCH_SIZE:
                return deleted

    async def _asset_keys(self) -> tuple[set[str], set[str]]:
        """Every asset key variant, plus the domain-only subset (WI-08 rules)."""
        rows = (
            await self.db.execute(
                select(Asset.asset_type, func.coalesce(Asset.normalized_value, Asset.asset_value))
            )
        ).all()
        keys: set[str] = set()
        domain_keys: set[str] = set()
        for asset_type, value in rows:
            keys |= asset_key_variants(asset_type, value)
            domain_keys |= domain_asset_variants(asset_type, value)
        return keys, domain_keys

    async def _delete_orphans(
        self, model, id_column, value_columns, linked_in_sql, is_linked
    ) -> int:
        """Delete rows the SQL anti-join flags, after ``is_linked`` confirms them.

        The anti-join is what makes this independent of the finding table's size:
        only the candidate rows — the ones about to be deleted — are read, instead
        of every finding and every asset. ``is_linked`` re-checks those candidates
        with the shared IDNA-aware rule, because SQL cannot tell that a Unicode
        spelling and its punycode form are the same host.
        """
        deleted = 0
        while True:
            rows = (
                await self.db.execute(
                    select(id_column, *value_columns)
                    .where(~linked_in_sql)
                    .order_by(id_column)
                    .limit(self.FINDING_BATCH_SIZE)
                )
            ).all()
            if not rows:
                return deleted
            orphan_ids = [row[0] for row in rows if not is_linked(*row[1:])]
            if not orphan_ids:
                return deleted
            result = await self.db.execute(delete(model).where(id_column.in_(orphan_ids)))
            deleted += result.rowcount or 0
            await self.db.commit()
            if len(rows) < self.FINDING_BATCH_SIZE:
                return deleted

    async def clean_orphan_phishing_findings(self) -> int:
        """Delete phishing findings whose matched asset no longer exists (WI-10)."""
        from app.models.phishing import PhishingDomain

        asset_keys, _ = await self._asset_keys()
        linked_in_sql = exists(
            select(Asset.id).where(asset_sql_key() == sql_key(PhishingDomain.matched_asset))
        )
        return await self._delete_orphans(
            PhishingDomain,
            PhishingDomain.id,
            (PhishingDomain.matched_asset,),
            linked_in_sql,
            lambda matched_asset: bool(key_variants(matched_asset) & asset_keys),
        )

    async def clean_orphan_breach_findings(self) -> int:
        """Delete breach findings that no longer match any configured asset (WI-10)."""
        from app.models.breach import Breach

        asset_keys, domain_keys = await self._asset_keys()
        linked_in_sql = exists(
            select(Asset.id).where(
                or_(
                    asset_sql_key() == sql_key(Breach.matched_domain),
                    asset_sql_key() == sql_key(Breach.matched_email),
                    email_domain_join_predicate(Breach.matched_email),
                )
            )
        )

        def is_linked(matched_email, matched_domain) -> bool:
            domain = str(matched_domain or "").strip()
            email = str(matched_email or "").strip()
            if key_variants(domain) & asset_keys or key_variants(email) & asset_keys:
                return True
            return bool(email) and bool(email_domain_variants(email) & domain_keys)

        return await self._delete_orphans(
            Breach,
            Breach.id,
            (Breach.matched_email, Breach.matched_domain),
            linked_in_sql,
            is_linked,
        )

    async def get_active_assets_by_types(self, types: list[AssetType]) -> list[Asset]:
        result = await self.db.execute(
            select(Asset).where(
                Asset.asset_type.in_(types),
                Asset.is_active.is_(True),
            )
        )
        return list(result.scalars().all())
