import uuid
from typing import Optional

from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.exceptions import BadRequestException, ConflictException
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetUpdate, validate_and_normalize_asset_value
from app.schemas.user import AssetType


class AssetService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_assets(
        self,
        *,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[str] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Asset], int]:
        stmt = select(Asset)
        count_stmt = select(func.count(Asset.id)).select_from(Asset)

        conditions = []
        if asset_type is not None:
            conditions.append(Asset.asset_type == asset_type)
        if criticality is not None:
            conditions.append(Asset.criticality == criticality)
        if is_active is not None:
            conditions.append(Asset.is_active.is_(is_active))
        if search:
            raw_search = search.strip()[:100]
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

        if conditions:
            stmt = stmt.where(*conditions)
            count_stmt = count_stmt.where(*conditions)

        stmt = stmt.order_by(Asset.created_at.desc(), Asset.id.desc()).offset(skip).limit(limit)

        items_result = await self.db.execute(stmt)
        items = list(items_result.scalars().all())

        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar() or 0

        return (items, total)

    async def get_asset(self, asset_id: uuid.UUID) -> Optional[Asset]:
        result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
        return result.scalar_one_or_none()

    async def create_asset(self, data: AssetCreate) -> Asset:
        try:
            values = data.model_dump()
            values["asset_value"] = validate_and_normalize_asset_value(
                values["asset_type"], values["asset_value"]
            )
            values["normalized_value"] = values["asset_value"]
            duplicate = (
                await self.db.execute(
                    select(Asset.id).where(
                        Asset.asset_type == values["asset_type"],
                        Asset.normalized_value == values["normalized_value"],
                    ).limit(1)
                )
            ).scalar_one_or_none()
            if duplicate is not None:
                raise ConflictException("Asset with this value already exists")
            asset = Asset(**values)
            self.db.add(asset)
            await self.db.commit()
            await self.db.refresh(asset)
        except IntegrityError as exc:
            await self.db.rollback()
            raise ConflictException("Asset with this value already exists") from exc
        except ValueError as exc:
            await self.db.rollback()
            raise BadRequestException(str(exc)) from exc
        return asset

    async def update_asset(self, asset: Asset, data: AssetUpdate) -> Asset:
        update_dict = data.model_dump(exclude_unset=True)
        final_type = update_dict.get("asset_type", asset.asset_type)
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
        update_dict["asset_value"] = normalized
        update_dict["normalized_value"] = normalized
        # Keep a stable, canonical identity for all matching paths.
        for key, value in update_dict.items():
            setattr(asset, key, value)
        try:
            await self.db.commit()
        except IntegrityError as exc:
            await self.db.rollback()
            raise ConflictException("Asset with this value already exists") from exc
        await self.db.refresh(asset)
        return asset

    async def delete_asset(
        self, asset: Asset, *, cascade_findings: bool = False
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

            asset_value = asset.asset_value
            phishing_result = await self.db.execute(
                delete(PhishingDomain).where(PhishingDomain.matched_asset == asset_value)
            )
            breach_conditions = [
                Breach.matched_email == asset_value,
                Breach.matched_domain == asset_value,
            ]
            breach_result = await self.db.execute(
                delete(Breach).where(or_(*breach_conditions))
            )
            generic_result = await self.db.execute(
                delete(Finding).where(Finding.matched_asset == asset_value)
            )
            phishing_deleted = phishing_result.rowcount or 0
            breach_deleted = breach_result.rowcount or 0
            generic_deleted = generic_result.rowcount or 0

        await self.db.delete(asset)
        await self.db.commit()
        return phishing_deleted, breach_deleted, generic_deleted


    async def clean_orphan_phishing_findings(self) -> int:
        """Delete phishing findings whose matched asset no longer exists."""
        from app.models.phishing import PhishingDomain

        assets_result = await self.db.execute(select(Asset.asset_value))
        asset_values = {
            str(value).strip().casefold()
            for (value,) in assets_result.all()
            if value is not None
        }
        findings_result = await self.db.execute(
            select(PhishingDomain.id, PhishingDomain.matched_asset)
        )
        orphan_ids = [
            finding_id
            for finding_id, matched_asset in findings_result.all()
            if str(matched_asset or "").strip().casefold() not in asset_values
        ]
        if not orphan_ids:
            return 0
        result = await self.db.execute(
            delete(PhishingDomain).where(PhishingDomain.id.in_(orphan_ids))
        )
        await self.db.commit()
        return result.rowcount or 0

    async def clean_orphan_breach_findings(self) -> int:
        """Delete breach findings that no longer match any configured asset."""
        from app.models.breach import Breach

        assets_result = await self.db.execute(
            select(Asset.asset_value, Asset.asset_type)
        )
        assets_by_value = {
            str(value).strip().casefold(): getattr(asset_type, "value", asset_type)
            for value, asset_type in assets_result.all()
            if value is not None
        }
        findings_result = await self.db.execute(
            select(
                Breach.id,
                Breach.matched_email,
                Breach.matched_domain,
            )
        )
        orphan_ids = []
        for finding_id, matched_email, matched_domain in findings_result.all():
            domain = str(matched_domain or "").strip()
            email = str(matched_email or "").strip()
            email_domain = email.rsplit("@", 1)[1].strip() if "@" in email else ""
            linked = (
                (domain and domain.casefold() in assets_by_value)
                or (
                    email
                    and assets_by_value.get(email.casefold()) == "email_account"
                )
                or (
                    email_domain
                    and assets_by_value.get(email_domain.casefold()) == "domain"
                )
            )
            if not linked:
                orphan_ids.append(finding_id)
        if not orphan_ids:
            return 0
        result = await self.db.execute(
            delete(Breach).where(Breach.id.in_(orphan_ids))
        )
        await self.db.commit()
        return result.rowcount or 0

    async def get_active_assets_by_types(self, types: list[AssetType]) -> list[Asset]:
        result = await self.db.execute(
            select(Asset).where(
                Asset.asset_type.in_(types),
                Asset.is_active.is_(True),
            )
        )
        return list(result.scalars().all())
