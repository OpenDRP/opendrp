from fastapi import APIRouter, Depends, Request
from sqlalchemy import Date, cast, func, select
from sqlalchemy.sql import literal_column
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_viewer_plus
from app.core.audit import AuditLogger

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def dashboard_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    from datetime import datetime, timedelta, timezone
    from app.models import Asset, Breach as H, DrpPhishingDomain as P

    now = datetime.now(timezone.utc)

    total_assets = (await db.execute(select(func.count(Asset.id)).where(Asset.is_active.is_(True)))).scalar_one()
    total_ph = (await db.execute(select(func.count(P.id)))).scalar_one()
    total_hb = (await db.execute(select(func.count(H.id)))).scalar_one()
    seven = now - timedelta(days=7)
    act7d = (await db.execute(select(func.count(P.id)).where(P.created_at >= seven))).scalar_one()

    # One aggregate query replaces the former 60 per-day count queries. The
    # calendar is completed in Python so days with no findings remain visible.
    start_date = (now - timedelta(days=29)).date()
    timeline_rows = await db.execute(
        select(
            func.date(cast(P.created_at, Date)).label("day"),
            func.count(P.id).label("phishing"),
            literal_column("0").label("breaches"),
        )
        .where(P.created_at >= datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc))
        .group_by(func.date(cast(P.created_at, Date)))
        .union_all(
            select(
                func.date(cast(H.created_at, Date)).label("day"),
                literal_column("0").label("phishing"),
                func.count(H.id).label("breaches"),
            )
            .where(H.created_at >= datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc))
            .group_by(func.date(cast(H.created_at, Date)))
        )
    )
    totals_by_day: dict[str, dict[str, int]] = {}
    for day, phishing, breaches in timeline_rows.all():
        key = day.isoformat() if hasattr(day, "isoformat") else str(day)
        bucket = totals_by_day.setdefault(key, {"phishing": 0, "breaches": 0})
        bucket["phishing"] += int(phishing or 0)
        bucket["breaches"] += int(breaches or 0)
    timeline = []
    for i in range(29, -1, -1):
        d = (now - timedelta(days=i)).date()
        bucket = totals_by_day.get(d.isoformat(), {"phishing": 0, "breaches": 0})
        timeline.append({"date": d.isoformat(), **bucket})

    pb = (await db.execute(select(P.detection_source, func.count(P.id)).group_by(P.detection_source))).all()
    phishing_by_source = [{"source": src or "unknown", "count": cnt} for (src, cnt) in pb]

    ab = (await db.execute(select(Asset.criticality, func.count(Asset.id)).where(Asset.is_active.is_(True)).group_by(Asset.criticality))).all()
    assets_by_criticality = [{"criticality": c or "medium", "count": cnt} for (c, cnt) in ab]

    await AuditLogger.emit_background(
        db,
        action="dashboard.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "total_assets": int(total_assets),
            "total_phishing": int(total_ph),
            "total_breaches": int(total_hb),
            "active_threats_7d": int(act7d),
        },
    )

    return {
        "kpi": {
            "total_assets": total_assets,
            "total_phishing": total_ph,
            "total_breaches": total_hb,
            "active_threats_7d": act7d,
        },
        "timeline": timeline,
        "phishing_by_source": phishing_by_source,
        "assets_by_criticality": assets_by_criticality,
    }
