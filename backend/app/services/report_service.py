from datetime import datetime, timezone
import os
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.breach_severity import severity_label, severity_rank_case


def _breach_kpi_caption(kpi: dict, key: str) -> str:
    """The caption a breach KPI key carries, taken from the report's own data.

    The caption travels with the number, so the sentence printed beside a figure is the
    one the shared rule wrote for it (WI-16). A report rendered from data an older build
    gathered has no captions; it falls back to this wording rather than printing a blank.
    """
    captions = (kpi.get("breach_kpi") or {}).get("captions") or {}
    declared = captions.get(key)
    if isinstance(declared, str) and declared:
        return declared
    return "incidents the configured sources added to their own catalogues in the last 7 days"


def _report_pdf_text_values(report_data: dict, generated_by_email: str) -> list[str]:
    """Return row-field strings actually sent to PDF cells, tables, and footers."""
    values = [generated_by_email]
    for asset in report_data.get("assets", []):
        values.extend(
            str(value)
            for value in (
                getattr(asset, "asset_value", ""),
                getattr(asset, "asset_type", ""),
                getattr(asset, "criticality", ""),
                "YES" if getattr(asset, "is_active", False) else "NO",
            )
        )
    for finding in report_data.get("phishing", []):
        values.extend(
            str(value or "-")
            for value in (
                getattr(finding, "phishing_domain", ""),
                getattr(finding, "ip_address", None),
                getattr(finding, "detection_source", ""),
                getattr(finding, "status", ""),
            )
        )
    for breach in report_data.get("breaches", []):
        values.extend(
            str(value or "-")
            for value in (
                getattr(breach, "matched_email", None),
                getattr(breach, "breach_name", ""),
                getattr(breach, "domain", ""),
                # Rendered in their own columns, so the class and the severity are part
                # of the text the PDF receives and are validated like every other value
                # that reaches a cell.
                getattr(breach, "exposure_kind", None) or "breach",
                severity_label(getattr(breach, "severity", None)),
                getattr(breach, "breach_date", ""),
            )
        )
    for section_key in ("exposure", "dns"):
        for row in report_data.get(section_key, []):
            values.extend((str(row.subject), str(row.source), str(row.first_seen_at), str(row.last_seen_at)))
            if section_key == "exposure":
                values.extend(
                    str(value)
                    for value in (
                        row.matched_asset,
                        (row.payload or {}).get("port", "-"),
                        (row.payload or {}).get("protocol", "unknown"),
                        row.observed_at or "unknown",
                    )
                )
            else:
                values.extend((str(row.observation_type), str(row.value or "-")))
    return values


def _find_unicode_pdf_font() -> str | None:
    """Return the first configured or known system Unicode font, if present."""
    candidates = (
        os.environ.get("OPENDRP_PDF_FONT"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/tru/dejavu/DejaVuSans.ttf",
        "/usr/local/share/fonts/DejaVuSans.ttf",
        "C:/Windows/Fonts/DejaVuSans.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/arialuni.ttf",
    )
    return next((candidate for candidate in candidates if candidate and os.path.isfile(candidate)), None)


def _validate_pdf_text_unicode(report_data: dict, generated_by_email: str) -> None:
    """Reject text a core PDF font would silently corrupt or fail to encode."""
    import re

    for value in _report_pdf_text_values(report_data, generated_by_email):
        if re.search(r"[^\x00-\xff]", value):
            raise ValueError(
                "PDF Unicode font is unavailable; install DejaVu Sans or configure OPENDRP_PDF_FONT"
            )
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError(
                "PDF Unicode font is unavailable; install DejaVu Sans or configure OPENDRP_PDF_FONT"
            ) from exc


class ReportService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.last_truncation_metadata: dict | None = None
        self.snapshot_at: str | None = None

    async def gather_report_data(self) -> dict:
        """Gather a bounded report from one short, consistent DB snapshot.

        The session must not contain pending writes: report generation commits
        the snapshot before handing its data to the PDF renderer. PostgreSQL uses
        a read-only REPEATABLE READ transaction; SQLite receives an explicit read
        transaction for deterministic unit-test semantics.
        """
        from datetime import timedelta

        from sqlalchemy import func, select, text
        from app.models import Asset, Breach, DrpPhishingDomain
        from app.services.breach_kpi import breach_kpi
        from app.models.dns_observation import DNSObservation
        from app.models.source_observation import SourceObservation
        from app.core.config import settings

        if self.db.in_transaction():
            sync_session = self.db.sync_session
            if sync_session.new or sync_session.dirty or sync_session.deleted:
                raise RuntimeError("report data gathering requires a clean database session")

        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)
        settings_row_limit = settings.REPORT_MAX_ROWS
        row_limit = min(int(settings_row_limit), 50000)
        if row_limit < 1:
            raise ValueError("REPORT_MAX_ROWS must be positive")
        try:
            connection = await self.db.connection()
            dialect = connection.dialect.name
            if dialect == "postgresql":
                # This must be the first statement of the transaction. It fixes
                # one MVCC view and prevents report SELECTs from observing
                # different ingestion commits under PostgreSQL READ COMMITTED.
                await self.db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            elif dialect == "sqlite":
                # SQLAlchemy's SQLite autobegin is logical; explicitly BEGIN so
                # consecutive reads share the same SQLite read snapshot too.
                await connection.exec_driver_sql("BEGIN")

            total_inventory_assets = int((await self.db.execute(select(func.count(Asset.id)))).scalar_one())
            total_assets = int((await self.db.execute(
                select(func.count(Asset.id)).where(Asset.is_active.is_(True))
            )).scalar_one())
            total_phishing = int((await self.db.execute(select(func.count(DrpPhishingDomain.id)))).scalar_one())
            # The breach half of the KPI is the shared rule the dashboard reads too, read
            # inside this snapshot: a report that disagreed with the page about the same
            # installation would be worse than either number alone (WI-16).
            breach = await breach_kpi(self.db, now=now)
            total_breaches = breach["total_findings"]
            open_statuses = ("active", "investigating")
            active_phishing = int((await self.db.execute(
                select(func.count(DrpPhishingDomain.id)).where(
                    DrpPhishingDomain.created_at >= seven_days_ago,
                    DrpPhishingDomain.status.in_(open_statuses),
                )
            )).scalar_one())
            kpi = {
                "total_assets": total_assets,
                "total_phishing": total_phishing,
                "total_breaches": total_breaches,
                "active_threats_7d": active_phishing + int(breach["active_findings_7d"]),
                # A finding is what happened to one of our accounts; an incident is what a
                # source added to its catalogue, whether or not any address of ours is in
                # it. Reporting only the first let a quiet week of scanning read as a quiet
                # week of incidents (F-09).
                "new_breach_incidents_7d": breach["new_incidents_7d"],
                "breach_kpi": breach,
            }

            assets = list((await self.db.execute(
                select(Asset).order_by(
                    Asset.criticality.desc(), Asset.asset_type, Asset.id
                ).limit(row_limit)
            )).scalars().all())
            phishing = list((await self.db.execute(
                select(DrpPhishingDomain).order_by(
                    DrpPhishingDomain.created_at.desc(), DrpPhishingDomain.id.desc()
                ).limit(row_limit)
            )).scalars().all())
            # Loudest first, the same order the list offers: a report read top-down is
            # a triage, and alphabetical severity would put an address list above a
            # plaintext credential (F-13, WI-28).
            breaches = list((await self.db.execute(
                select(Breach).order_by(
                    severity_rank_case(Breach.severity).desc(),
                    Breach.created_at.desc(),
                    Breach.id.desc(),
                ).limit(row_limit)
            )).scalars().all())
            exposure_query = select(SourceObservation).where(SourceObservation.module == "exposure")
            exposure_total = int((await self.db.execute(
                select(func.count(SourceObservation.id)).where(SourceObservation.module == "exposure")
            )).scalar_one())
            dns_total = int((await self.db.execute(select(func.count(DNSObservation.id)))).scalar_one())
            exposure = list((await self.db.execute(
                exposure_query.order_by(SourceObservation.last_seen_at.desc(), SourceObservation.id.desc()).limit(row_limit)
            )).scalars().all())
            dns = list((await self.db.execute(
                select(DNSObservation).order_by(
                    DNSObservation.last_seen_at.desc(), DNSObservation.id.desc()
                ).limit(row_limit)
            )).scalars().all())

            assets_by_criticality: dict[str, int] = {}
            for asset in assets:
                assets_by_criticality[asset.criticality] = assets_by_criticality.get(asset.criticality, 0) + 1
            phishing_by_source: dict[str, int] = {}
            for finding in phishing:
                source = finding.detection_source or "unknown"
                phishing_by_source[source] = phishing_by_source.get(source, 0) + 1

            totals = {
                "assets": total_inventory_assets,
                "phishing": total_phishing,
                "breaches": total_breaches,
                "exposure": exposure_total,
                "dns": dns_total,
            }
            included = {
                "assets": len(assets),
                "phishing": len(phishing),
                "breaches": len(breaches),
                "exposure": len(exposure),
                "dns": len(dns),
            }
            sections = {
                name: {
                    "total": totals[name],
                    "included": included[name],
                    "limit": row_limit,
                    "truncated": totals[name] > included[name],
                }
                for name in totals
            }
            self.snapshot_at = now.isoformat()
            self.last_truncation_metadata = {
                "snapshot_at": self.snapshot_at,
                "limit": row_limit,
                "sections": sections,
                "truncated": any(section["truncated"] for section in sections.values()),
            }
            result = {
                "generated_at_iso": now.isoformat(),
                "snapshot_at": self.snapshot_at,
                "kpi": kpi,
                "assets": assets,
                "assets_by_criticality": assets_by_criticality,
                "phishing": phishing,
                "phishing_by_source": phishing_by_source,
                "breaches": breaches,
                "exposure": exposure,
                "dns": dns,
                "truncation": self.last_truncation_metadata,
            }
            # Release both the snapshot and its connection before PDF rendering.
            await self.db.commit()
            return result
        except BaseException:
            await self.db.rollback()
            raise

    @staticmethod
    def generate_pdf_sync(file_path: str, report_data: dict, generated_by_email: str) -> None:
        from fpdf import FPDF
        import os

        unicode_font = _find_unicode_pdf_font()
        if unicode_font is None:
            _validate_pdf_text_unicode(report_data, generated_by_email)

        class OpenDRPReport(FPDF):
            def __init__(self):
                super().__init__()
                self.alias_nb_pages()
                # Font selection and Unicode validation use the same discovered
                # file, so a supported platform font cannot be detected and then
                # ignored by the renderer.
                self.unicode_font = unicode_font
                if self.unicode_font:
                    self.add_font("DejaVu", style="", fname=self.unicode_font, uni=True)
                    bold = self.unicode_font.replace("DejaVuSans.ttf", "DejaVuSans-Bold.ttf")
                    if not os.path.isfile(bold):
                        bold = os.path.join(os.path.dirname(self.unicode_font), "arialbd.ttf")
                    if os.path.isfile(bold):
                        self.add_font("DejaVu", style="B", fname=bold, uni=True)
                self._opendrp_font_family = "DejaVu" if self.unicode_font else "Helvetica"

            def set_font(self, family, style="", size=0):
                selected = self._opendrp_font_family if family in {"Helvetica", "DejaVu"} else family
                if selected == "DejaVu":
                    registered = {str(key).lower() for key in self.fonts}
                    if f"{selected}{style}".lower() not in registered:
                        style = "B" if "B" in style and f"{selected}B".lower() in registered else ""
                return FPDF.set_font(self, selected, style, size)

            def header(self):
                if self.page_no() == 1:
                    return
                self.set_font("Helvetica", "B", 10)
                self.set_text_color(255, 255, 255)
                self.set_fill_color(17, 24, 39)
                self.rect(0, 0, 210, 14, "F")
                self.cell(105, 14, "OpenDRP - Digital Risk Protection Platform Report", 0, 0, "L", fill=False)
                self.set_font("Helvetica", "", 9)
                self.cell(105, 14, f"Generated: {report_data.get('generated_at_iso', '')[:19]} UTC", 0, 1, "R", fill=False)
                self.ln(10)

            def footer(self):
                self.set_y(-18)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(100, 100, 100)
                self.cell(0, 8, f"Page {self.page_no()}/{{nb}} - CONFIDENTIAL | Prepared by OpenDRP Platform for {generated_by_email}", border=0, align="C")
                self.set_draw_color(34, 197, 94)
                self.set_line_width(0.6)
                self.line(10, self.get_y() + 10, 200, self.get_y() + 10)

        pdf = OpenDRPReport()
        pdf.set_auto_page_break(auto=True, margin=25)
        # OpenDRPReport.set_font routes all document text through the chosen
        # Unicode-capable family, including automatic page headers/footers.

        pdf.add_page()
        pdf.set_fill_color(17, 24, 39)
        pdf.rect(0, 0, 210, 297, "F")
        pdf.set_fill_color(34, 197, 94)
        pdf.rect(0, 90, 210, 6, "F")
        pdf.ln(60)
        pdf.set_font("Helvetica", "B", 50)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 25, "OpenDRP", ln=1, align="C")
        pdf.set_font("Helvetica", "", 22)
        pdf.set_text_color(34, 197, 94)
        pdf.cell(0, 15, "Digital Risk Protection & Brand Protection Report", ln=1, align="C")
        pdf.ln(20)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 12, "EXECUTIVE INTELLIGENCE REPORT", ln=1, align="C")
        pdf.ln(30)
        pdf.set_draw_color(34, 197, 94)
        pdf.set_fill_color(31, 41, 55)
        pdf.set_line_width(0.5)
        pdf.rect(30, 180, 150, 70, "DF")
        pdf.set_xy(38, 186)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(34, 197, 94)

        def kv(pdf, k, v):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(200, 200, 200)
            pdf.cell(50, 8, k, 0)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 8, str(v)[:100], 0, 1)

        kv(pdf, "Generated At:", report_data.get("generated_at_iso", "")[:19] + " UTC")
        kv(pdf, "Generated By:", generated_by_email)
        kv(pdf, "Active Assets:", report_data['kpi']['total_assets'])
        kv(pdf, "Phishing Threats:", report_data['kpi']['total_phishing'])
        kv(pdf, "Breach Findings:", report_data['kpi']['total_breaches'])
        kv(pdf, "Active Threats (7d):", report_data['kpi']['active_threats_7d'])
        # The two are not the same number and the report says so where the numbers are
        # printed: findings are about our accounts, incidents are about what the sources
        # added to their catalogues (WI-16).
        kv(pdf, "New Breach Incidents (7d):", report_data['kpi'].get('new_breach_incidents_7d', 0))
        pdf.ln(30)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 5, "This document contains confidential and sensitive security information.", 0, 1, align="C")
        pdf.cell(0, 5, "Distribution is restricted to authorized personnel only.", 0, 1, align="C")

        def section_heading(title: str, idx: str):
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 22)
            pdf.set_text_color(17, 24, 39)
            pdf.cell(0, 14, f"{idx}.  {title}", ln=1)
            pdf.set_draw_color(34, 197, 94)
            pdf.set_line_width(1.2)
            pdf.line(10, pdf.get_y() + 2, 200, pdf.get_y() + 2)
            pdf.ln(10)

        def section_counts(section_key: str, rows: list) -> None:
            info = (report_data.get("truncation") or {}).get("sections", {}).get(section_key, {})
            included = info.get("included", len(rows))
            total = info.get("total", len(rows))
            limit = info.get("limit", (report_data.get("truncation") or {}).get("limit", "n/a"))
            suffix = "; TRUNCATED" if info.get("truncated") else ""
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(75, 85, 99)
            pdf.cell(0, 6, f"{included} included / {total} total; limit {limit}{suffix}", ln=1)

        section_heading("EXECUTIVE SUMMARY", "1")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(55, 65, 81)
        pdf.multi_cell(0, 7,
            "The following report summarizes inventory, phishing, breach, Exposure, and DNS Security "
            "observations collected by the configured sources of the OpenDRP platform. Counts describe "
            "stored records; provider observations are not, by themselves, proof of ownership or compromise.\n")
        for section_key, section_label in (("assets", "Assets"), ("phishing", "Phishing"), ("breaches", "Breach findings"), ("exposure", "Exposure"), ("dns", "DNS Security")):
            info = (report_data.get("truncation") or {}).get("sections", {}).get(section_key, {})
            pdf.set_font("Helvetica", "", 9)
            truncation_flag = "; TRUNCATED" if info.get("truncated") else ""
            pdf.cell(0, 6, f"{section_label}: {info.get('included', len(report_data.get(section_key, [])))} included / {info.get('total', len(report_data.get(section_key, [])))} total; limit {info.get('limit', (report_data.get('truncation') or {}).get('limit', 'n/a'))}{truncation_flag}", ln=1)
        pdf.cell(0, 6, f"Snapshot collected at: {report_data.get('snapshot_at') or report_data.get('generated_at_iso', '')}", ln=1)
        pdf.ln(2)
        kpi = report_data['kpi']
        boxes = [
            ("PROTECTED ASSETS", kpi['total_assets'], "Building2"),
            ("PHISHING THREATS", kpi['total_phishing'], "ShieldAlert"),
            ("BREACH FINDINGS", kpi['total_breaches'], "AlertTriangle"),
            ("ACTIVE THREATS (7D)", kpi['active_threats_7d'], "Activity"),
        ]
        x = 10
        y = pdf.get_y()
        w = 46
        box_h = 32
        for i, (label, val, _) in enumerate(boxes):
            pdf.set_xy(x, y)
            pdf.set_fill_color(249, 250, 251)
            pdf.set_draw_color(229, 231, 235)
            pdf.rect(x, y, w, box_h, "DF")
            pdf.set_fill_color(34, 197, 94)
            pdf.rect(x, y, w, 3, "F")
            pdf.set_xy(x + 3, y + 6)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(w - 6, 5, label, 0, 1)
            pdf.set_xy(x + 3, y + 14)
            pdf.set_font("Helvetica", "B", 22)
            pdf.set_text_color(17, 24, 39)
            pdf.cell(w - 6, 12, str(val), 0)
            x += w + 4
        pdf.set_y(y + box_h + 12)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(0, 8, "Asset Criticality Distribution (included rows)", 0, 1)
        data = report_data.get("assets_by_criticality") or {}
        colors = {"critical": (220, 38, 38), "high": (234, 88, 12), "medium": (234, 179, 8), "low": (16, 185, 129)}
        for crit in ["critical", "high", "medium", "low"]:
            v = data.get(crit, 0)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(17, 24, 39)
            pdf.cell(20, 8, crit.upper())
            bar_max = 140
            total_max = max(sum(data.values()), 1)
            bar_w = int(v / total_max * bar_max)
            pdf.set_fill_color(*colors.get(crit, (100, 100, 100)))
            pdf.rect(30, pdf.get_y() + 1, bar_w, 6, "F")
            pdf.set_xy(32 + bar_max, pdf.get_y())
            pdf.cell(0, 8, str(v), 0, 1)
        pdf.ln(5)

        section_heading("PROTECTED ASSETS INVENTORY", "2")
        assets = report_data.get("assets", [])
        section_counts("assets", assets)
        headers = ["#", "Asset Value", "Type", "Criticality", "Active"]
        widths = [8, 82, 35, 28, 17]
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        for i, h in enumerate(headers):
            pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
        pdf.ln()
        fill = False
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(17, 24, 39)
        for idx, a in enumerate(assets, 1):
            if pdf.get_y() > 270:
                pdf.add_page()
                pdf.set_fill_color(17, 24, 39)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 10)
                for i, h in enumerate(headers):
                    pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
                pdf.ln()
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(17, 24, 39)
            if fill:
                pdf.set_fill_color(249, 250, 251)
            else:
                pdf.set_fill_color(255, 255, 255)
            cells = [idx, a.asset_value, a.asset_type, a.criticality.upper(), "YES" if a.is_active else "NO"]
            for i, c in enumerate(cells):
                align = "L" if i == 1 else "C"
                pdf.cell(widths[i], 8, str(c)[:70], border=1, align=align, fill=True)
            pdf.ln()
            fill = not fill

        section_heading("PHISHING & BRAND IMPERSONATION THREATS", "3")
        phishing = report_data.get("phishing", [])
        section_counts("phishing", phishing)
        headers = ["#", "Phishing Domain", "IP", "Source", "Status"]
        widths = [8, 70, 33, 30, 20]
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        for i, h in enumerate(headers):
            pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
        pdf.ln()
        fill = False
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(17, 24, 39)
        for idx, p in enumerate(phishing, 1):
            if pdf.get_y() > 270:
                pdf.add_page()
                pdf.set_fill_color(17, 24, 39)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 10)
                for i, h in enumerate(headers):
                    pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
                pdf.ln()
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(17, 24, 39)
            if fill:
                pdf.set_fill_color(249, 250, 251)
            else:
                pdf.set_fill_color(255, 255, 255)
            cells = [idx, str(p.phishing_domain)[:55], p.ip_address or "-", p.detection_source, p.status]
            for i, c in enumerate(cells):
                align = "L" if i in (1, 2) else "C"
                pdf.cell(widths[i], 8, str(c)[:60], border=1, align=align, fill=True)
            pdf.ln()
            fill = not fill

        section_heading("BREACH FINDINGS", "4")
        breaches = report_data.get("breaches", [])
        section_counts("breaches", breaches)
        # The class of exposure is its own column: a compromised account is a password
        # reset and a stealer log is a session to revoke, so a report that names the
        # incident without it leaves the reader to find out elsewhere (WI-21). The token
        # printed is the one the API filters on, not a second vocabulary.
        headers = ["#", "Matched Email", "Breach", "Domain", "Exposure", "Severity", "Breach Date"]
        widths = [8, 44, 46, 28, 24, 22, 18]
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        for i, h in enumerate(headers):
            pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
        pdf.ln()
        fill = False
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(17, 24, 39)
        for idx, b in enumerate(breaches, 1):
            if pdf.get_y() > 270:
                pdf.add_page()
                pdf.set_fill_color(17, 24, 39)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 10)
                for i, h in enumerate(headers):
                    pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
                pdf.ln()
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(17, 24, 39)
            if fill:
                pdf.set_fill_color(249, 250, 251)
            else:
                pdf.set_fill_color(255, 255, 255)
            cells = [
                idx,
                b.matched_email,
                b.breach_name,
                b.domain,
                getattr(b, "exposure_kind", None) or "breach",
                severity_label(getattr(b, "severity", None)),
                str(b.breach_date),
            ]
            for i, c in enumerate(cells):
                align = "L" if i in (1, 2, 3) else "C"
                pdf.cell(widths[i], 8, str(c)[:60], border=1, align=align, fill=True)
            pdf.ln()
            fill = not fill


        section_heading("CONCLUSION & RECOMMENDATIONS", "5")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(55, 65, 81)
        breach_payload = kpi.get("breach_kpi") or {}
        undated_incidents = int(breach_payload.get("undated_incidents", 0) or 0)
        undated_note = (
            f"    ({undated_incidents} stored incidents carry no date from their source, so they cannot be counted in that window.)\n"
            if undated_incidents > 0
            else ""
        )
        # The class of exposure behind the findings total, from the same payload the
        # dashboard reads: a compromised account and a stealer-log row are one number to
        # the KPI and two different jobs for the operator (WI-16).
        kinds = breach_payload.get("findings_by_exposure_kind") or {}
        kinds_note = (
            f"  - {_breach_kpi_caption(kpi, 'findings_by_exposure_kind')}: "
            + ", ".join(f"{kind} {int(count)}" for kind, count in kinds.items())
            + ".\n"
            if kinds
            else ""
        )
        pdf.multi_cell(0, 7,
            "SUMMARY: The OpenDRP platform has identified the following security posture:\n"
            f"  - {kpi['total_assets']} active asset records are present in the inventory.\n"
            f"  - {kpi['total_phishing']} phishing findings are stored (all statuses).\n"
            f"  - {kpi['total_breaches']} breach findings are stored (all configured sources).\n"
            f"  - {kpi['active_threats_7d']} phishing and breach findings are active or under investigation and were created in the last 7 days.\n"
            f"  - {kpi.get('new_breach_incidents_7d', 0)} {_breach_kpi_caption(kpi, 'new_incidents_7d')}.\n"
            + undated_note
            + kinds_note
            + "\n"
            "RECOMMENDATIONS:\n"
            " 1. Validate high-priority findings against their source and current status before taking action.\n"
            " 2. For confirmed account exposure, follow the organization's credential-response policy.\n"
            " 3. Review passive observations for relevance; shared infrastructure is not proof of ownership.\n"
            " 4. Confirm enabled sources, scan budgets, schedules, alert recipients, and asset coverage.\n"
        )
        pdf.ln(10)
        pdf.set_draw_color(34, 197, 94)
        pdf.set_line_width(0.6)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, f"Report generated by OpenDRP Platform on {report_data.get('generated_at_iso', '')[:19]} UTC", 0, 1, align="C")
        pdf.cell(0, 6, f"Initiator: {generated_by_email}", 0, 1, align="C")

        for section, label in (("exposure", "Exposure"), ("dns", "DNS Security")):
            rows = report_data.get(section, [])
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 18)
            pdf.set_text_color(17, 24, 39)
            pdf.cell(0, 12, label, ln=1)
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5, "Passive provider observations, not verified vulnerabilities. Shared infrastructure is not proof of ownership. Missing or truncated results do not resolve earlier evidence.")
            section_counts(section, rows)
            if not rows:
                pdf.cell(0, 8, "No observations included.", ln=1)
            for row in rows:
                details = f"{row.subject} | source: {row.source} | first: {row.first_seen_at} | last: {row.last_seen_at}"
                if section == "exposure":
                    details += f" | asset: {row.matched_asset} | service: {row.payload.get('port', '-')} / {row.payload.get('protocol', 'unknown')} | provider observed: {row.observed_at or 'unknown'}"
                else:
                    details += f" | {row.observation_type}: {row.value or '-'}"
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(pdf.w-pdf.l_margin-pdf.r_margin, 5, details)
                pdf.ln(2)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        pdf.output(file_path)
        if os.path.getsize(file_path) < 10240:
            import structlog
            log = structlog.get_logger()
            log.warning("pdf_small", size=os.path.getsize(file_path))

    async def generate_and_save(self, *, report_id, user_email: str) -> tuple[str, dict | None]:
        """Render the PDF and return the *name* it was stored under.

        The name, not the absolute path: the caller persists this string in
        `reports.file_path`, and a stored path is a path the reader has to
        trust. See `app/core/artifact_path.py`.
        """
        from app.core.artifact_path import artifact_filename, artifact_path
        from app.core.config import settings

        import asyncio

        loop = asyncio.get_running_loop()
        generation_started = loop.time()
        try:
            data = await asyncio.wait_for(
                self.gather_report_data(),
                timeout=settings.REPORT_GENERATION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError("report generation exceeded its configured time limit during data collection") from exc

        remaining_timeout = settings.REPORT_GENERATION_TIMEOUT_SECONDS - (loop.time() - generation_started)
        if remaining_timeout <= 0:
            raise TimeoutError("report generation exceeded its configured time limit before PDF rendering")

        target = artifact_path(report_id)
        # A timeout cannot stop a Python thread already executing fpdf2. Use a
        # unique sibling for every attempt and shield the executor future: the
        # coroutine may time out, but the late writer must finish before its
        # temporary file is removed. The old fixed-name + immediate-unlink
        # approach allowed a late attempt to recreate a file after cleanup, and
        # allowed a retry to collide with the first attempt.
        temporary = target.with_name(f".{uuid.uuid4().hex}.pdf.tmp")
        render_future = loop.run_in_executor(
            None, self.generate_pdf_sync, str(temporary), data, user_email
        )
        timed_out = False

        def _cleanup_late_render(_future) -> None:
            # Consume a late renderer exception after the timeout so asyncio does
            # not emit an unhandled-future warning; the task already reports the
            # bounded timeout as the operator-facing failure.
            try:
                _future.exception()
            except BaseException:
                pass
            if not timed_out:
                return
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

        render_future.add_done_callback(_cleanup_late_render)
        remaining_timeout = settings.REPORT_GENERATION_TIMEOUT_SECONDS - (loop.time() - generation_started)
        try:
            await asyncio.wait_for(asyncio.shield(render_future), timeout=remaining_timeout)
            os.replace(temporary, target)
        except asyncio.TimeoutError:
            timed_out = True
            # The callback runs when the executor really stops writing. If it
            # completed in the same event-loop turn as the timeout, perform the
            # same cleanup immediately because the callback may have observed
            # the old flag value.
            if render_future.done():
                _cleanup_late_render(render_future)
            # Do not unlink an active temporary here: that would race with the
            # still-running renderer.
            raise TimeoutError("report generation exceeded its configured time limit")
        except Exception:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        return artifact_filename(report_id), data.get("truncation") or self.last_truncation_metadata
