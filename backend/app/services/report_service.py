from datetime import datetime, timezone
import os
import uuid

from sqlalchemy.ext.asyncio import AsyncSession


class ReportService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.last_truncation_metadata: dict | None = None

    async def gather_report_data(self) -> dict:
        from sqlalchemy import select, func
        from datetime import timedelta
        from app.models import Asset, Breach, DrpPhishingDomain

        total_assets = (await self.db.execute(select(func.count(Asset.id)))).scalar_one()
        total_phishing = (await self.db.execute(select(func.count(DrpPhishingDomain.id)))).scalar_one()
        total_breaches = (await self.db.execute(select(func.count(Breach.id)))).scalar_one()
        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)
        active7d = (await self.db.execute(
            select(func.count(DrpPhishingDomain.id)).where(DrpPhishingDomain.created_at >= seven_days_ago)
        )).scalar_one()
        kpi = {
            "total_assets": total_assets,
            "total_phishing": total_phishing,
            "total_breaches": total_breaches,
            "active_threats_7d": active7d,
        }
        from app.core.config import settings
        row_limit = settings.REPORT_MAX_ROWS
        # Reuse the KPI counts for truncation metadata; do not add another
        # round-trip per section merely to explain the row limit.
        asset_total = int(total_assets)
        phishing_total = int(total_phishing)
        breach_total = int(total_breaches)
        assets = list((await self.db.execute(select(Asset).order_by(Asset.criticality.desc(), Asset.asset_type).limit(row_limit))).scalars().all())
        assets_by_criticality: dict[str, int] = {}
        for a in assets:
            assets_by_criticality[a.criticality] = assets_by_criticality.get(a.criticality, 0) + 1
        phishing = list((await self.db.execute(select(DrpPhishingDomain).order_by(DrpPhishingDomain.created_at.desc()).limit(row_limit))).scalars().all())
        phishing_by_source: dict[str, int] = {}
        for p in phishing:
            phishing_by_source[p.detection_source] = phishing_by_source.get(p.detection_source, 0) + 1
        breaches = list((await self.db.execute(select(Breach).order_by(Breach.created_at.desc()).limit(row_limit))).scalars().all())
        self.last_truncation_metadata = {
            "limit": row_limit,
            "sections": {
                "assets": {"total": asset_total, "included": len(assets), "truncated": asset_total > len(assets)},
                "phishing": {"total": phishing_total, "included": len(phishing), "truncated": phishing_total > len(phishing)},
                "breaches": {"total": breach_total, "included": len(breaches), "truncated": breach_total > len(breaches)},
            },
            "truncated": any((asset_total > len(assets), phishing_total > len(phishing), breach_total > len(breaches))),
        }
        return {
            "generated_at_iso": now.isoformat(),
            "kpi": kpi,
            "assets": assets,
            "assets_by_criticality": assets_by_criticality,
            "phishing": phishing,
            "phishing_by_source": phishing_by_source,
            "breaches": breaches,
            "truncation": self.last_truncation_metadata,
        }

    @staticmethod
    def generate_pdf_sync(file_path: str, report_data: dict, generated_by_email: str) -> None:
        from fpdf import FPDF
        import os

        class OpenDRPReport(FPDF):
            def __init__(self):
                super().__init__()
                self.alias_nb_pages()
                # Prefer a bundled/system Unicode font. Helvetica is retained as
                # a fallback for minimal installations, but never silently drops
                # Cyrillic, accented names, or non-ASCII provider data.
                import os
                candidates = [
                    os.environ.get("OPENDRP_PDF_FONT"),
                    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                    "/usr/share/fonts/tru/dejavu/DejaVuSans.ttf",
                    "/usr/local/share/fonts/DejaVuSans.ttf",
                ]
                self.unicode_font = next((p for p in candidates if p and os.path.isfile(p)), None)
                if self.unicode_font:
                    self.add_font("DejaVu", style="", fname=self.unicode_font, uni=True)
                    bold = self.unicode_font.replace("DejaVuSans.ttf", "DejaVuSans-Bold.ttf")
                    if os.path.isfile(bold):
                        self.add_font("DejaVu", style="B", fname=bold, uni=True)
                self._opendrp_font_family = "DejaVu" if self.unicode_font else "Helvetica"

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
        # All report text goes through the selected family. On the production
        # image this is DejaVu Sans; the fallback keeps PDF generation available
        # in stripped-down test/dev environments.
        def set_safe_font(family, style="", size=0):
            selected = pdf._opendrp_font_family if family in {"Helvetica", "DejaVu"} else family
            # fpdf2 stores registered styles by lower-case family/style keys.
            # The production image ships regular and bold DejaVu faces, but not
            # italic. Map unsupported styles to a registered face instead of
            # asking fpdf2 to resolve e.g. ``dejavuI`` and failing the whole PDF.
            if selected == "DejaVu":
                registered = {str(key).lower() for key in pdf.fonts}
                requested = f"{selected}{style}".lower()
                if requested not in registered:
                    bold_key = f"{selected}B".lower()
                    style = "B" if "B" in style and bold_key in registered else ""
            return FPDF.set_font(pdf, selected, style, size)
        pdf.set_font = set_safe_font

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
        kv(pdf, "Total Assets:", report_data['kpi']['total_assets'])
        kv(pdf, "Phishing Threats:", report_data['kpi']['total_phishing'])
        kv(pdf, "Credential Breaches:", report_data['kpi']['total_breaches'])
        kv(pdf, "Active 7d Threats:", report_data['kpi']['active_threats_7d'])
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

        section_heading("EXECUTIVE SUMMARY", "1")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(55, 65, 81)
        pdf.multi_cell(0, 7,
            "The following report summarizes the cybersecurity posture of protected assets as monitored by "
            "the OpenDRP Digital Risk Protection (DRP) platform. It includes an inventory of protected assets, "
            "active phishing and brand-impersonation threats detected via DNS mutation scanning (dnstwist) and Shodan "
            "Hunting, plus credential leaks identified through HaveIBeenPwned integration.\n")
        kpi = report_data['kpi']
        boxes = [
            ("PROTECTED ASSETS", kpi['total_assets'], "Building2"),
            ("PHISHING THREATS", kpi['total_phishing'], "ShieldAlert"),
            ("CREDENTIAL LEAKS", kpi['total_breaches'], "AlertTriangle"),
            ("NEW THREATS (7D)", kpi['active_threats_7d'], "Activity"),
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
        pdf.cell(0, 8, "Asset Criticality Distribution", 0, 1)
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
        headers = ["#", "Asset Value", "Type", "Criticality", "Active"]
        widths = [8, 82, 35, 28, 17]
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        for i, h in enumerate(headers):
            pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
        pdf.ln()
        fill = False
        assets = report_data.get("assets", [])
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
        headers = ["#", "Phishing Domain", "IP", "Source", "Status"]
        widths = [8, 70, 33, 30, 20]
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        for i, h in enumerate(headers):
            pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
        pdf.ln()
        phishing = report_data.get("phishing", [])
        fill = False
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(17, 24, 39)
        for idx, p in enumerate(phishing[:500], 1):
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
        phishing_truncation = (report_data.get("truncation") or {}).get("sections", {}).get("phishing", {})
        if phishing_truncation.get("truncated"):
            pdf.cell(0, 8, f"... truncated at {phishing_truncation.get('included', len(phishing))} rows, total: {phishing_truncation.get('total')}", 0, 1)

        section_heading("CREDENTIAL LEAKS - HAVEIBEENPWNED", "4")
        headers = ["#", "Matched Email", "Breach", "Domain", "Breach Date"]
        widths = [8, 60, 55, 40, 27]
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        for i, h in enumerate(headers):
            pdf.cell(widths[i], 10, str(h), border=1, align="C", fill=True)
        pdf.ln()
        breaches = report_data.get("breaches", [])
        fill = False
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(17, 24, 39)
        for idx, b in enumerate(breaches[:500], 1):
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
            cells = [idx, b.matched_email, b.breach_name, b.domain, str(b.breach_date)]
            for i, c in enumerate(cells):
                align = "L" if i in (1, 2, 3) else "C"
                pdf.cell(widths[i], 8, str(c)[:60], border=1, align=align, fill=True)
            pdf.ln()
            fill = not fill

        breach_truncation = (report_data.get("truncation") or {}).get("sections", {}).get("breaches", {})
        if breach_truncation.get("truncated"):
            pdf.cell(0, 8, f"... truncated at {breach_truncation.get('included', len(breaches))} rows, total: {breach_truncation.get('total')}", 0, 1)

        section_heading("CONCLUSION & RECOMMENDATIONS", "5")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(55, 65, 81)
        pdf.multi_cell(0, 7,
            "SUMMARY: The OpenDRP platform has identified the following security posture:\n"
            f"  - {kpi['total_assets']} digital assets under continuous monitoring.\n"
            f"  - {kpi['total_phishing']} active phishing / brand-impersonation threats detected "
            "(via dnstwist mutation scanning + Shodan Hunting: SSL cert / http.title / favicon hash).\n"
            f"  - {kpi['total_breaches']} credential-leak records linked to protected accounts from HaveIBeenPwned.\n\n"
            "RECOMMENDATIONS:\n"
            " 1. Priority remediation: Investigate CRITICAL phishing domains and initiate abuse reports\n"
            "    with the hosting providers / registrars (see abuse contacts in the Phishing module).\n"
            " 2. Compromised credentials: Force password reset and MFA re-enrollment for breached accounts.\n"
            " 3. Continuous monitoring: Keep DNSTwist (every 6h) and Shodan daily schedules enabled.\n"
            " 4. Alert tuning: Ensure Alert Recipient Email and Telegram integration are configured in System Settings.\n"
            " 5. Review asset inventory: Confirm all high/critical assets are onboarded with correct types.\n"
        )
        pdf.ln(10)
        pdf.set_draw_color(34, 197, 94)
        pdf.set_line_width(0.6)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, f"Report generated by OpenDRP Platform v1.0 on {report_data.get('generated_at_iso', '')[:19]} UTC", 0, 1, align="C")
        pdf.cell(0, 6, f"Initiator: {generated_by_email}", 0, 1, align="C")

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

        data = await self.gather_report_data()
        import asyncio
        loop = asyncio.get_running_loop()
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
        try:
            await asyncio.wait_for(
                asyncio.shield(render_future),
                timeout=settings.REPORT_GENERATION_TIMEOUT_SECONDS,
            )
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
