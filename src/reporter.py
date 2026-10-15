"""Defensible intelligence report generator (Markdown / PDF)."""

from __future__ import annotations

import logging
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.models import Confidence, InvestigationResult

logger = logging.getLogger("osint-engine.reporter")

CLASSIFICATION_BANNER = "UNCLASSIFIED // FOR INVESTIGATIVE USE ONLY"
DISCLAIMER = (
    "This briefing aggregates publicly available information from open sources. "
    "Findings are not assertions of wrongdoing. Confidence tags reflect source "
    "authoritativeness, corroboration, and data freshness. Validate critical "
    "findings against primary records before operational use."
)


class IntelligenceReporter:
    """Format aggregated findings into structured Markdown / PDF briefings."""

    def __init__(self, result: InvestigationResult) -> None:
        self.result = result

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        r = self.result
        lines: list[str] = []

        lines.append(f"# Intelligence Briefing: `{r.target}`")
        lines.append("")
        lines.append(f"**Classification:** {CLASSIFICATION_BANNER}")
        lines.append(f"**Generated (UTC):** {r.completed_at}")
        lines.append(f"**Investigation Window:** {r.started_at} → {r.completed_at}")
        lines.append(f"**Target Type:** {r.target_type.value}")
        lines.append(f"**Overall Confidence:** {r.overall_confidence().value}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(self._executive_summary())
        lines.append("")
        lines.append(f"> {DISCLAIMER}")
        lines.append("")

        lines.append("## 2. Entity Profiles")
        lines.append("")
        for idx, (ident, profile) in enumerate(
            sorted(r.profiles.items(), key=lambda kv: (kv[1].entity_type.value, kv[0])),
            start=1,
        ):
            lines.append(f"### 2.{idx} `{ident}`")
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("| --- | --- |")
            lines.append(f"| Entity Type | {profile.entity_type.value} |")
            lines.append(f"| First Seen | {profile.first_seen or 'N/A'} |")
            lines.append(f"| Last Seen | {profile.last_seen or 'N/A'} |")
            summary = profile.confidence_summary()
            lines.append(
                f"| Confidence Mix | High={summary['High']}, "
                f"Medium={summary['Medium']}, Low={summary['Low']} |"
            )
            related = ", ".join(f"`{x}`" for x in profile.related_identifiers[:15]) or "None"
            lines.append(f"| Related Entities | {related} |")
            lines.append("")
            if profile.notes:
                for note in profile.notes:
                    lines.append(f"- *Note:* {note}")
                lines.append("")
            if profile.findings:
                lines.append(
                    "| ID | Source | Category | Value | Confidence | Timestamp |"
                )
                lines.append("| --- | --- | --- | --- | --- | --- |")
                for f in profile.findings[:40]:
                    val = f.value.replace("|", "\\|")
                    if len(val) > 80:
                        val = val[:77] + "..."
                    lines.append(
                        f"| {f.finding_id} | {f.source.value} | {f.category} | "
                        f"`{val}` | **{f.confidence.value}** | {f.timestamp or 'N/A'} |"
                    )
                if len(profile.findings) > 40:
                    lines.append(
                        f"| … | … | … | *{len(profile.findings) - 40} additional "
                        f"findings truncated* | … | … |"
                    )
                lines.append("")

        # 3. Digital Trace Timeline
        lines.append("## 3. Digital Trace Timeline")
        lines.append("")
        if not r.timeline:
            lines.append("*No timestamped events collected.*")
            lines.append("")
        else:
            lines.append("| Timestamp (UTC) | Event | Entity | Source | Confidence |")
            lines.append("| --- | --- | --- | --- | --- |")
            for event in r.timeline:
                lines.append(
                    f"| {event.timestamp} | {event.description} | `{event.entity}` | "
                    f"{event.source.value} | **{event.confidence.value}** |"
                )
            lines.append("")

        # 4. Link Relationship Map
        lines.append("## 4. Link Relationship Map")
        lines.append("")
        if r.graph_png:
            lines.append(f"![Link Relationship Map]({Path(r.graph_png).name})")
            lines.append("")
        if r.graph_html:
            lines.append(
                f"- Interactive graph: [`{Path(r.graph_html).name}`]({Path(r.graph_html).name})"
            )
            lines.append("")
        if r.edges:
            lines.append("| Source Entity | Relation | Target Entity |")
            lines.append("| --- | --- | --- |")
            for src, dst, rel in r.edges[:100]:
                lines.append(f"| `{src}` | `{rel}` | `{dst}` |")
            if len(r.edges) > 100:
                lines.append(
                    f"| … | *{len(r.edges) - 100} additional edges truncated* | … |"
                )
            lines.append("")
        else:
            lines.append("*No inter-entity relationships identified.*")
            lines.append("")

        # 5. Source Validation & Confidence
        lines.append("## 5. Source Validation & Confidence Scores")
        lines.append("")
        lines.append(
            "Confidence tags follow a defensible rubric suitable for compliance "
            "and federal investigative documentation:"
        )
        lines.append("")
        lines.append("| Tag | Criteria |")
        lines.append("| --- | --- |")
        lines.append(
            "| **High** | Authoritative registry/DNS/CT source; or corroborated "
            "across ≥2 independent sources; data ≤365 days old |"
        )
        lines.append(
            "| **Medium** | Reputable open threat-intel or enrichment API; "
            "single-source observation |"
        )
        lines.append(
            "| **Low** | Derived/inferred link, partial record, or stale (>365 days) data |"
        )
        lines.append("")
        lines.append(self._source_validation_table())
        lines.append("")

        if r.errors:
            lines.append("## 6. Collection Exceptions")
            lines.append("")
            lines.append(
                "The following non-fatal collection errors were recorded and do not "
                "invalidate remaining findings:"
            )
            lines.append("")
            for err in r.errors:
                lines.append(f"- `{err}`")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            "*End of briefing. Generated by OSINT Footprint & Entity Investigation Engine.*"
        )
        lines.append("")
        return "\n".join(lines)

    def write_markdown(self, path: str | Path) -> str:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.to_markdown()
        path.write_text(content, encoding="utf-8")
        logger.info("Wrote Markdown briefing → %s", path)
        return str(path)

    # ------------------------------------------------------------------
    # PDF
    # ------------------------------------------------------------------

    def write_pdf(self, path: str | Path) -> str:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        r = self.result

        doc = SimpleDocTemplate(
            str(path),
            pagesize=LETTER,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title=f"Intelligence Briefing: {r.target}",
        )
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="Banner",
                parent=styles["Normal"],
                fontSize=9,
                textColor=colors.HexColor("#1f4e79"),
                alignment=TA_CENTER,
                spaceAfter=8,
                fontName="Helvetica-Bold",
            )
        )
        styles.add(
            ParagraphStyle(
                name="BriefTitle",
                parent=styles["Heading1"],
                fontSize=16,
                spaceAfter=10,
                textColor=colors.HexColor("#1a1a1a"),
            )
        )
        styles.add(
            ParagraphStyle(
                name="SectionHead",
                parent=styles["Heading2"],
                fontSize=12,
                spaceBefore=14,
                spaceAfter=8,
                textColor=colors.HexColor("#1f4e79"),
            )
        )
        styles.add(
            ParagraphStyle(
                name="BodyJust",
                parent=styles["Normal"],
                fontSize=9,
                leading=12,
                alignment=TA_JUSTIFY,
                spaceAfter=6,
            )
        )
        styles.add(
            ParagraphStyle(
                name="Small",
                parent=styles["Normal"],
                fontSize=8,
                leading=10,
                alignment=TA_LEFT,
            )
        )

        story: list = []
        story.append(Paragraph(CLASSIFICATION_BANNER, styles["Banner"]))
        story.append(Paragraph(f"Intelligence Briefing: {r.target}", styles["BriefTitle"]))
        meta = (
            f"<b>Generated (UTC):</b> {r.completed_at}<br/>"
            f"<b>Window:</b> {r.started_at} → {r.completed_at}<br/>"
            f"<b>Target Type:</b> {r.target_type.value}<br/>"
            f"<b>Overall Confidence:</b> {r.overall_confidence().value}"
        )
        story.append(Paragraph(meta, styles["Small"]))
        story.append(Spacer(1, 8))

        story.append(Paragraph("1. Executive Summary", styles["SectionHead"]))
        story.append(Paragraph(self._executive_summary(), styles["BodyJust"]))
        story.append(Paragraph(f"<i>{DISCLAIMER}</i>", styles["Small"]))

        story.append(Paragraph("2. Entity Profiles", styles["SectionHead"]))
        for ident, profile in sorted(
            r.profiles.items(), key=lambda kv: (kv[1].entity_type.value, kv[0])
        )[:25]:
            story.append(
                Paragraph(
                    f"<b>{_pdf_escape(ident)}</b> ({profile.entity_type.value})",
                    styles["Small"],
                )
            )
            summary = profile.confidence_summary()
            rows = [
                ["Field", "Value"],
                ["First Seen", profile.first_seen or "N/A"],
                ["Last Seen", profile.last_seen or "N/A"],
                [
                    "Confidence",
                    f"H={summary['High']} M={summary['Medium']} L={summary['Low']}",
                ],
                ["Findings", str(len(profile.findings))],
            ]
            table = Table(rows, colWidths=[1.4 * inch, 5.2 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f5f5f5")],
                        ),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 6))

        story.append(Paragraph("3. Digital Trace Timeline", styles["SectionHead"]))
        if r.timeline:
            trows = [["Timestamp", "Event", "Source", "Conf."]]
            for event in r.timeline[:40]:
                trows.append(
                    [
                        event.timestamp,
                        _pdf_escape(event.description[:90]),
                        event.source.value,
                        event.confidence.value,
                    ]
                )
            ttable = Table(
                trows, colWidths=[1.4 * inch, 3.6 * inch, 0.9 * inch, 0.7 * inch]
            )
            ttable.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(ttable)
        else:
            story.append(Paragraph("No timestamped events collected.", styles["Small"]))

        story.append(Paragraph("4. Link Relationship Map", styles["SectionHead"]))
        if r.graph_png and Path(r.graph_png).exists():
            try:
                img = Image(r.graph_png, width=6.5 * inch, height=4.5 * inch)
                story.append(img)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not embed PNG in PDF: %s", exc)
                story.append(
                    Paragraph(f"Chart path: {r.graph_png}", styles["Small"])
                )
        if r.edges:
            erows = [["Source", "Relation", "Target"]]
            for src, dst, rel in r.edges[:35]:
                erows.append(
                    [_pdf_escape(src)[:40], rel, _pdf_escape(dst)[:40]]
                )
            etable = Table(erows, colWidths=[2.4 * inch, 1.6 * inch, 2.4 * inch])
            etable.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                    ]
                )
            )
            story.append(Spacer(1, 6))
            story.append(etable)

        story.append(PageBreak())
        story.append(
            Paragraph("5. Source Validation & Confidence Scores", styles["SectionHead"])
        )
        story.append(
            Paragraph(
                "High = authoritative or corroborated; Medium = single open TI/enrichment "
                "source; Low = derived, partial, or stale (&gt;365 days).",
                styles["BodyJust"],
            )
        )
        story.append(Paragraph(self._source_validation_html(), styles["Small"]))

        if r.errors:
            story.append(Paragraph("6. Collection Exceptions", styles["SectionHead"]))
            for err in r.errors:
                story.append(Paragraph(f"• {_pdf_escape(err)}", styles["Small"]))

        story.append(Spacer(1, 16))
        story.append(
            Paragraph(
                "End of briefing — OSINT Footprint &amp; Entity Investigation Engine",
                styles["Banner"],
            )
        )

        doc.build(story)
        logger.info("Wrote PDF briefing → %s", path)
        return str(path)

    # ------------------------------------------------------------------
    # Shared narrative helpers
    # ------------------------------------------------------------------

    def _executive_summary(self) -> str:
        r = self.result
        n_profiles = len(r.profiles)
        n_findings = sum(len(p.findings) for p in r.profiles.values())
        n_edges = len(r.edges)
        n_events = len(r.timeline)
        high = sum(
            1
            for p in r.profiles.values()
            for f in p.findings
            if f.confidence == Confidence.HIGH
        )
        threat_hits = sum(
            1
            for p in r.profiles.values()
            for f in p.findings
            if f.category in ("threat_ioc", "malware_url")
            and "No " not in f.value
            and "no_results" not in str(f.metadata.get("status", ""))
        )
        parts = [
            f"Investigation of target `{r.target}` ({r.target_type.value}) produced "
            f"{n_profiles} entity profile(s), {n_findings} normalized finding(s), "
            f"{n_edges} relationship edge(s), and {n_events} timeline event(s).",
            f"Overall assessment confidence is **{r.overall_confidence().value}** "
            f"({high} High-confidence finding(s)).",
        ]
        if threat_hits:
            parts.append(
                f"**Threat-indicator hits:** {threat_hits} open-source IOC/URL "
                f"association(s) warrant analyst review."
            )
        else:
            parts.append(
                "No affirmative malware/IOC associations were confirmed in ThreatFox "
                "or URLhaus for the primary host at time of collection."
            )
        if r.errors:
            parts.append(
                f"{len(r.errors)} non-fatal collection exception(s) were logged "
                f"(see Collection Exceptions)."
            )
        return " ".join(parts)

    def _source_validation_table(self) -> str:
        counts: dict[str, dict[str, int]] = {}
        for profile in self.result.profiles.values():
            for f in profile.findings:
                src = f.source.value
                counts.setdefault(src, {"High": 0, "Medium": 0, "Low": 0, "total": 0})
                counts[src][f.confidence.value] += 1
                counts[src]["total"] += 1
        if not counts:
            return "*No sources queried successfully.*"
        rows = [
            "| Source | Findings | High | Medium | Low | Validation Notes |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        notes = {
            "WHOIS": "Registry / registrar RDAP-equivalent; authoritative for registration",
            "DNS": "Live resolution via recursive DNS; authoritative for current mapping",
            "crt.sh": "Public Certificate Transparency logs; high integrity historical SANs",
            "ThreatFox": "abuse.ch community TI; medium pending corroboration",
            "URLhaus": "abuse.ch malware URL corpus; medium pending corroboration",
            "ip-api": "Commercial geo/ASN enrichment (free tier); medium confidence",
            "Derived": "Inferred by correlation engine; requires analyst validation",
        }
        for src, c in sorted(counts.items()):
            rows.append(
                f"| {src} | {c['total']} | {c['High']} | {c['Medium']} | {c['Low']} | "
                f"{notes.get(src, 'Open-source collector')} |"
            )
        return "\n".join(rows)

    def _source_validation_html(self) -> str:
        """HTML-ish paragraph list for ReportLab."""
        md = self._source_validation_table()
        lines = []
        for line in md.splitlines():
            if line.startswith("| Source") or line.startswith("| ---"):
                continue
            if line.startswith("|"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                if len(cells) >= 6:
                    lines.append(
                        f"<b>{_pdf_escape(cells[0])}</b>: {cells[1]} findings "
                        f"(H{cells[2]}/M{cells[3]}/L{cells[4]}) — {_pdf_escape(cells[5])}"
                    )
        return "<br/>".join(lines) if lines else "No sources queried successfully."


def _pdf_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
