#!/usr/bin/env python3
"""
OSINT Footprint & Entity Investigation Engine — CLI orchestrator.

Example:
    python main.py --target example.com --output reports/example_brief.md
    python main.py --target example.com --format both --graph both -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from src import __app_name__, __version__
from src.correlator import LinkCorrelator
from src.ingestion import DataIngester
from src.models import utc_now_iso
from src.reporter import IntelligenceReporter
from src.utils import classify_target, sanitize_filename, setup_logging


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target entity: domain, IP, email, username, or organization name.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(),
    help="Output path for the intelligence briefing (default: reports/<target>_brief.md).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["md", "pdf", "both"], case_sensitive=False),
    default="md",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--graph",
    type=click.Choice(["png", "html", "both", "none"], case_sensitive=False),
    default="both",
    show_default=True,
    help="Link-relationship chart export format.",
)
@click.option(
    "--json-export",
    "json_export",
    default=None,
    type=click.Path(),
    help="Optional path to dump the raw InvestigationResult as JSON.",
)
@click.option(
    "--timeout",
    default=20,
    show_default=True,
    type=int,
    help="HTTP/DNS timeout in seconds per source request.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable debug logging.",
)
@click.version_option(version=__version__, prog_name=__app_name__)
def main(
    target: str,
    output: str | None,
    fmt: str,
    graph: str,
    json_export: str | None,
    timeout: int,
    verbose: bool,
) -> None:
    """Automated OSINT collection, correlation, and intelligence report generation."""
    logger = setup_logging(verbose=verbose)
    target = target.strip()
    if not target:
        raise click.ClickException("Target must be a non-empty string.")

    target_type = classify_target(target)
    started_at = utc_now_iso()
    safe = sanitize_filename(target)
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    if output is None:
        output = str(reports_dir / f"{safe}_brief.md")
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stem = output_path.with_suffix("")

    click.echo(f"{__app_name__} v{__version__}")
    click.echo(f"Target: {target}  |  Classified as: {target_type.value}")
    click.echo("-" * 60)

    # --- Phase 1: Ingestion ---
    logger.info("Phase 1/3 — Data ingestion")
    click.echo("[1/3] Ingesting public OSINT sources…")
    ingester = DataIngester(timeout=timeout)
    try:
        payload = ingester.ingest(target, target_type)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Fatal ingestion failure")
        raise click.ClickException(f"Ingestion failed: {exc}") from exc

    profiles = payload["profiles"]
    timeline = payload["timeline"]
    errors = payload["errors"]
    click.echo(
        f"      Profiles={len(profiles)}  Timeline events={len(timeline)}  "
        f"Source errors={len(errors)}"
    )

    # --- Phase 2: Correlation & charts ---
    logger.info("Phase 2/3 — Correlation & link charting")
    click.echo("[2/3] Correlating entities and building link chart…")
    correlator = LinkCorrelator()
    result = correlator.correlate(
        target=target,
        target_type=target_type,
        profiles=profiles,
        timeline=timeline,
        errors=errors,
        started_at=started_at,
    )
    stats = correlator.graph_stats()
    click.echo(
        f"      Graph nodes={stats['nodes']}  edges={stats['edges']}  "
        f"density={stats['density']}"
    )

    if graph in ("png", "both"):
        png_path = stem.with_name(stem.name + "_linkchart.png")
        result.graph_png = correlator.export_png(
            png_path, title=f"Link Map: {target}"
        )
        click.echo(f"      PNG chart → {result.graph_png}")
    if graph in ("html", "both"):
        html_path = stem.with_name(stem.name + "_linkchart.html")
        result.graph_html = correlator.export_html(
            html_path, title=f"Link Map: {target}"
        )
        click.echo(f"      HTML chart → {result.graph_html}")

    # --- Phase 3: Reporting ---
    logger.info("Phase 3/3 — Intelligence briefing")
    click.echo("[3/3] Generating intelligence briefing…")
    reporter = IntelligenceReporter(result)
    written: list[str] = []

    if fmt in ("md", "both"):
        md_path = output_path if output_path.suffix.lower() in {".md", ".markdown"} else Path(str(stem) + ".md")
        written.append(reporter.write_markdown(md_path))
        click.echo(f"      Markdown → {md_path}")

    if fmt in ("pdf", "both"):
        pdf_path = (
            output_path
            if output_path.suffix.lower() == ".pdf"
            else Path(str(stem) + ".pdf")
        )
        written.append(reporter.write_pdf(pdf_path))
        click.echo(f"      PDF → {pdf_path}")

    if json_export:
        jp = Path(json_export)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        click.echo(f"      JSON → {jp}")

    click.echo("-" * 60)
    click.echo(
        f"Done. Overall confidence: {result.overall_confidence().value}  |  "
        f"Outputs: {', '.join(written)}"
    )
    if errors:
        click.echo(
            f"Note: {len(errors)} non-fatal source error(s) recorded in the briefing."
        )


if __name__ == "__main__":
    try:
        main()
    except click.ClickException as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nAborted by user.", err=True)
        sys.exit(130)
