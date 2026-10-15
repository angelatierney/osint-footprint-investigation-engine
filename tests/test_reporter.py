"""Unit tests for intelligence briefing generation."""

from pathlib import Path

from src.models import (
    Confidence,
    EntityProfile,
    EntityType,
    Finding,
    InvestigationResult,
    SourceName,
    TimelineEvent,
)
from src.reporter import CLASSIFICATION_BANNER, IntelligenceReporter


def _sample_result() -> InvestigationResult:
    profile = EntityProfile(identifier="example.com", entity_type=EntityType.DOMAIN)
    profile.add_finding(
        Finding(
            source=SourceName.WHOIS,
            category="registrar",
            value="Example Registrar Inc.",
            confidence=Confidence.HIGH,
            timestamp="2020-01-01T00:00:00Z",
        )
    )
    profile.add_finding(
        Finding(
            source=SourceName.DNS,
            category="dns_a",
            value="93.184.216.34",
            confidence=Confidence.HIGH,
            timestamp="2024-06-01T00:00:00Z",
        )
    )
    profile.related_identifiers = ["93.184.216.34"]

    return InvestigationResult(
        target="example.com",
        target_type=EntityType.DOMAIN,
        started_at="2024-06-01T12:00:00Z",
        completed_at="2024-06-01T12:05:00Z",
        profiles={"example.com": profile},
        timeline=[
            TimelineEvent(
                timestamp="2020-01-01T00:00:00Z",
                event_type="domain_registration",
                description="Domain example.com registered",
                source=SourceName.WHOIS,
                confidence=Confidence.HIGH,
                entity="example.com",
            )
        ],
        edges=[("example.com", "93.184.216.34", "resolves_to")],
        errors=[],
    )


class TestIntelligenceReporter:
    def test_markdown_contains_required_sections(self):
        md = IntelligenceReporter(_sample_result()).to_markdown()
        assert CLASSIFICATION_BANNER in md
        assert "## 1. Executive Summary" in md
        assert "## 2. Entity Profiles" in md
        assert "## 3. Digital Trace Timeline" in md
        assert "## 4. Link Relationship Map" in md
        assert "## 5. Source Validation & Confidence Scores" in md
        assert "example.com" in md
        assert "**High**" in md or "High" in md

    def test_write_markdown(self, tmp_path: Path):
        out = tmp_path / "brief.md"
        path = IntelligenceReporter(_sample_result()).write_markdown(out)
        assert Path(path).exists()
        text = Path(path).read_text(encoding="utf-8")
        assert "Intelligence Briefing" in text

    def test_write_pdf(self, tmp_path: Path):
        out = tmp_path / "brief.pdf"
        path = IntelligenceReporter(_sample_result()).write_pdf(out)
        assert Path(path).exists()
        assert Path(path).stat().st_size > 500

    def test_executive_summary_mentions_counts(self):
        reporter = IntelligenceReporter(_sample_result())
        summary = reporter._executive_summary()
        assert "1 entity profile" in summary or "1 entity profile(s)" in summary
        assert "Overall assessment confidence" in summary
