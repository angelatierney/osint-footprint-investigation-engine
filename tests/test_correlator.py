"""Unit tests for entity correlation and graph export."""

from pathlib import Path

from src.correlator import LinkCorrelator, build_edges_from_profiles
from src.models import (
    Confidence,
    EntityProfile,
    EntityType,
    Finding,
    SourceName,
    TimelineEvent,
)


def _sample_profiles() -> dict[str, EntityProfile]:
    domain = EntityProfile(identifier="example.com", entity_type=EntityType.DOMAIN)
    ip = EntityProfile(identifier="93.184.216.34", entity_type=EntityType.IP)
    sub = EntityProfile(identifier="www.example.com", entity_type=EntityType.SUBDOMAIN)

    domain.related_identifiers = ["93.184.216.34", "www.example.com"]
    domain.add_finding(
        Finding(
            source=SourceName.DNS,
            category="resolves_to",
            value="93.184.216.34",
            confidence=Confidence.HIGH,
            timestamp="2024-06-01T00:00:00Z",
        )
    )
    domain.add_finding(
        Finding(
            source=SourceName.CRTSH,
            category="ssl_san",
            value="www.example.com",
            confidence=Confidence.HIGH,
            timestamp="2024-05-01T00:00:00Z",
        )
    )
    # Same IP observed via second source → corroboration candidate
    ip.add_finding(
        Finding(
            source=SourceName.IP_API,
            category="geo_country",
            value="United States",
            confidence=Confidence.MEDIUM,
            timestamp="2024-06-01T00:00:00Z",
        )
    )
    ip.add_finding(
        Finding(
            source=SourceName.DNS,
            category="linked_from_resolves_to",
            value="example.com",
            confidence=Confidence.HIGH,
            timestamp="2024-06-01T00:00:00Z",
        )
    )
    # Value shared across sources for corroboration
    domain.add_finding(
        Finding(
            source=SourceName.WHOIS,
            category="registrar",
            value="Example Registrar",
            confidence=Confidence.MEDIUM,
            timestamp="2024-01-01T00:00:00Z",
        )
    )
    domain.add_finding(
        Finding(
            source=SourceName.CRTSH,
            category="ssl_issuer_org",
            value="Example Registrar",
            confidence=Confidence.LOW,
            timestamp="2024-01-01T00:00:00Z",
        )
    )
    return {
        "example.com": domain,
        "93.184.216.34": ip,
        "www.example.com": sub,
    }


class TestLinkCorrelator:
    def test_builds_edges(self):
        edges = build_edges_from_profiles(_sample_profiles())
        pairs = {(s, t) for s, t, _ in edges}
        assert ("example.com", "93.184.216.34") in pairs
        assert ("example.com", "www.example.com") in pairs

    def test_timeline_sorted(self):
        correlator = LinkCorrelator()
        timeline = [
            TimelineEvent(
                timestamp="2024-06-01T00:00:00Z",
                event_type="dns",
                description="later",
                source=SourceName.DNS,
                confidence=Confidence.HIGH,
                entity="example.com",
            ),
            TimelineEvent(
                timestamp="2023-01-01T00:00:00Z",
                event_type="whois",
                description="earlier",
                source=SourceName.WHOIS,
                confidence=Confidence.HIGH,
                entity="example.com",
            ),
        ]
        result = correlator.correlate(
            target="example.com",
            target_type=EntityType.DOMAIN,
            profiles=_sample_profiles(),
            timeline=timeline,
        )
        assert result.timeline[0].description == "earlier"
        assert result.timeline[-1].description == "later"

    def test_corroboration_raises_confidence(self):
        correlator = LinkCorrelator()
        profiles = _sample_profiles()
        # Before: one finding for "Example Registrar" is LOW
        low_before = [
            f
            for f in profiles["example.com"].findings
            if f.value == "Example Registrar" and f.confidence == Confidence.LOW
        ]
        assert low_before
        correlator.correlate(
            target="example.com",
            target_type=EntityType.DOMAIN,
            profiles=profiles,
            timeline=[],
        )
        registrar_findings = [
            f
            for f in profiles["example.com"].findings
            if f.value == "Example Registrar"
        ]
        assert any(f.confidence == Confidence.HIGH for f in registrar_findings) or any(
            "corroborated_sources" in f.metadata for f in registrar_findings
        )

    def test_export_png(self, tmp_path: Path):
        correlator = LinkCorrelator()
        correlator.correlate(
            target="example.com",
            target_type=EntityType.DOMAIN,
            profiles=_sample_profiles(),
            timeline=[],
        )
        out = tmp_path / "chart.png"
        path = correlator.export_png(out)
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0

    def test_export_html(self, tmp_path: Path):
        correlator = LinkCorrelator()
        correlator.correlate(
            target="example.com",
            target_type=EntityType.DOMAIN,
            profiles=_sample_profiles(),
            timeline=[],
        )
        out = tmp_path / "chart.html"
        path = correlator.export_html(out)
        assert Path(path).exists()
        content = Path(path).read_text(encoding="utf-8")
        assert "example.com" in content or "vis" in content.lower()

    def test_overall_confidence_on_result(self):
        correlator = LinkCorrelator()
        result = correlator.correlate(
            target="example.com",
            target_type=EntityType.DOMAIN,
            profiles=_sample_profiles(),
            timeline=[],
        )
        assert result.overall_confidence() in (
            Confidence.HIGH,
            Confidence.MEDIUM,
            Confidence.LOW,
        )
