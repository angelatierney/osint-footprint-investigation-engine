"""Unit tests for confidence scoring and target classification."""

from src.models import Confidence, EntityType, SourceName
from src.utils import (
    classify_target,
    confidence_from_ratio,
    parse_timestamp,
    score_confidence,
)


class TestClassifyTarget:
    def test_domain(self):
        assert classify_target("example.com") == EntityType.DOMAIN
        assert classify_target("sub.example.co.uk") == EntityType.DOMAIN

    def test_ip(self):
        assert classify_target("8.8.8.8") == EntityType.IP
        assert classify_target("192.168.1.1") == EntityType.IP

    def test_email(self):
        assert classify_target("admin@example.com") == EntityType.EMAIL

    def test_username(self):
        assert classify_target("@osint_analyst") == EntityType.USERNAME
        assert classify_target("threat_hunter42") == EntityType.USERNAME

    def test_organization(self):
        assert classify_target("Acme Corporation") == EntityType.ORGANIZATION


class TestScoreConfidence:
    def test_whois_baseline_high(self):
        assert score_confidence(SourceName.WHOIS) == Confidence.HIGH

    def test_threatfox_baseline_medium(self):
        assert score_confidence(SourceName.THREATFOX) == Confidence.MEDIUM

    def test_derived_baseline_low(self):
        assert score_confidence(SourceName.DERIVED) == Confidence.LOW

    def test_corroboration_raises_medium_to_high(self):
        assert (
            score_confidence(SourceName.THREATFOX, corroborated=True)
            == Confidence.HIGH
        )

    def test_stale_data_downgrades(self):
        assert (
            score_confidence(SourceName.WHOIS, stale_days=400) == Confidence.MEDIUM
        )

    def test_partial_downgrades(self):
        assert score_confidence(SourceName.DNS, partial=True) == Confidence.MEDIUM

    def test_stale_and_partial_floor_at_low(self):
        assert (
            score_confidence(SourceName.URLHAUS, stale_days=500, partial=True)
            == Confidence.LOW
        )


class TestConfidenceFromRatio:
    def test_majority_high(self):
        assert confidence_from_ratio(6, 2, 1) == Confidence.HIGH

    def test_majority_medium_band(self):
        assert confidence_from_ratio(2, 4, 2) == Confidence.MEDIUM

    def test_majority_low(self):
        assert confidence_from_ratio(0, 1, 5) == Confidence.LOW

    def test_empty(self):
        assert confidence_from_ratio(0, 0, 0) == Confidence.LOW


class TestParseTimestamp:
    def test_iso_z(self):
        assert parse_timestamp("2024-01-15T12:30:00Z") == "2024-01-15T12:30:00Z"

    def test_date_only(self):
        assert parse_timestamp("2024-01-15") == "2024-01-15T00:00:00Z"

    def test_none(self):
        assert parse_timestamp(None) is None
        assert parse_timestamp("") is None
