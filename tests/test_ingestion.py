"""Unit tests for source parsing and ingestion helpers."""

import responses

from src.ingestion import DataIngester, parse_crtsh_records
from src.models import Confidence, EntityType, SourceName
from src.utils import flatten_list


SAMPLE_CRTSH = [
    {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "not_before": "2024-06-01T00:00:00",
        "serial_number": "abc123",
    },
    {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "mail.example.com",
        "name_value": "mail.example.com",
        "not_before": "2023-01-01T00:00:00",
        "serial_number": "def456",
    },
]


class TestParseCrtshRecords:
    def test_extracts_sans_and_domains(self):
        findings = parse_crtsh_records(SAMPLE_CRTSH, "example.com")
        values = {f.value for f in findings}
        assert "example.com" in values
        assert "www.example.com" in values
        assert "mail.example.com" in values

    def test_confidence_is_high(self):
        findings = parse_crtsh_records(SAMPLE_CRTSH, "example.com")
        assert all(f.confidence == Confidence.HIGH for f in findings)
        assert all(f.source == SourceName.CRTSH for f in findings)

    def test_deduplicates_identical_names(self):
        dupes = SAMPLE_CRTSH + [SAMPLE_CRTSH[0]]
        findings = parse_crtsh_records(dupes, "example.com")
        # same name+serial should collapse
        www = [f for f in findings if f.value == "www.example.com"]
        assert len(www) == 1

    def test_empty_input(self):
        assert parse_crtsh_records([], "example.com") == []


class TestFlattenList:
    def test_scalar(self):
        assert flatten_list("Acme") == ["Acme"]

    def test_list(self):
        assert flatten_list(["a", "b"]) == ["a", "b"]

    def test_none(self):
        assert flatten_list(None) == []


class TestDataIngesterCrtsh:
    @responses.activate
    def test_crtsh_populates_subdomains(self):
        responses.add(
            responses.GET,
            "https://crt.sh/",
            json=SAMPLE_CRTSH,
            status=200,
        )
        # Stub other endpoints lightly so ingest doesn't fail loudly
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query_status": "no_result"},
            status=200,
        )
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            json={"query_status": "no_results"},
            status=200,
        )

        ingester = DataIngester(timeout=5)
        # Call CT collector directly to avoid live WHOIS/DNS
        profiles: dict = {}
        timeline: list = []
        ingester._ingest_crtsh("example.com", profiles, timeline)

        assert "example.com" in profiles
        related = profiles["example.com"].related_identifiers
        assert "www.example.com" in related or "mail.example.com" in related
        assert any(e.event_type == "certificate_issued" for e in timeline)

    @responses.activate
    def test_threatfox_no_results_records_clean_finding(self):
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query_status": "no_result"},
            status=200,
        )
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            json={"query_status": "no_results"},
            status=200,
        )
        ingester = DataIngester(timeout=5, abusech_api_key="test-key")
        profiles: dict = {}
        timeline: list = []
        ingester._ingest_threat_indicators("example.com", profiles, timeline)
        findings = profiles["example.com"].findings
        assert any("No ThreatFox" in f.value for f in findings)

    def test_threat_indicators_skipped_without_api_key(self):
        ingester = DataIngester(timeout=5, abusech_api_key="")
        # Force empty key even if env is set
        ingester.abusech_api_key = None
        profiles: dict = {}
        timeline: list = []
        ingester._ingest_threat_indicators("example.com", profiles, timeline)
        assert any(
            "ABUSECH_API_KEY" in f.value for f in profiles["example.com"].findings
        )

    def test_resolve_domain_from_email(self):
        ingester = DataIngester()
        assert (
            ingester._resolve_domain("admin@Example.COM", EntityType.EMAIL)
            == "example.com"
        )
