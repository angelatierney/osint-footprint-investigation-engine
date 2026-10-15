"""Standardized entity models for OSINT data normalization."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4


class Confidence(str, Enum):
    """Source-derived confidence tagging for investigative findings."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class EntityType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    USERNAME = "username"
    ORGANIZATION = "organization"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    SUBDOMAIN = "subdomain"
    NAMESERVER = "nameserver"
    UNKNOWN = "unknown"


class SourceName(str, Enum):
    WHOIS = "WHOIS"
    CRTSH = "crt.sh"
    DNS = "DNS"
    THREATFOX = "ThreatFox"
    URLHAUS = "URLhaus"
    IP_API = "ip-api"
    DERIVED = "Derived"


@dataclass
class Finding:
    """A single normalized OSINT finding with provenance."""

    source: SourceName
    category: str
    value: str
    confidence: Confidence
    timestamp: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid4())[:8])

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["source"] = self.source.value
        data["confidence"] = self.confidence.value
        return data


@dataclass
class EntityProfile:
    """Normalized profile for an investigated or correlated entity."""

    identifier: str
    entity_type: EntityType
    findings: list[Finding] = field(default_factory=list)
    related_identifiers: list[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        ts = finding.timestamp
        if ts:
            if not self.first_seen or ts < self.first_seen:
                self.first_seen = ts
            if not self.last_seen or ts > self.last_seen:
                self.last_seen = ts

    def confidence_summary(self) -> dict[str, int]:
        summary = {c.value: 0 for c in Confidence}
        for f in self.findings:
            summary[f.confidence.value] += 1
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "entity_type": self.entity_type.value,
            "findings": [f.to_dict() for f in self.findings],
            "related_identifiers": self.related_identifiers,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "notes": self.notes,
            "confidence_summary": self.confidence_summary(),
        }


@dataclass
class TimelineEvent:
    """Chronological digital-trace event."""

    timestamp: str
    event_type: str
    description: str
    source: SourceName
    confidence: Confidence
    entity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "source": self.source.value,
            "confidence": self.confidence.value,
            "entity": self.entity,
        }


@dataclass
class InvestigationResult:
    """Aggregate output of a full investigation run."""

    target: str
    target_type: EntityType
    started_at: str
    completed_at: str
    profiles: dict[str, EntityProfile] = field(default_factory=dict)
    timeline: list[TimelineEvent] = field(default_factory=list)
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    graph_png: Optional[str] = None
    graph_html: Optional[str] = None

    def overall_confidence(self) -> Confidence:
        """Roll up confidence from all findings."""
        counts = {Confidence.HIGH: 0, Confidence.MEDIUM: 0, Confidence.LOW: 0}
        for profile in self.profiles.values():
            for finding in profile.findings:
                counts[finding.confidence] += 1
        total = sum(counts.values())
        if total == 0:
            return Confidence.LOW
        if counts[Confidence.HIGH] / total >= 0.5:
            return Confidence.HIGH
        if (counts[Confidence.HIGH] + counts[Confidence.MEDIUM]) / total >= 0.5:
            return Confidence.MEDIUM
        return Confidence.LOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "overall_confidence": self.overall_confidence().value,
            "profiles": {k: v.to_dict() for k, v in self.profiles.items()},
            "timeline": [e.to_dict() for e in self.timeline],
            "edges": [
                {"source": s, "target": t, "relation": r} for s, t, r in self.edges
            ],
            "errors": self.errors,
            "graph_png": self.graph_png,
            "graph_html": self.graph_html,
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
