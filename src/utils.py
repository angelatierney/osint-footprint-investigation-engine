"""Shared helpers: logging, target classification, confidence scoring, parsing."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from src.models import Confidence, EntityType, SourceName

# Well-known public/authoritative sources → baseline confidence
SOURCE_CONFIDENCE: dict[SourceName, Confidence] = {
    SourceName.WHOIS: Confidence.HIGH,
    SourceName.DNS: Confidence.HIGH,
    SourceName.CRTSH: Confidence.HIGH,
    SourceName.THREATFOX: Confidence.MEDIUM,
    SourceName.URLHAUS: Confidence.MEDIUM,
    SourceName.IP_API: Confidence.MEDIUM,
    SourceName.DERIVED: Confidence.LOW,
}

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9_]{3,32}$")


def setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger("osint-engine")


def classify_target(target: str) -> EntityType:
    """Classify an investigative target string into an entity type."""
    value = target.strip()
    if not value:
        return EntityType.UNKNOWN
    if IPV4_RE.match(value):
        return EntityType.IP
    if EMAIL_RE.match(value):
        return EntityType.EMAIL
    if DOMAIN_RE.match(value.lower()):
        return EntityType.DOMAIN
    if value.startswith("@") or USERNAME_RE.match(value):
        return EntityType.USERNAME
    # Multi-word or capitalized org names
    if " " in value or (value[0].isupper() and not DOMAIN_RE.match(value.lower())):
        return EntityType.ORGANIZATION
    if USERNAME_RE.match(value):
        return EntityType.USERNAME
    return EntityType.ORGANIZATION


def score_confidence(
    source: SourceName,
    *,
    corroborated: bool = False,
    stale_days: Optional[int] = None,
    partial: bool = False,
) -> Confidence:
    """
    Calculate a confidence tag for a finding.

    Rules (defensible for compliance briefs):
    - Start from source baseline (authoritative registries = High).
    - Corroboration across independent sources raises Medium → High.
    - Stale data (>365 days) or partial/incomplete records downgrade one tier.
    """
    baseline = SOURCE_CONFIDENCE.get(source, Confidence.LOW)
    order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    idx = order.index(baseline)

    if corroborated and idx < 2:
        idx += 1
    if partial and idx > 0:
        idx -= 1
    if stale_days is not None and stale_days > 365 and idx > 0:
        idx -= 1

    return order[idx]


def confidence_from_ratio(high: int, medium: int, low: int) -> Confidence:
    """Aggregate numeric confidence counts into a single tag."""
    total = high + medium + low
    if total == 0:
        return Confidence.LOW
    if high / total >= 0.5:
        return Confidence.HIGH
    if (high + medium) / total >= 0.5:
        return Confidence.MEDIUM
    return Confidence.LOW


def parse_timestamp(value: Any) -> Optional[str]:
    """Normalize heterogeneous timestamp values to ISO-8601 UTC strings."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    text = str(value).strip().replace("+00:00", "Z")
    if text.endswith(".0"):
        text = text[:-2]

    candidates = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in candidates:
        try:
            trial = text
            if fmt.endswith("Z") and not trial.endswith("Z"):
                continue
            if not fmt.endswith("Z") and trial.endswith("Z"):
                trial = trial[:-1]
            dt = datetime.strptime(trial, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return text[:32] if text else None


def days_since(iso_ts: Optional[str]) -> Optional[int]:
    """Return whole days elapsed since an ISO timestamp, or None."""
    if not iso_ts:
        return None
    try:
        cleaned = iso_ts.rstrip("Z")
        dt = datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


def flatten_list(value: Any) -> list[str]:
    """Coerce WHOIS-style scalar-or-list fields into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if v is not None and str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name.strip())[:120]
