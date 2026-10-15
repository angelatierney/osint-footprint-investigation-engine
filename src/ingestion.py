"""Data ingestion & scraping from open OSINT endpoints."""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import dns.exception
import dns.resolver
import requests
import whois

from src.models import (
    Confidence,
    EntityProfile,
    EntityType,
    Finding,
    SourceName,
    TimelineEvent,
    utc_now_iso,
)
from src.utils import (
    days_since,
    flatten_list,
    parse_timestamp,
    score_confidence,
)

logger = logging.getLogger("osint-engine.ingestion")

USER_AGENT = "OSINT-Footprint-Engine/1.0 (+investigative-research; respectful)"
DEFAULT_TIMEOUT = 20
CRTSH_URL = "https://crt.sh/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
IP_API_URL = "http://ip-api.com/json/{ip}"


class IngestionError(Exception):
    """Raised when a source fetch fails in a non-recoverable way."""


class DataIngester:
    """
    Fetch and normalize public digital-footprint data for a target entity.

    Sources (all open / unauthenticated where possible):
      - WHOIS registry data
      - Certificate Transparency (crt.sh)
      - DNS resource records
      - ThreatFox / URLhaus public threat indicators
      - ip-api geolocation enrichment for resolved IPs
    """

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        timeout: int = DEFAULT_TIMEOUT,
        abusech_api_key: Optional[str] = None,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", USER_AGENT)
        self.timeout = timeout
        self.errors: list[str] = []
        # abuse.ch APIs require a free Auth-Key (https://auth.abuse.ch/)
        self.abusech_api_key = (
            abusech_api_key
            or os.environ.get("ABUSECH_API_KEY")
            or os.environ.get("AUTH_KEY")
        )
        if self.abusech_api_key:
            self.session.headers.setdefault("Auth-Key", self.abusech_api_key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, target: str, target_type: EntityType) -> dict[str, Any]:
        """
        Run all applicable collectors and return a raw investigation payload.

        Returns:
            {
              "profiles": dict[str, EntityProfile],
              "timeline": list[TimelineEvent],
              "errors": list[str],
            }
        """
        self.errors = []
        profiles: dict[str, EntityProfile] = {}
        timeline: list[TimelineEvent] = []

        primary = EntityProfile(identifier=target, entity_type=target_type)
        profiles[target] = primary

        domain = self._resolve_domain(target, target_type)
        if domain:
            logger.info("Collecting WHOIS for %s", domain)
            self._ingest_whois(domain, profiles, timeline)

            logger.info("Collecting Certificate Transparency for %s", domain)
            self._ingest_crtsh(domain, profiles, timeline)

            logger.info("Collecting DNS records for %s", domain)
            self._ingest_dns(domain, profiles, timeline)

            logger.info("Collecting threat indicators for %s", domain)
            self._ingest_threat_indicators(domain, profiles, timeline)
        elif target_type == EntityType.IP:
            logger.info("Collecting IP enrichment for %s", target)
            self._ingest_ip_enrichment(target, profiles, timeline)
            self._ingest_threat_indicators(target, profiles, timeline)
        elif target_type in (EntityType.USERNAME, EntityType.ORGANIZATION):
            # Domain-less targets: search crt.sh by organization / name string
            logger.info("Running name-based CT search for %s", target)
            self._ingest_crtsh_query(target, profiles, timeline)
            primary.notes.append(
                "Target is not a resolvable domain; limited collectors applied. "
                "Provide a domain for full WHOIS/DNS coverage."
            )
        else:
            primary.notes.append("Unable to map target to a domain-scoped collector set.")

        return {"profiles": profiles, "timeline": timeline, "errors": list(self.errors)}

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    def _ingest_whois(
        self,
        domain: str,
        profiles: dict[str, EntityProfile],
        timeline: list[TimelineEvent],
    ) -> None:
        try:
            raw = whois.whois(domain)
        except Exception as exc:  # noqa: BLE001 — WHOIS libs raise varied types
            msg = f"WHOIS lookup failed for {domain}: {exc}"
            logger.warning(msg)
            self.errors.append(msg)
            return

        if not raw:
            self.errors.append(f"WHOIS returned empty response for {domain}")
            return

        data = dict(raw) if hasattr(raw, "items") else {}
        profile = profiles.setdefault(
            domain, EntityProfile(identifier=domain, entity_type=EntityType.DOMAIN)
        )

        def _first_ts(*keys: str) -> Optional[str]:
            for key in keys:
                values = flatten_list(data.get(key))
                if values:
                    return parse_timestamp(values[0])
            return None

        created = _first_ts("creation_date", "created")
        updated = _first_ts("updated_date", "updated")
        expires = _first_ts("expiration_date", "expires")

        stale = days_since(updated or created)
        conf = score_confidence(SourceName.WHOIS, stale_days=stale)

        registrar = flatten_list(data.get("registrar"))
        if registrar:
            profile.add_finding(
                Finding(
                    source=SourceName.WHOIS,
                    category="registrar",
                    value=registrar[0],
                    confidence=conf,
                    timestamp=updated or created or utc_now_iso(),
                    metadata={"raw_field": "registrar"},
                )
            )

        for org in flatten_list(data.get("org") or data.get("organization")):
            self._link_related(
                profiles,
                domain,
                org,
                EntityType.ORGANIZATION,
                "whois_org",
                SourceName.WHOIS,
                conf,
                created,
            )

        for email in flatten_list(data.get("emails") or data.get("email")):
            self._link_related(
                profiles,
                domain,
                email.lower(),
                EntityType.EMAIL,
                "whois_email",
                SourceName.WHOIS,
                conf,
                updated or created,
            )

        for ns in flatten_list(data.get("name_servers") or data.get("name_server")):
            ns_clean = ns.lower().rstrip(".")
            self._link_related(
                profiles,
                domain,
                ns_clean,
                EntityType.NAMESERVER,
                "nameserver",
                SourceName.WHOIS,
                conf,
                updated or created,
            )

        if created:
            timeline.append(
                TimelineEvent(
                    timestamp=created,
                    event_type="domain_registration",
                    description=f"Domain {domain} registered (WHOIS creation date)",
                    source=SourceName.WHOIS,
                    confidence=conf,
                    entity=domain,
                )
            )
            profile.add_finding(
                Finding(
                    source=SourceName.WHOIS,
                    category="creation_date",
                    value=created,
                    confidence=conf,
                    timestamp=created,
                )
            )
        if expires:
            profile.add_finding(
                Finding(
                    source=SourceName.WHOIS,
                    category="expiration_date",
                    value=expires,
                    confidence=conf,
                    timestamp=expires,
                )
            )
        if updated:
            timeline.append(
                TimelineEvent(
                    timestamp=updated,
                    event_type="whois_update",
                    description=f"WHOIS record updated for {domain}",
                    source=SourceName.WHOIS,
                    confidence=conf,
                    entity=domain,
                )
            )

    def _ingest_crtsh(
        self,
        domain: str,
        profiles: dict[str, EntityProfile],
        timeline: list[TimelineEvent],
    ) -> None:
        self._ingest_crtsh_query(domain, profiles, timeline, domain_hint=domain)

    def _ingest_crtsh_query(
        self,
        query: str,
        profiles: dict[str, EntityProfile],
        timeline: list[TimelineEvent],
        domain_hint: Optional[str] = None,
    ) -> None:
        params = {"q": f"%.{query}" if domain_hint else query, "output": "json"}
        if domain_hint:
            params["q"] = f"%.{domain_hint}"
        try:
            resp = self.session.get(CRTSH_URL, params=params, timeout=self.timeout)
            resp.raise_for_status()
            # crt.sh sometimes returns empty body or HTML on rate limit
            if not resp.text or not resp.text.strip().startswith(("[", "{")):
                self.errors.append(f"crt.sh returned non-JSON for query={query}")
                return
            records = resp.json()
        except (requests.RequestException, ValueError) as exc:
            msg = f"crt.sh lookup failed for {query}: {exc}"
            logger.warning(msg)
            self.errors.append(msg)
            return

        if not isinstance(records, list):
            self.errors.append("crt.sh response was not a list")
            return

        # Deduplicate by name_value + not_before
        seen: set[str] = set()
        anchor = domain_hint or query
        profile = profiles.setdefault(
            anchor,
            EntityProfile(
                identifier=anchor,
                entity_type=EntityType.DOMAIN
                if domain_hint
                else EntityType.ORGANIZATION,
            ),
        )

        for rec in records[:200]:  # Cap for production responsiveness
            name_value = str(rec.get("name_value") or "").strip()
            not_before = parse_timestamp(rec.get("not_before"))
            issuer = str(rec.get("issuer_name") or "")
            serial = str(rec.get("serial_number") or "")
            for name in {n.strip().lower() for n in name_value.split("\n") if n.strip()}:
                key = f"{name}|{not_before}|{serial}"
                if key in seen:
                    continue
                seen.add(key)

                conf = score_confidence(SourceName.CRTSH)
                is_sub = name != anchor and name.endswith(f".{anchor}")
                etype = EntityType.SUBDOMAIN if is_sub else EntityType.DOMAIN

                if name != anchor:
                    self._link_related(
                        profiles,
                        anchor,
                        name,
                        etype,
                        "ssl_san",
                        SourceName.CRTSH,
                        conf,
                        not_before,
                        metadata={"issuer": issuer, "serial": serial},
                    )
                else:
                    profile.add_finding(
                        Finding(
                            source=SourceName.CRTSH,
                            category="ssl_certificate",
                            value=serial or name,
                            confidence=conf,
                            timestamp=not_before,
                            metadata={"issuer": issuer, "cn": name},
                        )
                    )

                if not_before:
                    timeline.append(
                        TimelineEvent(
                            timestamp=not_before,
                            event_type="certificate_issued",
                            description=f"CT log cert observed for {name}",
                            source=SourceName.CRTSH,
                            confidence=conf,
                            entity=name,
                        )
                    )

                # Capture issuer org as weak link
                if "O=" in issuer:
                    org_part = issuer.split("O=")[-1].split(",")[0].strip()
                    if org_part and len(org_part) > 2:
                        self._link_related(
                            profiles,
                            name,
                            org_part,
                            EntityType.ORGANIZATION,
                            "ssl_issuer_org",
                            SourceName.CRTSH,
                            Confidence.LOW,
                            not_before,
                        )

    def _ingest_dns(
        self,
        domain: str,
        profiles: dict[str, EntityProfile],
        timeline: list[TimelineEvent],
    ) -> None:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        profile = profiles.setdefault(
            domain, EntityProfile(identifier=domain, entity_type=EntityType.DOMAIN)
        )
        now = utc_now_iso()
        conf = score_confidence(SourceName.DNS)

        record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.resolver.YXDOMAIN,
            ):
                continue
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"DNS {rtype} lookup error for {domain}: {exc}")
                continue

            for rdata in answers:
                value = str(rdata).rstrip(".")
                if rtype == "MX":
                    value = str(rdata.exchange).rstrip(".")  # type: ignore[attr-defined]
                profile.add_finding(
                    Finding(
                        source=SourceName.DNS,
                        category=f"dns_{rtype.lower()}",
                        value=value,
                        confidence=conf,
                        timestamp=now,
                    )
                )
                if rtype in ("A", "AAAA"):
                    self._link_related(
                        profiles,
                        domain,
                        value,
                        EntityType.IP,
                        "resolves_to",
                        SourceName.DNS,
                        conf,
                        now,
                    )
                    self._ingest_ip_enrichment(value, profiles, timeline)
                elif rtype == "NS":
                    self._link_related(
                        profiles,
                        domain,
                        value.lower(),
                        EntityType.NAMESERVER,
                        "nameserver",
                        SourceName.DNS,
                        conf,
                        now,
                    )
                elif rtype == "MX":
                    self._link_related(
                        profiles,
                        domain,
                        value.lower(),
                        EntityType.DOMAIN,
                        "mail_exchange",
                        SourceName.DNS,
                        conf,
                        now,
                    )

        timeline.append(
            TimelineEvent(
                timestamp=now,
                event_type="dns_enumeration",
                description=f"DNS resource records collected for {domain}",
                source=SourceName.DNS,
                confidence=conf,
                entity=domain,
            )
        )

    def _ingest_threat_indicators(
        self,
        host: str,
        profiles: dict[str, EntityProfile],
        timeline: list[TimelineEvent],
    ) -> None:
        profile = profiles.setdefault(
            host,
            EntityProfile(
                identifier=host,
                entity_type=EntityType.DOMAIN
                if "." in host and not host.replace(".", "").isdigit()
                else EntityType.IP,
            ),
        )

        if not self.abusech_api_key:
            note = (
                "ThreatFox/URLhaus skipped — set ABUSECH_API_KEY "
                "(free key from https://auth.abuse.ch/) to enable"
            )
            logger.info(note)
            profile.add_finding(
                Finding(
                    source=SourceName.THREATFOX,
                    category="threat_ioc",
                    value=note,
                    confidence=Confidence.LOW,
                    timestamp=utc_now_iso(),
                    metadata={"status": "auth_key_missing"},
                )
            )
            return

        # ThreatFox search
        try:
            payload = {"query": "search_ioc", "search_term": host}
            resp = self.session.post(
                THREATFOX_URL, json=payload, timeout=self.timeout
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("query_status") == "ok" and body.get("data"):
                for item in body["data"][:50]:
                    ts = parse_timestamp(item.get("first_seen"))
                    conf = score_confidence(
                        SourceName.THREATFOX,
                        stale_days=days_since(ts),
                    )
                    ioc = str(item.get("ioc") or host)
                    malware = str(item.get("malware") or "unknown")
                    profile.add_finding(
                        Finding(
                            source=SourceName.THREATFOX,
                            category="threat_ioc",
                            value=f"{ioc} ({malware})",
                            confidence=conf,
                            timestamp=ts or utc_now_iso(),
                            metadata={
                                "threat_type": item.get("threat_type"),
                                "confidence_level": item.get("confidence_level"),
                                "malware": malware,
                            },
                        )
                    )
                    if ts:
                        timeline.append(
                            TimelineEvent(
                                timestamp=ts,
                                event_type="threat_indicator",
                                description=f"ThreatFox IOC linked to {host}: {malware}",
                                source=SourceName.THREATFOX,
                                confidence=conf,
                                entity=host,
                            )
                        )
            else:
                profile.add_finding(
                    Finding(
                        source=SourceName.THREATFOX,
                        category="threat_ioc",
                        value="No ThreatFox IOCs found",
                        confidence=Confidence.HIGH,
                        timestamp=utc_now_iso(),
                        metadata={"status": body.get("query_status", "empty")},
                    )
                )
        except (requests.RequestException, ValueError) as exc:
            msg = f"ThreatFox lookup failed for {host}: {exc}"
            logger.warning(msg)
            self.errors.append(msg)

        # URLhaus host lookup
        try:
            resp = self.session.post(
                URLHAUS_URL, data={"host": host}, timeout=self.timeout
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("query_status") == "ok" and body.get("urls"):
                for item in body["urls"][:30]:
                    ts = parse_timestamp(item.get("date_added"))
                    conf = score_confidence(SourceName.URLHAUS, stale_days=days_since(ts))
                    url = str(item.get("url") or "")
                    profile.add_finding(
                        Finding(
                            source=SourceName.URLHAUS,
                            category="malware_url",
                            value=url,
                            confidence=conf,
                            timestamp=ts or utc_now_iso(),
                            metadata={
                                "threat": item.get("threat"),
                                "url_status": item.get("url_status"),
                            },
                        )
                    )
                    if ts:
                        timeline.append(
                            TimelineEvent(
                                timestamp=ts,
                                event_type="malware_url",
                                description=f"URLhaus malware URL reported for {host}",
                                source=SourceName.URLHAUS,
                                confidence=conf,
                                entity=host,
                            )
                        )
            elif body.get("query_status") in ("no_results", "ok"):
                profile.add_finding(
                    Finding(
                        source=SourceName.URLHAUS,
                        category="malware_url",
                        value="No URLhaus entries found",
                        confidence=Confidence.HIGH,
                        timestamp=utc_now_iso(),
                        metadata={"status": body.get("query_status")},
                    )
                )
        except (requests.RequestException, ValueError) as exc:
            msg = f"URLhaus lookup failed for {host}: {exc}"
            logger.warning(msg)
            self.errors.append(msg)

    def _ingest_ip_enrichment(
        self,
        ip: str,
        profiles: dict[str, EntityProfile],
        timeline: list[TimelineEvent],
    ) -> None:
        profile = profiles.setdefault(
            ip, EntityProfile(identifier=ip, entity_type=EntityType.IP)
        )
        try:
            resp = self.session.get(
                IP_API_URL.format(ip=ip),
                params={"fields": "status,message,country,regionName,city,isp,org,as,query"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            msg = f"ip-api enrichment failed for {ip}: {exc}"
            logger.warning(msg)
            self.errors.append(msg)
            return

        if data.get("status") != "success":
            self.errors.append(f"ip-api status error for {ip}: {data.get('message')}")
            return

        now = utc_now_iso()
        conf = score_confidence(SourceName.IP_API)
        for field_name, category in (
            ("isp", "isp"),
            ("org", "asn_org"),
            ("as", "asn"),
            ("country", "geo_country"),
            ("city", "geo_city"),
        ):
            value = data.get(field_name)
            if value:
                profile.add_finding(
                    Finding(
                        source=SourceName.IP_API,
                        category=category,
                        value=str(value),
                        confidence=conf,
                        timestamp=now,
                    )
                )
                if field_name == "org" and str(value).strip():
                    self._link_related(
                        profiles,
                        ip,
                        str(value).strip(),
                        EntityType.ORGANIZATION,
                        "ip_org",
                        SourceName.IP_API,
                        conf,
                        now,
                    )

        timeline.append(
            TimelineEvent(
                timestamp=now,
                event_type="ip_enrichment",
                description=f"Geolocation/ASN enrichment collected for {ip}",
                source=SourceName.IP_API,
                confidence=conf,
                entity=ip,
            )
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_domain(self, target: str, target_type: EntityType) -> Optional[str]:
        if target_type == EntityType.DOMAIN:
            return target.lower().strip(".")
        if target_type == EntityType.EMAIL and "@" in target:
            return target.split("@", 1)[1].lower()
        return None

    def _link_related(
        self,
        profiles: dict[str, EntityProfile],
        parent: str,
        related: str,
        entity_type: EntityType,
        category: str,
        source: SourceName,
        confidence: Confidence,
        timestamp: Optional[str],
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        related = related.strip()
        if not related:
            return
        parent_profile = profiles.setdefault(
            parent,
            EntityProfile(identifier=parent, entity_type=EntityType.UNKNOWN),
        )
        child = profiles.setdefault(
            related, EntityProfile(identifier=related, entity_type=entity_type)
        )
        if related not in parent_profile.related_identifiers:
            parent_profile.related_identifiers.append(related)
        if parent not in child.related_identifiers:
            child.related_identifiers.append(parent)

        finding = Finding(
            source=source,
            category=category,
            value=related,
            confidence=confidence,
            timestamp=timestamp or utc_now_iso(),
            metadata=metadata or {},
        )
        parent_profile.add_finding(finding)
        child.add_finding(
            Finding(
                source=source,
                category=f"linked_from_{category}",
                value=parent,
                confidence=confidence,
                timestamp=timestamp or utc_now_iso(),
                metadata=metadata or {},
            )
        )


def parse_crtsh_records(records: list[dict[str, Any]], domain: str) -> list[Finding]:
    """
    Pure parser for crt.sh JSON records — used by unit tests and callers
    that already hold raw CT responses.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for rec in records:
        name_value = str(rec.get("name_value") or "").strip()
        not_before = parse_timestamp(rec.get("not_before"))
        serial = str(rec.get("serial_number") or "")
        for name in {n.strip().lower() for n in name_value.split("\n") if n.strip()}:
            key = f"{name}|{serial}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    source=SourceName.CRTSH,
                    category="ssl_san" if name != domain else "ssl_certificate",
                    value=name,
                    confidence=score_confidence(SourceName.CRTSH),
                    timestamp=not_before,
                    metadata={"serial": serial, "issuer": rec.get("issuer_name")},
                )
            )
    return findings
