"""Entity correlation & link-charting engine (NetworkX + pyvis/matplotlib)."""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402
from pyvis.network import Network  # noqa: E402

from src.models import (
    Confidence,
    EntityProfile,
    EntityType,
    InvestigationResult,
    SourceName,
    TimelineEvent,
    utc_now_iso,
)
from src.utils import score_confidence

logger = logging.getLogger("osint-engine.correlator")

# Categories that imply a directed edge from parent finding entity → value
EDGE_CATEGORIES = {
    "resolves_to": "resolves_to",
    "nameserver": "uses_nameserver",
    "mail_exchange": "uses_mx",
    "ssl_san": "ssl_san",
    "whois_email": "whois_contact",
    "whois_org": "registered_to",
    "ip_org": "hosted_by",
    "ssl_issuer_org": "cert_issued_by",
}


class LinkCorrelator:
    """
    Correlate IPs, subdomains, SSL contacts, and timestamps across ingested
    datasets, then export relationship charts as PNG or interactive HTML.
    """

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()

    def correlate(
        self,
        target: str,
        target_type: EntityType,
        profiles: dict[str, EntityProfile],
        timeline: list[TimelineEvent],
        errors: Optional[list[str]] = None,
        started_at: Optional[str] = None,
    ) -> InvestigationResult:
        """Build graph edges, cross-source corroboration, and InvestigationResult."""
        started = started_at or utc_now_iso()
        edges: list[tuple[str, str, str]] = []

        # Seed graph nodes from profiles
        for ident, profile in profiles.items():
            self.graph.add_node(
                ident,
                entity_type=profile.entity_type.value,
                finding_count=len(profile.findings),
            )

        # Derive edges from findings + related_identifiers
        for ident, profile in profiles.items():
            for related in profile.related_identifiers:
                relation = self._infer_relation(profile, related)
                edges.append((ident, related, relation))
                self.graph.add_edge(ident, related, relation=relation)

            for finding in profile.findings:
                relation = EDGE_CATEGORIES.get(finding.category)
                if relation and finding.value in profiles and finding.value != ident:
                    edge = (ident, finding.value, relation)
                    if edge not in edges:
                        edges.append(edge)
                        self.graph.add_edge(ident, finding.value, relation=relation)

        # Cross-source corroboration: bump confidence when ≥2 sources share a value
        self._apply_corroboration(profiles)

        # Deduplicate & sort timeline
        timeline_sorted = sorted(
            timeline,
            key=lambda e: e.timestamp or "",
        )

        # Deduplicate edges while preserving order
        unique_edges: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for edge in edges:
            if edge not in seen and edge[0] != edge[1]:
                seen.add(edge)
                unique_edges.append(edge)

        result = InvestigationResult(
            target=target,
            target_type=target_type,
            started_at=started,
            completed_at=utc_now_iso(),
            profiles=profiles,
            timeline=timeline_sorted,
            edges=unique_edges,
            errors=list(errors or []),
        )
        logger.info(
            "Correlation complete: %d nodes, %d edges, %d timeline events",
            self.graph.number_of_nodes(),
            len(unique_edges),
            len(timeline_sorted),
        )
        return result

    def export_png(self, path: str | Path, title: Optional[str] = None) -> str:
        """Render a static link chart with matplotlib."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if self.graph.number_of_nodes() == 0:
            # Empty placeholder chart
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.text(0.5, 0.5, "No entities to chart", ha="center", va="center")
            ax.axis("off")
            fig.savefig(path, dpi=150, bbox_inches="tight")
            plt.close(fig)
            return str(path)

        # Work on a simple DiGraph projection for layout clarity
        simple = nx.DiGraph()
        for u, v, data in self.graph.edges(data=True):
            simple.add_edge(u, v, relation=data.get("relation", "related"))
        for n, data in self.graph.nodes(data=True):
            if n not in simple:
                simple.add_node(n, **data)

        pos = nx.spring_layout(simple, k=1.8, seed=42)
        type_colors = {
            "domain": "#1f4e79",
            "subdomain": "#2e75b6",
            "ip": "#c45911",
            "email": "#548235",
            "organization": "#7030a0",
            "nameserver": "#833c0c",
            "username": "#385723",
            "certificate": "#7f7f7f",
            "unknown": "#595959",
        }
        node_colors = [
            type_colors.get(simple.nodes[n].get("entity_type", "unknown"), "#595959")
            for n in simple.nodes()
        ]

        fig, ax = plt.subplots(figsize=(14, 10))
        nx.draw_networkx_nodes(
            simple, pos, node_color=node_colors, node_size=900, alpha=0.9, ax=ax
        )
        nx.draw_networkx_labels(
            simple,
            pos,
            labels={n: self._short_label(n) for n in simple.nodes()},
            font_size=7,
            font_color="white",
            ax=ax,
        )
        nx.draw_networkx_edges(
            simple,
            pos,
            edge_color="#888888",
            arrows=True,
            arrowsize=12,
            width=1.2,
            alpha=0.7,
            ax=ax,
        )
        edge_labels = {
            (u, v): d.get("relation", "") for u, v, d in simple.edges(data=True)
        }
        nx.draw_networkx_edge_labels(
            simple, pos, edge_labels=edge_labels, font_size=6, ax=ax
        )
        ax.set_title(title or "OSINT Link Relationship Map", fontsize=14, pad=12)
        ax.axis("off")
        fig.tight_layout()
        fig.savefig(path, dpi=160, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        logger.info("Wrote PNG link chart → %s", path)
        return str(path)

    def export_html(self, path: str | Path, title: Optional[str] = None) -> str:
        """Render an interactive pyvis network graph."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        net = Network(
            height="750px",
            width="100%",
            directed=True,
            bgcolor="#ffffff",
            font_color="#111111",
            heading=title or "OSINT Link Relationship Map",
        )
        net.barnes_hut()

        type_colors = {
            "domain": "#1f4e79",
            "subdomain": "#2e75b6",
            "ip": "#c45911",
            "email": "#548235",
            "organization": "#7030a0",
            "nameserver": "#833c0c",
            "username": "#385723",
            "certificate": "#7f7f7f",
            "unknown": "#595959",
        }

        for node, data in self.graph.nodes(data=True):
            et = data.get("entity_type", "unknown")
            net.add_node(
                node,
                label=self._short_label(node),
                title=f"{node}\nType: {et}\nFindings: {data.get('finding_count', 0)}",
                color=type_colors.get(et, "#595959"),
                shape="dot",
                size=18 + min(int(data.get("finding_count", 0)), 20),
            )

        for u, v, data in self.graph.edges(data=True):
            net.add_edge(u, v, title=data.get("relation", "related"), label=data.get("relation", ""))

        # pyvis write_html may try to open a browser; disable notebook mode
        net.write_html(str(path), open_browser=False, notebook=False)
        logger.info("Wrote interactive HTML link chart → %s", path)
        return str(path)

    def graph_stats(self) -> dict[str, Any]:
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": round(nx.density(self.graph), 4) if self.graph.number_of_nodes() else 0,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _apply_corroboration(self, profiles: dict[str, EntityProfile]) -> None:
        """Raise confidence when the same value appears from ≥2 distinct sources."""
        value_sources: dict[str, set[SourceName]] = defaultdict(set)
        for profile in profiles.values():
            for finding in profile.findings:
                value_sources[finding.value.lower()].add(finding.source)

        for profile in profiles.values():
            for finding in profile.findings:
                sources = value_sources.get(finding.value.lower(), set())
                if len(sources) >= 2 and finding.confidence != Confidence.HIGH:
                    finding.confidence = score_confidence(
                        finding.source, corroborated=True
                    )
                    finding.metadata["corroborated_sources"] = [
                        s.value for s in sources
                    ]

    def _infer_relation(self, profile: EntityProfile, related: str) -> str:
        for finding in profile.findings:
            if finding.value == related and finding.category in EDGE_CATEGORIES:
                return EDGE_CATEGORIES[finding.category]
        return "related_to"

    @staticmethod
    def _short_label(ident: str, max_len: int = 28) -> str:
        if len(ident) <= max_len:
            return ident
        return ident[: max_len - 1] + "…"


def build_edges_from_profiles(
    profiles: dict[str, EntityProfile],
) -> list[tuple[str, str, str]]:
    """Pure helper for tests: extract correlation edges without side effects."""
    correlator = LinkCorrelator()
    result = correlator.correlate(
        target="test",
        target_type=EntityType.DOMAIN,
        profiles=profiles,
        timeline=[],
    )
    return result.edges
