# OSINT Footprint & Entity Investigation Engine

Production-ready Python CLI for **automated open-source intelligence (OSINT) collection**, entity correlation, link charting, and defensible intelligence report generation.

Designed for investigative workflows, digital footprint mapping, and compliance-oriented briefing output.

---

## Features

| Module | Capability |
| --- | --- |
| **Ingestion** (`src/ingestion.py`) | WHOIS, Certificate Transparency (crt.sh), DNS (A/AAAA/MX/NS/TXT/CNAME), ThreatFox, URLhaus, ip-api enrichment |
| **Correlation** (`src/correlator.py`) | NetworkX graph of domains ↔ IPs ↔ orgs ↔ emails ↔ certs; PNG + interactive HTML exports |
| **Reporting** (`src/reporter.py`) | Structured Markdown / PDF Intelligence Briefing with confidence tags |
| **CLI** (`main.py`) | Click-based orchestrator with progress logging and modular phases |

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │              main.py (CLI)           │
                    │   argparse/click orchestration       │
                    └───────────────┬─────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │  DataIngester    │  │  LinkCorrelator  │  │ Intelligence     │
   │  ingestion.py    │─▶│  correlator.py   │─▶│ Reporter         │
   │                  │  │                  │  │ reporter.py      │
   │ • WHOIS          │  │ • NetworkX graph │  │                  │
   │ • crt.sh         │  │ • Corroboration  │  │ • Markdown brief │
   │ • DNS            │  │ • PNG (mpl)      │  │ • PDF brief      │
   │ • ThreatFox      │  │ • HTML (pyvis)   │  │ • Confidence     │
   │ • URLhaus        │  │                  │  │   scoring        │
   │ • ip-api         │  │                  │  │                  │
   └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
            │                     │                     │
            ▼                     ▼                     ▼
     EntityProfile /        InvestigationResult      reports/*.md
     Finding / Timeline     edges + graph files      reports/*.pdf
```

**Data flow:** classify target → ingest open sources → normalize to `EntityProfile` / `Finding` models → correlate into a MultiDiGraph → export charts → render briefing with High/Medium/Low confidence tags.

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone <repo-url> osint-footprint-investigation-engine
cd osint-footprint-investigation-engine

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### Optional: abuse.ch Auth-Key

ThreatFox and URLhaus require a free API key from [auth.abuse.ch](https://auth.abuse.ch/). Without it, those collectors are skipped gracefully; WHOIS, DNS, crt.sh, and ip-api still run.

```bash
export ABUSECH_API_KEY="your-key-here"
```

---

## Usage

```bash
# Basic Markdown briefing
python main.py --target example.com --output reports/example_brief.md

# Markdown + PDF, PNG + interactive HTML link charts, verbose logs
python main.py -t example.com --format both --graph both -v

# IP target with JSON dump
python main.py -t 8.8.8.8 --format md --json-export reports/8.8.8.8.json

# Organization / username (limited collectors; domain preferred)
python main.py -t "Acme Corporation" -o reports/acme_brief.md
```

### CLI options

| Option | Description |
| --- | --- |
| `-t / --target` | Domain, IP, email, username, or organization (**required**) |
| `-o / --output` | Briefing path (default: `reports/<target>_brief.md`) |
| `--format` | `md` \| `pdf` \| `both` (default: `md`) |
| `--graph` | `png` \| `html` \| `both` \| `none` (default: `both`) |
| `--json-export` | Optional raw `InvestigationResult` JSON path |
| `--timeout` | Per-request timeout seconds (default: `20`) |
| `-v / --verbose` | Debug logging |

---

## Confidence rubric

| Tag | Criteria |
| --- | --- |
| **High** | Authoritative registry / DNS / CT source; or corroborated across ≥2 independent sources; data ≤365 days old |
| **Medium** | Reputable open threat-intel or enrichment API; single-source observation |
| **Low** | Derived/inferred link, partial record, or stale (>365 days) data |

---

## Testing

```bash
pytest
pytest --cov=src --cov-report=term-missing   # optional coverage
```

Tests cover source parsing (`parse_crtsh_records`), confidence score calculations, correlation edge building, and report section structure — without requiring live network access for the core suite (HTTP collectors are stubbed with `responses`).

---

## Project layout

```
.
├── main.py                 # CLI orchestrator
├── requirements.txt
├── pytest.ini
├── README.md
├── reports/                # Generated briefings & charts
│   └── sample_brief.md
├── src/
│   ├── __init__.py
│   ├── models.py           # EntityProfile, Finding, InvestigationResult
│   ├── utils.py            # Classification, confidence, timestamps
│   ├── ingestion.py        # Open-source collectors + parsers
│   ├── correlator.py       # NetworkX + pyvis/matplotlib
│   └── reporter.py         # Markdown / PDF briefing
└── tests/
    ├── test_confidence.py
    ├── test_ingestion.py
    ├── test_correlator.py
    └── test_reporter.py
```

---

## Sample OSINT output report

Excerpt from `reports/sample_brief.md` (illustrative — run the CLI against a live target for current data):

```markdown
# Intelligence Briefing: `example.com`

**Classification:** UNCLASSIFIED // FOR INVESTIGATIVE USE ONLY
**Generated (UTC):** 2024-06-15T14:22:01Z
**Investigation Window:** 2024-06-15T14:21:40Z → 2024-06-15T14:22:01Z
**Target Type:** domain
**Overall Confidence:** High

---

## 1. Executive Summary

Investigation of target `example.com` (domain) produced 5 entity profile(s),
18 normalized finding(s), 4 relationship edge(s), and 6 timeline event(s).
Overall assessment confidence is **High** (12 High-confidence finding(s)).
No affirmative malware/IOC associations were confirmed in ThreatFox or URLhaus
for the primary host at time of collection.

> This briefing aggregates publicly available information from open sources...

## 2. Entity Profiles

### 2.1 `example.com`

| Field | Value |
| --- | --- |
| Entity Type | domain |
| First Seen | 1995-08-14T04:00:00Z |
| Last Seen | 2024-06-15T14:21:55Z |
| Confidence Mix | High=10, Medium=2, Low=0 |
| Related Entities | `93.184.216.34`, `www.example.com`, `iana-servers.net` |

| ID | Source | Category | Value | Confidence | Timestamp |
| --- | --- | --- | --- | --- | --- |
| a1b2c3d4 | WHOIS | registrar | `RESERVED-Internet Assigned Numbers Authority` | **High** | 2024-01-01T00:00:00Z |
| e5f6g7h8 | DNS | dns_a | `93.184.216.34` | **High** | 2024-06-15T14:21:50Z |
| i9j0k1l2 | crt.sh | ssl_san | `www.example.com` | **High** | 2024-03-10T00:00:00Z |

## 3. Digital Trace Timeline

| Timestamp (UTC) | Event | Entity | Source | Confidence |
| --- | --- | --- | --- | --- |
| 1995-08-14T04:00:00Z | Domain example.com registered (WHOIS creation date) | `example.com` | WHOIS | **High** |
| 2024-03-10T00:00:00Z | CT log cert observed for www.example.com | `www.example.com` | crt.sh | **High** |
| 2024-06-15T14:21:50Z | DNS resource records collected for example.com | `example.com` | DNS | **High** |

## 4. Link Relationship Map

| Source Entity | Relation | Target Entity |
| --- | --- | --- |
| `example.com` | `resolves_to` | `93.184.216.34` |
| `example.com` | `ssl_san` | `www.example.com` |
| `example.com` | `uses_nameserver` | `a.iana-servers.net` |

## 5. Source Validation & Confidence Scores

| Source | Findings | High | Medium | Low | Validation Notes |
| --- | --- | --- | --- | --- | --- |
| WHOIS | 4 | 4 | 0 | 0 | Registry / registrar; authoritative for registration |
| DNS | 6 | 6 | 0 | 0 | Live resolution; authoritative for current mapping |
| crt.sh | 5 | 5 | 0 | 0 | Public Certificate Transparency logs |
| ThreatFox | 1 | 1 | 0 | 0 | No IOCs found (negative result, High) |
| URLhaus | 1 | 1 | 0 | 0 | No entries found (negative result, High) |
| ip-api | 1 | 0 | 1 | 0 | Geo/ASN enrichment; medium confidence |

---
*End of briefing. Generated by OSINT Footprint & Entity Investigation Engine.*
```

---

## Ethics & legal notice

Use only against assets you are authorized to investigate. This tool queries **public** endpoints and does not attempt credentialed access, exploitation, or invasive scanning. Operators are responsible for compliance with local law, organizational policy, and terms of service of upstream data providers.

---

## License

Provided for defensive security research and authorized investigative use.
