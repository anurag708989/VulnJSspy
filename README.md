# 🚀 VulnJSpy Professional

**Async JavaScript secret-scanning and recon toolkit for authorized bug bounty and pentest engagements.**

[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

VulnJSpy Professional discovers, fetches, and scans public JavaScript assets for exposed
secrets — API keys, cloud credentials, tokens, and endpoints — using a 135-pattern regex
engine, entropy scoring, and multi-source URL discovery (`gau`, Wayback Machine, CommonCrawl).
It ships with a Rich terminal UI, optional Telegram alerting, and JSON/CSV reporting for
downstream tooling.

> ⚠️ **Authorized use only.** This tool is built for bug bounty programs, penetration tests,
> and security research where you have explicit permission to test the target. Running it
> against systems you don't have authorization for may violate the CFAA, the UK Computer Misuse
> Act, or equivalent laws in your jurisdiction, and will breach most bug bounty program terms.
> You are responsible for confirming scope before you scan. See [SECURITY.md](SECURITY.md).

---

## Table of Contents

- [Why VulnJSpy](#why-vulnjspy)
- [How It Works](#how-it-works)
- [Feature Overview](#feature-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Output](#output)
- [Comparison to Other Tools](#comparison-to-other-tools)
- [Benchmarks & Methodology Notes](#benchmarks--methodology-notes)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

Additional docs: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (workflow diagrams),
[`patterns.json`](patterns.json) (full pattern library, machine-readable),
[`CHANGELOG.md`](CHANGELOG.md) (every fix in the current release, with rationale).

---

## Why VulnJSpy

Most public JS secret scanners fall into two camps: lightweight single-file tools with a
narrow pattern set, or heavyweight commercial platforms with a subscription paywall.
VulnJSpy Professional targets the middle ground — a scriptable, self-hosted tool with:

- A **135-pattern library** (see `patterns.json`) across cloud providers, payment gateways, communication APIs,
  CI/CD services, and generic secret formats — see [`docs/FEATURES.md`](docs/FEATURES.md)
  for the full breakdown by category.
- **Three input modes**: a single local file, a single remote URL, or full-domain discovery
  that aggregates JS URLs from `gau`, the Wayback Machine, and CommonCrawl.
- **Entropy- and context-aware scoring** to cut down obvious false positives (placeholder
  values, test keys, sample UUIDs) before they hit your report.
- **Structured output** (JSON + CSV) designed to feed into other tooling — dedupe scripts,
  Burp/Nuclei pipelines, or a ticketing system.
- Optional **Telegram notifications** for long-running domain scans.

## How It Works

```
┌─────────────┐    ┌──────────────────┐    ┌────────────────┐    ┌──────────────┐
│  Discovery  │ →  │   Validation &    │ →  │  Pattern Match  │ →  │   Reporting  │
│ gau/Wayback │    │  Live URL Probe   │    │  + Entropy/     │    │ JSON/CSV/UI  │
│ /CommonCrawl│    │  (httpx/httprobe) │    │  Confidence     │    │ + Telegram   │
└─────────────┘    └──────────────────┘    └────────────────┘    └──────────────┘
```

1. **Discovery** — for `--domain` scans, JS URLs are aggregated from multiple public
   archive/crawl sources and filtered against a third-party exclusion list (jQuery,
   Bootstrap, common CDNs, analytics libraries, etc.) so the scanner spends time on
   application code, not vendored libraries.
2. **Validation** — candidate URLs are probed for a live 200 response before download.
3. **Pattern matching** — each JS file is scanned against the full pattern set. Matches are
   scored using pattern-specific confidence weights plus Shannon entropy on the matched
   value, and checked against a configurable exclude-word list (`test`, `placeholder`,
   `your_key_here`, etc.) to suppress obvious non-secrets.
4. **Reporting** — results are written to timestamped JSON and CSV files, printed to a Rich
   terminal table (top-N per pattern type via `--entropy-depth`), and optionally pushed to
   Telegram.

## Feature Overview

| Area | What it does |
|---|---|
| **Multi-mode scanning** | `--file`, `--url`, `--domain` — local file, single remote JS file, or full-domain recon |
| **Discovery engine** | `gau`, Wayback Machine API, CommonCrawl aggregation with de-duplication |
| **Pattern library** | 135 regex patterns across 20+ categories (cloud, payments, comms, CI/CD, databases, generic) — see `patterns.json` |
| **Confidence scoring** | Per-pattern base confidence + entropy validation + exclude-word filtering |
| **Concurrency** | Configurable async worker pool (`--workers`, capped at 50) |
| **Custom patterns** | Drop-in JSON pattern files (`--custom-patterns`) for org-specific secret formats |
| **Telegram alerts** | Scan-start and scan-complete notifications via bot token + chat ID |
| **Output formats** | JSON (full metadata), CSV (spreadsheet-ready), plain-text subdomain/email lists |
| **Terminal UI** | Rich-based tables, panels, and progress reporting |
| **Tunable noise control** | `--entropy-depth`, `--confidence-threshold`, `--exclude-words` |

Full deep-dive per feature, including every pattern category and how confidence scores are
computed, lives in [`docs/FEATURES.md`](docs/FEATURES.md).

## Installation

See [`docs/INSTALL.md`](docs/INSTALL.md) for the complete guide, including Docker and
Go-tool setup. Quick version:

```bash
git clone https://github.com/<your-org>/vulnjspy-professional.git
cd vulnjspy-professional

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

`requirements.txt`:
```
rich>=13.0.0
aiohttp>=3.9.0
requests>=2.31.0
python-telegram-bot>=20.0        # optional, only needed for --telegram-token
```

For `--domain` scanning you'll also want the Go-based discovery tools on your `PATH`:

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/httprobe@latest
```

## Quick Start

```bash
# Scan a single local JS file
python3 vulnjspy.py --file app.js

# Download and scan a single remote JS file
python3 vulnjspy.py --url https://example.com/static/app.js

# Full-domain discovery + scan (authorized scope only)
python3 vulnjspy.py --domain example.com --workers 10 --entropy-depth 3

# With Telegram alerts and a higher confidence floor
python3 vulnjspy.py --domain example.com \
  --telegram-token "$TG_TOKEN" --chatid "$TG_CHAT_ID" \
  --confidence-threshold 70

# Full built-in documentation, methodology, and comparison tables
python3 vulnjspy.py --help-full
```

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--file PATH` | — | Scan a local JavaScript file |
| `--url URL` | — | Download and scan a single remote JS file |
| `--domain DOMAIN` | — | Full discovery + scan across a domain |
| `--entropy-depth N` | `3` | Results shown per pattern type (max 10) |
| `--workers N` | `10` | Concurrent async workers (max 50) |
| `--timeout N` | `15` | Per-request HTTP timeout, seconds |
| `--output-dir DIR` | `vulnjspy_results` | Where JSON/CSV reports are written |
| `--custom-patterns FILE` | — | JSON file of additional regex patterns |
| `--exclude-words "a,b,c"` | — | Extra values to suppress as false positives |
| `--confidence-threshold N` | `50` | Minimum confidence (0–100) to report a finding |
| `--telegram-token TOKEN` | — | Bot token for live alerts |
| `--chatid ID` | — | Telegram chat ID to notify |
| `--verbose`, `-v` | off | Verbose logging |
| `--debug` | off | Full tracebacks on error |
| `--help-full` | — | Print built-in methodology + comparison docs |

`--file`, `--url`, and `--domain` are mutually exclusive — pick one mode per run.

### Custom pattern file format

```json
{
  "patterns": [
    {
      "name": "Internal API Key",
      "regex": "mycompany_[a-zA-Z0-9]{32}",
      "confidence": 95
    }
  ]
}
```

## Output

Each run writes timestamped files to `--output-dir`:

- `secrets_detailed_<timestamp>.json` — full match metadata (type, value, confidence,
  entropy, source URL, surrounding context, matched pattern)
- `secrets_<timestamp>.csv` — the same data, flattened for spreadsheet review
- `endpoints_<timestamp>.json` — discovered endpoints, tagged by type where identifiable
- `subdomains_<timestamp>.txt` — in-scope subdomains observed during discovery
- `emails_<timestamp>.txt` — email addresses found on the scope domain (see note below)
- `scan_stats_<timestamp>.json` — run metadata: duration, request success rate, patterns used

> **Note on email output:** the email list is a byproduct of pattern matching, not a
> dedicated OSINT feature. Treat it the same as any other in-scope finding — it belongs in
> a responsible-disclosure report if it reveals something like an exposed internal mailing
> list or leaked credential pair, not as a contact list for outreach.

## Comparison to Other Tools

This is a feature comparison based on published documentation for each tool at the time of
writing, not independent benchmarking. Pattern counts and false-positive rates for
competitors are approximate and sourced from their own docs; verify current numbers before
citing them externally.

| Feature | VulnJSpy Pro | Burp Suite (JS Link Finder) | SecretFinder | TruffleHog |
|---|---|---|---|---|
| Regex pattern count | 135 | ~50 | ~60 | Detector-based (rules, not raw regex) |
| Domain-wide discovery | ✅ gau/Wayback/CommonCrawl | ❌ Manual/per-page | ❌ Manual | ⚠️ Repo/bucket scanning, not JS-focused |
| Entropy scoring | ✅ | ❌ | ⚠️ Basic | ✅ |
| Live secret verification | ❌ (planned) | ❌ | ❌ | ✅ (for supported detectors) |
| Custom pattern support | ✅ JSON | ⚠️ Limited | ❌ | ✅ |
| Terminal UI | ✅ Rich | N/A (Burp extension) | ❌ Plain CLI | ✅ |
| Real-time alerting | ✅ Telegram | ❌ | ❌ | ❌ |
| License / cost | Free / self-hosted | Requires Burp Pro | Free | Free (OSS core), paid enterprise tier |

Honest positioning: VulnJSpy's edge is breadth of pattern coverage and an integrated
discovery-to-report pipeline for JS-specific recon. Tools like TruffleHog have an advantage
in **verified** secret detection (they actually test credentials against provider APIs where
safe to do so); VulnJSpy currently reports on pattern + entropy confidence only, so treat
"Critical" findings as high-priority leads to manually verify, not confirmed live secrets.

## Benchmarks & Methodology Notes

The tool's own `--help-full` output cites figures like "99.2% detection rate" and "<1% false
positives." These are internal estimates from the authors' own test runs against a small set
of targets, not results from an independent or peer-reviewed benchmark. If you publish this
project, we'd recommend either:

- Replacing these with a link to a reproducible benchmark script + dataset, or
- Softening the language to "internal testing suggests..." with the sample size and
  methodology disclosed.

Overstated accuracy claims are one of the fastest ways a security tool loses credibility on
GitHub — reviewers will test it themselves.

## Roadmap

- [ ] Live credential verification for supported providers (opt-in, rate-limited)
- [ ] SARIF output for CI/CD integration
- [ ] Dockerfile + prebuilt image
- [ ] Pattern-set versioning and changelog
- [ ] Web dashboard (see subscription/SaaS notes in [`docs/BUSINESS_MODEL.md`](docs/BUSINESS_MODEL.md))

## Contributing

Issues and PRs welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). New regex patterns should
include a source/rationale and, where possible, a test string in `tests/patterns/`.

## License

[MIT](LICENSE) for the open-source CLI. See [`docs/BUSINESS_MODEL.md`](docs/BUSINESS_MODEL.md)
for how to structure a paid tier without relicensing the core tool.

---
*VulnJSpy Professional — built for authorized security research.*
