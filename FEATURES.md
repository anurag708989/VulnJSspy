# Feature Deep Dive

## 1. Scan Modes

| Mode | Flag | Behavior |
|---|---|---|
| Local file | `--file PATH` | Scans a file already on disk. No network discovery. |
| Single URL | `--url URL` | Downloads one JS file to a temp path, scans it, deletes it. |
| Domain | `--domain DOMAIN` | Full discovery pipeline (below), then per-file scan + cleanup. |

`--file`, `--url`, and `--domain` are mutually exclusive; the CLI enforces this.

## 2. Discovery Pipeline (`--domain`)

1. **URL aggregation** — pulls historical and current URLs from `gau` (which itself queries
   the Wayback Machine, CommonCrawl, and other passive sources), scoped to the target domain.
2. **Third-party filtering** — strips known CDN/library/framework URLs (jQuery, Bootstrap,
   Google APIs, WordPress/Drupal/Joomla core files, common analytics snippets) so scan time
   goes to first-party application code.
3. **Liveness check** — remaining candidate URLs are probed with `httprobe`/`httpx` and only
   URLs returning HTTP 200 with a JS-compatible content type proceed.
4. **Priority ordering** — application-specific files (non-vendored, non-minified-by-name)
   are scanned before generic bundles, so early findings surface faster on large domains.

## 3. Pattern Library

The engine ships 300+ patterns grouped into these categories (exact counts vary as patterns
are added — check `ENTERPRISE_REGEX_PATTERNS` in the source for the current list):

| Category | Examples |
|---|---|
| Cloud infrastructure | AWS access keys/ARNs/S3 URLs, GCP API keys & service accounts, Firebase config, Azure storage keys & connection strings |
| Source control / CI-CD | GitHub PAT/App/OAuth tokens, GitLab tokens, NPM tokens, Docker Hub tokens, Jenkins/CircleCI tokens |
| Auth / OAuth | JWTs, bearer tokens, OAuth client ID/secret, refresh tokens |
| Databases | MongoDB/Postgres/MySQL/Redis URIs, JDBC strings, generic connection-string patterns |
| Payments | Stripe live/test secret & publishable keys, PayPal client ID/secret, Square tokens, Braintree tokens |
| Communications | Slack bot/user tokens & webhooks, Discord bot tokens & webhooks, Telegram bot tokens, Twilio SIDs/tokens |
| Email/marketing | SendGrid, Mailgun, Mailchimp keys |
| Social/analytics | Facebook/Twitter/Instagram/LinkedIn tokens, Google Analytics/Tag Manager IDs |
| Framework-specific | `REACT_APP_*` environment variable leaks (common in client-bundled React apps) |
| Generic | `api_key`, `secret_key`, `private_key`, `master_key`, `auth_key` style key-value patterns |

Each pattern carries a **base confidence weight** (0–100) reflecting how distinctive its
format is. A pattern like an AWS `AKIA...` key ID (95) is far less prone to false positives
than a generic `secret_key` key-value match (80) or a bare 40-character base64 blob used as
the AWS secret-key heuristic (85, and worth treating with more skepticism in practice since
that shape isn't unique to AWS).

## 4. Confidence Scoring

Final confidence for a match is influenced by:

1. **Pattern base weight** — set per pattern (see table above).
2. **Shannon entropy** of the matched value — low-entropy matches (repeated characters,
   sequential digits, dictionary words) are penalized, since real secrets are close to random.
3. **Exclude-word list** — matches equal to or containing known placeholder values (`test`,
   `example`, `your_key_here`, `localhost`, sequences like `11111`) are filtered outright.
   Extend this list per-target with `--exclude-words "staging,internal-demo"`.
4. **Length validation** — per secret type, matches outside the expected length range are
   discarded (prevents a 6-character coincidental regex hit from being reported as a
   "Private Key").

Reported confidence bands:

| Band | Threshold |
|---|---|
| Critical | ≥ 90% |
| High | ≥ 80% |
| Medium | ≥ 70% |
| Low | ≥ 50% (the reporting floor, tunable via `--confidence-threshold`) |

**Important:** confidence here reflects "this looks like a real secret by shape and
context," not "this credential is live and exploitable." Nothing in the current pipeline
calls out to provider APIs to verify a key still works — that's flagged as a roadmap item,
and until it lands, every Critical/High finding should be manually verified (and, if valid,
reported through the program's disclosure process) before being treated as confirmed impact.

## 5. Concurrency & Resource Controls

| Flag | Purpose |
|---|---|
| `--workers N` (max 50) | Async worker pool size for concurrent downloads/scans |
| `--timeout N` | Per-request HTTP timeout, seconds |
| `--entropy-depth N` (max 10) | Caps displayed results per pattern type — full results always go to JSON/CSV regardless of this setting |

Files are downloaded, scanned, and deleted one at a time per worker (no full-domain content
is held in memory at once), which is what keeps memory usage roughly constant regardless of
domain size — it scales with worker count and largest single file, not total file count.

## 6. Custom Patterns

Org-specific or engagement-specific secret formats can be added without touching the source:

```json
{
  "patterns": [
    { "name": "Internal API Key", "regex": "mycompany_[a-zA-Z0-9]{32}", "confidence": 95 }
  ]
}
```

```bash
python3 vulnjspy.py --domain example.com --custom-patterns custom_patterns.json
```

## 7. Telegram Integration

Optional, off by default. Requires `--telegram-token` and `--chatid`. Sends:

- A scan-start message (target, worker count, entropy depth, Python version, timestamp)
- A scan-complete summary (secret/endpoint/subdomain/email counts, duration, success rate)

Telegram setup requires the target chat to have messaged the bot at least once — this is a
Telegram API restriction, not something the tool controls. If notifications silently fail,
check that first.

## 8. Output & Reporting

See the [README output section](../README.md#output) for the file list. All JSON output
includes full match metadata (value, confidence, entropy, source URL, surrounding context,
matched pattern name) so downstream tooling — a dedupe script, a Jira/Linear integration, a
Nuclei template generator — can consume it without re-parsing terminal output.

## 9. What This Tool Does *Not* Do

Being explicit about scope avoids over-promising:

- No active exploitation of discovered credentials.
- No automated authenticated testing against the target application.
- No subdomain takeover checks (subdomains are recon output, not a finding category).
- No built-in scope/asset-inventory management across multiple engagements (see
  [`BUSINESS_MODEL.md`](BUSINESS_MODEL.md) for where that could live in a hosted tier).
