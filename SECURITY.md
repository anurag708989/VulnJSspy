# Security & Responsible Use Policy

## Scope of authorized use

VulnJSpy Professional is a **passive reconnaissance tool** — it reads publicly accessible
JavaScript files and reports on patterns that look like exposed secrets. It does not exploit
credentials, authenticate against target systems, or modify anything on the target.

That said, running any scanner against a domain without permission can still violate:

- The target's Terms of Service
- Computer-crime law in your jurisdiction (e.g. the US CFAA, UK Computer Misuse Act 1990,
  and equivalents elsewhere)
- The rules of engagement for any bug bounty or pentest program you're working under

**Only run this tool against:**
- Domains you own
- Targets explicitly in scope for a bug bounty program you're enrolled in (check the
  program's current scope page immediately before scanning — scope changes)
- Systems covered by a signed penetration-testing engagement letter

## Handling findings

If a scan surfaces a live secret:

1. **Do not use the credential** beyond the minimum needed to confirm it's real and
   in-scope. Do not access data, modify resources, or pivot further with it.
2. **Report through the program's official channel** (HackerOne, Bugcrowd, Intigriti, or the
   organization's own disclosure process) promptly, following that program's disclosure
   timeline.
3. **Don't publish findings** (write-ups, screenshots, the raw secret value) before the
   program has remediated and given permission, per standard responsible-disclosure norms.

## Reporting a vulnerability in VulnJSpy itself

If you find a security issue in the *tool* (e.g. unsafe handling of downloaded content, a
path traversal in output writing), please report it privately rather than opening a public
issue — see the contact method in the repo's root README or open a GitHub Security Advisory
against this repository.

## Data handling

- Downloaded JS files for `--url`/`--domain` scans are written to a temp directory and
  deleted after scanning (see `cleanup_temp_files` in the scanner).
- Discovered secrets, emails, and endpoints are written unencrypted to your local
  `--output-dir`. Treat that directory as sensitive — it may contain live credentials for
  third-party systems. Don't commit it to a public repo, and clean it up after you've filed
  your report.
