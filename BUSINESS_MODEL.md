# Turning VulnJSpy Into a Commercial / Subscription Product

This is general product-strategy guidance, not legal or tax advice — talk to a lawyer before
you finalize licensing terms or start charging money, especially given the tool touches
security scanning across third-party domains.

## 1. Decide what stays free vs. what's paid

Open-sourcing the CLI (as you're planning) and monetizing something *around* it is the most
common path for tools like this — it's what let TruffleHog, Semgrep, and Nuclei build paid
tiers on top of genuinely useful free cores. The free/paid split usually looks like:

**Free (open source, MIT or Apache-2.0):**
- The CLI itself, full pattern library, local/URL/domain scan modes
- JSON/CSV output
- Community-contributed patterns

**Paid (hosted or licensed separately):**
- A hosted dashboard: scan history, diffing between runs (what secrets are *new* since last
  scan — this is usually the single highest-value paid feature for a recon tool), team
  access
- Continuous/scheduled scanning of a program's assets rather than one-off CLI runs
- Live credential verification (calling provider APIs to confirm a key is still active,
  behind explicit opt-in and rate limiting) — this is valuable enough to bounty hunters that
  it alone can justify a subscription, but it's also the feature most likely to draw
  provider ToS scrutiny, so gate it carefully and document exactly what it does
- Multi-target/multi-program asset inventory and reporting exports (PDF/DOCX report
  generation for client or program submissions)
- Priority pattern updates / private pattern sets
- SSO, audit logs, seat management — standard enterprise-tier line items if you ever sell to
  security teams rather than individual researchers

Keeping the core scanner free is also what makes the GitHub launch credible — a security tool
that's paywalled from the first `git clone` gets far less community trust and far fewer
external pattern contributions than one that's genuinely open.

## 2. Licensing structure

Two common patterns:

- **MIT/Apache-2.0 core + proprietary hosted service** — the CLI stays fully open, the
  dashboard/API/verification service is closed-source SaaS. Simplest to reason about, no
  license enforcement problem, but anyone can self-host the CLI and never pay you (which is
  fine — that's the point of "open core").
- **BSL (Business Source License)** — source is visible but competitors can't offer it as a
  competing hosted service for a defined period (commonly 2–4 years) before it converts to
  Apache-2.0. More protection against a cloud provider or competitor re-hosting your exact
  product, but adds friction and confusion for casual open-source users, and some
  communities react negatively to it. Worth it mainly if the hosted product, not the CLI, is
  your actual business.

Given this tool's audience (individual bug bounty hunters, not enterprises), MIT-core +
paid-hosted-layer is the lower-friction choice.

## 3. Pricing shape (illustrative, not a recommendation of specific numbers)

A typical structure for a tool at this stage:

| Tier | Who it's for | What it adds over the free CLI |
|---|---|---|
| Free | Individual hunters, evaluators | Full CLI, community patterns |
| Individual (monthly/annual) | Active bounty hunters running frequent scans | Hosted scheduling, scan diffing, history, export reports |
| Team | Small security consultancies | Multi-user, shared program/target lists, role-based access |
| Enterprise | In-house AppSec teams | SSO, audit logging, custom pattern sets, SLA, on-prem option |

Anchor pricing against what your target user already pays for adjacent tools (Burp Suite Pro,
a bug bounty platform's private program tooling, etc.) rather than against a stat like "$399
vs free" — bounty hunters are price-sensitive and will churn fast if the paid tier doesn't
save them more time than the subscription costs.

## 4. What NOT to do

- **Don't gate the pattern library itself behind a paywall** without also keeping a
  reasonably capable free set — a "free tier with 10 patterns, pay for the other 290" model
  reads as bait-and-switch to a security community and will tank GitHub stars/trust fast.
- **Don't market unverified accuracy numbers** as differentiators (see the note in the main
  README) — a paying customer who churns after finding the 99.2%/less-than-1% figures aren't
  reproducible is worse for the business than never claiming them.
- **Don't build "live credential verification" without careful legal review** — actively
  testing whether a found key works against AWS/Stripe/etc. can itself look like unauthorized
  access if done against a target outside your user's authorized scope. If you build this,
  gate it tightly to require the user affirm they have authorization for the target, log
  consent, and rate-limit aggressively.

## 5. Practical first step

Before building a subscription tier, the highest-leverage move is usually: open-source the
CLI now, see what people actually build workflows around (scan diffing? report export?
CI integration?), and let the first paid feature be whatever real users ask for repeatedly —
not the feature that looked most impressive in a pitch. A hosted "run this on a schedule and
tell me what's new" service is the most commonly requested feature for tools in this category,
so it's a reasonable default bet if you want to start building before demand is fully proven.
