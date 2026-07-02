# Contributing to VulnJSpy Professional

Thanks for considering a contribution. This project accepts:

- New/improved regex patterns
- Bug fixes
- Documentation improvements
- New output integrations (SARIF, ticketing systems, etc.)

## Adding a new secret pattern

1. Add the pattern to `ENTERPRISE_REGEX_PATTERNS` in the main script, following the existing
   `(name, regex, base_confidence)` tuple format.
2. Add at least one **realistic but fake** test string to `tests/patterns/` — never commit a
   real credential, even an expired one, as a test fixture.
3. In your PR description, note:
   - The source/vendor for this secret format (link to their docs if public)
   - Why the chosen base confidence is appropriate (how distinctive is the format?)
   - Any known false-positive shapes this pattern could match

## Reporting false positives

Open an issue with:
- The pattern name that fired
- A redacted/synthetic example of what matched (do **not** paste a real leaked secret into a
  public issue)
- What made it a false positive (placeholder value? coincidental format overlap?)

## Code style

- Match the existing async/await structure — avoid introducing blocking calls inside worker
  coroutines.
- Keep new CLI flags documented in both `create_parser()` help text and `README.md`.
- Run existing tests before submitting: `pytest tests/`

## Code of conduct

Be respectful. This tool exists to help authorized security research — contributions or
discussion aimed at enabling unauthorized access will be rejected and may result in a ban
from the repository.
