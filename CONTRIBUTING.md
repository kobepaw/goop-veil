# Contributing to goop-veil

Thanks for helping improve goop-veil.

This project is currently a **software-only research preview**. We move quickly, but we want changes to remain reviewable, truthful, and safe by default.

## Good ways to contribute
- Router compatibility reports
- Detection quality improvements
- Docs and truth-alignment fixes
- Issue reproduction and test coverage
- Experimental firmware work (clearly scoped as experimental)

## Before you open a PR
Please:
1. Keep the PR small and reviewable when possible.
2. Explain the problem being solved.
3. Describe the scope boundaries.
4. Include validation notes (tests, manual verification, docs updates).
5. Make sure public docs still match implementation.

See `.github/pull_request_template.md` for the expected structure.

## Truth-alignment matters
If behavior changes, update the docs in the same PR when needed.

Examples:
- README command examples
- Known limitations
- FAQ
- Experimental vs supported scope
- Router compatibility notes

Overclaiming is a project quality issue.

## Safety-sensitive areas
Changes touching these areas need extra care:
- `python/goop_veil/mcp/`
- `python/goop_veil/mitigation/router/`
- `python/goop_veil/mitigation/legal/` / reporting paths
- `firmware/`
- README and launch-facing docs

See `docs/SECURITY_REVIEW.md` for the maintainer review posture.

## Local validation
At minimum, contributors should run relevant targeted tests for changed areas when possible.

Example:
```bash
PYTHONPATH=python pytest tests/test_cli.py tests/test_mitigation -q
```

For CI-related or repo-wide changes, these checks are also useful:
```bash
PYTHONPATH=python pytest --cov=goop_veil --cov-report=term-missing --cov-report=xml tests -q
ruff check python tests
mypy --ignore-missing-imports python/goop_veil
python scripts/check_secrets.py
pip-audit
```

If you cannot run a test locally, say so clearly in the PR.

## Experimental firmware contributions
Firmware-related work is currently **experimental** and not part of the initial supported public release surface.

If you contribute there, include:
- hardware assumptions
- safety notes
- test procedure
- what remains incomplete

## Reporting issues
Please use issue templates when available.

High-signal reports usually include:
- OS / Python version and adapter/router/firmware details
- exact command(s) run and capture duration
- expected vs actual behavior in cautious, non-attribution language
- enough reproduction detail for a maintainer to follow the same path
- redacted logs or pcap-derived excerpts (or safe metadata when raw artifacts should not be shared)

For false-positive / false-negative reports specifically:
- use the dedicated issue template
- include the observed output snippet and why it may be incorrect
- include reproducibility notes so maintainers can route to parser, thresholding, environment, or docs follow-up work
- redact sensitive fields (for example SSIDs, BSSIDs/MACs, IPs, hostnames, account IDs, addresses, or personal identifiers) before posting

See [docs/DETECTION_QUALITY_REPORTING.md](./docs/DETECTION_QUALITY_REPORTING.md) for contributor-facing guidance and privacy-safe evidence examples.

## Community expectations
Be direct, respectful, and evidence-oriented.

We care about:
- honest scope
- reproducibility
- safe defaults
- useful feedback
