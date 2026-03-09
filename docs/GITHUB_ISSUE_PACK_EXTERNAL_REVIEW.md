# GitHub Issue Pack — External Review Response

This issue pack translates the verified external-review findings into actionable GitHub issues.

## Priority structure
- **P0** — trust-critical / immediate
- **P1** — stabilization / week-one
- **P2** — structural improvement / roadmap

---

## P0-1: Enforce explicit signing-key policy for verifiable artifacts
**Labels:** `security-sensitive`, `public-surface`, `release-blocker`, `priority:p0`

### Summary
Remove silent random signing-key fallback in normal runtime for reporting artifacts. If no signing key is configured, either fail closed for verifiable mode or clearly downgrade output to unsigned/temporary mode.

### Why
Current behavior can create artifacts that appear durable/verified but cannot be reliably verified later if the random key is lost. This is a trust-boundary problem.

### Scope
- Review `python/goop_veil/mitigation/legal/log_exporter.py`
- Review evidence/report generation callers
- Define dev/test behavior separately from normal runtime behavior
- Ensure runtime messaging clearly communicates artifact verification state

### Acceptance criteria
- Normal runtime does not silently generate random signing keys for durable signed artifacts
- Missing key causes either:
  - explicit failure for verifiable mode, or
  - explicit unsigned/temporary output mode
- Docs explain `VEIL_LOG_SIGNING_KEY`
- Tests cover key present vs missing behavior

---

## P0-2: Harden CLI confirmation flow for state-changing actions
**Labels:** `security-sensitive`, `router-impact`, `priority:p0`

### Summary
Align CLI auto-apply behavior with the stronger confirmation expectations already used in the MCP path.

### Why
State-changing actions should not be easier to trigger from the CLI than from other control surfaces.

### Scope
- Review CLI paths that pass `confirmed=True` directly
- Introduce explicit second-step confirmation or safer interaction model
- Preserve dry-run as default

### Acceptance criteria
- CLI state-changing behavior requires explicit confirmation beyond a single flag where appropriate
- Help text/docs explain the confirmation model
- Tests cover refusal vs confirmed execution

---

## P0-3: Truth-align simulated and stubbed paths
**Labels:** `truth-alignment`, `public-surface`, `priority:p0`

### Summary
Mark mocked/simulated/stubbed behavior clearly in user-facing outputs and docs.

### Why
Users should not mistake simulated behavior or placeholder integrations for deployed protection or active federation.

### Scope
- Review MCP activate path and any mock HAL usage
- Review integration bridges that currently return success-like behavior without full implementation
- Update docs/tool descriptions accordingly

### Acceptance criteria
- Simulated/mock behavior is labeled clearly in runtime outputs and docs
- Stub integrations no longer imply full success silently
- README/FAQ/limitations reflect current reality

---

## P0-4: Fix runtime status/report correctness issues
**Labels:** `type:bug`, `truth-alignment`, `priority:p0`

### Summary
Ensure status/reporting surfaces reflect actual active runtime values rather than config defaults where possible.

### Why
Silent mismatches between configured and actual active state erode trust quickly.

### Scope
- Review `PrivacyEnhancer.status()` and related runtime state reporting
- Identify any other user-visible mismatches in status output

### Acceptance criteria
- Status reflects actual active values or clearly labels values as configured/default only
- Tests cover corrected behavior

---

## P0-5: Clean remaining launch-surface drift
**Labels:** `type:docs`, `truth-alignment`, `public-surface`, `priority:p0`

### Summary
Remove stale launch-state/version references and tighten the public release surface.

### Why
Even small stale details undermine trust during early launch.

### Scope
- Fix stale docs such as repo visibility/status references
- Align `0.1.0` vs `0.1.0-beta` posture where needed
- Remove any lingering public wording that implies stronger certainty than intended

### Acceptance criteria
- Public docs present a single coherent release posture
- No stale “repo private” style references remain
- Versioning language is consistent enough for external readers

---

## P1-1: Add coverage reporting to CI
**Labels:** `type:feature`, `docs-required`, `priority:p1`

### Summary
Add `pytest --cov` (or equivalent) to CI as a non-blocking visibility step first, then later introduce a threshold.

### Why
Large passing test count exists, but coverage quality is not currently measured.

### Acceptance criteria
- CI produces coverage output/artifact
- Coverage is visible to maintainers
- Initial rollout does not destabilize the current pipeline

---

## P1-2: Add lint/type/security gates to CI
**Labels:** `security-sensitive`, `priority:p1`

### Summary
Add pragmatic week-one CI gates: `ruff`, `mypy`, dependency audit, and lightweight secret scanning.

### Why
Trust and release discipline improve when obvious correctness and security hygiene checks run automatically.

### Acceptance criteria
- Lint job added
- Type-check job added
- Dependency audit added
- Lightweight secret scan/check added if safe
- Documentation updated if contributor workflow changes

---

## P1-3: Harden release workflow with smoke validation
**Labels:** `type:feature`, `priority:p1`

### Summary
Add post-build smoke validation to the release pipeline and clarify Python-version install expectations.

### Why
Release automation exists, but artifact truthfulness and install validation can be stronger.

### Scope
- Verify built wheel tags
- Add smoke install/import checks
- Decide whether to build 3.11 artifacts too or document fallback clearly

### Acceptance criteria
- Release workflow validates built artifacts more directly
- Supported install paths are documented truthfully

---

## P1-4: Document reporting artifact verification semantics
**Labels:** `type:docs`, `truth-alignment`, `priority:p1`

### Summary
Explain exactly what makes a reporting artifact verifiable, temporary, unsigned, or environment-dependent.

### Why
Users need a clear mental model for the integrity story.

### Acceptance criteria
- README/FAQ/limitations/release notes clearly explain verification states
- `VEIL_LOG_SIGNING_KEY` setup documented in one obvious place

---

## P1-5: Seed contributor intake and triage structure
**Labels:** `type:feature`, `priority:p1`

### Summary
Create labels, starter issues, and a visible contributor runway to convert attention into useful participation.

### Why
The repo now has intake templates, but it still needs labels and seeded issues.

### Acceptance criteria
- Domain-specific labels exist
- 8–12 starter issues are seeded
- 4+ issues marked `good first issue`
- README or pinned issue points contributors to the intake path

---

## P2-1: Replace title-based mitigation execution with structured actions
**Labels:** `type:feature`, `security-sensitive`, `priority:p2`

### Summary
Stop deriving machine behavior from human-readable recommendation titles.

### Why
String-matching on titles is brittle and can break silently if wording changes.

### Acceptance criteria
- Recommendation model carries structured action payload/type
- Execution path no longer depends on title text matching
- Relevant tests updated

---

## P2-2: Extract shared analysis pipeline helpers for CLI and MCP
**Labels:** `type:feature`, `priority:p2`

### Summary
Reduce duplicated scan/analyze/assess orchestration across CLI and MCP.

### Why
Shared flow duplication increases maintenance cost and drift risk.

### Acceptance criteria
- Common analysis helper/service exists
- CLI and MCP call through the shared path where appropriate
- No launch-surface regressions introduced

---

## P2-3: Refactor MCP shared mutable state
**Labels:** `security-sensitive`, `area:mcp`, `priority:p2`

### Summary
Reduce or eliminate module-level shared mutable singleton state in the MCP server.

### Why
Shared state can create concurrency issues and state bleed under load.

### Acceptance criteria
- Clear lifecycle for scanner/engine state
- Concurrency risk reduced
- Behavior remains understandable and testable

---

## P2-4: Improve MCP and integration-bridge test coverage
**Labels:** `type:research`, `area:mcp`, `priority:p2`

### Summary
Add focused tests for MCP tools, confirmation gates, and integration bridges.

### Why
These are high-trust surfaces where behavior needs to be explicit and regression-resistant.

### Acceptance criteria
- MCP confirmation behavior covered
- Integration bridges tested or clearly marked stubbed in tests/docs
- Coverage in high-trust surfaces improves materially

---

## P2-5: Add claims-and-sources ledger
**Labels:** `type:docs`, `public-surface`, `priority:p2`

### Summary
Create a single source-of-truth doc for major quantitative/policy claims and their sources/confidence.

### Why
Helps prevent drift and makes external review easier to answer cleanly.

### Acceptance criteria
- `docs/claims-and-sources.md` (or equivalent) exists
- Major public claims are mapped to source/confidence/context

---

## Suggested execution order
1. P0-1 signing-key policy
2. P0-2 CLI confirmation hardening
3. P0-3 simulated/stubbed truth alignment
4. P0-4 status/report correctness
5. P0-5 launch-surface cleanup
6. P1 CI/release improvements
7. P1 contributor intake / seeded issues
8. P2 structural refactors
