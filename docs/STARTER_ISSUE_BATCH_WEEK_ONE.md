# Starter Issue Batch — Week One

This file seeds a maintainer-ready issue batch for the first week of public contributor intake. It assumes issue creation will happen manually in GitHub later.

## Use

- create 8 to 12 issues from this list
- preserve the proposed labels unless a better repo-local label exists
- mark at least 4 issues with `good-first-issue`
- keep issue bodies short and concrete when copying into GitHub

## Starter issues

### 1. Add coverage reporting artifact to CI

**Labels:** `type:feature`, `priority:p1`, `docs-required`, `good-first-issue`

Add a non-blocking coverage step to CI so maintainers can see which areas are still under-tested without destabilizing the pipeline.

**Acceptance criteria**
- CI emits coverage output or artifact
- the new step does not fail the build on an initial threshold
- contributor docs mention the coverage command if workflow changes

### 2. Add `VEIL_LOG_SIGNING_KEY` setup docs to one obvious contributor path

**Labels:** `type:docs`, `priority:p1`, `truth-alignment`, `public-surface`, `good-first-issue`

Document how signed, unsigned, and temporary evidence artifacts differ, with one obvious setup section for local testing.

**Acceptance criteria**
- one contributor-facing doc explains key setup
- README, FAQ, or limitations no longer leave verification state ambiguous
- wording does not imply courtroom or certification guarantees

### 3. Audit README command examples against current CLI output

**Labels:** `type:docs`, `priority:p1`, `truth-alignment`, `public-surface`, `good-first-issue`

Check every README command example for drift against the current CLI behavior and fix stale wording or unsupported implications.

**Acceptance criteria**
- each documented command is either verified or corrected
- any simulated or partial flows are labeled clearly
- no command example implies stronger certainty than the implementation provides

### 4. Add smoke install/import validation to release automation

**Labels:** `type:feature`, `priority:p1`, `public-surface`

Strengthen the release workflow so built artifacts are smoke-tested before they are treated as publishable.

**Acceptance criteria**
- release workflow installs the built package in a clean environment
- workflow verifies a basic import or CLI help command
- any Python-version constraints are documented truthfully

### 5. Improve false positive/false negative intake docs

**Labels:** `type:docs`, `priority:p1`, `truth-alignment`, `good-first-issue`

Make it easier for contributors to submit high-signal detection-quality reports without leaking unnecessary sensitive data.

**Acceptance criteria**
- contributor guidance explains what evidence is useful
- docs mention redaction expectations for logs or pcaps
- false-positive reports are easier to route into reproducible follow-up work

### 6. Add lightweight lint and type-check CI jobs

**Labels:** `type:feature`, `priority:p1`, `security-sensitive`

Introduce pragmatic week-one correctness checks without turning the pipeline into a migration project.

**Acceptance criteria**
- lint job added
- type-check job added, even if scoped narrowly at first
- docs mention any new local validation commands contributors should run

### 7. Publish a router compatibility matrix from existing support claims

**Labels:** `type:docs`, `priority:p1`, `area:mitigation-router`, `public-surface`

Translate current router support statements into a truth-aligned matrix that makes supported, experimental, and unverified paths obvious.

**Acceptance criteria**
- at least OpenWrt, UniFi, and TP-Link are listed
- each entry states supported, experimental, or unverified
- known gaps and validation limits are visible

### 8. Tighten CLI confirmation copy for state-changing actions

**Labels:** `type:feature`, `priority:p0`, `security-sensitive`, `router-impact`

Review CLI copy and interaction flow for any state-changing action that may currently be too easy to trigger or too vague about consequences.

**Acceptance criteria**
- state-changing paths require explicit confirmation where appropriate
- help text makes dry-run and apply behavior clear
- tests cover refusal and confirmed execution paths

### 9. Add a maintainer triage checklist for new public issues

**Labels:** `type:docs`, `priority:p1`, `good-first-issue`

Create a short triage checklist maintainers can follow when a new public issue arrives.

**Acceptance criteria**
- checklist covers repro quality, scope, trust risk, and routing
- checklist points to label guidance
- checklist is short enough to use during active launch week

### 10. Replace any stale launch-state references in public docs

**Labels:** `type:docs`, `priority:p0`, `truth-alignment`, `public-surface`, `good-first-issue`

Remove stale beta, release, visibility, or posture references that could confuse external readers.

**Acceptance criteria**
- public-facing docs use a coherent release posture
- outdated “private repo” or similar wording is removed
- version naming is consistent enough for week-one launch

## Recommended first batch to file

If maintainers only want to file 8 issues immediately, start with:

1. Add coverage reporting artifact to CI
2. Add `VEIL_LOG_SIGNING_KEY` setup docs to one obvious contributor path
3. Audit README command examples against current CLI output
4. Add smoke install/import validation to release automation
5. Improve false positive/false negative intake docs
6. Add lightweight lint and type-check CI jobs
7. Tighten CLI confirmation copy for state-changing actions
8. Replace any stale launch-state references in public docs
