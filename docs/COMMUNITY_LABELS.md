# Community Labels Guide

This file defines a practical label set for week-one triage. It is intentionally small enough to create quickly and specific enough to route contributors without maintainer guesswork.

## Goals

- make new issues sortable within a few seconds
- separate trust-critical work from normal backlog items
- give contributors a visible runway into docs, testing, and router work
- keep labels aligned with existing issue templates and governance notes

## Week-one label set

Create these labels first.

### Type labels

- `type:bug` — reproducible product defect or regression
- `type:docs` — docs, wording, examples, FAQ, README, or limitation updates
- `type:feature` — additive product or workflow change
- `type:research` — investigation, validation, compatibility testing, or exploratory work

### Priority labels

- `priority:p0` — trust-critical, release-blocking, or safety-sensitive
- `priority:p1` — important week-one stabilization or contributor runway work
- `priority:p2` — roadmap work that should not displace urgent fixes

### Domain labels

- `truth-alignment` — implementation, docs, or messaging do not match
- `security-sensitive` — auth, transport, secrets, signing, confirmation, or state-management risk
- `docs-required` — code change is not complete until docs land with it
- `public-surface` — affects README, CLI UX, release copy, or user-visible trust posture
- `router-impact` — changes router behavior, safety defaults, or compatibility posture
- `area:mitigation-router` — router adapters, router support matrix, or apply/dry-run behavior
- `area:mcp` — MCP server or tool invocation surface
- `privacy-redaction` — logs, captures, evidence bundles, or redaction policy
- `firmware-experimental` — firmware work outside the supported initial public surface
- `release-blocker` — must be resolved before the next public release cut
- `good-first-issue` — narrow scope, clear acceptance criteria, and low-risk review path

## How to apply labels

Use one label from each of these groups on almost every issue:

- one `type:*`
- one `priority:*`
- one or more domain labels

Recommended examples:

- CLI confirmation bug: `type:bug`, `priority:p0`, `security-sensitive`, `router-impact`
- README wording drift: `type:docs`, `priority:p1`, `truth-alignment`, `public-surface`
- Router compatibility report: `type:research`, `priority:p1`, `area:mitigation-router`
- New contributor docs task: `type:docs`, `priority:p1`, `good-first-issue`

## Triage rules

- Add `release-blocker` only when the issue can directly damage trust, safety, or launch readiness.
- Add `good-first-issue` only if a new contributor can finish the work without changing shared architecture or security-critical code.
- Prefer `truth-alignment` whenever docs or runtime messaging could overstate capability or certainty.
- Prefer `docs-required` on feature or hardening work that changes user-visible behavior.
- Avoid label overload. If an issue already has a clear type, priority, and 2 domain labels, that is usually enough.

## Issue template mapping

The current templates already map cleanly onto this set:

- bug report -> `type:bug`
- docs / truth-alignment -> `type:docs`, `truth-alignment`
- false positive / false negative -> `type:research`
- router compatibility -> `type:research`, `area:mitigation-router`

After labels are created in GitHub, update templates only if maintainers want additional defaults. That is optional for week one.

## Suggested creation order

If maintainers want the fastest possible setup, create labels in this order:

1. `type:bug`
2. `type:docs`
3. `type:feature`
4. `type:research`
5. `priority:p0`
6. `priority:p1`
7. `priority:p2`
8. `truth-alignment`
9. `security-sensitive`
10. `public-surface`
11. `router-impact`
12. `area:mitigation-router`
13. `good-first-issue`

The remaining labels can follow once the initial queue is live.
