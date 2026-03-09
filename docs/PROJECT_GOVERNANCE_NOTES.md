# Project Governance Notes

These notes describe how changes should be introduced so the repository can move quickly without losing trust.

## Preferred PR types

### 1. Capability PRs
New features, adapters, commands, or workflows.

### 2. Hardening PRs
Safer defaults, auth/transport fixes, confirmation flows, redaction, rollback, or defensive behavior.

### 3. Truth-alignment PRs
README fixes, limitation updates, launch copy cleanup, scope clarification, experimental labeling.

Where possible, keep these categories separate so reviewers can reason about them clearly.

## Labels to use
Recommended label set:
- `security-sensitive`
- `truth-alignment`
- `docs-required`
- `router-impact`
- `mcp-surface`
- `firmware-experimental`
- `privacy-redaction`
- `public-surface`
- `release-blocker`
- `good-first-issue`

## Release posture rules
- Supported scope must be explicitly documented.
- Experimental paths must remain visibly experimental.
- Public messaging should never outrun implementation.
- Repo hygiene matters: internal runbooks and private operational notes should not live in the public surface.

## Contributor guidance
Contributors should prefer:
- small, reviewable PRs
- visible validation notes
- clear follow-up items
- honest limitation updates when needed

## Maintainer question set
Before merging, ask:
1. Is this safer by default than before?
2. Do docs still match behavior?
3. Could this confuse users about capability or certainty?
4. Does this need a Known Limitations or FAQ update?
5. Would a skeptical reviewer understand why this is safe to land?
