# Launch Sequence — goop-veil v0.1.0-beta

## Status
- Repo: private
- Prerelease tag: `v0.1.0-beta`
- Prerelease page exists on GitHub
- Public launch copy drafted in `docs/`

## Goal
Flip visibility and publish a narrow software-only research preview without overclaiming.

## Preconditions
- Final human review complete
- Repo surface re-checked
- Release notes approved
- No internal-only docs remain

## Step 1 — Make repo public
```bash
gh repo edit kobepaw/goop-veil --visibility public --accept-visibility-change-consequences
```

## Step 2 — Verify public surfaces
- README
- `docs/KNOWN_LIMITATIONS.md`
- `docs/FAQ.md`
- release page body
- no accidental private/internal files

## Step 3 — Publish first-wave posts
### GitHub
- point people to prerelease page

### X
- use `docs/X_THREAD_v0.1.0-beta.md`
- pin reply with limitations / scope if needed

### HN
- use `docs/HN_POST_v0.1.0-beta.md`
- stay active for technical questions

## Step 4 — Hold broader rollout briefly
- Watch first responses
- Patch obvious copy/install issues fast
- Only then expand to Reddit / wider forums

## Messaging rules
- Say "software-only research preview"
- Say "heuristic detection"
- Say "not legal advice"
- Keep firmware experimental
- Avoid "first/100%/proof/certified" language

## Rapid-response checklist
- install issue?
- false positive report?
- router compatibility failure?
- legal/compliance misunderstanding?
- media/social overstatement?

## Abort conditions
Pause broader rollout if:
- serious repo hygiene issue found
- major install breakage found
- public copy still implies unsupported claims
- release artifact exposes internal/private material
