# goop-veil v0.1.0-beta

**Release type:** software-only research preview

## What this release is
This release is a narrow public beta focused on the software stack:
- detection / scan workflows
- guarded mitigation guidance and router integration paths
- documentation / report package generation

## What changed before beta
- hardened router adapter defaults and confirmation flows
- improved redaction behavior in logs/evidence artifacts
- improved CLI behavior when optional dependencies are missing
- aligned major public documentation toward a research-preview posture
- cleaned internal-only release artifacts from the public repo surface

## What this release is not
- not a determination product
- not a compliance certification product
- not a guarantee of detection accuracy, mitigation effectiveness, or admissibility
- not a finished firmware release

## Known constraints
- Linux-first for scanning/capture flows
- router support varies by model and firmware
- detection is heuristic
- mitigation outcomes vary by RF environment and attacker behavior

## Recommended usage
1. Start with scan/detect/evidence workflows
2. Review mitigation guidance carefully before applying router changes
3. Treat outputs as technical documentation artifacts, not official conclusions
4. File issues with reproducible details when something breaks

## Call for feedback
We want:
- router compatibility reports
- false positive / false negative examples
- reproducible install issues
- documentation corrections
- contributors for the experimental firmware path
