# goop-veil v0.1.0-beta

**Software-only research preview**

goop-veil is an open-source research preview for detecting potential WiFi sensing activity, applying guarded router-based mitigations, and generating documentation artifacts for review.

## What’s in this beta
- WiFi scan / detection workflows
- Guarded mitigation guidance and router integration paths
- Evidence / documentation bundle generation
- Linux-first scanning and capture flows

## What changed before beta
- hardened router adapter defaults and confirmation flows
- improved redaction in logs and evidence artifacts
- improved CLI behavior when optional dependencies are missing
- aligned public docs around a narrower research-preview posture
- removed internal-only release artifacts from the repo surface

## Important limits
- This is a **research preview**, not a finished compliance or determination product
- Detection is heuristic and should be treated as a lead, not proof or attribution
- Mitigation effectiveness varies by environment, router model, and attacker setup
- Generated artifacts are technical records, not guarantees of admissibility or official outcome
- Firmware-related components in the repo are currently experimental and not part of the initial supported release surface

## Recommended first steps
```bash
pip install goop-veil[cli]
goop-veil scan
goop-veil detect capture.pcap
goop-veil mitigate
goop-veil evidence capture.pcap
```

## Feedback we want
- router compatibility reports
- reproducible install issues
- false positive / false negative examples
- documentation corrections
- contributors for the experimental firmware path

See also:
- `docs/KNOWN_LIMITATIONS.md`
- `docs/FAQ.md`
- `docs/CONTRIBUTING_FIRMWARE.md`
