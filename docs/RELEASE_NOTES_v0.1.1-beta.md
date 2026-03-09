# goop-veil v0.1.1-beta

**Software-only WiFi privacy defense research preview**

Your WiFi can be used to sense you through walls. goop-veil is an open-source research preview that helps **detect, degrade, and document** potential WiFi CSI surveillance using supported consumer routers.

## Highlights
- sharper public repo positioning around through-wall WiFi sensing risk
- explicit signing-key policy hardening for evidence/documentation artifacts
- tighter release workflow aimed at producing real wheel artifacts on tag builds
- CI upgrades: coverage artifact, staged lint/type/audit jobs, lightweight secret scan
- contributor runway: labels, starter issues, and week-one triage docs

## What this beta does
- **Detect** suspicious sensing indicators such as Espressif mesh patterns, channel hopping, and CSI-related signatures
- **Degrade** sensing reliability through supported router controls and legitimate traffic orchestration
- **Document** incidents with timestamped, HMAC-signed evidence bundles for review/reporting workflows

## Important limits
- This is a **research preview**, not a determination, attribution, or compliance certification product.
- Detection is heuristic and should be treated as a lead, not proof.
- Mitigation aims to reduce sensing reliability, not guarantee prevention.
- Effectiveness depends on router model, RF environment, traffic conditions, and attacker behavior.
- Firmware-related components remain experimental and are not part of the supported initial release surface.

## Recommended first steps
```bash
pip install goop-veil[cli]
goop-veil scan
goop-veil detect capture.pcap
goop-veil mitigate
goop-veil evidence capture.pcap
```

## Feedback we want
- install friction reports
- router compatibility reports
- false positive / false negative examples
- documentation corrections
- contributor help on clearly scoped starter issues

See also:
- `docs/KNOWN_LIMITATIONS.md`
- `docs/LAUNCH_PACK_2026-03-09.md`
- `CONTRIBUTING.md`
