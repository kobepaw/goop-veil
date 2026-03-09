# Known Limitations

This release is a **software-only research preview**.

## Scope
- The initial supported surface is the Python/Rust software stack.
- Firmware-related components in this repository are **experimental** and are **not** part of the initial supported release promise.
- Linux is currently required for WiFi scanning/capture workflows described in the README.

## Detection
- Detection is heuristic and should be treated as a **lead**, not proof or attribution.
- False positives and false negatives are possible.
- Performance depends on router hardware, chipset behavior, traffic conditions, RF environment, and attacker setup.

## Mitigation
- Mitigation guidance is research-informed, but real-world effectiveness varies.
- Router automation is model/firmware dependent.
- Changes to WiFi settings can affect connectivity, roaming, performance, and device compatibility.
- Use dry-run/review flows before applying state-changing actions.

## Evidence / Documentation
- Evidence bundles are technical documentation artifacts.
- They are **not** determinations and not a guarantee of admissibility in any court, agency, or dispute process.
- If signing keys are not handled correctly in deployment, later verification may be limited.

## Platform / Support
- No Windows support in this release.
- Router compatibility is still evolving.
- Some advanced features require extras, privileges, or hardware not covered by the default install path.

## Safety / Compliance
- goop-veil is designed with conservative guardrails, but it does **not** certify compliance for a specific deployment.
- Laws and radio rules vary by jurisdiction and context.
- Validate reporting and response paths for your own context before relying on outputs.
