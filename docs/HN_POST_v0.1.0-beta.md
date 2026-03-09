# Show HN: goop-veil — software-only WiFi sensing defense research preview

I built goop-veil because practical defensive tooling for WiFi sensing/privacy risk is still early.

This project is a **software-only research preview** that focuses on three things:
- detecting potential WiFi sensing indicators
- applying guarded router-based mitigations on supported setups
- generating documentation artifacts for review

A lot of the current public conversation mixes real research with exaggerated assumptions. Through-wall RF sensing is real, but deployment conditions, hardware, and attacker capabilities vary a lot.

That’s why this release is intentionally scoped and cautious.

**What it is:**
- open source (Apache-2.0)
- Rust + Python
- Linux-first for scanning/capture workflows
- focused on detect / mitigate / document

**What it is not:**
- not legal advice
- not a compliance certification product
- not proof or attribution engine
- not a finished firmware release

I’d especially value feedback on:
- detection quality / false positives
- router compatibility
- install friction
- documentation clarity

Repo:
https://github.com/kobepaw/goop-veil
