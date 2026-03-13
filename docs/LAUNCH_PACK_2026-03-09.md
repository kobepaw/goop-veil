# goop-veil Launch Pack

Date: 2026-03-09
Status: ready to execute
Repo: https://github.com/kobepaw/goop-veil

## Core message

**Your WiFi can be used to sense you through walls.** goop-veil is a software-only WiFi privacy defense that helps detect, degrade, and document potential CSI surveillance using your existing router.

## Positioning

### One-line pitch
To our knowledge, goop-veil is the first open-source tool built specifically to detect, degrade, and document WiFi CSI surveillance by programmatically reconfiguring existing consumer routers.

### 50-word pitch
WiFi CSI sensing can infer presence, motion, breathing, and heartbeat through walls using cheap hardware such as ESP32s. goop-veil is a software-only research preview that detects suspicious sensing conditions, degrades sensing reliability through supported routers, and generates signed report packages for reporting and review workflows.

### Taglines
- Detect. Degrade. Document.
- Defend your physical privacy over WiFi.
- Fight back against through-wall WiFi sensing.
- The open-source WiFi privacy defense.

## Messaging guardrails
- Say **software-only research preview**.
- Say **detect / degrade / document**.
- Say **supported routers** and be explicit about which ones.
- Say **degradation, not guaranteed prevention**.
- Do not imply legal certainty, attribution certainty, or courtroom admissibility.
- Keep firmware experimental unless/until promoted explicitly.

## Launch order
1. Ship trust fixes and release workflow fixes.
2. Update README and public repo surface.
3. Set GitHub topics.
4. Seed labels + starter issues.
5. Push launch copy pack.
6. Publish/refresh GitHub prerelease notes.
7. Post HN.
8. Post X thread.
9. Watch responses and patch friction fast.

## GitHub release short description
Open-source software-only WiFi privacy defense research preview. Detects, degrades, and documents potential WiFi CSI surveillance using supported consumer routers.

## Hacker News submission

### Title
Show HN: goop-veil — open-source defense against through-wall WiFi sensing

### First comment
Hey HN — I built goop-veil because WiFi sensing is becoming more practical while defensive tooling is still early.

IEEE 802.11bf standardized WiFi sensing in 2025, but the underlying threat was already here: ordinary WiFi signals can be used to infer presence, motion, breathing, and heartbeat through walls. Cheap ESP32 hardware can do meaningful sensing from the next room, and there is still no obvious consumer defense category.

So this release focuses on a narrow, honest goal: **detect, degrade, and document**.

- **Detect:** scan for Espressif mesh networks, suspicious traffic patterns, rapid channel hopping, and CSI-related signatures.
- **Degrade:** reconfigure supported routers (OpenWrt, UniFi, TP-Link) to reduce sensing reliability using research-backed countermeasures like cover traffic, TX power variation, and band steering.
- **Document:** generate timestamped, HMAC-signed report packages for review and reporting workflows.

It is a **software-only research preview**, not a determination engine, attribution engine, or compliance certification product. The point is to make sensing less reliable and better documented — not to pretend the problem is solved.

Repo: https://github.com/kobepaw/goop-veil

Happy to answer questions about the signal physics, router controls, measured countermeasure effectiveness, or what this still does *not* defend against.

## X thread

1. Your WiFi can be used to sense you through walls.

   Presence. Motion. Breathing. Even heartbeat.

   Cheap hardware can do it quietly, and 802.11bf just standardized WiFi sensing.

   We need defensive tooling here.

2. goop-veil is a new open-source, software-only WiFi privacy defense.

   It helps **detect, degrade, and document** potential WiFi CSI surveillance using your existing router.

3. The threat is physical privacy, not just networking trivia.

   CSI sensing can turn ordinary RF reflections into signals about whether you’re home, moving, breathing, or stationary behind a wall.

4. goop-veil does three things:
   - Detect suspicious sensing conditions
   - Reconfigure supported routers to degrade sensing reliability
   - Generate HMAC-signed report packages for reporting/review workflows

5. It’s backed by published countermeasure research, but the promise is intentionally honest:

   **degradation, not magical prevention**

   Attackers adapt. Environments vary. The tool is a research preview, not a silver bullet.

6. Current surface:
   - OpenWrt / UniFi / TP-Link router paths
   - Rust core + Python orchestration
   - 500+ automated tests
   - MCP support for agent-driven workflows

7. If you care about RF privacy, wireless security, or the future of through-wall sensing defense, take a look:

   https://github.com/kobepaw/goop-veil

   Feedback on install friction, router support, and false-positive/false-negative behavior especially welcome.

## Reddit post skeleton

### Title
Your WiFi can be used to sense you through walls. goop-veil is an open-source defense that fights back with your existing router.

### Body opener
WiFi CSI sensing has moved from niche research into something cheap, practical, and now standards-backed. goop-veil is a software-only research preview built to help detect suspicious sensing conditions, degrade sensing reliability through supported routers, and generate documentation artifacts for review/reporting workflows.

## Repo topics
- wifi-security
- wifi-privacy
- wireless-security
- network-security
- privacy-tools
- openwrt
- unifi
- tplink
- cybersecurity
- rust-python
- mcp

## First 12 issues to seed
1. Enforce explicit signing-key policy for verifiable artifacts
2. Harden CLI confirmation flow for state-changing actions
3. Truth-align simulated and stubbed paths
4. Add CI coverage + lint/type/security gates
5. Seed contributor intake with labels and starter issues
6. Publish router compatibility matrix from existing support claims
7. Audit README command examples against current CLI output
8. Add smoke install/import validation to release automation
9. Improve false positive/false negative intake docs
10. Replace stale launch-state references in public docs
11. Add ASUS Merlin adapter investigation ticket
12. Add field-testing guidance for false-positive/false-negative tuning

## Fast-response playbook
If launch traffic lands, respond in this priority order:
1. install failures
2. unsupported-router confusion
3. overclaiming misunderstandings
4. false-positive reports
5. contribution requests

## Success metrics for the first 72 hours
- Stars
- Release downloads
- Open issues from real users
- Router compatibility reports
- Meaningful HN/X/Reddit replies
- First outside contributor interactions
