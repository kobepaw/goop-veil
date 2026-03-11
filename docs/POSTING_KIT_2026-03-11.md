# goop-veil Posting Kit

Date: 2026-03-11
Status: ready
Repo: https://github.com/kobepaw/goop-veil

## Core line
Your WiFi can be used to sense you through walls. goop-veil is a software-only research preview that helps **detect, degrade, and document** potential WiFi CSI surveillance using supported routers.

## Short repo blurb
Software-only WiFi privacy defense for an emerging sensing threat. Detect, degrade, and document potential CSI surveillance with supported routers.

## Guardrails
Use these every time:
- say **software-only research preview**
- say **detect / degrade / document**
- say **supported routers**
- say **results vary by environment**
- avoid proof/certainty/compliance-certification language
- keep firmware experimental unless explicitly discussing it

## HN title options
1. Show HN: goop-veil — software-only defense against through-wall WiFi sensing
2. Show HN: goop-veil — detect, degrade, and document WiFi CSI surveillance
3. Show HN: open-source WiFi privacy defense for an emerging sensing threat

## HN first comment
I built goop-veil because WiFi sensing is becoming more practical while defensive tooling is still early.

The project is intentionally narrow: it helps **detect, degrade, and document** potential WiFi CSI surveillance using supported routers.

What it is:
- open source (Apache-2.0)
- Rust + Python
- Linux-first for scanning/capture workflows
- cautious about claims and limitations

What it is not:
- not proof or attribution
- not a compliance-certification product
- not guaranteed prevention
- not a finished firmware release

If people kick the tires, the most useful feedback is:
- install friction
- router compatibility reports
- false positives / false negatives
- docs clarity

Repo: https://github.com/kobepaw/goop-veil

## X thread

### Post 1
Your WiFi can be used to sense you through walls.

Presence. Motion. Breathing. Even heartbeat.

goop-veil is a new open-source, software-only research preview built to help **detect, degrade, and document** potential WiFi CSI surveillance using supported routers.

https://github.com/kobepaw/goop-veil

### Post 2
This is about RF sensing, not reading your internet traffic.

Researchers have shown that ordinary WiFi signals can reveal physical activity under some conditions — including through walls.

### Post 3
The goal is intentionally modest and honest:
- detect suspicious sensing indicators
- degrade sensing reliability where possible
- document what you’re seeing

Not hype. Not magical prevention claims.

### Post 4
Current public surface:
- Linux-first scan/capture workflows
- supported router paths: OpenWrt, UniFi, selected TP-Link
- Rust core + Python orchestration
- 500+ automated tests

### Post 5
Important caveat: this is a **research preview**.

Detection is heuristic.
Mitigation effectiveness varies.
The repo documents limits instead of pretending the problem is solved.

### Post 6
If you test it, the most useful feedback is:
- install issues
- router compatibility reports
- false positives / negatives
- docs corrections

## X reply fragments
- Fair pushback. The repo is intentionally framed as a research preview, not proof or guaranteed prevention.
- Yep — supported-router scope matters here. OpenWrt and UniFi are the clearest current paths; TP-Link is more model-dependent.
- To be precise: heuristic detection, guarded mitigations, documentation artifacts. Not attribution.
- If you hit install friction, I’d rather hear that than get empty hype. That feedback is genuinely useful.

## Reddit: r/privacy
**Title:** Your WiFi can be used to sense you through walls. goop-veil is an open-source research-preview defense.

**Body:**
WiFi sensing is moving from niche research toward practical deployment, while consumer defense tooling is still early.

I built goop-veil as a software-only research preview that helps **detect, degrade, and document** potential WiFi CSI surveillance using supported routers.

What it does:
1. detect suspicious sensing indicators
2. apply guarded router-based mitigations where supported
3. generate documentation artifacts for review/reporting workflows

What it does not do:
- it does not prove someone is spying on you
- it does not guarantee prevention
- it is not a compliance-certification tool

Repo: https://github.com/kobepaw/goop-veil

If people want to test it, I especially want feedback on router compatibility, install friction, and false positives/negatives.

## Reddit: r/netsec
**Title:** goop-veil: software-only WiFi CSI surveillance defense (Rust + Python)

**Body:**
Sharing goop-veil, an open-source research preview for detecting potential WiFi sensing activity, degrading sensing reliability through supported routers, and generating documentation artifacts.

Current posture:
- Rust + Python
- Linux-first scan/capture workflows
- OpenWrt / UniFi / selected TP-Link paths
- 500+ automated tests
- explicit limitations and non-certification language

Looking for technical feedback on:
- detection quality
- false positives / negatives
- router adapter coverage
- install and packaging friction

Repo: https://github.com/kobepaw/goop-veil

## Reddit: r/selfhosted
**Title:** Built a software-only WiFi privacy defense that works through supported routers

**Body:**
I’ve been working on a project called goop-veil: a software-only research preview for detecting potential WiFi sensing activity, applying guarded mitigations through supported routers, and generating documentation artifacts.

Why self-hosted people may care:
- no cloud dependency
- local-first workflows
- OpenWrt / UniFi / selected TP-Link support
- Linux-first scanning/capture
- plain CLI install path

Quick start:
```bash
pip install 'git+https://github.com/kobepaw/goop-veil.git#egg=goop-veil[cli]'
goop-veil scan
```

Repo: https://github.com/kobepaw/goop-veil

## Call to action variants
- Star the repo if you want to see open-source defense tooling exist in this category.
- If you test it on real hardware, router compatibility reports are gold.
- The most helpful early feedback is install friction, false positives, and unsupported-router confusion.
- If you want to contribute, ASUS Merlin and field validation are strong targets.
