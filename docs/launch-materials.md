# goop-veil Launch Materials

All marketing materials for the public launch of goop-veil v0.1.0.

---

## 1. Twitter/X Launch Thread (7 tweets)

**Tweet 1 (Hook):**

Your WiFi router can identify you with ~100% accuracy through walls.

Not with a camera. With WiFi signals.

30M+ homes already have the hardware. IEEE 802.11bf made it a standard last year.

There is no defense product for this. Until today.

**Tweet 2 (Explain the threat):**

WiFi Channel State Information (CSI) captures how signals reflect off your body.

From the next room, $10 of hardware can detect:
- Your presence
- Your movement
- Your breathing rate
- Your heartbeat

No camera. No microphone. No consent.

**Tweet 3 (Visceral moment):**

Your WiFi router can see you breathe through walls.

Not metaphorically. Researchers at KIT demonstrated ~100% identification accuracy using beamforming data that routers already collect.

This data is unencrypted. It is not covered by any federal privacy law.

**Tweet 4 (Introduce goop-veil):**

goop-veil is the first open-source defense against WiFi CSI surveillance.

Pure software. No hardware to buy.

pip install goop-veil

Scans your environment, detects sensing devices, applies countermeasures through your existing router, and generates legal evidence packages.

**Tweet 5 (What it does):**

Three steps:

1. SCAN — finds sensing devices near you (no root needed)
2. MITIGATE — reconfigures your router to degrade sensing accuracy (TX power variation alone causes 93% misclassification)
3. DOCUMENT — generates HMAC-signed evidence for FCC complaints

**Tweet 6 (Research backing):**

Every countermeasure backed by peer-reviewed research:

- UChicago 2020: cover traffic drops detection to 47%
- Wi-Spoof 2025: TX power variation = 93% misclassification
- ITU-R P.2040: 5 GHz adds ~22 dB extra wall attenuation

569 tests. Rust core. Apache-2.0.

#WiFiPrivacy

**Tweet 7 (CTA):**

goop-veil is free, open source, and available now:

github.com/kobepaw/goop-veil

pip install goop-veil[cli]

The first WiFi CSI privacy case will set legal precedent. This tool generates the evidence to bring it.

Star it. Share it. Protect yourself.

#WiFiSensing

---

## 2. Hacker News Submission

### Title (Primary)

Show HN: goop-veil -- Detect and counter WiFi CSI surveillance (open source)

### Alternative Titles

1. Show HN: Open-source defense against WiFi through-wall sensing (802.11bf)
2. Show HN: goop-veil -- Software-only countermeasures for WiFi body sensing
3. Show HN: WiFi routers can detect your breathing -- here's an open-source defense

### First Comment (~200 words)

Hey HN -- I built goop-veil because the WiFi CSI surveillance problem has no existing defense tool.

The threat: 802.11bf was ratified September 2025, standardizing WiFi sensing. Researchers at KIT demonstrated near-perfect human identification through walls using beamforming feedback. UChicago showed that $10 of ESP32 hardware can detect breathing and heartbeat from adjacent rooms. 30M+ homes already have routers with the hardware capability.

What goop-veil does:

- **Detection**: Scans for Espressif sensing meshes, suspicious traffic patterns, CSI extraction signatures. No root for basic scans.
- **Mitigation**: Reconfigures your router (OpenWrt, UniFi, TP-Link) to degrade sensing accuracy. TX power variation alone causes 93% misclassification (Wi-Spoof, JISA 2025). Cover traffic drops detection accuracy to 47% (UChicago, NDSS 2020). Band steering to 5 GHz adds ~22 dB additional wall attenuation.
- **Legal evidence**: HMAC-signed detection logs, device fingerprints, and chain-of-custody documentation for FCC complaints. No court has ruled on WiFi CSI yet -- the first case will set precedent.

Architecture: Rust core (802.11 frame parsing, FFT, Fresnel zone physics) for performance, Python for usability. 569 tests. FCC Part 15 compliant by design -- never sends deauth frames, never exceeds 20 dBm conducted power. Apache-2.0 license.

Install: `pip install goop-veil[cli]`

Happy to answer questions about the signal physics, legal landscape, or countermeasure effectiveness measurements.

### Key Points to Address for HN Commenters

**"Is this legal?"**
Yes. All countermeasures use legitimate network traffic and standard router configuration changes (channel, TX power, bandwidth, PMF). The system never sends deauth frames, never exceeds FCC Part 15.247 power limits (20 dBm conducted), and never addresses frames to third-party devices. Every transmission is tagged with a legitimate purpose and audit-logged. The compliance module (`compliance.py`) enforces terminology and power limits at the code level.

**"Does this actually work?"**
Every mitigation is backed by peer-reviewed research with measured effectiveness. Co-channel traffic: detection drops to 47% (UChicago "Et Tu Alexa," NDSS 2020). TX power variation: 93% misclassification (Wi-Spoof, JISA 2025). Band steering to 5 GHz: ~45 dB wall attenuation vs ~23 dB at 2.4 GHz (ITU-R P.2040). Bandwidth widening (80/160 MHz): invalidates trained sensing models. The mitigation implementation plan cites all sources.

**"Why not just use a Faraday cage / RF shielding?"**
goop-veil includes a room vulnerability assessment command (`goop-veil assess`) that recommends physical materials. But most people rent, cannot modify walls, or need a solution today. Software-only countermeasures applied through your existing router work immediately with zero hardware purchases.

**"What routers are supported?"**
OpenWrt (UCI/ubus, full control), UniFi (REST API, good control), TP-Link (HTTP, model-dependent). ASUS Merlin planned. The `BaseRouterAdapter` ABC makes it straightforward to add new adapters.

**"Why Rust + Python?"**
802.11 frame parsing at >1M frames/sec needs native performance. The Rust core handles frame classification, FFT/spectral analysis, Fresnel zone physics, OUI lookups (250K+ entries), and signal propagation modeling. Python handles the detection engine, router APIs, traffic orchestration, and CLI. Built with maturin/PyO3.

**"What about 802.11bf specifically?"**
802.11bf (ratified September 2025) defines a new Measurement Setup action frame for coordinated sensing. goop-veil's signature database includes 802.11bf-specific detection patterns. The standard makes this worse because it moves sensing from a side-channel exploit to a first-class protocol feature. Future routers will advertise sensing capability in their beacons.

**"What does this NOT defend against?"**
PHY-layer defenses like CSI randomization (MIMOCrypt) or CSI fuzzing require controlling the transmitter hardware. goop-veil works purely through your own router and legitimate traffic. It also cannot prevent sensing from devices outside your network -- it can only detect them and generate evidence. SnoopFi (2025) showed that CSI fuzzing can be bypassed with few-shot learning, which is why software-only countermeasures focus on degrading SNR rather than injecting fake CSI.

---

## 3. Reddit Posts

### r/privacy Post

**Title:** Your WiFi router can detect your breathing through walls -- 802.11bf made it a standard, and there's no law against it. Here's an open-source tool to defend yourself.

**Body:**

Last week, researchers at KIT demonstrated that WiFi beamforming data can identify individuals through walls with near-perfect accuracy. This isn't new science -- University of Chicago showed in 2020 that $10 of ESP32 hardware could detect breathing and heartbeat from adjacent rooms -- but 802.11bf, ratified in September 2025, just made WiFi sensing a standard feature of the protocol.

**The scale of the problem:**

- 30M+ homes already have routers with the hardware capability
- No light turns on. No notification. No consent mechanism exists
- The data is unencrypted beamforming feedback (BFI), readable by any device on or near the network
- No federal law explicitly prohibits private WiFi CSI sensing
- Kyllo v. US (2001) established that through-wall sensing is a Fourth Amendment violation, but only constrains government actors -- not your neighbor with an ESP32

**What you can actually do about it:**

I released goop-veil, an open-source tool (Apache-2.0) that does three things:

1. **Detects** WiFi sensing devices near you. Scans for Espressif hardware, suspicious traffic patterns, and CSI extraction signatures. No root required for basic scans.

2. **Mitigates** through your existing router. Software-only countermeasures that degrade sensing accuracy: TX power variation (93% misclassification rate per Wi-Spoof 2025), cover traffic generation (drops detection to 47% per UChicago NDSS 2020), band steering to 5 GHz (doubles wall attenuation), and more.

3. **Documents** everything for legal action. Generates HMAC-signed evidence packages with device fingerprints, timestamps, and chain-of-custody documentation suitable for FCC complaints, BIPA claims (Illinois: $1K-$5K per violation with private right of action), or CCPA/CPRA complaints in California.

No court has ever ruled on WiFi CSI sensing by private parties. The first case will set precedent. This tool generates the evidence you need.

**How to get it:**

```
pip install goop-veil[cli]
goop-veil scan
```

Source: https://github.com/kobepaw/goop-veil

Pure software, zero hardware purchases, 569 tests, Rust core for performance. Supports OpenWrt, UniFi, and TP-Link routers. Works on Linux and macOS.

The strongest legal tools right now are Illinois BIPA (biometric data) and California CCPA/CPRA (physiological characteristics). If WiFi-derived breathing and heartbeat data qualifies as biometric information -- and there are strong arguments that it does -- then unauthorized collection could carry significant statutory damages.

---

### r/netsec Post

**Title:** goop-veil: Open-source WiFi CSI surveillance detection and countermeasures (Rust + Python, 569 tests)

**Body:**

Releasing goop-veil, a tool for detecting and countering WiFi Channel State Information (CSI) surveillance. This is the attack surface that 802.11bf just standardized.

**The threat model:**

An attacker deploys 2-3 ESP32 devices (~$5 each) forming a sensing mesh. They capture per-subcarrier CSI (amplitude + phase from OFDM) to detect presence (>10 dB SNR, 10-25 pps), motion (>15 dB SNR, >99% accuracy through walls), breathing (>20 dB SNR, 2-4m range), and heartbeat (>25 dB SNR, 500-1000 pps). LeakyBeam (NDSS 2025) showed that beamforming feedback (BFI) is transmitted in plaintext, making this even easier on modern APs.

**Architecture:**

- **Rust core** (PyO3/maturin): 802.11 frame parsing at >1M frames/sec, FFT spectral analysis, Fresnel zone body intersection calculations, OUI database (250K+ entries), CSI perturbation modeling, material attenuation calculations
- **Python detection engine**: Beacon scanner (Espressif OUI, suspicious SSID patterns, mesh topology), traffic analyzer (channel hopping detection, null data ratios, action frame analysis), CSI signature matching, alert engine with confidence scoring
- **Router adapters**: OpenWrt (UCI/ubus JSON-RPC), UniFi (REST), TP-Link (HTTP token auth). ABC-based, easy to extend
- **Countermeasures**: Ranked by measured effectiveness with auto-apply capability
- **Legal evidence**: HMAC-signed logs, timestamped device fingerprints, chain-of-custody documentation

**Measured countermeasure effectiveness:**

| Mitigation | Measured Effect | Source |
|---|---|---|
| Co-channel traffic | Detection accuracy drops to 47% | UChicago "Et Tu Alexa" (NDSS 2020) |
| TX power variation | 93% misclassification | Wi-Spoof (JISA 2025) |
| Band steering 2.4 -> 5 GHz | ~45 dB vs ~23 dB wall attenuation | ITU-R P.2040 |
| Bandwidth widening (80/160 MHz) | Invalidates trained sensing models | WiFi Sensing Survey 2025 |
| Beamforming disable | Eliminates BFI plaintext leak | LeakyBeam (NDSS 2025) |
| PMF (802.11w) | Prevents forced disassociation attacks | IEEE 802.11w |

**What it cannot do:**

PHY-layer CSI randomization (MIMOCrypt, AntiSense) requires controlling the transmitter. CSI fuzzing (openwifi FPGA) was shown to be bypassable with few-shot learning (SnoopFi, Computer Networks 2025). Software-only countermeasures focus on degrading the attacker's SNR and breaking temporal coherence, not injecting fake CSI.

**FCC compliance:**

All transmissions stay within Part 15.247 limits. Never sends deauth frames, never exceeds 20 dBm conducted, never addresses frames to third-party devices. Signed audit logs prove compliance. The compliance module enforces this at the code level with prohibited terminology checks and hardware PA cutoffs.

569 tests (Python + Rust), Apache-2.0. Supports Linux and macOS.

```
pip install goop-veil[cli]
goop-veil scan            # No root needed
goop-veil detect file.pcap
goop-veil mitigate --router-host 192.168.1.1 --router-type openwrt
goop-veil evidence file.pcap
```

Source: https://github.com/kobepaw/goop-veil

Interested in contributions on additional router adapters (ASUS Merlin especially) and 802.11bf-specific detection signatures.

---

### r/selfhosted Post

**Title:** Built an open-source tool to detect WiFi sensing devices and harden your router against through-wall surveillance

**Body:**

I've been down a rabbit hole on WiFi CSI (Channel State Information) surveillance for the past few months. The short version: ordinary WiFi signals bouncing off your body carry enough information to detect your presence, movement, breathing, and heartbeat through walls. IEEE 802.11bf standardized this in September 2025. 30M+ homes already have routers with the hardware to do it.

I built goop-veil because no defense tool existed.

**What it does on your home network:**

1. `goop-veil scan` -- scans your WiFi environment for sensing devices. Flags Espressif hardware (the most common CSI sensing platform), hidden SSIDs, suspicious mesh topologies. No root needed, works with any WiFi adapter.

2. `goop-veil mitigate --router-host 192.168.1.1 --router-type openwrt` -- analyzes your router configuration and applies countermeasures. Supports OpenWrt (full control via UCI/ubus), UniFi (REST API), and TP-Link (HTTP). Changes include:
   - TX power variation (93% misclassification per Wi-Spoof 2025)
   - Band steering to 5 GHz (~22 dB additional wall attenuation)
   - Channel hopping (breaks CSI temporal coherence)
   - Bandwidth widening to 80/160 MHz (invalidates trained models)
   - PMF (802.11w) enable (prevents forced disassociation)
   - Beacon interval adjustment (reduces passive CSI samples)

3. `goop-veil monitor --interval 30` -- continuous background scanning. Runs without root. Alerts when new suspicious devices appear.

4. `goop-veil assess --room 4.5x3.5x2.7 --budget 200` -- room vulnerability assessment with material recommendations and cost estimates (RF shielding film, metallic curtains, etc.).

5. `goop-veil evidence capture.pcap` -- generates HMAC-signed legal evidence packages if you need to file complaints.

**Technical details for the self-hosted crowd:**

- Python 3.11+ with Rust native extension (maturin/PyO3) for high-performance 802.11 frame parsing
- Pure `pip install` -- no Docker required, no cloud services, no accounts
- All data stays local. No telemetry, no phone-home
- Router credentials passed via environment variable only (`VEIL_ROUTER_PASSWORD`), never stored in config files
- MCP server mode available for integration with AI assistants
- Web dashboard optional (`pip install goop-veil[dashboard]`)
- 569 tests, Apache-2.0 license

**For OpenWrt users:** You get the best experience. Full UCI/ubus control means goop-veil can adjust channel, TX power, bandwidth, beacon interval, PMF, and RTS threshold. Dry-run mode is the default -- it shows you what it would change before touching anything.

**Install:**

```bash
pip install goop-veil[cli]
goop-veil scan
```

Or from source if you want the Rust core compiled for your platform:

```bash
pip install git+https://github.com/kobepaw/goop-veil.git#egg=goop-veil[cli]
```

Source: https://github.com/kobepaw/goop-veil

This is v0.1.0. ASUS Merlin support is planned. Happy to take feature requests and PRs.

---

## 4. Blog Post

# Your WiFi Can See You Breathe -- Here's How to Stop It

In September 2025, the IEEE ratified 802.11bf, a new amendment to the WiFi standard. It did not make headlines. It should have.

802.11bf standardizes WiFi Sensing -- the ability of ordinary WiFi hardware to detect human presence, movement, breathing rate, and heartbeat through walls, ceilings, and floors. Not with cameras. Not with microphones. With the same radio signals that carry your Netflix stream.

Researchers have known about this capability for years. What changed is that it is now a first-class feature of the protocol. Future routers will not just be able to do this -- they will advertise the capability in their beacon frames, coordinate sensing sessions through standardized action frames, and share the results over standard interfaces.

There are 30 million homes in the United States alone that already have routers with the hardware to perform WiFi sensing. There is no notification when it happens. There is no consent mechanism. And there is no law that explicitly prohibits it.

Until today, there was also no defense tool. goop-veil changes that.

## What WiFi Sensing Can Actually Detect

The physics are well-established and have been demonstrated repeatedly in peer-reviewed research.

WiFi signals at 2.4 GHz have a wavelength of about 12.5 centimeters -- roughly the width of your hand. When these signals travel between a transmitter and receiver, they form ellipsoidal regions called Fresnel zones. The first Fresnel zone, which carries approximately half of the signal energy, has a radius of about 55 centimeters at a 10-meter range.

A human body is almost entirely within this zone. Our tissue is approximately 70% water, with a relative permittivity of about 50 at 2.4 GHz -- making us extraordinarily visible to radio waves. When you stand in a Fresnel zone, you cause measurable changes to both the amplitude and phase of the WiFi signal. When you breathe, those changes are periodic at 0.15 to 0.5 Hz. When your heart beats, they oscillate at 0.8 to 2.0 Hz.

Modern WiFi hardware reports these signal characteristics as Channel State Information (CSI) -- per-subcarrier amplitude and phase data from OFDM (Orthogonal Frequency-Division Multiplexing) frames. In a standard 20 MHz WiFi channel, there are 56 subcarriers, each providing an independent measurement of the signal path. This gives an attacker a 56-dimensional time series that encodes everything happening in the physical space between transmitter and receiver.

The research results are sobering:

- **KIT (Karlsruhe Institute of Technology)**: Demonstrated near-perfect identification of individuals through walls using beamforming feedback data that routers already broadcast in plaintext. [LeakyBeam, NDSS 2025]
- **University of Chicago**: Showed that $10 of ESP32 hardware can detect breathing and heartbeat from adjacent rooms. Proposed cover traffic as a countermeasure. ["Et Tu Alexa," NDSS 2020]
- **Wi-Spoof**: Demonstrated that even small variations in transmit power cause 93% misclassification in WiFi sensing systems. [JISA 2025]

This is not a theoretical concern. The hardware is commodity. The software is open source. A sensing mesh can be deployed in minutes for under $15.

## The Regulatory Vacuum

Here is the uncomfortable legal reality: no federal law explicitly prohibits private WiFi CSI sensing.

**Kyllo v. United States (2001)** established that government use of technology not in general public use to explore the details of a private home constitutes a Fourth Amendment search. This is directly on point -- thermal imaging through walls is legally analogous to WiFi sensing through walls. But Kyllo only constrains government actors. Your neighbor with three ESP32 devices is not bound by the Fourth Amendment.

**47 USC 333** makes it illegal to "willfully or maliciously interfere with or cause interference to any radio communications." But WiFi sensing does not interfere with communications. It passively analyzes the physical characteristics of signals that are already being transmitted. The statute protects communication content, not signal physics.

**The Wiretap Act (18 USC 2511)** prohibits intercepting the "contents" of communications. WiFi CSI does not decode communication contents -- it measures how the signal propagates through space. This is a gray area, but current legal interpretation favors the argument that CSI is not "content."

The strongest existing tools are at the state level:

- **Illinois BIPA (740 ILCS 14)**: Protects biometric information with a private right of action and statutory damages of $1,000-$5,000 per violation. If WiFi-derived breathing patterns and heartbeat signatures qualify as "biometric identifiers" or "biometric information" -- and there are strong arguments that they do -- then unauthorized collection would be actionable.
- **California CCPA/CPRA**: Covers collection of data derived from "physiological or behavioral characteristics." CSI-derived presence, movement, and vital signs data fits squarely within this language.

No court has ever ruled on WiFi CSI sensing. The first case will set precedent that shapes the regulatory landscape for years. The evidence needed to bring that case -- timestamped detection logs, device fingerprints, signal analysis, chain-of-custody documentation -- needs to exist before the case can be filed.

## Introducing goop-veil

goop-veil is the first open-source tool for detecting WiFi sensing activity, applying software-only countermeasures through your existing router, and generating legal evidence packages. It is available today under the Apache-2.0 license.

It is pure software. There is nothing to buy. You install it with pip and run it on any Linux or macOS machine with a WiFi adapter.

```
pip install goop-veil[cli]
```

### Detection

The simplest command requires no root access and no special hardware:

```
goop-veil scan
```

This scans your WiFi environment for sensing devices. It checks for Espressif hardware (the dominant platform for WiFi CSI sensing), hidden SSIDs, suspicious naming patterns, and mesh topologies consistent with sensing deployments. The scan uses your existing WiFi adapter's built-in scanning capability.

For deeper analysis, you can capture raw WiFi traffic and analyze it:

```
sudo goop-veil capture --duration 60
goop-veil detect capture.pcap
```

The detection engine looks for rapid channel hopping, high null-data frame ratios, non-standard beacon intervals, 802.11bf Measurement Setup action frames, and other indicators. It produces a threat assessment with a confidence score.

### Mitigation

goop-veil can reconfigure your router to degrade WiFi sensing accuracy. Every countermeasure is backed by peer-reviewed research with measured effectiveness:

**Co-channel traffic generation**: The single most effective software-only countermeasure. The University of Chicago's "Et Tu Alexa" paper (NDSS 2020) demonstrated that legitimate co-channel traffic drops WiFi sensing detection accuracy to 47% and raises the false positive rate to 50%. goop-veil orchestrates legitimate HTTP, DNS, NTP, and streaming traffic across the WiFi channel.

**TX power variation**: Wi-Spoof (JISA 2025) measured a 93% misclassification rate when transmit power is varied. WiFi sensing systems train on a specific signal environment; changing TX power invalidates the calibration. goop-veil cycles your router's transmit power through safe levels via its native API.

**Band steering to 5 GHz**: WiFi signals at 5 GHz experience approximately 45 dB of attenuation through typical interior walls, compared to approximately 23 dB at 2.4 GHz (ITU-R P.2040). Steering your devices to the 5 GHz band roughly doubles the wall attenuation that an external attacker must overcome.

**Channel hopping**: CSI sensing requires temporal coherence -- a stable sequence of measurements on a consistent channel. Periodic channel changes break this coherence and force the attacker to re-calibrate.

**Bandwidth widening (80/160 MHz)**: Sensing models are trained on specific channel bandwidths. Switching from 20 MHz to 80 or 160 MHz changes the subcarrier structure and invalidates trained models.

**Beamforming disable**: LeakyBeam (NDSS 2025) demonstrated that beamforming feedback information (BFI) is transmitted in plaintext, providing an easy high-resolution sensing channel. Disabling beamforming on your AP eliminates this data source.

**PMF (802.11w)**: Protected Management Frames prevent an attacker from forcing your devices to disassociate and reconnect on a channel the attacker controls.

These countermeasures are applied through your router's native API. goop-veil supports OpenWrt (UCI/ubus), UniFi (REST API), and TP-Link (HTTP) routers. Dry-run mode is the default -- you see what would change before anything is applied.

```
goop-veil mitigate --router-host 192.168.1.1 --router-type openwrt
```

### Legal Evidence

goop-veil generates HMAC-signed evidence packages suitable for FCC complaints, cease-and-desist letters, civil lawsuits under BIPA or CCPA, and law enforcement referrals.

Each evidence package includes timestamped detection logs, device fingerprints with OUI attribution, signal analysis with Fresnel zone calculations, a timeline of sensing activity, and chain-of-custody documentation. Reports are hash-signed for integrity verification.

```
goop-veil evidence capture.pcap --output-dir data/legal
```

## How the Technology Works

Under the hood, goop-veil combines a high-performance Rust core with a Python detection and mitigation engine.

The Rust core handles 802.11 frame parsing at over one million frames per second. It classifies management frames (beacons, probe requests, action frames), extracts CSI-relevant metadata, performs FFT spectral analysis to identify periodic signals in the breathing (0.15-0.5 Hz) and heartbeat (0.8-2.0 Hz) bands, calculates Fresnel zone geometry for given room configurations, models signal propagation and material attenuation using ITU-R P.2040 parameters, and maintains a 250,000+ entry OUI database for vendor identification.

The Python layer implements the detection engine (beacon scanning, traffic analysis, CSI signature matching, alert generation), router adapters for mitigation, traffic orchestration, the legal evidence pipeline, and the CLI. An adaptive defense system uses Thompson sampling to select and tune countermeasure combinations based on observed effectiveness in your specific environment.

Every transmission generated by goop-veil stays within FCC Part 15.247 power limits. Every frame is tagged with a legitimate purpose. Signed audit logs prove compliance. The system never sends deauthentication frames, never exceeds 20 dBm conducted power, and never addresses frames to third-party devices. This is enforced at the code level through a compliance module that prohibits specific terminology and caps power output with hardware-level cutoffs.

## Getting Started

Install goop-veil with CLI support:

```bash
pip install goop-veil[cli]
```

Run your first scan:

```bash
goop-veil scan
```

If you find suspicious devices, capture traffic for deeper analysis:

```bash
sudo goop-veil capture --duration 60 --output scan.pcap
goop-veil detect scan.pcap
```

Get mitigation recommendations:

```bash
goop-veil mitigate
```

Or auto-apply safe countermeasures to your router:

```bash
goop-veil mitigate --router-host 192.168.1.1 --router-type openwrt --auto-apply
```

Assess your room's physical vulnerability:

```bash
goop-veil assess --room 4.5x3.5x2.7 --budget 200
```

Generate a legal evidence package:

```bash
goop-veil evidence scan.pcap --output-dir data/legal
```

goop-veil also runs as an MCP server for integration with AI assistants, and offers a web dashboard for continuous monitoring.

## What Comes Next

The legal landscape will change. 802.11bf moves WiFi sensing from a research curiosity to a standardized protocol feature. As sensing-capable routers proliferate, the regulatory pressure will build. The question is not whether lawmakers will address this -- it is whether they will act before or after widespread deployment.

Several developments are worth watching:

- **BIPA litigation**: If an Illinois court rules that WiFi-derived vital signs constitute biometric information, it opens a powerful enforcement mechanism with statutory damages.
- **FCC rulemaking**: The Commission has not addressed passive WiFi sensing under Part 15. A petition for rulemaking could force the issue.
- **802.11bf privacy amendments**: The IEEE is aware of the privacy implications. Future amendments may require sensing capability advertisements in beacons and opt-out mechanisms -- but these are years away.
- **State privacy laws**: Washington, Texas, Colorado, and other states with biometric privacy laws may provide additional avenues.

In the meantime, the defense is software. goop-veil is available now, free and open source, and it works with the router you already own.

Source code: [https://github.com/kobepaw/goop-veil](https://github.com/kobepaw/goop-veil)

License: Apache-2.0

---

## 5. Privacy Guides Forum Post

**Title:** WiFi CSI sensing defense: open-source detection and countermeasures (goop-veil)

**Body:**

I want to share an open-source tool I built to address a privacy gap that does not have an existing solution: WiFi Channel State Information (CSI) surveillance.

**The threat in brief:** WiFi signals reflect off human bodies in ways that encode presence, movement, breathing rate, and heartbeat. This has been demonstrated repeatedly in peer-reviewed research (UChicago NDSS 2020, Wi-Spoof JISA 2025, LeakyBeam NDSS 2025, KIT beamforming identification). IEEE 802.11bf, ratified September 2025, standardizes WiFi sensing as a protocol feature. 30M+ US homes already have routers with the hardware capability. No federal law explicitly prohibits private WiFi CSI sensing, and no commercial or open-source defense tool existed before this one.

**What goop-veil does:**

1. **Detection** -- scans for sensing devices (Espressif hardware, suspicious mesh topologies, 802.11bf action frames, CSI extraction patterns). Basic scans require no root access. Pcap analysis provides deeper assessment with confidence scoring.

2. **Software-only countermeasures** -- reconfigures your existing router via its native API (OpenWrt, UniFi, TP-Link supported). All countermeasures are documented with peer-reviewed sources and measured effectiveness values. Key mitigations: TX power variation (93% misclassification, Wi-Spoof 2025), co-channel traffic generation (detection drops to 47%, UChicago 2020), band steering to 5 GHz (~22 dB additional wall attenuation, ITU-R P.2040), bandwidth widening, beamforming disable, PMF enable.

3. **Legal evidence generation** -- HMAC-signed evidence packages with device fingerprints, timestamped detection logs, and chain-of-custody documentation for FCC complaints or state-level privacy claims (BIPA, CCPA/CPRA).

**Technical details:**

- Python 3.11+ with Rust native extension for 802.11 frame parsing and signal processing
- 569 tests (Python + Rust)
- No cloud services, no telemetry, no accounts. All data stays local
- Router credentials via environment variable only, never stored in config
- Apache-2.0 license
- FCC Part 15.247 compliant -- never sends deauth frames, max 20 dBm conducted, audit-logged

**What it does NOT do:**

- Does not require hardware purchases
- Does not use PHY-layer techniques (CSI randomization, CSI fuzzing) that require controlling the attacker's transmitter or FPGA hardware
- Cannot prevent sensing by external devices -- can only detect, degrade, and document
- Does not claim to be a complete solution. Physical RF shielding (the tool includes a room assessment command) and legal action are complementary

**Install and use:**

```
pip install goop-veil[cli]
goop-veil scan
goop-veil mitigate --router-host 192.168.1.1 --router-type openwrt
```

Source: https://github.com/kobepaw/goop-veil

I built this because the 802.11bf ratification closed the last remaining argument that WiFi sensing was a niche research concern. It is now a standardized capability, and the defense tooling needs to exist. Feedback on detection accuracy, router adapter coverage, and legal framework assumptions is welcome.

---

## 6. GitHub Release Notes (v0.1.0)

### goop-veil v0.1.0

The first public release of goop-veil -- WiFi privacy defense.

**What's in this release:**

Detection, mitigation, and legal evidence generation for WiFi CSI (Channel State Information) surveillance. Pure software, zero hardware purchases.

**Key Capabilities:**

- **WiFi scanning** -- detect sensing devices in your environment (Espressif hardware, suspicious mesh topologies, 802.11bf signatures). No root required for basic scans
- **Pcap analysis** -- deep 802.11 frame analysis with threat assessment and confidence scoring
- **Router countermeasures** -- software-only mitigations applied through your existing router's API. Supports OpenWrt (UCI/ubus), UniFi (REST), and TP-Link (HTTP). TX power variation, band steering, channel hopping, bandwidth widening, beamforming disable, PMF enable, beacon interval adjustment
- **Traffic orchestration** -- legitimate co-channel traffic generation to degrade sensing accuracy
- **Room vulnerability assessment** -- physical material recommendations with cost estimates
- **Legal evidence packages** -- HMAC-signed detection logs, device fingerprints, and chain-of-custody documentation for FCC complaints and privacy claims
- **Continuous monitoring** -- background scanning with configurable alerts
- **MCP server** -- 7 tools for AI assistant integration
- **Web dashboard** -- optional FastAPI-based monitoring UI
- **Adaptive defense** -- Thompson sampling selects countermeasure combinations based on observed effectiveness

**Architecture:**

- Rust core: 802.11 frame parsing (>1M frames/sec), FFT spectral analysis, Fresnel zone physics, OUI database (250K+ entries), material attenuation modeling
- Python: detection engine, router adapters, traffic orchestration, legal pipeline, CLI, MCP server
- 569 tests (Python + Rust)
- FCC Part 15.247 compliant by design

**Installation:**

```bash
pip install goop-veil[cli]
```

From source (requires Rust toolchain):

```bash
pip install git+https://github.com/kobepaw/goop-veil.git#egg=goop-veil[cli]
```

**Known Limitations:**

- ASUS Merlin router support is planned but not yet implemented
- TP-Link adapter coverage varies by model
- Monitor mode capture (`goop-veil capture`) requires root/sudo
- ESP32 active countermeasure hardware control requires `[active]` extras and serial connection
- No Windows support in this release

**Research Citations:**

- UChicago "Et Tu Alexa" (NDSS 2020) -- co-channel traffic countermeasure
- Wi-Spoof (JISA 2025) -- TX power variation, 93% misclassification
- LeakyBeam (NDSS 2025) -- beamforming feedback plaintext attack
- ITU-R P.2040 -- building material attenuation models
- IEEE 802.11bf-2025 -- WiFi sensing standard
- SnoopFi (Computer Networks 2025) -- CSI fuzzing bypass limitations
- IRShield (Ruhr-Universitat Bochum 2022) -- IRS metasurface countermeasure
- Kyllo v. US, 533 U.S. 27 (2001) -- through-wall sensing precedent
- Carpenter v. US, 585 U.S. 296 (2018) -- continuous digital surveillance

**License:** Apache-2.0

---

## 7. One-Liner Descriptions

**GitHub repo description:**
Detect, counter, and document WiFi CSI surveillance. Software-only defense against through-wall sensing. Rust core, Python CLI.

**PyPI package description:**
WiFi privacy defense -- detect sensing devices, apply router countermeasures, generate legal evidence packages.

**Twitter bio addition:**
Creator of goop-veil -- open-source defense against WiFi through-wall surveillance

**HN submission subtitle:**
Open-source WiFi CSI surveillance detection and software-only countermeasures (Rust + Python)

**Blog post meta description:**
802.11bf standardized WiFi sensing, letting routers detect breathing and heartbeat through walls. goop-veil is the first open-source tool to detect, counter, and document this surveillance.
