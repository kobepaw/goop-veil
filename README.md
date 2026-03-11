# goop-veil

Your WiFi can be used to sense you through walls. goop-veil is a software-only WiFi privacy defense that helps **detect, degrade, and document** potential CSI surveillance using supported routers.

**Research preview. Linux-first for WiFi scanning/capture. Supported router families today: OpenWrt, UniFi, and selected TP-Link paths.**

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-500%2B%20automated-brightgreen)

## Start here

```bash
pip install 'git+https://github.com/kobepaw/goop-veil.git#egg=goop-veil[cli]'
goop-veil scan
```

- New here? Read [FAQ](./docs/FAQ.md)
- Evaluating support? Read [ROUTER_COMPATIBILITY.md](./docs/ROUTER_COMPATIBILITY.md)
- Want the limits first? Read [KNOWN_LIMITATIONS.md](./docs/KNOWN_LIMITATIONS.md)

> goop-veil is a **software-only research preview**. It provides technical signals and documentation artifacts, not determinations, proof, or compliance certification. Detection and mitigation results vary by environment.

---

## The Problem

IEEE 802.11bf was ratified in September 2025. It standardized what researchers have known for years: ordinary WiFi signals can detect human presence, movement, breathing, and heartbeat through walls.

- **Cheap hardware makes this practical.** A small ESP32 mesh can capture CSI from the next room.
- **No consent required.** No light turns on. No notification. Nothing.
- **The impact is physical, not just digital.** Presence, motion, breathing, and heartbeat can all become sensing targets.
- **Policy still lags the capability.** There is no clear federal ban on private-party WiFi CSI sensing.
- **Practical defense tooling is still early.** goop-veil is built for detection, degradation, and documentation rather than magical prevention claims.

To our knowledge, goop-veil is the first open-source tool built specifically to programmatically reconfigure existing consumer routers to fight back against WiFi CSI surveillance. It is an open-source research preview that detects potential sensing activity, applies software-only countermeasures through supported routers, and generates evidence bundles for documentation workflows.

---

## What goop-veil Does

### 1. Detect
Scan your WiFi environment for sensing devices and suspicious conditions. Identifies Espressif mesh networks, suspicious traffic patterns, rapid channel hopping, and CSI extraction signatures. No root required for basic scans.

### 2. Degrade
Software-only countermeasures applied through your existing router. No new hardware needed. Reconfigures channel, bandwidth, TX power, band steering, and PMF settings via router APIs (OpenWrt, UniFi, TP-Link). Orchestrates legitimate network traffic to degrade sensing accuracy.

### 3. Document
Generates timestamped, HMAC-signed evidence packages for incident documentation and reporting/review workflows.

goop-veil is software-only and currently positioned as a research preview. The goal is to make sensing less reliable and better documented, not to promise perfect prevention or attribution.

---

## Quick Start

```bash
# Install from source (requires Rust toolchain for the native frame parser)
pip install 'git+https://github.com/kobepaw/goop-veil.git#egg=goop-veil[cli]'

# Scan nearby networks for suspicious sensing indicators (no root needed)
goop-veil scan

# Analyze a packet capture for sensing activity
goop-veil detect capture.pcap

# Review mitigation recommendations before applying any router changes
goop-veil mitigate

# Generate an evidence/documentation package
goop-veil evidence capture.pcap
```

If you are evaluating router support first, see [docs/ROUTER_COMPATIBILITY.md](./docs/ROUTER_COMPATIBILITY.md).

---

## CLI Commands

> Example outputs below are representative CLI snapshots (sample/simulated environments). Exact counts, threat levels, and recommendations vary by capture quality, RF conditions, and router capabilities.

### `goop-veil scan`
Scan nearby WiFi networks for sensing hardware. No root required. Flags Espressif OUIs, suspicious SSIDs, and hidden networks.

```
$ goop-veil scan
WiFi Network Scan
Found 12 networks, 2 suspicious

  BSSID              SSID          Vendor       Ch  Signal  Flags
  A4:CF:12:xx:xx:xx  [hidden]      Espressif    6   -42     espressif_hardware, hidden_ssid
  A4:CF:12:xx:xx:xx  ESP_MESH_01   Espressif    6   -38     espressif_hardware, suspicious_ssid

WARNING: 2 suspicious network(s) detected
```

### `goop-veil detect capture.pcap`
Deep analysis of captured WiFi traffic. Identifies sensing capabilities, mesh coordination, and CSI extraction patterns.

```
$ goop-veil detect capture.pcap
WiFi Sensing Detection Report
Threat Level: HIGH
Confidence: 87%
Summary: Espressif mesh with CSI extraction detected on channel 6
```

### `goop-veil mitigate`
Ranked countermeasure recommendations. Optional router changes are only applied when explicitly requested with `--auto-apply` plus router connection details.

```
$ goop-veil mitigate --pcap capture.pcap
Mitigation Recommendations
Threat level: MEDIUM
Estimated effectiveness: 80%

  #  Mitigation                         Effectiveness  Difficulty  Auto  WiFi Impact
  1  Migrate to 5 GHz band              85%            easy              brief_drop
  2  Enable TX power variation          80%            moderate          none
  3  Switch to channel 11               75%            easy              brief_drop
  4  Widen bandwidth to 80 MHz          65%            easy              brief_drop
  5  Enable 802.11w PMF (required)      40%            easy              none
```

### `goop-veil evidence capture.pcap`
Generate an evidence package with chain-of-custody documentation.

```
$ goop-veil evidence capture.pcap --output-dir data/reports
Evidence Package Generated
Output: data/reports/evidence_20260308_143022/
Report hash: a3f8c91b2d4e7f01...
Devices documented: 2
Timeline events: 47
```

### `goop-veil capture --duration 60`
Live WiFi traffic capture to pcap. Requires root for monitor mode.

```
$ sudo goop-veil capture --duration 60 --output scan.pcap
Starting monitor mode capture (60s)...
Captured to scan.pcap (2,847,392 bytes)
Restored managed mode.

Running detection analysis...
# (detection report output omitted for brevity)
```

### `goop-veil monitor`
Continuous background scanning with alerts. No root required.

```
$ goop-veil monitor --interval 30
Continuous WiFi monitoring (interval=30s)
Press Ctrl+C to stop.

14:30:22  Scan #1: clear (11 networks)
14:30:52  Scan #2: 1 suspicious / 12 networks
14:31:22  Scan #3: 2 suspicious / 12 networks
```

### `goop-veil assess --room 4.5x3.5x2.7`
Room vulnerability assessment with material recommendations.

```
$ goop-veil assess --room 4.5x3.5x2.7 --budget 200
Room Vulnerability Assessment
Room: 4.5x3.5x2.7m
Vulnerability: 82%

  Material               Location     Attenuation   Cost
  RF shielding film      Windows      12.0 dB       $45
  Metallic curtains      Windows      18.0 dB       $60
  Aluminum mesh          Thin wall    25.0 dB       $35
```

### `goop-veil status`
System status and WiFi interface diagnostics.

---

## How It Works

**Rust core** -- Native 802.11 frame parser handles >1M frames/sec. Parses beacons, probe requests, CSI-bearing frames, and management frames. Includes Fresnel zone calculation, OUI lookup (250K+ entries), and signal propagation modeling.

**Python detection engine** -- Beacon scanner, traffic analyzer, and CSI signature analyzer feed into an alert engine that produces threat assessments with confidence scores.

**Router reconfiguration** -- Programmatic control of consumer routers via their native APIs. OpenWrt (SSH+UCI), UniFi (HTTPS REST), and TP-Link (HTTPS; insecure HTTP only with explicit override) adapters reconfigure WiFi parameters that degrade sensing accuracy.

**Traffic orchestration** -- Generates legitimate network traffic (HTTP, DNS, NTP, streaming) across the WiFi channel. Co-channel traffic is the single most effective software-only countermeasure against CSI sensing.

**BroRL adaptive defense** -- Thompson sampling selects and adapts countermeasure techniques based on observed effectiveness. Learns which combinations work against the specific sensing hardware detected in your environment.

**Compliance-oriented guardrails (not certification)** -- The software is designed to avoid deauth/disassoc traffic and to use conservative power-related defaults where supported by router APIs. Logs can aid review, but this project does not certify compliance for any specific deployment.

---

## Measured Effectiveness

Countermeasures are informed by peer-reviewed research. Real-world outcomes vary by environment, hardware, and attacker setup.

| Mitigation | Measured Effect | Source |
|---|---|---|
| Co-channel traffic | Detection accuracy drops to 47% | UChicago "Et Tu Alexa" (NDSS 2020) |
| TX power variation | 93% misclassification rate | Wi-Spoof (JISA 2025) |
| Band steering to 5 GHz | ~45 dB wall attenuation (vs 23 dB at 2.4 GHz) | ITU-R P.2040 |
| Channel hopping | Breaks CSI temporal coherence | Multiple peer-reviewed sources |
| Bandwidth widening (80/160 MHz) | Invalidates trained sensing models | WiFi Sensing Survey 2025 |
| Beamforming disable | Eliminates BFI plaintext leak | LeakyBeam (NDSS 2025) |
| PMF (802.11w) | Prevents forced disassociation attacks | IEEE 802.11w standard |

---

## Reporting Context and Regulatory Landscape

**No federal law directly prohibits private WiFi CSI sensing.** This is the gap.

- **Kyllo v. US (2001)** established that through-wall sensing invades privacy, but only constrains government actors.
- **47 USC 333** covers "radio communications" -- not passive sensing of signal physics.
- **Illinois BIPA** provides statutory damages with a private right of action; WiFi-derived breathing/heartbeat data may be argued to qualify in some scenarios.
- **California CCPA/CPRA** references "physiological or behavioral characteristics"; whether specific CSI-derived inferences qualify is fact-dependent.

Reporting and regulatory outcomes are jurisdiction-specific and evolving. goop-veil can generate timestamped logs and documentation artifacts that may help with internal records, reporting workflows, or professional review.

---

## Known Limitations

- Research preview: output quality and false-positive/false-negative rates can vary across environments.
- Detection confidence is heuristic and should be treated as a lead, not a definitive attribution.
- Mitigation effectiveness depends on router model/firmware, RF conditions, and attacker behavior.
- Router support varies by family, model, and firmware; see [docs/ROUTER_COMPATIBILITY.md](./docs/ROUTER_COMPATIBILITY.md).
- Evidence bundles provide integrity-oriented logging, not courtroom admissibility guarantees.
- The project provides technical tooling only and does not determine reporting or regulatory outcomes.

---

## Contributing Paths

If you want to help in week one, start with [CONTRIBUTING.md](./CONTRIBUTING.md).

- Contributors: use the issue templates, then look for `good-first-issue`, docs, detection-quality, or router compatibility work. For detection-quality reports, use [docs/DETECTION_QUALITY_REPORTING.md](./docs/DETECTION_QUALITY_REPORTING.md).
- Maintainers: use [docs/COMMUNITY_LABELS.md](./docs/COMMUNITY_LABELS.md) for label setup and [docs/STARTER_ISSUE_BATCH_WEEK_ONE.md](./docs/STARTER_ISSUE_BATCH_WEEK_ONE.md) to seed the first public issue batch.

---

## Router Support

See the full compatibility notes in [docs/ROUTER_COMPATIBILITY.md](./docs/ROUTER_COMPATIBILITY.md).

| Router | Status | Control path | Notes |
|---|---|---|---|
| OpenWrt | Supported | UCI / ubus JSON-RPC | Strongest current support surface |
| UniFi | Supported | REST API | Good support, controller/device variation applies |
| TP-Link | Experimental | HTTPS token auth | Selected model paths; model-dependent, insecure HTTP is opt-in only |
| ASUS Merlin | Unverified | SSH + `wl` CLI (target path) | Investigation work still needed before any support claim |

Router credentials are passed via the `VEIL_ROUTER_PASSWORD` environment variable. Never stored in config files.

---

## MCP Integration

goop-veil exposes 7 tools via the Model Context Protocol for agent-driven WiFi defense:

| Tool | Description |
|---|---|
| `detect_wifi_sensing` | Analyze pcap for sensing activity |
| `assess_room_vulnerability` | Room assessment with material recommendations |
| `activate_veil` | Activate ESP32 privacy enhancement mesh |
| `deploy_countermeasures` | BroRL-adaptive technique selection |
| `share_sensing_signature` | Share detection signatures with federation |
| `mitigate_wifi_sensing` | Recommend and apply router mitigations |
| `generate_evidence_report` | Evidence package generation |

Configure in your MCP client:

```json
{
  "mcpServers": {
    "goop-veil": {
      "command": "python",
      "args": ["-m", "goop_veil.mcp.server"]
    }
  }
}
```

---

## Requirements

- **Python 3.11+**
- **Rust toolchain** (for building the native frame parser from source)
- **Linux** (`scan` uses `nmcli` or `iw`; monitor capture uses `iw` + `tcpdump`)
- Root/sudo only required for `capture` command (monitor mode)

### Optional Dependencies

```bash
pip install goop-veil[cli]        # CLI with rich terminal output
pip install goop-veil[mcp]        # MCP server for agent integration
pip install goop-veil[active]     # ESP32 hardware control via serial
pip install goop-veil[dashboard]  # Web dashboard (FastAPI + uvicorn)
pip install goop-veil[all]        # Everything
```

---

## Project Structure

```
goop-veil/
  src/                    # Rust core (802.11 frame parsing, Fresnel, OUI, signal)
  python/goop_veil/
    detection/            # Beacon scanner, traffic analyzer, CSI signatures, alerts
    passive/              # Room assessment, material database, placement optimizer
    active/               # ESP32 privacy enhancement control
    adversarial/          # BroRL-adaptive countermeasure selection
    mitigation/
      router/             # OpenWrt, UniFi, TP-Link adapters
      traffic/            # Legitimate traffic orchestration
      reporting/          # Evidence/reporting templates and HMAC-signed logs
    mcp/                  # MCP server (7 tools)
    hardware/             # WiFi HAL, ESP32 HAL
    integration/          # goop-net federation bridge
  firmware/               # ESP32 firmware
  tests/                  # 500+ automated tests
```

---

## License

[Apache-2.0](LICENSE)

## Contributing

Issues and PRs welcome. Contributions should keep terminology and compliance-related phrasing accurate, cautious, and evidence-based.
