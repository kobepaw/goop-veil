# goop-veil Mitigation Layer — Implementation Plan

## Research Summary

Four parallel research tracks completed 2026-03-08:
1. Router APIs — programmatic control of consumer WiFi routers
2. CSI countermeasures — academic literature on what degrades WiFi sensing
3. Legal framework — what laws apply, evidence requirements
4. Architecture design — module structure and interfaces

---

## What Actually Works (Software-Only, Quantified)

### The Threat Model

An attacker deploys 2-3 ESP32 devices (~$5 each) forming a sensing mesh.
They capture CSI (per-subcarrier amplitude/phase from OFDM frames) to detect:
- Presence: >10 dB SNR, 10-25 pps
- Motion/activity: >15 dB SNR, 100-500 pps (>99% accuracy through walls)
- Breathing: >20 dB SNR, 10-20 pps, range 2-4m
- Heartbeat: >25 dB SNR, 500-1000 pps, range 2-4m

### Software-Only Countermeasures (Ranked by Measured Effectiveness)

| # | Mitigation | Measured Effect | Source | Auto-Applicable |
|---|-----------|----------------|--------|-----------------|
| 1 | **Co-channel traffic injection** | Detection → 47%, FPR → 50% | UChicago "Et Tu Alexa" | Yes (traffic gen) |
| 2 | **TX power variation** | 93% misclassification | Wi-Spoof 2025 | Yes (router API) |
| 3 | **Band steering to 5/6 GHz** | ~45 dB wall atten (vs 23 at 2.4) | ITU-R P.2040 | Yes (router API) |
| 4 | **Channel hopping** | Breaks CSI temporal coherence | Multiple papers | Yes (router API) |
| 5 | **Bandwidth widening (80/160 MHz)** | Invalidates trained models | Survey 2025 | Yes (router API) |
| 6 | **Beacon interval increase** | 5-10x reduction in passive CSI samples | Standard spec | Yes (router API) |
| 7 | **Beamforming disable** | Eliminates BFI plaintext leak | LeakyBeam NDSS 2025 | Yes (router API) |
| 8 | **PMF (802.11w) enable** | Prevents forced disassociation | IEEE 802.11w | Yes (router API) |
| 9 | **Environmental noise** (fans, robot vacs) | Degrades motion isolation | Survey papers | Via smart home |
| 10 | **Legal action** | Regulatory remedy | No court precedent | Evidence gen |

### What Does NOT Work (Software-Only)

- CSI randomization, MIMOCrypt, DFSS, AntiSense — require controlling the attacker's TX (PHY-layer)
- CSI Fuzzer — requires FPGA/SDR hardware (openwifi), not commodity routers
- Also: SnoopFi (2025) demonstrated CSI fuzzing can be bypassed with few-shot learning

### The Key Insight

**No existing product does this.** There is zero commercial or open-source software that
programmatically reconfigures a consumer router to counter WiFi CSI sensing. This is greenfield.

---

## Router API Support Matrix

| Router | Protocol | WiFi Config | Python Library | Priority |
|--------|----------|-------------|----------------|----------|
| OpenWrt | UCI/ubus JSON-RPC | **Full** (channel, txpower, htmode, beacon_int, PMF, RTS) | `openwrt-ubus-rpc` | P1 |
| UniFi | REST (unofficial) | **Good** (channel, txpower, bandwidth) | `unificontrol` | P2 |
| TP-Link | HTTP (token) | **Model-dependent** | `pytplinkrouter` | P3 |
| ASUS Merlin | SSH + `wl` CLI | **Moderate** | `asusrouter` | P4 |
| Netgear/Orbi | SOAP | **Read-only** for wireless | `pynetgear` | Skip |
| Eero | Cloud API | **Very limited** (band steering only) | `eero-api` | Skip |
| Google Nest | None | **Not viable** | N/A | Skip |

---

## Legal Landscape

### No Law Directly Prohibits Private WiFi CSI Sensing

- **Federal**: No statute covers passive through-wall sensing by private parties
- **Kyllo v. US**: Establishes through-wall sensing invades privacy, but only constrains government
- **Wiretap Act**: Gray area — sensing analyzes signal physics, not communication content
- **47 USC 333**: Covers interference, not passive sensing

### Strongest State Tools

- **Illinois BIPA**: $1K-$5K per violation, private right of action — if CSI captures biometric data
- **California CCPA/CPRA**: "Physiological/behavioral characteristics" — breathing/heartbeat may qualify
- **Two-party consent states (13)**: Creative argument under broader state wiretap statutes

### Evidence Requirements

For FCC complaint: timestamps, signal analysis, source attribution, interference documentation
For civil lawsuit: detection logs, expert testimony, impact documentation, chain of custody
For criminal complaint: pattern of conduct, criminal intent, victim impact

### No Court Has Ever Ruled on WiFi CSI Sensing

First case will be precedent-setting. Evidence packages generated now position homeowners
for the first regulatory window.

---

## Module Architecture

```
python/goop_veil/mitigation/
├── __init__.py
├── advisor.py                    # MitigationAdvisor — ranking brain
├── models.py                     # Pydantic models for recommendations
├── router/
│   ├── __init__.py
│   ├── base.py                   # BaseRouterAdapter (ABC)
│   ├── openwrt.py                # OpenWrt via UCI/ubus
│   ├── unifi.py                  # UniFi via REST API
│   ├── tplink.py                 # TP-Link via HTTP
│   ├── mock.py                   # MockRouterAdapter (testing)
│   └── strategies.py             # Channel, bandwidth, power, PMF strategies
├── traffic/
│   ├── __init__.py
│   ├── orchestrator.py           # TrafficOrchestrator controller
│   ├── generators.py             # Legitimate traffic pattern generators
│   ├── smart_home.py             # IoT device coordination (mDNS/SSDP)
│   └── scheduler.py              # Scheduled task manager
└── reporting/
    ├── __init__.py
    ├── package.py                 # ReportPackageGenerator
    ├── templates.py               # FCC complaint, C&D, incident report
    └── log_exporter.py            # HMAC-signed detection log export
```

### Key Interfaces

**BaseRouterAdapter** (ABC):
```python
connect() → bool
get_status() → RouterStatus
set_channel(channel: int) → bool
set_bandwidth(bandwidth_mhz: int) → bool
set_tx_power(power_dbm: float) → bool
enable_pmf(mode: "required"|"optional"|"disabled") → bool
set_band(band: "2.4"|"5"|"6") → bool
get_neighbor_aps() → list[dict]
```

**MitigationAdvisor**:
```python
assess_and_recommend(detection_result, home_network) → MitigationPlan
auto_apply(plan, dry_run=True) → list[str]  # applied mitigation names
```

**Ranking formula**:
```
score = 0.5 * effectiveness + 0.2 * ease + 0.2 * speed + 0.1 * auto_bonus
```

### New MCP Tools

1. `mitigate_wifi_sensing` — analyze + recommend + optionally auto-apply
2. `generate_report_summary` — signed report package with HMAC-signed logs

### New CLI Commands

1. `goop-veil mitigate` — recommend and apply mitigations
2. `goop-veil report` — generate signed incident documentation

---

## Smart Home Traffic Orchestration

High-bandwidth legitimate traffic degrades CSI sensing (UChicago: 47% detection rate).

| Device | Protocol | Bandwidth | Python Library |
|--------|----------|-----------|----------------|
| Chromecast 4K | Cast/DIAL | 25 Mbps | `pychromecast` |
| Roku | ECP REST | 25 Mbps | `rokuecp` |
| Apple TV | AirPlay | 25 Mbps | `aiohomekit` |
| Smart speakers | Cast/AirPlay | 0.3-1 Mbps | `pychromecast` |
| Security cameras | RTSP/cloud | 2-8 Mbps/cam | Device-specific |
| Home Assistant | REST API | Hub for all | `homeassistant` |

---

## Config Additions

```python
class MitigationConfig(_VeilBaseConfig):
    router: RouterConfig        # adapter_type, host, apply_changes (default: False = dry-run)
    traffic: TrafficConfig      # enabled, max_bandwidth_mbps, schedule_enabled
    reporting: ReportingConfig  # output_dir, include_disclaimer (always True)
```

Router credentials via `VEIL_ROUTER_PASSWORD` env var (never in config files).

---

## Build Order

| Sprint | Days | What | Deliverable |
|--------|------|------|-------------|
| S1 | 1-4 | Models, config, router base/mock, strategies, advisor | Ranking engine works with mock |
| S2 | 5-9 | OpenWrt adapter, UniFi adapter, traffic generators, orchestrator | Auto-apply functional |
| S3 | 10-13 | Legal templates, evidence generator, log exporter, smart home | Evidence pipeline complete |
| S4 | 14-18 | MCP tools, CLI commands, integration tests, terminology audit | Ship-ready |

### Estimates

- ~3,000 new Python LOC
- ~223 new tests
- ~18 days total
- 2 new MCP tools, 2 new CLI commands

---

## Design Decisions

1. **Dry-run by default** — `apply_changes: bool = False`. No accidental network disruption.
2. **Credentials via env var** — never stored in config files.
3. **Legitimate traffic only** — all generated traffic is real HTTP/DNS/NTP. No jamming.
4. **Advisory disclaimer always included** — "This is NOT legal advice."
5. **Markdown output for reporting docs** — lightweight, convertible to PDF externally.
6. **Smart home discovery optional** — `zeroconf` not in base install.
7. **Terminology compliance** — all new code scanned by CI gate. Legal templates use approved terms.

---

## References

### CSI Countermeasures
- UChicago "Et Tu Alexa" (NDSS 2020) — cover traffic injection
- Wi-Spoof (JISA 2025) — TX power manipulation, 93% misclassification
- IRShield (Ruhr-Universität Bochum 2022) — IRS metasurface, 95% attack block
- MIMOCrypt (NTU Singapore, IEEE S&P 2024) — MIMO-based CSI encryption
- SnoopFi (Computer Networks 2025) — bypasses CSI fuzzing defenses
- LeakyBeam (NDSS 2025) — plaintext beamforming feedback attack

### Legal
- Kyllo v. US, 533 U.S. 27 (2001) — through-wall sensing = search
- Carpenter v. US, 585 U.S. 296 (2018) — continuous digital surveillance
- Illinois BIPA (740 ILCS 14) — biometric privacy, private right of action
- California CCPA/CPRA — physiological/behavioral data protection
- IEEE 802.11bf-2025 — WiFi sensing standard (ratified Sep 2025)

### Router APIs
- OpenWrt UCI/ubus: `openwrt-ubus-rpc` (PyPI)
- UniFi REST: `unificontrol` (PyPI)
- TP-Link HTTP: `pytplinkrouter` (PyPI)
- Home Assistant: REST API for device orchestration
