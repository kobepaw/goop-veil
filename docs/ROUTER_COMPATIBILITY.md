# Router Compatibility Matrix

This matrix is intentionally conservative. It is meant to show the current public support posture clearly rather than imply that every model in a vendor family is equally supported.

## Status legend
- **Supported** — actively implemented and part of the intended software-only public surface
- **Partial** — implemented in meaningful depth, but some controls or model paths vary
- **Experimental** — present in the repo or under active investigation, but not part of the supported public promise
- **Planned** — not yet implemented to a supportable level

| Router family | Status | Control path | Notes |
|---|---|---|---|
| OpenWrt | Supported | SSH + UCI / ubus JSON-RPC | Strongest current support surface for channel, TX power, bandwidth, beacon, and PMF changes |
| UniFi | Supported | HTTPS REST API | Good support for channel, TX power, and bandwidth controls; behavior can vary by controller/device generation |
| TP-Link | Partial | HTTPS token auth | Model-dependent; insecure HTTP is opt-in only and should be treated carefully |
| ASUS Merlin | Planned | Likely SSH + `wl` CLI | Investigation/validation work needed before any support claim |

## Important notes
- Router compatibility depends on model, firmware version, privileges, and local configuration.
- Even on supported families, not every mitigation is guaranteed to be available on every device.
- Prefer dry-run/review flows before applying state-changing changes.
- Changes to WiFi settings can affect connectivity, roaming, throughput, and device compatibility.

If you want to help expand support, router compatibility reports are a high-value contribution path.
