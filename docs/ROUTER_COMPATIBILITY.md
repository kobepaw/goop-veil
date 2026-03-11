# Router Compatibility Matrix

This matrix is intentionally conservative. It translates current public claims into a clear status view so contributors and users do not over-assume support.

## Status legend
- **Supported** — actively implemented and part of the intended software-only public surface
- **Experimental** — implemented in the repo, but validation coverage is limited and behavior can vary by model/firmware
- **Unverified** — not validated enough for support claims yet

| Router family | Status | Control path | Validation scope | Known gaps / limits |
|---|---|---|---|---|
| OpenWrt | Supported | SSH + UCI / ubus JSON-RPC | Strongest validation depth in current release path | Model/firmware differences still apply; not every mitigation is available on every device |
| UniFi | Supported | HTTPS REST API | Validated path for core channel / TX power / bandwidth style controls | Controller and device generation differences can change behavior |
| TP-Link | Experimental | HTTPS token auth (HTTP only with explicit override) | Selected model paths only; early validation compared with OpenWrt/UniFi | Family-wide support is not claimed; coverage is model-dependent and should be tested before relying on auto-apply |
| ASUS Merlin | Unverified | Likely SSH + `wl` CLI | Investigation notes exist, but no release-level validation | No supported adapter claim yet |

## Important notes
- Router compatibility depends on model, firmware version, privileges, and local configuration.
- Even on supported families, not every mitigation is guaranteed to be available on every device.
- Prefer dry-run/review flows before applying state-changing changes.
- Changes to WiFi settings can affect connectivity, roaming, throughput, and client compatibility.

If you want to help expand support, router compatibility reports are a high-value contribution path.
