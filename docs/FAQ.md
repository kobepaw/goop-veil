# FAQ

## What is goop-veil?
goop-veil is a software-only research preview focused on detecting potential WiFi sensing activity, degrading sensing reliability through guarded router-based mitigations, and generating documentation artifacts for review.

## Does it prove that someone is spying on me?
No. Detection output should be treated as a technical signal or lead, not definitive proof or attribution.

## Does it block all WiFi sensing?
No. It is designed to help detect, degrade, and document risk. It does not guarantee prevention against every sensing setup.

## Do I need special hardware?
Not for the basic software workflows. Some advanced or experimental paths in the repository involve additional hardware, but the initial supported release is software-first.

## Which platforms are supported?
This release is Linux-first for the WiFi scanning/capture workflows described in the repo. Other platforms may still be useful for reading docs, reviewing outputs, or developing parts of the codebase, but the primary tested operational path is Linux.

## Which routers are supported?
OpenWrt and UniFi are the clearest current support paths. TP-Link support is more model-dependent. See [ROUTER_COMPATIBILITY.md](./ROUTER_COMPATIBILITY.md) for the current conservative support matrix and notes.

## Is it safe to auto-apply router changes?
Treat router changes carefully. Review recommendations first, prefer dry-run flows, and expect that some changes can affect WiFi behavior.

## Does any data leave my machine?
The project is designed around local workflows. Optional sharing/integration features should be reviewed carefully before use.

## Can this help with reporting?
Yes — the project can generate documentation artifacts that may help with internal records and reporting workflows. Whether a specific response path makes sense depends on context.

## How do I make report artifacts durably verifiable during local testing?
Set `VEIL_LOG_SIGNING_KEY` before running report-generation flows. The value must be base64-encoded key material.

```bash
python - <<'PY'
import base64, secrets
print(base64.b64encode(secrets.token_bytes(32)).decode())
PY
export VEIL_LOG_SIGNING_KEY="<paste-base64-key-here>"
```

If you explicitly enable temporary dev/test signing instead, generated artifacts are only temporarily verifiable for the lifetime of that in-memory key.

## Are the report packages court-ready?
No guarantee is made that generated artifacts will satisfy any court, regulator, or agency requirement. They are technical documentation artifacts that may help with internal review or reporting workflows.

## What about the firmware in this repo?
Firmware-related components are currently experimental and are not part of the initial supported public release surface.

## How can I help?
Issues, reproducible bug reports, router compatibility reports, docs fixes, and contributions to the experimental firmware path are all useful.
