# FAQ

## What is goop-veil?
goop-veil is a software-only research preview focused on detecting potential WiFi sensing activity, applying guarded router-based mitigations, and generating documentation artifacts for review.

## Does it prove that someone is spying on me?
No. Detection output should be treated as a technical signal or lead, not definitive proof or attribution.

## Does it block all WiFi sensing?
No. It is designed to help detect, degrade, and document risk. It does not guarantee prevention against every sensing setup.

## Do I need special hardware?
Not for the basic software workflows. Some advanced or experimental paths in the repository involve additional hardware, but the initial supported release is software-first.

## Which platforms are supported?
This release is Linux-first for WiFi scanning/capture workflows described in the repo.

## Which routers are supported?
OpenWrt, UniFi, and some TP-Link paths are supported in varying depth. Compatibility depends on model and firmware version.

## Is it safe to auto-apply router changes?
Treat router changes carefully. Review recommendations first, prefer dry-run flows, and expect that some changes can affect WiFi behavior.

## Does any data leave my machine?
The project is designed around local workflows. Optional sharing/integration features should be reviewed carefully before use.

## Can this help with reporting?
Yes — the project can generate documentation artifacts that may help with internal records and reporting workflows. Whether a specific response path makes sense depends on context.

## Are the evidence bundles court-ready?
No guarantee is made that generated artifacts will satisfy any court, regulator, or agency requirement. They are technical documentation artifacts that may help with internal review or reporting workflows.

## What about the firmware in this repo?
Firmware-related components are currently experimental and are not part of the initial supported public release surface.

## How can I help?
Issues, reproducible bug reports, router compatibility reports, docs fixes, and contributions to the experimental firmware path are all useful.
