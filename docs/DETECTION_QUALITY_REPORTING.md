# Detection-quality reporting guide

Use this guide when filing a **false positive** or **false negative** report.

Goal: provide enough technical signal for maintainers to reproduce and investigate, while avoiding oversharing sensitive network data.

## Reporting principles

- Treat detections as technical leads, not proof or attribution.
- Share the minimum evidence required for debugging.
- Prefer reproducible steps over long narrative.
- If you cannot safely share raw artifacts, share sanitized excerpts and metadata.

## What evidence is most useful

Include, when available:

1. **Observed output**
   - Relevant CLI snippet (`detect`/`evidence`) and confidence/score fields.
   - Approximate timestamp/time window for the questionable result.

2. **Expected behavior and reasoning**
   - Why the result appears incorrect.
   - Any controlled baseline context (for example known benign traffic run).

3. **Reproduction details**
   - Exact commands used.
   - Capture duration and basic environment setup.
   - Whether maintainers can likely reproduce with the provided details.

4. **Environment details**
   - OS and Python version.
   - Adapter/chipset details if known.
   - Router model + firmware version.

## Redaction expectations for logs and pcaps

Before posting artifacts publicly, redact or remove sensitive values, including:

- SSIDs
- BSSIDs / MAC addresses
- internal and public IP addresses
- account IDs, usernames, hostnames, or device nicknames
- street addresses, geolocation clues, or other personal identifiers

If a raw pcap is too sensitive to share:
- provide a short sanitized excerpt,
- provide packet/time-window metadata,
- and note any hashes/checksums that help correlate local analysis.

## Routing reports into follow-up work

To help maintainers route quickly, include a best-effort guess for likely scope:

- parser / feature extraction
- thresholding / classification behavior
- environment or RF-noise sensitivity
- docs or expectation mismatch
- unsure

This routing hint is optional and does **not** imply certainty.

## Where to file

Use the GitHub **False positive / false negative report** issue template.
