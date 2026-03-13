# Enforce explicit signing-key policy for verifiable artifacts

## Summary
Remove silent random signing-key fallback in normal runtime for reporting artifacts. If no signing key is configured, either fail closed for verifiable mode or clearly downgrade output to unsigned/temporary mode.

## Why
Current behavior can create artifacts that appear durable/verified but cannot be reliably verified later if the random key is lost. This is a trust-boundary problem.

## Scope
- Review `python/goop_veil/mitigation/reporting/log_exporter.py`
- Review evidence/report generation callers
- Define dev/test behavior separately from normal runtime behavior
- Ensure runtime messaging clearly communicates artifact verification state

## Acceptance criteria
- Normal runtime does not silently generate random signing keys for durable signed artifacts
- Missing key causes either explicit failure for verifiable mode or explicit unsigned/temporary output mode
- Docs explain `VEIL_LOG_SIGNING_KEY`
- Tests cover key present vs missing behavior
