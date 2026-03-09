# Harden CLI confirmation flow for state-changing actions

## Summary
Align CLI auto-apply behavior with the stronger confirmation expectations already used in the MCP path.

## Why
State-changing actions should not be easier to trigger from the CLI than from other control surfaces.

## Scope
- Review CLI paths that pass `confirmed=True` directly
- Introduce explicit second-step confirmation or safer interaction model
- Preserve dry-run as default

## Acceptance criteria
- CLI state-changing behavior requires explicit confirmation beyond a single flag where appropriate
- Help text/docs explain the confirmation model
- Tests cover refusal vs confirmed execution
