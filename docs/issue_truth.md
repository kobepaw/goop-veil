# Truth-align simulated and stubbed paths

## Summary
Mark mocked/simulated/stubbed behavior clearly in user-facing outputs and docs.

## Why
Users should not mistake simulated behavior or placeholder integrations for deployed protection or active federation.

## Scope
- Review MCP activate path and any mock HAL usage
- Review integration bridges that currently return success-like behavior without full implementation
- Update docs/tool descriptions accordingly

## Acceptance criteria
- Simulated/mock behavior is labeled clearly in runtime outputs and docs
- Stub integrations no longer imply full success silently
- README/FAQ/limitations reflect current reality
