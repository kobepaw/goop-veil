# Add CI coverage + lint/type/security gates

## Summary
Add pragmatic week-one CI/CD upgrades: coverage reporting, `ruff`, `mypy`, dependency audit, and lightweight secret scanning.

## Why
Trust and release discipline improve when obvious correctness and security hygiene checks run automatically.

## Scope
- Add coverage reporting job (non-blocking first)
- Add `ruff`
- Add `mypy`
- Add dependency audit
- Add lightweight secret scan if safe

## Acceptance criteria
- CI produces coverage output/artifact
- Lint and type-check jobs exist
- Dependency/security hygiene checks run in CI
- Contributor workflow/docs updated if needed
