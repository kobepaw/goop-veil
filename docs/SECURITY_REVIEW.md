# Security Review Guide

This repository moves quickly, but trust has to move with it.

This document defines how to review security-sensitive changes before merge.

## Core principles

### 1. Default-safe beats convenient
If a feature can be implemented with a safer default, choose the safer default first.
Unsafe modes should require explicit opt-in and visible warnings.

### 2. Public docs are part of security
If README, release notes, or launch copy overstate behavior, that is a security and trust issue.
Claims must match implementation.

### 3. Dangerous actions need friction
Any feature that can change router state, activate hardware, export sensitive artifacts, or broaden tool authority should require confirmation, guardrails, and rollback guidance.

### 4. Experimental means experimental
If a path is incomplete, fragile, or lightly tested, label it clearly as experimental instead of silently treating it as supported.

## High-scrutiny areas
Changes touching these areas require extra care:
- `python/goop_veil/mcp/`
- `python/goop_veil/mitigation/router/`
- `python/goop_veil/mitigation/legal/` (or future reporting/documentation path)
- `python/goop_veil/integration/`
- `firmware/`
- `README.md`
- launch/release docs in `docs/`

## Review checklist

### Transport / auth
- Is TLS verification enabled by default?
- Are insecure transport modes explicit opt-in only?
- Are hostnames / addresses validated?
- Are host keys or certificates handled safely?

### State-changing actions
- Does this alter router or device state?
- Is there explicit confirmation or dry-run behavior?
- Is rollback guidance documented?
- Could prompt injection or accidental invocation cause unsafe behavior?

### Reporting / artifact generation
- Are artifacts redacted safely by default?
- Are signing/integrity claims truthful?
- Are we implying admissibility, compliance, or official determinations that the code cannot support?

### Firmware / hardware
- Are safety comments and actual behavior aligned?
- Is incomplete firmware being presented as supported?
- Are dangerous control paths authenticated or clearly scoped as experimental?

### Public truth alignment
- Does any new copy imply:
  - certification?
  - guaranteed outcomes?
  - proof or attribution?
  - production readiness beyond reality?

If yes, soften it before merge.

## Merge posture
A change is not “done” just because tests pass.
It should also be:
- understandable
- bounded in scope
- honest in docs
- safe by default
- easy to review later
