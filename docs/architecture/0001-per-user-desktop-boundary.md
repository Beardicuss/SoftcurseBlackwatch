# ADR 0001: Per-user desktop security boundary

- Status: accepted
- Date: 2026-09-01

## Decision

Softcurse Blackwatch ships as a per-user desktop application. The unused `Softcurse.Service` worker is excluded from the product solution and installer. The installer writes beneath the current user's local application-data directory and does not request elevation.

All supported process termination flows pass through `BlackwatchCleaner`, which requires native user consent, a short-lived target-bound authorization, immediate process identity verification, and a durable action-journal outcome. Scanner and monitor components are read-only and must not expose mutation helpers.

## Rationale

The former worker duplicated scanning but had no UI connection, Windows Service registration, authentication, or IPC protocol. Shipping or advertising it would create an unclear privilege boundary without adding product functionality. The per-user architecture is smaller, testable, and honest about monitoring lifetime.

## Consequences

- Monitoring stops when the desktop application exits.
- Operations are limited to permissions already held by the signed-in user.
- Features that require elevation must fail clearly; the application must not silently relaunch itself elevated.
- A future service requires a new ADR and security review covering authenticated named-pipe ACLs, client identity, replay protection, request schemas, rate limits, audit records, service hardening, install/update lifecycle, and adversarial IPC tests.
