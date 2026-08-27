# ADR 0001: Embedded fail-closed policy

Status: accepted — 2026-08-26

## Decision

The reviewed manifest embedded in the binary is authoritative for execution.
External manifests may be inspected but cannot enable a backend. Unknown,
missing, invalid, or expired states block.

## Rationale

A compromised file or stale compatibility report must not expose an account to
an unsupported anti-cheat environment. A future remote-update design will need
signed metadata, rollback protection, expiry, and an independently reviewed code
adapter before it can affect execution.

