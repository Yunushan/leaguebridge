# ADR 0003: Remote physical-host handoff

Status: accepted as experimental — 2026-08-26

## Decision

LeagueBridge may invoke an installed Moonlight client to reach a user-owned,
explicitly confirmed physical Windows host. It will not install or configure
Sunshine automatically, handle credentials, or claim local compatibility.

Streaming requires an acknowledgement that the method is unverified. The command
is constructed without a shell and the host/app values are strictly bounded.

## Consequences

This offers Linux/FreeBSD/OpenBSD users a practical interface today, but needs
real hardware, patch-day, latency, audio, and input validation before it can be
called fully supported.

