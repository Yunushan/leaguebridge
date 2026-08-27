# ADR 0004: Physical macOS remote handoff

Status: accepted as experimental and unvalidated — 2026-08-26

## Context

Riot publishes a native macOS League client, and Sunshine documents macOS 14.2
or newer as an experimental host. This is materially different from trying to
run the Windows client through Wine, copied DLLs, or a VM: League remains on a
separately managed physical Mac. Sunshine's macOS limitations include no
gamepad hosting, and the project has no physical-Mac session evidence.

## Decision

LeagueBridge adds `physical-macos-remote` as an explicit Moonlight handoff route
for Linux/BSD amd64 clients. The embedded route is fixed to `handoff-only`,
`deny`, and `unverified`. It does not authorize local execution, installation,
service changes, security changes, or anti-cheat workarounds.

Config schema v2 stores one exact `route_id` and one `remote_host`; there is no
parallel Windows/macOS state or implicit precedence. The loader may strictly
accept the original Windows-only schema v1 and normalize it in memory, but all
new output is v2.

The optional `macos-host` doctor runs on the Mac, accepts Darwin amd64/arm64,
performs only passive discovery, executes no commands, and cannot return ready
while physicality, OS version, hardware, permissions, local gameplay, and
stream behavior remain manually unverified.

## Consequences

Linux/BSD users can form a route-bound, shell-free Moonlight argument vector for
a user-confirmed physical Mac after explicit stream acknowledgement. This is
not Riot endorsement, local Linux/BSD support, or evidence that macOS streaming
works.

Validation-evidence schema v1 remains scoped to `physical-windows-remote`;
macOS observations cannot be submitted under that contract. Readiness schema
v3 represents the macOS route separately at hard zero. The initial signed
schema-v2 set verifier is also Windows/v1-record backed, so macOS still needs a
separate route-bound record profile, production reviewer trust, physical
evidence, and readiness schema v4. The release contract includes Darwin amd64
and arm64 diagnostic archives, but cross-compilation and hosted lifecycle
execution alone do not establish physical-Mac or gameplay support.
