# ADR 0002: No Wine, VM, or DLL gameplay backend

Status: accepted — 2026-08-26

## Decision

LeagueBridge will not start League through Wine/Proton, provision a Windows VM
for League, collect DLLs, copy Vanguard, conceal virtualization, or weaken host
security.

## Rationale

Riot states that Wine cannot satisfy Vanguard's driver requirements and directs
VM users to ordinary Windows. DLLs do not provide kernel/boot attestation. A
working bypass would conflict with the project's safety and authorization gates.

