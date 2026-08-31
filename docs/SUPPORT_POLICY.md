# Support policy

## Separate scores

LeagueBridge tracks three independent facts:

1. **Engineering readiness**: quality of this open-source tool.
2. **Local gameplay readiness**: League actually executes on the named Linux or
   BSD platform.
3. **Remote handoff readiness**: the Linux/BSD device is a viewer/controller for
   a separately managed physical host. Readiness is route-specific and cannot
   be transferred between Windows and macOS.

Documentation, tests, or packaging can improve engineering readiness but can
never raise local gameplay readiness through averaging.

## Hard gameplay gates

A local platform may be called supported only when all of these are true:

- Riot officially supports or expressly authorizes the exact OS/runtime path.
- The path needs no bypass, concealment, tampering, copied proprietary DLL, or
  unsupported VM.
- Current end-to-end evidence covers the exact League patch, OS, kernel,
  graphics stack, hardware class, region, and locale.
- Install, patch, sign-in, MFA, champion select, Practice Tool, custom games,
  reconnect, representative queues, input, audio, networking, display, repair,
  and uninstall gates pass.
- Validation is manual or conducted through a Riot-approved automation program;
  LeagueBridge never automates public gameplay or matchmaking.

Unavailable or rotating queues are recorded as `not_available`, never silently
counted as passing.

## Evidence freshness

Every platform claim records a source URL, retrieval date, review date, and
expiry. Expired evidence remains visible but cannot authorize execution. A live
service update may demote a route immediately.

Readiness schema v3 accepts no remote evidence sets and keeps all remote gates
false, so every remote route and platform remains at zero. The implemented
validation-evidence schema-v2 verifier authenticates one exact route-bound
Windows or macOS record and artifact set, but its production reviewer policy
has no keys and v3 cannot consume its result. The schema-v4 evaluator and
`evidence v2 promote` command derive a route-specific result only from an
opaque authenticated set; they do not provision trust or alter v3. A gate can
pass only after production trust, physical evidence, and the reviewed
readiness integration are present.
The eventual overall remote score will be the minimum platform score, never an
average. Builds, unit tests, and package availability are engineering evidence
and do not substitute for physical-host or end-to-end session observations.

Validation-evidence schema v1 covers both `physical-windows-remote` and
`physical-macos-remote`, with route-specific host platform and architecture
binding. Readiness schema v3 represents both routes as separate, fixed,
hard-zero contracts. Neither route can be promoted until production trust keys,
signed physical evidence, and the readiness-schema-v4 integration are reviewed
and provisioned.
Windows observations cannot promote macOS, and macOS observations cannot
promote Windows.

Cross-compilation proves build portability, not platform support. Native smoke
tests and real hardware evidence are required before promotion.

## Current support

- Local League on Linux and BSD: **blocked by Riot/Vanguard requirements**.
- Wine/Proton and Windows VMs: **blocked for gameplay**.
- Physical Windows via Moonlight: **handoff-only and currently unvalidated**.
- Physical macOS via Moonlight: **implemented handoff-only, experimental, and
  unvalidated; represented in readiness v3 but not currently promotable**.
- Dual boot: **documented escape hatch; not Linux/BSD execution**.
