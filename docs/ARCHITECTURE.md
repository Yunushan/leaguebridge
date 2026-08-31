# Architecture

LeagueBridge is a small, unprivileged control plane. It does not contain a
Windows compatibility layer, a game client, an anti-cheat implementation, or a
credential broker.

## Trust boundaries

```text
untrusted local configuration       embedded reviewed policy
             |                               |
             v                               v
       strict parser -----> application/policy gate <----- read-only probes
                                      |
                          blocked -----+----- handoff-only
                             |                    |
                    redacted report       Moonlight argument vector
                                                  |
                              separately managed physical Windows PC or Mac
```

The embedded manifest is the launch-safety authority. A file supplied by a user
may be validated or inspected, but it cannot turn a blocked backend into an
allowed backend. Runtime discovery is evidence, not authorization.

LeagueBridge never executes a shell. The remote handoff adapter constructs a
fixed argument vector for a discovered Moonlight executable. Host and app values
are bounded and validated before use.
Real PATH discovery normalizes the selected client to an absolute path and
requires its final target to be a regular executable before planning can use it;
package-manager symlinks are allowed only when they resolve to that kind of file.
The real-environment binding also snapshots the resolved file identity and
the discovered client selection, and the planner snapshots the exact generated
argument vector. It rejects a plan when the selected client or argv changes
before execution, or when the path no longer names the discovered file. This is
a bounded replacement check, not a claim that an untrusted same-account host
process can be made race-free by a path-based launcher.
Passive `Environment` implementations can be used to compose or inspect a
dry-run plan, but `Execute` refuses to cross the process boundary unless the
real environment has supplied that executable identity.
Only a plan returned by `BuildDiscoveredPlan` carries the private
execution-validation and passive-discovery markers plus exact snapshots of the
selected client fields and generated argv; decoded, hand-built, or mutated
plans are rejected at the execution boundary, so JSON output is inspectable
but cannot be replayed or redirected as launch authority.

## Components

- `internal/compat`: embedded, versioned compatibility data and fail-closed
  policy decisions.
- `internal/config`: strict, bounded, credential-free JSON configuration.
- `internal/probe`: read-only host and client capability checks.
- `internal/remote`: Moonlight discovery, handoff planning, and execution.
- `internal/evidence`: immutable schema-v1 host/client/session records,
  freshness evaluation, and exact-file/artifact verification.
- `internal/evidencev2`: strict set-level payload/envelope parsing, scoped
  Ed25519 reviewer verification, and opaque verified-set results. Its production
  trust policy currently has no keys. Evidence never changes launch policy.
- `internal/packageinfo` and `internal/vendorintegrity`: the exact compiled
  dependency allowlist, release inventory, and complete offline vendor lock.
- `internal/diagnostics` and `internal/redact`: allowlisted reports and bounded,
  local support bundles.
- `cmd/leaguebridge`: stable CLI and JSON contract.

There is no daemon and no privileged helper. A normal diagnostic command must
never launch Wine, Proton, Docker, QEMU, bhyve, Riot software, or arbitrary
commands.

## Release dependency boundary

The CLI's sole compiled third-party module is the pinned, vendored
`filippo.io/edwards25519` v1.2.0 used for prime-subgroup reviewer-key checks.
Release tooling runs with module proxy, checksum-database, and VCS access off,
verifies the entire committed vendor tree before building, and rejects a binary
with a missing, additional, replaced, wrong-version, or non-vendored dependency.
Because Go omits module sums from vendored build information, the verifier
restores the pinned upstream h1 only after the observable dependency boundary
matches; the source-tree lock and v4 build identity provide the corresponding
byte and provenance bindings.

## Backend states

- `blocked`: an upstream or safety gate prohibits this route.
- `handoff-only`: League executes on a different, physical supported host.
- `supported`: reserved for a route with an implemented, currently evidenced
  support path. A launch still requires the separate `authorization: official`
  field; state alone never enables execution.

Unknown states, missing evidence, stale evidence, or malformed data fail closed.

Validation records are a separate trust path from execution. A standalone
session record can show that binding-shaped digests were entered, but only
`evidence verify-set` recomputes those digests over the supplied host and client
files. Even a complete independently reviewed set is an input to a human
readiness decision; it cannot promote an embedded backend or invoke Moonlight.

Schema v2 adds cryptographic reviewer authentication around one exact,
artifact-verified route-bound Windows or macOS schema-v1 set. The verifier
derives linkage and completion from the records rather than trusting signed
score or pass fields. The official policy is unprovisioned and readiness schema
v3 is still hard-zero, so the new verifier cannot yet promote any route.
Reviewer-key provisioning and readiness schema v4 require separate review;
macOS records are bound to the Mac route and cannot reuse Windows host evidence.

## Remote physical-host handoff

Remote play is intentionally separate from local compatibility. Moonlight runs
on the Linux/BSD client and connects to Sunshine on a user-owned physical host.
For `physical-windows-remote`, League, Riot Client, and Vanguard remain entirely
on Windows. For `physical-macos-remote`, League runs only through Riot's native
macOS client and Sunshine's host support is experimental; gamepad hosting is
unavailable, while capture, audio, keyboard/mouse, and gameplay behavior remain
unvalidated.

Every handoff operation requires confirmation that the server is physical (not
a VM). Starting a stream additionally requires acknowledgement that remote
streaming is an unverified access method rather than Riot's endorsement of
Linux/BSD. Authentication remains inside Riot Client. Config schema v2 binds a
single exact manifest `route_id` to one `remote_host`; the loader accepts the
old Windows-only schema v1 only to normalize it in memory.

Before a live stream process is started, the controller runs a bounded
Moonlight application-list operation with the same discovered client and
requires the exact final launch application to be advertised by the host. A
missing entry stops the stream; `--dry-run` remains a local argument-vector
check and does not contact the host.

The `macos-host` doctor profile is host-side, read-only, and non-certifying. It
exists only for the optional external-host handoff and never establishes a
LeagueBridge macOS product target. There is no macOS LeagueBridge package,
release archive, or native lifecycle job; any separately reviewed host-side
build remains an inspection aid and retains unresolved manual gates.

The `compatibility` doctor profile is a separate, read-only audit of local
Wine-compatible frontends (including CrossOver, Bottles, and PlayOnLinux),
Proton and Proton-capable launchers (including Steam, Heroic, protontricks, and
UMU),
Lutris, container/VM launchers (including Dockur-style, libvirt,
VirtualBox, VMware, WinBoat, and bhyve paths), and other layers such as Darling
and Waydroid. It exists to make attempted alternatives explicit, not to create
another execution backend: discovery checks PATH and known system/user Flatpak
app directories, never starts a launcher, and the profile always retains the
native Vanguard block. Its serialized report is schema v2.

## Future authorized runtime

If Riot publishes or expressly authorizes a Linux/BSD route, adding it requires
both a reviewed code adapter and reviewed embedded policy. Data alone can never
introduce an executable command. Lifecycle mutations must then use explicit
plans, idempotent operations, crash-safe journals, and rollback.
