# Threat model

## Assets

- Riot accounts and session credentials
- Host integrity and user files
- Vanguard's trust and the player's account standing
- Accuracy of compatibility claims
- Diagnostic privacy
- Release dependency provenance and third-party license accuracy

## Adversaries and failures

- A malicious or compromised compatibility/configuration file
- Command or option injection through a host or application name
- A package or website falsely claiming that a VM is physical
- Accidental inclusion of tokens, usernames, addresses, or paths in a bundle
- Stale evidence after a Riot, Windows, Wine, Moonlight, or game update
- Forged, reordered, self-attested, or mismatched host/client/session evidence
- Partial bundle writes, symlinks, oversized input, or archive path traversal
- A stale, substituted, replaced, or locally modified vendored dependency
- A contributor attempting to add VM concealment, anti-cheat bypass, or
  proprietary binaries

## Controls

- Embedded policy is authoritative and validates strictly; external data cannot
  enable execution.
- User-selected configuration and manifest inputs must remain the same regular,
  non-symlink file across opening; Unix opens are nonblocking so a raced-in FIFO
  cannot hang the CLI before type validation.
- All unknown, malformed, or stale compatibility decisions fail closed.
- Validation evidence is bounded and strictly parsed with duplicate/unknown-key
  rejection, exact check inventories, timestamps, artifact references, review
  levels, and expiry. Set verification recomputes exact-file SHA-256 bindings;
  standalone session records cannot claim promotion-safe linkage.
- Authenticated evidence v2 signs one exact set-level payload with
  domain-separated Ed25519 messages. Reviewer identity, roles, route/client
  scopes, validity, and revocation come only from an application-controlled
  policy. Policy validation rejects non-canonical, identity, small-order, and
  mixed-order reviewer public keys before quorum evaluation. A record,
  repository evidence set, flag, environment variable, or arbitrary key file
  cannot supply production trust. Every declared artifact is opened beneath
  one held directory root and re-hashed before a verified-set token can exist.
- Remote commands use `exec` argument arrays, never a shell; all values are
  length- and character-bounded. Real PATH discovery resolves the selected
  Moonlight client to an absolute path and requires a regular executable target
  before the handoff plan can invoke it. A private, non-serialized provenance
  marker binds executable plans to that passive discovery result, and an exact
  private client snapshot detects post-plan path/flavor/prefix mutation; decoded
  or hand-built client plans fail closed.
- A physical-host acknowledgement is mandatory. LeagueBridge does not inspect,
  alter, or conceal hypervisor identity.
- Reports are constructed from an allowlist. Redaction is defense in depth, not
  permission to collect raw logs.
- Bundles are local, bounded, atomically created, previewable, and never
  overwrite an existing file. Unix builds request mode 0600. Windows files
  inherit the destination directory DACL, which users must verify before sharing.
- The portable archive installer and uninstaller validate every visible path
  component and reject symlinks, but POSIX shell cannot hold ancestor directory
  handles across the complete operation. A privileged lifecycle therefore
  requires an archive extracted in a trusted directory and a destination whose
  existing ancestors are not writable by untrusted users. These scripts are not
  a safe privilege boundary when another process can rename or replace those
  ancestors concurrently.
- LeagueBridge downloads no Riot/Vanguard DLL, driver, installer, or game asset.
- CI and release builds run the pinned official Go vulnerability scanner. A
  production release is tied to the exact supported Go builder selected by the
  release contract; source compatibility with an older Go version does not make
  that version an approved release toolchain.
- Production builds resolve no modules from the network. A rooted offline
  verifier byte-locks `go.mod`, `go.sum`, `vendor/modules.txt`, all 111 vendored
  files, and the complete directory inventory before another release-local Go
  command runs. Release binaries must contain exactly the approved,
  unreplaced `filippo.io/edwards25519` v1.2.0 module. The v4 build identity and
  canonical SPDX SBOM bind its pinned upstream h1; the archive `LICENSE`
  reproduces its BSD-3-Clause binary-distribution notice.
- No command runs as root/Administrator by design.

## Explicit non-goals

LeagueBridge will not weaken Secure Boot, TPM, VBS/HVCI, IOMMU, driver signing,
or Vanguard; patch Riot processes; inject DLLs; spoof hardware; conceal a VM;
automate gameplay; collect credentials; or mirror proprietary software.

## Residual risk

Sunshine/Moonlight input behavior is not an official Riot Linux/BSD support
contract. Users must stop if Riot Client, Vanguard on Windows, or other Riot
software reports an error. Production promotion of remote play requires current
route-bound manual evidence on a non-valuable test account and, for any
player-facing commercial distribution, legal/product review. The experimental
macOS handoff currently has no eligible evidence or readiness-promotion path.
The v2 production reviewer policy is unprovisioned, so cryptographically valid
promotion is unavailable until independent trust keys and physical evidence are
established. A signature authenticates an approver and exact bytes; it cannot
prove liveness, honest observation, physical hardware, or Riot authorization.
The vendor lock proves that a build used the reviewed repository bytes; it does
not guarantee that upstream code is vulnerability-free. Current advisory scans,
dependency review, and future lock rotation remain necessary.
