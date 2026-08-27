# Changelog

All notable changes will be documented here. The format follows Keep a Changelog
and releases use semantic versioning.

## [Unreleased]

### Added

- Cross-platform Go CLI foundation.
- Embedded fail-closed compatibility policy and public schema.
- Read-only Linux/BSD client and Windows host diagnostics.
- Credential-free configuration and safe Moonlight handoff planning.
- Route-bound configuration schema v2 for separate physical Windows and
  experimental physical macOS handoffs, with strict legacy-v1 normalization.
- A public offline-tested configuration schema for current v2 and read-only
  legacy Windows v1 documents.
- Privacy-safe support-bundle generation.
- Architecture, threat model, support, privacy, legal, governance, and readiness
  documentation.
- Cross-platform tests, CI, and release automation.
- Native-kernel runtime and shipped-archive lifecycle jobs for FreeBSD,
  OpenBSD, NetBSD, and DragonFly BSD.
- Versioned host/client/session validation records with strict artifact-bundle
  verification and bounded streaming measurement methodology.
- Strict authenticated validation-evidence v2 payload, signature-envelope, and
  reviewer-policy schemas plus an Ed25519 set verifier and explicit CLI path.
  The application-owned production reviewer policy remains unprovisioned.
- Deterministic Unix install, upgrade/repair, and exact-file uninstall scripts.
- Canonical content-addressed package manifests for every Linux, BSD, and
  Windows release archive, plus Darwin amd64 and arm64 diagnostic archives.
- Read-only, non-certifying physical-macOS host inventory and hosted Darwin
  amd64/arm64 install-lifecycle workflow definitions.
- Hosted Linux amd64 runtime and shipped-archive install-lifecycle smoke
  evidence, with an explicit headless-client block rather than a gameplay claim.
- A dated 27 August 2026 primary-source support check confirming that current
  Riot, Proton, VM, and cloud-gaming constraints have not opened a local
  Linux/BSD League route.

### Security

- Bound executable Moonlight handoffs to private passive-discovery and exact
  client snapshots so decoded, hand-built, or post-plan-mutated client plans
  cannot substitute an arbitrary launcher after discovery.

### Changed

- Migrated the readiness scorecard to schema v3: fixed 30 ordered binary
  subcriteria, content-addressed repository evidence, derived category/total
  scores, authenticated-evidence class locks, and separate hard-locked zero
  Windows/macOS remote matrices—without an aggregate support score—until
  production reviewer keys, physical evidence, and readiness schema v4 exist.
- Reframed physical Windows streaming as a remote handoff, not local Linux/BSD
  execution.
- Expanded the dated feasibility audit to include CrossOver, WinBoat,
  Waydroid/Android containers, and third-party cloud gaming services.
- Corrected the Vanguard VM reference to VAN 138.
- Replaced the qualitative remote-handoff score with a fixed five-platform,
  four-gate scorecard that starts at zero and requires content-addressed
  runtime evidence for every earned gate.
- Hardened the BSD runtime smoke verifier to reject symlinked executables and
  emit an explicit non-gameplay result under deterministic shell settings.
- Bound evidence to a canonical compatibility-manifest digest so line-ending or
  JSON formatting changes cannot alter semantic identity.
- Hardened release validation around exact archive layout, reproducible
  metadata, binary target/build identity, checksums, and binary-bound SPDX.
- Pinned production release builds to Go 1.27.0 and bound the exact builder to
  both structured build IDs and package provenance.
- Replaced the external ZIP utility with a bounded canonical in-repository
  Windows archive writer.
- Expanded the release contract to exactly eight targets and added canonical
  in-repository tar generation, source-tree provenance, and a clean exported
  commit snapshot boundary.
- Vendored `filippo.io/edwards25519` v1.2.0 for offline release builds, moved
  structured release/build identities to v4 with the exact dependency token,
  and restricted release binaries to that one unreplaced compiled module.

### Security

- Normalize real PATH-discovered Moonlight clients to an absolute regular
  executable before they enter a remote handoff plan, while preserving normal
  package-manager symlink layouts.
- Re-validate the Moonlight client flavor and fixed command prefix at execution
  time, require a BuildPlan validation marker, and re-check the physical-host
  route so a hand-built or decoded plan cannot bypass the safe remote argv and
  handoff contract.
- Re-validate the complete client-specific Moonlight argument grammar at
  execution time, rejecting injected operations, options, hosts, and app names
  before any runner is invoked.
- Re-check release, archive, package-manifest, readiness, and SBOM input paths
  after reading or hashing so a pathname replacement cannot alter a
  content-addressed build input without failing closed.
- Enforced the fixed Moonlight command prefix for Flatpak and rejected mutable
  prefixes on Embedded and Qt plans.
- Re-check content-addressed evidence paths after hashing so a pathname
  replacement during readiness verification cannot be accepted as stable.
- Re-checked regular input paths after opening so a pathname replaced during a
  read cannot redirect through a symlink to the original file.
- Made Moonlight discovery cancellation-aware around every PATH lookup so a
  canceled handoff cannot return a discovered client, with a regression test
  for cancellation racing a lookup.
- Kept all manual validation records ineligible for automatic readiness
  promotion because schema v1 has no trusted reviewer key or signature.
- Rejected duplicate JSON keys, symlinks, special files, oversized inputs,
  unexpected artifacts, path traversal, and unsafe lifecycle destinations.
- Pinned artifact-bundle traversal to one `os.Root`, with exact entry-set,
  identity, type, size, and digest checks before authenticated evidence can use
  an opaque verification token.
- Required distinct, scoped lab-observer and independent-reviewer Ed25519 keys;
  evidence, files, flags, and environment variables cannot introduce production
  trust, and no private signing key is present in the application or repository.
- Required installed uninstall helpers to receive explicit `PREFIX` and
  `DESTDIR` values, and made release publication reject any unexpected file.
- Added a repository LF-normalization contract so content-addressed evidence is
  stable across Windows and Unix checkouts.
- Raised the Ed25519 point-validation dependency floor to v1.2.0 because
  v1.1.0 is covered by CVE-2026-26958 / GHSA-fw7p-63qq-7hpr. LeagueBridge did
  not call the affected `MultiScalarMult` API, but no production release pins
  the affected version. Every archive's existing `LICENSE` member includes the
  full BSD-3-Clause binary-redistribution notice.
