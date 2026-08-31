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
- Canonical content-addressed schema-version 3 package manifests for the five
  Linux/BSD amd64 release archives; Windows and macOS remain external
  host-handoff surfaces.
- Read-only, non-certifying physical-macOS host inventory for the optional
  external handoff; native macOS release and lifecycle jobs are out of scope.
- Hosted Linux amd64 runtime and shipped-archive install-lifecycle smoke
  evidence, with an explicit headless-client block rather than a gameplay claim.
- A dated 27 August 2026 primary-source support check confirming that current
  Riot, Proton, VM, and cloud-gaming constraints have not opened a local
  Linux/BSD League route.
- An overwrite-protected `evidence template-set` workflow that atomically
  creates bound host, client, and session templates for one validation run.
- An expanded compatibility preflight that inventories additional Wine
  frontends, Proton-capable launchers (Steam, Heroic, and protontricks),
  VM/container launchers, Darling, and Waydroid without executing any
  discovered tool; the native Linux/BSD Vanguard block remains unchanged.
- Moonlight diagnostics that follow the same Qt-first and target-specific
  Embedded naming convention as the Linux/BSD remote handoff resolver.
- Corrected FreeBSD and DragonFly Embedded source-build guidance to name their
  separate official `moonlight-embedded` ports.
- A safe `evidence v2 prepare` workflow that verifies complete artifact-backed
  validation sets and emits exact unsigned payload bytes for separately governed
  reviewer signing without adding a trust or promotion bypass.
- A derived readiness-schema-v4 remote-cell evaluator and fail-closed
  `evidence v2 promote` CLI path. It remains inactive until the application-owned
  production reviewer policy is provisioned.
- A strict `ciattestation -verify -kind release` verifier that checks the exact
  five-archive Linux/BSD publication set, canonical checksums, and every
  release attestation before publication.
- BSD package smoke jobs that cross-build the repository version validator for
  each BSD guest instead of assuming the VM image contains Go.
- A score-free native-runtime attestation v2 schema and verifier that binds
  hosted Linux and virtualized BSD smoke results to the exact executable,
  evidence files, source tree, workflow revision, and GitHub run.
- Separate Moonlight control-plane readiness from stream readiness: `remote
  pair` and `remote list` can run from a headless Linux/BSD terminal when the
  platform and launcher are valid, while `remote stream` still requires a
  reachable graphical session.
- Revalidated NVIDIA's current Linux GeForce NOW client against its Vanguard
  removal announcement; the Linux frontend exists, but no current League route
  was found, so cloud gaming remains outside the supported handoff surface.
- Added actionable, target-specific Moonlight installation guidance to the
  Linux/BSD client preflight and remote-play guide without adding
  package-manager execution or Windows/macOS targets.
- Added the explicit `moonlight-embedded` client alias so Linux/BSD users can
  select the package identity directly while retaining the legacy `moonlight`
  configuration value; passive discovery also accepts a binary with the
  explicit `moonlight-embedded` name.
- Documented the still-open Vanguard/Moonlight mouse-input limitation and
  explicitly rejected USB/IP, injected-input, and anti-cheat-bypass guidance.
- Added a copyable, non-exploit upstream request for Riot authorization of a
  Linux/BSD runtime; it does not claim authorization or change the block.
- Added an opt-in live application-list preflight to `remote stream`, preventing
  a stream from starting when the physical host does not advertise the exact
  configured League application.
- Preserved the remote application-list timeout classification after cleanup so
  unreachable physical hosts receive actionable timeout guidance.
- Extended the Linux/BSD remote smoke helper with an optional exact application
  assertion, so a passing reachability check can also verify the configured
  physical-host League entry before any stream is started; the helper now always
  binds that check to the configured launch application.
- Added `remote list --require-configured-app`, which performs the live
  application check against the exact application selected by the current
  configuration and rejects disagreement with an explicit `--require-app`.
- Added a bounded `remote stream --codec` control that translates normalized
  `auto`, `h264`, `hevc`, and `av1` choices to the current Moonlight Embedded and
  Qt command-line forms; `h264` is available as the broad-compatibility choice
  for Linux/BSD clients with limited hardware decoders.
- Added a bounded `remote stream --packet-size` control that translates the
  MTU-sensitive packet-size syntax of Moonlight Embedded and Qt, requiring a
  conservative multiple-of-16 value suitable for Linux/BSD client tuning.
- Hardened direct BSD client preflight against SDL's current KMSDRM limits:
  NetBSD SDL-KMSDRM is rejected, OpenBSD `/dev/drm*` endpoints are recognized,
  and documented WSCONS keyboard and mouse devices are accepted for direct SDL
  input checks.
- Added a bounded `remote stream --decoder` control for Moonlight Qt/Flatpak,
  with explicit rejection on Embedded clients that do not document decoder
  selection.
- Added a bounded `remote stream --display-mode` control for Moonlight
  Qt/Flatpak, translating `fullscreen`, `windowed`, and `borderless` to the
  documented Qt option; Embedded now accepts its documented `-windowed` mode
  and `-platform` backend selector, and continues to reject unsupported
  `borderless` mode.
- Added bounded custom `remote stream --resolution WIDTHxHEIGHT` support,
  translating the request to Qt's `-resolution` or Embedded's paired
  `-width`/`-height` options with conservative dimension limits.
- Added bounded `remote stream --audio-config` support, translating stereo and
  surround choices to the documented Moonlight Qt and Embedded forms for
  Linux/BSD audio tuning.
- Added `remote stream --preserve-host-settings`, mapping the documented
  Embedded `-nosops` and Qt `-no-game-optimization` controls to keep host game
  settings from being changed by the streaming client.
- Added bounded `remote stream --network-mode auto|lan|wan` support for
  Moonlight Embedded, mapping local/WAN choices to its documented `-remote`
  optimization values.
- Rechecked Riot's current Vanguard On-Demand requirements on 30 August 2026;
  the page still describes a Windows-only attestation path and adds no
  Linux/BSD, Wine, Proton, or virtual-machine exception.

### Security

- Bound executable Moonlight handoffs to private passive-discovery, a
  real-environment file identity, and exact client snapshots so passive fixture,
  decoded, hand-built, or post-plan-mutated client plans cannot cross into
  process execution or substitute an arbitrary launcher after discovery.
- Bound CI attestation verification to the exact workflow revision, GitHub run
  ID, and run attempt in addition to the repository, commit, tree, and ref.
- Kept virtualized BSD runtime evidence distinct from physical-hardware claims;
  native runtime subjects cannot carry readiness scores or gameplay promotion
  fields.
- Hardened configuration, evidence-template, support-bundle, and native-package
  publication with anchored, symlink-rejecting directory operations instead
  of pathname-following temporary-file creation.

### Changed

- Made Windows-target installation path synthesis use Windows separators even
  when cross-target probe fixtures run on Unix hosts; native Windows behavior
  remains unchanged.
- Revalidated the local Linux route through the available Debian and Ubuntu
  WSL2 guests: the Linux amd64 CLI runs and reports the fail-closed
  compatibility contract, while the guests have no Wine/Proton toolchain and
  remain virtualized and non-certifying for League/Vanguard gameplay.
- Fixed CI action resolution by pinning `actions/setup-go` to the published
  `v6.5.0` commit after the public CI run rejected the unavailable revision,
  and scoped formatting checks to tracked non-vendored Go sources.
- Refreshed the pinned Sunshine Windows AMD64 release metadata verification date
  after rechecking the official release API and page; asset identity and
  digests remain unchanged.
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
- Added bounded remote-stream resolution, FPS, and bitrate controls with
  client-specific fixed Moonlight argument generation and execution-time
  validation; arbitrary client flags remain rejected.
- Corrected the bounded 1440p handoff: Moonlight Embedded now receives its
  documented width/height pair, while Moonlight Qt keeps its dedicated `-1440`
  flag.
- Hardened release validation around exact archive layout, reproducible
  metadata, binary target/build identity, checksums, and binary-bound SPDX.
- Made release publication verify in a private same-filesystem staging directory
  first, preserve an existing `dist/` during replacement, and restore it when
  the final publication move is interrupted.
- Pinned production release builds to Go 1.27.0 and bound the exact builder to
  both structured build IDs and package provenance.
- Removed native Windows/macOS archive generation from the LeagueBridge release
  contract; the release set is now exactly five Linux/BSD amd64 tarballs with
  canonical in-repository generation, source-tree provenance, and a clean
  exported commit snapshot boundary.
- Vendored `filippo.io/edwards25519` v1.2.0 for offline release builds, moved
  structured release/build identities to v4 with the exact dependency token,
  and restricted release binaries to that one unreplaced compiled module.
- Fixed the tracked remote coverage test formatting so the Linux CI format gate
  can run the remaining test and verification steps.
- Bound the coverage driver's nested Go test invocation to the running
  toolchain, preventing a different Go installation earlier on PATH from
  invalidating the coverage gate.
- Scoped CI and release gofmt gates to project-owned Go sources while keeping
  the complete vendored tree covered by the independent vendor lock check.
- Rejected explicitly empty remote host, application, and client overrides
  instead of silently retaining persisted configuration values.
- Moved release-attestation verification into the tested source tree and binds
  the publish job to the tested commit before it downloads release artifacts.
- Revalidated the fixed Moonlight Embedded, Qt, Flatpak, FreeBSD, and DragonFly
  handoff forms against current upstream command parsers and package recipes;
  this confirms launcher compatibility only, not League gameplay support.
- Rechecked Sunshine's official latest-release page against the pinned Windows
  AMD64 tag; the pin remains current without downloading or installing the
  host software.
- Rechecked a current Wine/Proton/Vanguard research repository; it targets
  VALORANT rather than League, makes no working Linux claim, and stops at the
  Vanguard trust boundary, so no anti-cheat research patch was imported.
- Rechecked Darling's current upstream runtime and its League issue; GUI and
  application limitations remain, with no League implementation or validated
  playable route, so Darling remains outside the Linux/BSD gameplay path.

### Security

- Normalize real PATH-discovered Moonlight clients to an absolute regular
  executable before they enter a remote handoff plan, while preserving normal
  package-manager symlink layouts.
- Snapshot the discovered Moonlight flavor, executable, and fixed prefix before
  planning, and snapshot the exact generated argv so a caller cannot mutate the
  selected client or retarget the host/app between discovery and handoff
  construction.
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
- Made CI and release format checks enumerate only Git-tracked Go sources, so
  ignored build artifacts cannot create a false formatting failure.
- Required distinct, scoped lab-observer and independent-reviewer Ed25519 keys;
  evidence, files, flags, and environment variables cannot introduce production
  trust, and no private signing key is present in the application or repository.
- Required installed uninstall helpers to receive explicit `PREFIX` and
  `DESTDIR` values, and made release publication reject any unexpected file.
- Made release attestation verification recheck every subject from a pinned
  release directory before and after the external GitHub verification call.
- Made release and reproducibility cleanup refuse recursive removal when a
  private scratch path has been replaced by a symlink.
- Applied the same scratch-path cleanup guard to the Linux and BSD native
  package smoke jobs before they remove temporary package roots.
- Added a repository LF-normalization contract so content-addressed evidence is
  stable across Windows and Unix checkouts.
- Raised the Ed25519 point-validation dependency floor to v1.2.0 because
  v1.1.0 is covered by CVE-2026-26958 / GHSA-fw7p-63qq-7hpr. LeagueBridge did
  not call the affected `MultiScalarMult` API, but no production release pins
  the affected version. Every archive's existing `LICENSE` member includes the
  full BSD-3-Clause binary-redistribution notice.
