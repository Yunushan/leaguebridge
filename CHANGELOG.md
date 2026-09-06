# Changelog

All notable changes will be documented here. The format follows Keep a Changelog
and releases use semantic versioning.

## [Unreleased]

### Changed

- Share CI attestation generation and verification through a reusable internal
  Go package while preserving the existing command interface and authentication
  checks. Verification remains separate from readiness scoring and publication
  evidence.

### Fixed

- Require an explicit Moonlight Embedded success message before reporting
  successful pairing or unpairing, including when the client exits zero after
  a failure. Bound verification capture and serialize combined stdout/stderr
  forwarding while preserving complete output and destination errors.
- Reject Moonlight Embedded hostnames exceeding 116 bytes and pairing PIN
  `0000` before launch, matching the client's accepted inputs.
- Preserve the selected Qt backend during control preflight, and keep KVM
  browser sessions alive for the caller's session instead of stopping them
  after 60 seconds. Bound waits for inherited subprocess pipes.
- Reject rooted file reads when ancestor directories change during opening,
  including replacements that lead back to the original file. Reject raced
  FIFOs during both file and directory opens without blocking.
- Create missing BSD package staging parents and preserve required artifact
  paths and executable modes during CI transport. Include complete
  FreeBSD/DragonFly package inventories and correct NetBSD metadata and root
  ownership across its native, tar, and pax builders.
- Correct OpenBSD package-tool version checks and prevent BSD failure handling
  from appending a log to itself under ksh; diagnostics remain bounded.
- Preserve verified payload bytes during RPM creation and check every installed
  Linux package file against staging for contents, type, mode, and root
  ownership. Include documentation in private Debian smoke installations and
  remove privileged temporary package roots without hiding cleanup failures.
- Require a complete successful CI attempt for the exact main-branch commit
  before release attestation and publication, including all target runtime,
  native-package, and attestation-verification jobs.

### Added

- Hardened BSD native-package smoke jobs by invoking the discovered FreeBSD/
  DragonFly package tool through its absolute path (including `pkg-static`) and
  by tracking OpenBSD's filename-derived installed package identity; this
  prevents `sudo` secure-path failures and duplicate-name cleanup errors in
  hosted guests.
- Extended the hosted Linux runtime/install smoke and score-free native-runtime
  attestation matrix to execute and verify both Linux amd64 and arm64 runners;
  the verifier now rejects an incomplete two-architecture Linux evidence set.
- Added a host-free `linux-bsd-client-smoke.sh` helper that validates the
  Linux/BSD client preflight and fixed League remote plan without pairing,
  contacting a host, or claiming gameplay evidence; it is shipped in portable
  archives and native package payloads.
- Added `remote play`, a first-class Linux/BSD CLI shortcut for the guarded
  physical-host League handoff. It reuses the stream application's exact
  preflight and acknowledgement gates while providing the packaged helper's
  1080p/60 FPS/H.264 defaults; it does not create a local League runtime.
- Added an explicitly opt-in Linux/BSD live-session helper that validates the
  credential-free configuration, performs a fixed League application preflight,
  and starts a bounded 1080p/60 FPS/H.264 physical-host stream only after the
  caller supplies `--start`; it is now carried by portable and native package
  payloads, remains non-certifying, and never records gameplay evidence.
- Automatic Moonlight recovery now preserves the platform convention for a
  generic `moonlight` executable: Qt on Linux/OpenBSD/NetBSD and Embedded on
  FreeBSD/DragonFly, while the explicit legacy `--client moonlight` alias is
  unchanged.
- Added Qt `linuxfb` preflight coverage for both the conventional `/dev/fb0`
  device and Qt's `/dev/graphics/fb0` fallback path; the live gate now also
  requires read/write access because Qt opens and maps the framebuffer.
- Fixed Linux/BSD device-permission preflight to match Moonlight Embedded's
  read/write opens for live evdev and WSCONS input, plus direct DRM devices;
  explicit Embedded X11 modes now require an accessible evdev endpoint, direct
  DragonFly SDL KMS/DRM now fails closed for non-root processes, and `remote
  map` also checks the initial read/write device setup performed by the upstream
  mapping action.
- Added an early live-stream guard for Moonlight Embedded's current non-SDL
  `gamecontrollerdb.txt` requirement. Package data, an explicit
  `--input-mapping`, `SDL_GAMECONTROLLERCONFIG`, and the SDL backend are
  recognized before launch, with actionable guidance when no mapping is found.
- Fixed automatic stream-client selection for `--display-mode fullscreen`;
  Moonlight Embedded can satisfy fullscreen through its documented default,
  while Qt-only `borderless` selection remains unchanged.
- Fixed automatic Qt-only stream selection so a Linux installation with the
  official Moonlight Flatpak but no native Qt executable can still use decoder,
  display, and other Qt-surface options; incompatible Embedded candidates are
  filtered out before launch.
- Added one bounded automatic native-client recovery attempt to `remote pair`
  and `remote quit` after control preflight or process/transport failure;
  explicit selections, cancellation, and Embedded-only `remote unpair` remain
  fail-closed.
- Fixed automatic `remote map` selection so `--client auto` resolves to
  Moonlight Embedded, the only client surface that exposes local controller
  mapping.
- Fixed automatic `remote unpair` selection so the default `auto` client uses
  Moonlight Embedded, the only supported surface for that operation, instead
  of discovering Qt first and failing during plan construction.
- Added one bounded automatic Moonlight recovery attempt for a live stream
  whose initially selected native client cannot complete the host
  application-list handshake; another installed client is tried only before
  streaming, while explicit client choices and missing-app results remain
  fail-closed.
- Extended that live-stream recovery to a failed application-list guard before
  a bounded reconnect attempt, while retaining one total fallback, explicit
  client selection, cancellation, and missing-app fail-closed behavior.
- Added the same bounded automatic-client recovery to `remote list`: a failed
  application-list process or transport operation can retry once with another
  supported client, while successful missing-app results and explicit client
  choices remain fail-closed.
- Fixed Linux/BSD client selection so the Linux-only Moonlight Flatpak cannot be
  selected or discovered on FreeBSD, OpenBSD, NetBSD, or DragonFly BSD; BSD
  users now receive native Qt/Embedded package guidance.
- Added the current Moonlight Embedded `x11_vaapi` backend to the bounded
  Linux/BSD stream selector, including client-specific argument validation,
  X11 display preflight, and documentation. This is a decoder/backend
  capability improvement only; it does not change the native League/Vanguard
  support boundary.
- Added fail-fast validation for Moonlight Embedded's SDL backend: explicit
  audio or input-device selectors are now rejected before launch because SDL
  owns controller discovery and does not accept those device options.
- Normalized Moonlight client selections at the CLI and discovery boundaries,
  so case and surrounding whitespace cannot make a valid Linux/BSD client
  selection pass diagnostics and then fail during process discovery.
- Fixed Linux/BSD package and archive-install smoke checks so valid
  v-prefixed prerelease versions such as `v0.0.0-ci` reach the authoritative
  Semantic Version checker instead of being rejected by an incomplete shell
  pattern.
- Raised the DragonFly BSD CI guests to the action's 6 GiB memory baseline to
  reduce boot/SSH readiness timeouts without weakening runtime or package
  evidence gates.
- Fixed fully explicit hardware-KVM invocations such as `--route macos
  --url ... --confirm-physical-host` so they do not consult or conflict with
  an unrelated default configuration for another physical-host route.
- Fixed fully explicit Moonlight route invocations so a Linux/BSD user can
  switch to a physical Mac or Windows host without an unrelated default route
  blocking the selected handoff; named `--config` files remain authoritative.
- Fixed live stream backend selection so an `auto` Moonlight client follows an
  explicit Embedded or Qt display selector through both preflight and process
  discovery; conflicting selectors and incompatible explicit clients now fail
  before a handoff can start.
- Fixed remote application preflight to follow the selected client's lookup
  semantics: Qt and the Qt-based Flatpak accept case-insensitive advertised
  application names like the upstream launcher, while Moonlight Embedded keeps
  exact-name matching.
- Added an invocation-only `remote pair --pin` option for Moonlight Qt,
  Moonlight Embedded, and the Qt-based Flatpak, with strict four-digit
  validation and fail-closed rejection for dry-run output; pairing PINs are
  never persisted.
- Added a bounded `remote stream --qt-platform` selector for Qt/Flatpak display
  backends (`xcb`, `wayland`, `eglfs`, and `linuxfb`), with matching Linux/BSD
  preflight and a child-only `QT_QPA_PLATFORM` override; arbitrary environment
  injection and unsupported client flavors are rejected.
- Fixed the Flatpak form of that selector to place the bounded
  `--env=QT_QPA_PLATFORM=VALUE` option before the Moonlight app ID, ensuring the
  explicit display backend reaches the sandbox instead of relying only on
  inherited host environment state.
- Added a bounded Linux/BSD `remote wake` operation for sending a standard
  Wake-on-LAN packet to an already confirmed physical host before the normal
  remote handoff; the MAC is invocation-only and the command does not imply
  native League/Vanguard support.
- `remote stream` can now optionally send that Wake-on-LAN packet once and
  wait a bounded interval before its required host-application preflight,
  making the already-paired physical-host handoff a single invocation without
  persisting a MAC address or weakening the unverified-handoff boundary.
- `remote pair` and `remote list` can now use the same opt-in Wake-on-LAN
  bootstrap before the initial Moonlight pairing or application listing, so a
  sleeping physical host can be powered on and inspected from one Linux/BSD
  invocation while the unverified-handoff boundary remains explicit.
- WOL-backed `remote list` and the initial `remote stream` application
  preflight now retry failed Moonlight listings within a bounded, configurable
  window, improving slow physical-host boot recovery without retrying pairing,
  relaunching League, or weakening the application-presence guard.
- Extended the Linux/BSD remote smoke helper with optional Wake-on-LAN MAC,
  bounded wait, IPv4 destination, and UDP-port arguments; it records only that
  the bootstrap was used and never writes the MAC to evidence.
- Added an explicit, shell-free `remote kvm` convenience launcher for opening
  a clean hardware-KVM web endpoint through `xdg-open`, `gio`, or
  `sensible-browser`; credentials, query tokens, fragments, and implicit HTTP
  are rejected, and the command remains a manual unvalidated candidate rather
  than a new KVM backend or readiness promotion path.
- `remote kvm` now falls back to an installed allowlisted direct browser such as
  Firefox or Chromium when a Linux/BSD desktop has no URL-opener helper.
- `remote kvm` can now optionally send one Wake-on-LAN packet and wait a bounded
  interval before opening the hardware-KVM UI, keeping the MAC invocation-only
  and the physical-host/acknowledgement boundary explicit.
- Added a documented hardware-KVM-over-IP fallback for Linux/BSD users whose
  physical host rejects software-streamed mouse input; it keeps the host
  physical and unmodified, requires manual route-bound validation, and does not
  add a virtual-HID, USB/IP, or anti-cheat-bypass path.
- Bound the hardware-KVM candidate to PiKVM's documented HDMI-audio/WebRTC
  capability and clarified that full A/V validation requires an audio-capable
  device; VNC and DIY capture paths remain insufficient for that claim.
- Added optional credential-free KVM endpoint configuration via
  `config init --kvm-url` and `remote kvm --config`; physical-host confirmation can be
  reused, while the unverified-handoff acknowledgement remains per operation.
- `remote kvm` now follows the configured or explicit Windows/macOS route and
  verifies only that selected physical-host contract, so unrelated stale route
  evidence cannot block the chosen hardware-KVM handoff.
- Documented the current Sunshine Raw Input/Virtual HID Driver path as a
  separate experimental physical-Windows-host candidate. LeagueBridge does not
  install or license the host component, and the route remains unvalidated and
  non-certifying for Riot/Vanguard gameplay.
- New remote configurations now target Sunshine's exact `League of Legends`
  entry by default, while a separately published `Desktop` or Riot Client
  entry remains selectable with `--app` so physical-host prompts can be handled
  explicitly.
- Qt/Flatpak remote stream plans now explicitly request relative mouse capture
  by default; `--absolute-mouse` remains an opt-in override for the unvalidated
  physical-host input experiment.
- Documented Riot's optional Windows-host Vanguard On-Demand Pre-Check boundary
  (Windows 11 25H2, UEFI/Secure Boot, TPM 2.0, VBS/HVCI, and IOMMU) without
  treating it as Linux/BSD, Wine, Proton, or VM support.
- Recorded Sunshine's current Virtual HID Driver minimum (`2026.829.2338.54` or
  newer) and active-license requirement for the experimental Raw Input handoff;
  LeagueBridge still does not install, license, or authorize that host component.
- Recorded the vendor version pairing boundary: the current libvirtualhid release
  requires Sunshine `v2026.830.44125+`, while the matching public Sunshine builds
  are prereleases; the repository's stable Sunshine asset pin remains unchanged.
- Refreshed the separate Raw Input experiment record to the compatible
  Sunshine `v2026.831.233010` prerelease and stable `libvirtualhid`
  `v2026.829.2338.54` pair; it remains non-default, unvalidated, and
  non-certifying for Riot/Vanguard gameplay.
- Added an Embedded-only Linux/BSD `remote map` helper for Moonlight's local SDL
  controller-mapping action. It accepts one bounded evdev device, keeps host
  routes and stream flags out of the local plan, and live-runs only after the
  device is confirmed as a character device.
- Added bounded Embedded `--audio-device` and repeatable `--input-device` stream
  selectors (up to six evdev devices, matching Moonlight Embedded's current
  parser limit), plus the Embedded-only `remote unpair`
  recovery operation; device values are validated before they reach Moonlight,
  and live streams preflight every explicit evdev path as a character device.
- Added the Embedded-only `--input-mapping` selector for existing SDL
  gamecontroller database files, with absolute-path, fixed-argv, and live
  regular-file/8 MiB preflight validation.
- Added bounded Moonlight stream controls for host-side audio, Embedded
  gamepad-to-mouse emulation, and Qt/Flatpak multi-controller, background
  gamepad, mouse/controller mapping, diagnostics, HDR, and YUV444 behavior;
  each option translates to the documented client syntax and rejects the
  wrong client flavor before execution.
- Added an opt-in, bounded `remote stream --reconnect-attempts` recovery policy
  with a context-aware delay for transient Moonlight disconnects; retries reuse
  the same discovered executable and fixed host/application argument vector,
  recheck the advertised application before each retry, and never retry
  cancellation.
- Added `remote quit` as a bounded, route-bound Moonlight recovery operation
  for stopping a stale application on the already-paired physical host without
  starting a new stream.
- Added `remote stream --quit-after`, translating Moonlight Embedded's
  `-quitappafter` and Moonlight Qt's `-quit-after` cleanup toggles for dropped
  Linux/BSD client sessions.
- Prevented explicit Embedded selection from misclassifying Linux, OpenBSD, or
  NetBSD's generic Qt-convention `moonlight` executable; the resolver and
  client preflight now require the explicit Embedded executable on those
  targets while retaining the FreeBSD/DragonFly package fallback.
- Made the Linux/BSD client preflight honor the explicitly selected Moonlight
  flavor and require the official Moonlight Flatpak app to be installed before
  a Flatpak handoff can pass its control-plane gate; real-environment discovery
  now repeats that app-presence check before constructing an executable plan.
- Extended the read-only compatibility audit to identify additional container,
  micro-VM, OpenBSD VMM, Xen, LXC/Incus, and cross-platform VM launchers while
  keeping every discovered alternative explicitly non-certifying.
- Aligned compatibility Flatpak discovery with the client probe by checking
  validated colon-separated `XDG_DATA_DIRS` roots without executing Flatpak.
- Corrected Wayland and X11 endpoint checks to join paths using the inspected
  Linux/BSD target's separator, preserving cross-target diagnostic accuracy.
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
- Hosted Linux amd64 and arm64 runtime and shipped-archive install-lifecycle
  smoke evidence, with an explicit headless-client block rather than a gameplay
  claim.
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
- Added bounded Qt/Flatpak `remote stream --frame-pacing auto|on|off` and
  `--keep-awake` controls for frame-pacing stability and display-sleep
  prevention during Linux/BSD remote sessions.
- Added bounded Qt/Flatpak `remote stream --capture-system-keys` modes for
  controlling documented system-key capture behavior during Linux/BSD remote
  sessions.
- Added bounded Qt/Flatpak `remote stream --vsync auto|on|off` support for
  explicit local display synchronization during Linux/BSD remote sessions.
- Hardened Linux/BSD graphical-session preflight by validating display syntax
  and checking resolvable Wayland endpoints for a Unix socket before allowing
  a live stream; abstract X11 sockets remain explicitly runtime-validated.
- Hardened direct SDL/Qt Linux/BSD preflight to require real DRM, framebuffer,
  evdev, and OpenBSD WSCONS device nodes instead of accepting regular-file
  placeholders.
- Rechecked Riot's current Vanguard On-Demand requirements on 30 August 2026;
  the page still describes a Windows-only attestation path and adds no
  Linux/BSD, Wine, Proton, or virtual-machine exception.
- Rechecked Riot's current Player Support and Vanguard pages on 31 August
  2026; League remains supported only on Windows and macOS, and no authorized
  Linux/BSD, Wine, Proton, or virtual-machine gameplay route was added.
- Rechecked Riot's public Vanguard issue tracker on 4 September 2026; the
  Linux request remains an unassigned user report with no implementation or
  authorization, and the readiness assessment window was refreshed to bind
  that dated status.

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

- Fixed non-PR CI package smoke invocations to preserve their intended
  multiline shell arguments and corrected the downloaded race/vet attestation
  subject path; the workflow now exercises the same argument and artifact
  layout that its attestation jobs consume.
- Added an explicit `cpa.sh` availability gate after BSD VM startup so a
  timed-out or partially initialized guest cannot trigger misleading follow-up
  shell and evidence-sync failures.
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
