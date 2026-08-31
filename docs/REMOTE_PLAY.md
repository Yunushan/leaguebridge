# Remote play from Linux and BSD

LeagueBridge implements two remote handoff routes from Linux/BSD clients: a
physical Windows host and an explicitly unvalidated physical Mac host. Neither
route is local Linux/BSD compatibility, and neither is a Riot endorsement of
remote play.

## Topology

```text
Linux / FreeBSD / OpenBSD
NetBSD / DragonFly BSD (runtime unverified)
        Moonlight client
            |
       trusted LAN or VPN
            |
physical Windows 11 gaming PC
   Sunshine + official Riot software + Vanguard

                    or

physical Intel or Apple-silicon Mac
   Sunshine (experimental host) + Riot's native macOS client
```

Do not use a cloud VM, Dockur, QEMU/KVM, bhyve, or another virtualized host.
For the Windows route, use retail Windows 11; do not use Windows Server or
Windows Enterprise. Riot's current Windows requirements call for ordinary
supported Windows, and the pinned Sunshine host release lists Windows 11+;
Vanguard reports a VM-specific error. The macOS route likewise requires a
user-confirmed physical Mac; LeagueBridge does not attempt to hide or spoof
virtualization.

## Physical Windows host preparation

1. Use an activated physical Windows PC that satisfies Riot's current
   [system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends).
2. Install League only from Riot and confirm a direct local Practice Tool session
   works before adding streaming.
3. Install Sunshine from its
   [official project](https://github.com/LizardByte/Sunshine), bind its management
   interface safely, and add a `League of Legends` application entry. If you use
   Sunshine's built-in `Desktop` entry instead, set `--app Desktop` when
   initializing the client configuration.
4. Keep the host on a trusted LAN or private VPN. Do not expose Sunshine's web UI
   directly to the public internet.

Complete Riot/Vanguard's own per-machine checks and a local Practice Tool session
on the physical host before adding streaming. LeagueBridge does not ship a
Windows/macOS host package. If a separately reviewed host-side build is
available, `leaguebridge doctor --profile windows-host` is only a bounded,
read-only checklist: it deliberately exits with blocked code 3 whenever
physicality, hardware, TPM/IOMMU, or active Vanguard state remains unprovable.
Treat it as supplementary evidence, never as Riot or hardware certification.
The optional read-only Sunshine MSI inspector is described below.

On a Linux/BSD client, `leaguebridge doctor --profile compatibility --json`
records whether Wine-compatible frontends (including CrossOver, Bottles, and
PlayOnLinux), Proton and Proton-capable launchers (including Steam, Heroic,
protontricks, and UMU), Lutris, Docker/Podman, QEMU, WSL, WinBoat, libvirt,
VirtualBox, VMware, bhyve, Darling, or Waydroid are present. This is an
inventory-only check: every such path remains non-certifying because it cannot
provide Riot's required physical Vanguard host, and LeagueBridge never launches
or modifies any of those tools.

### Read-only Sunshine inspection

The repository pins the official Windows AMD64 asset metadata checked on 29
August 2026 in
[`compatibility/sunshine-windows-amd64.lock.json`](../compatibility/sunshine-windows-amd64.lock.json).
The official Sunshine release API and release page were rechecked on that date
and still report the pinned `v2026.516.143833` tag and locked asset metadata;
this does not re-download or independently rehash the locked assets.
The supported inspector path is the MSI that Sunshine documents as its preferred
Windows package. The portable ZIP is recorded only as an integrity reference;
Sunshine describes that package as a reduced-performance, unsupported lite
option, so it is not accepted by this workflow.

There is no Windows LeagueBridge release archive or supported Windows package.
If this optional external-host inspection is needed, use a separately reviewed
source build of the inspector on the physical host and treat it as a
non-release diagnostic aid, not as Windows League support. Place the MSI and
that executable on a fixed local drive in
directories whose entire ancestor chain is non-reparse and not writable by
untrusted users; do not use a network share, junction, symlink, or shared
download directory:

```powershell
powershell -NoProfile -File .\scripts\inspect-sunshine-host.ps1 `
  -ConsentToReadOnlyInspection `
  -ArtifactPath 'C:\LeagueBridge-Inspection\Sunshine-Windows-AMD64-installer.msi' `
  -LeagueBridgePath 'C:\LeagueBridge-Inspection\leaguebridge.exe' `
  -ExpectedLeagueBridgeSha256 '<lowercase leaguebridge.exe SHA-256 from PACKAGE-MANIFEST.json>' `
  -Json
```

The consent applies only to reading the two files, computing their hashes,
checking the MSI's Windows Authenticode status, and invoking the fixed
`doctor --profile windows-host --json` probe. The script neither downloads nor
executes Sunshine and never installs software, starts or changes a service,
opens a firewall port, changes security settings, or handles credentials. It
always reports `installation_authorized: false` and `launch_authorized: false`
and exits blocked (3), even when artifact integrity succeeds. Review the output
before retaining it as a validation artifact; it is not proof of a physical
machine or permission to proceed.

The inspector rejects UNC paths, mapped/network and non-fixed drives, and
reparse points in either file's full ancestor chain. It holds each verified leaf open with write/delete sharing
denied throughout all path-based inspections, and through LeagueBridge doctor
execution. Windows does not provide a security boundary between mutually
untrusted processes running as the same account: use a clean dedicated session
and ACL-restricted local directories if that threat is relevant.

The inspector also opens the MSI database in mode 0 (read-only) and reports the
`Property`, `CustomAction`, `ServiceInstall`, `ServiceControl`, `Registry`, and
`Environment` tables. Treat custom-action targets as inert data; the inspector
does not invoke them. For the pinned MSI, service tables are absent and service
or firewall work is delegated to Sunshine's setup custom action, so the MSI
tables alone cannot enumerate every machine change. The reported uninstall and
rollback action names are a review aid, not permission to execute them. The
supported rollback route remains Windows Installed Apps/Apps & features using
Sunshine's signed uninstaller, after a separate user decision and after
credentials or evidence have been retained or removed as intended.

For the pinned v2026.516.143833 MSI, the read-only inventory currently reports
14 properties, 9 custom actions, 5 registry rows, and no `ServiceInstall`,
`ServiceControl`, or `Environment` table. `ALLUSERS=1` requests a per-machine
installation. The custom actions explicitly call the packaged
`scripts\sunshine-setup.ps1` with `install`, `uninstall`, and silent variants;
the registry rows target `Software\LizardByte\Sunshine`, while the WiX actions
create and roll back internet shortcuts. Because the setup script—not the
declarative service tables—owns additional setup, a reviewer must treat service,
firewall, and optional driver effects as unresolved until they inspect the
selected installer options and vendor setup implementation. Do not infer safety
from the empty service tables.

Installation is a separate, user-authorized operation. Before granting that
authorization, recheck the pinned tag and digest against Sunshine's official
release page, confirm the machine is physical and supported, review every MSI
option, and decide the required private-network firewall scope. Configure
Sunshine credentials and Moonlight pairing directly in those applications;
never place passwords, PINs, account identifiers, or pairing material in
LeagueBridge output or evidence.

## Physical macOS host preparation (experimental and unvalidated)

The `physical-macos-remote` route is implemented only as a Moonlight handoff.
League itself must run unmodified through Riot's native macOS client on a
user-owned physical Mac. Sunshine documents macOS 14.2 or newer as an
experimental host, with gamepad hosting unavailable. LeagueBridge has no real
Mac evidence for capture, audio, keyboard/mouse, session quality, or gameplay,
so this route remains `handoff-only`, `deny`, and `unverified` in the embedded
manifest.

Before separately authorizing any installation or launch on the Mac:

1. Confirm the physical Intel or Apple-silicon Mac meets Riot's current native
   macOS requirements.
2. Install Riot Client and League only from Riot, then complete a direct local
   Practice Tool session.
3. Review Sunshine's current official macOS documentation, experimental limits,
   permissions, and rollback instructions. Configure credentials and pairing
   only inside Sunshine and Moonlight.
4. Keep the host on a trusted LAN or private VPN; do not expose Sunshine's web
   interface directly to the public internet.

`leaguebridge doctor --profile macos-host` is an optional external-host
inspection profile intended to run on the Mac, not a macOS LeagueBridge
product command. It performs only passive application-directory and PATH
discovery; it runs no subprocesses and does not read credentials or application
contents. It always exits blocked because physicality, macOS version, hardware,
permissions, Sunshine behavior, and a local Practice Tool session require manual
evidence. No macOS LeagueBridge package, release archive, or native CI lifecycle
job is provided. Any separately reviewed host-side build remains non-release and
does not validate local Linux/BSD support, Riot authorization, or remote
gameplay.

## Linux/BSD client prerequisites

- Linux: use Moonlight Qt from the project's documented Flatpak, Snap, AppImage,
  or trusted distribution package. For the official Flatpak, configure a
  trusted Flathub remote and run `flatpak install flathub
  com.moonlight_stream.Moonlight`.
- FreeBSD: run `pkg install moonlight-qt` or `pkg install moonlight-embedded`
  from a configured signed repository, or build the official
  [Moonlight Qt ports tree](https://cgit.freebsd.org/ports/tree/games/moonlight-qt)
  or [Moonlight Embedded ports tree](https://cgit.freebsd.org/ports/tree/games/moonlight-embedded).
- OpenBSD: run `pkg_add moonlight-qt` from a configured signed repository, or
  build the `games/moonlight-qt` port from the
  [official ports tree](https://cvsweb.openbsd.org/ports/games/moonlight-qt).
- NetBSD: run `pkgin install moonlight-qt` from a configured signed pkgsrc
  binary repository, or build
  [`games/moonlight-qt`](https://cdn.netbsd.org/pub/pkgsrc/current/pkgsrc/games/moonlight-qt/index.html)
  from pkgsrc.
- DragonFly BSD: run `pkg install moonlight-qt` or `pkg install
  moonlight-embedded` from a configured signed repository, or build
  [`games/moonlight-qt`](https://github.com/DragonFlyBSD/DPorts/tree/master/games/moonlight-qt)
  or [`games/moonlight-embedded`](https://github.com/DragonFlyBSD/DPorts/tree/master/games/moonlight-embedded)
  from DPorts.

The BSD package-source links and package names above were checked on 30 August
2026. None of these entries is a completed LeagueBridge native runtime
validation, so they are availability evidence—not support or gameplay claims.

After installation, run `leaguebridge doctor --profile client --json` and keep
the launcher on `PATH`. A passing package-discovery check only proves that a
Moonlight executable is present; it does not prove decoder, display, audio,
input, latency, or League/Vanguard behavior. Package names and availability can
change with the OS release, so use the package manager's signature and
repository policy and do not pipe an unverified download into a shell.

LeagueBridge discovery uses `LookPath` only and never starts a candidate client.
The executable path is normalized and checked as a regular executable, and the
production handoff snapshots the discovered client flavor, executable, and fixed
prefix before planning, then snapshots the exact generated argv. It binds
private plan provenance and real-environment file identity to that discovery
result, rejecting a changed client, retargeted argv, or replaced path before
execution; this is a bounded replacement check rather than a complete
same-account TOCTOU boundary;
hand-built or replayed JSON plans cannot substitute a launcher.
`auto` treats a generic `moonlight` executable as Embedded on FreeBSD and
DragonFly BSD, and as Qt elsewhere. Explicitly set `client` to
`moonlight-embedded` (or its backwards-compatible `moonlight` alias) for
Moonlight Embedded; the resolver accepts either the `moonlight-embedded`
executable name or the generic `moonlight` name. Select `moonlight-qt` when a
downstream Qt package uses the generic binary name. When only the trusted Flatpak launcher is
available, set `client` to `flatpak`; LeagueBridge uses the fixed
`flatpak run com.moonlight_stream.Moonlight` prefix and does not execute a
shell.

For a real Linux/BSD desktop, the repository includes a manual client-side
smoke helper. It requires an already-created credential-free configuration and
an already-paired Moonlight host; it does not install software, pair accounts,
start League, or retain the host's application-list output:

```sh
sh scripts/linux-bsd-remote-smoke.sh \
  ./leaguebridge ./remote-evidence "$HOME/.config/leaguebridge/config.json" \
  "League of Legends"
```

The fourth argument is optional. When supplied, the helper requires the
physical host to advertise that exact application as well as the configured
stream application; it must match the configured application. Even without
the fourth argument, the helper always checks the configured application before
recording a passing remote-list check.

The helper requires the client preflight to pass, records the Linux/BSD client
readiness and kernel identity, exercises `remote list` on the configured
physical-host route, and records only a stream dry-run plan.
After reviewing the output, run `leaguebridge remote stream` yourself and
validate a local Practice Tool session on the physical host. The helper writes
`gameplay=not-tested` deliberately: a passing Linux/BSD client smoke cannot
prove Riot/Vanguard behavior, streamed input, latency, reconnects, or ordinary
match play.

Create a credential-free schema-v2 config for the intended host route, set the
host, and confirm `physical_host_confirmed` only when it truly is physical.

```sh
# Choose one route. Record physicality only after checking the named machine.
# Windows host (the backward-compatible default)
leaguebridge config example --route windows
leaguebridge config init --route windows --host gaming-pc.local --confirm-physical-host

# Experimental, unvalidated macOS host
leaguebridge config example --route macos
leaguebridge config init --route macos --host gaming-mac.local --confirm-physical-host
```

For a stream, the controller exposes only bounded common Moonlight quality
settings; arbitrary client flags are rejected at the execution boundary. For
example:

```sh
leaguebridge remote stream \
  --resolution 1080 --fps 60 --bitrate 20000 --packet-size 1392 --codec h264 \
  --audio-config stereo \
  --preserve-host-settings \
  --acknowledge-unverified-handoff
```

Resolution accepts `720`, `1080`, `1440`, `4k`, or a custom `WIDTHxHEIGHT` pair
with width 640–7680 and height 360–4320. FPS accepts 10–480; and bitrate accepts
500–500000 Kbps. Packet size accepts 1024–9000 bytes and must be a multiple of
16; choose a value below the path MTU (`1392` is a common LAN value and `1024`
is a conservative WAN value). Codec accepts `auto`, `h264`,
`hevc`, or `av1`; `h265` is accepted as an alias for `hevc`. The values are
passed only to the stream operation, use Moonlight Embedded's or Qt's
documented option spelling, and are not stored in the credential-free
configuration. `h264` is the broadest decoder compatibility choice; `auto`
keeps the client default. Audio config accepts `stereo`, `5.1-surround`, or
`7.1-surround`; Embedded leaves stereo at its default and maps surround to
`-surround 5.1` or `-surround 7.1`, while Qt/Flatpak uses `-audio-config`.
Audio channel selection remains dependent on the local Linux/BSD audio backend
and host configuration. These are quality hints, not evidence that the client
can decode the stream or that League gameplay is working. In particular, 1440p
becomes Embedded's documented `-width 2560 -height 1440` pair and Qt/Flatpak's
`-1440` option; packet size becomes Embedded's `-packetsize` or Qt's
`-packet-size`; codec becomes Embedded's `-codec` or Qt's `-video-codec` plus
its corresponding codec name. These spellings are based on [Moonlight Qt's
current stream parser](https://raw.githubusercontent.com/moonlight-stream/moonlight-qt/master/app/cli/commandlineparser.cpp)
and [Moonlight Embedded's command reference](https://github.com/moonlight-stream/moonlight-embedded/blob/master/docs/README.pod).

`--preserve-host-settings` asks the chosen client not to apply its game/settings
optimization path. It maps to Embedded's documented `-nosops` or Qt/Flatpak's
`-no-game-optimization` option. This can keep the physical host's League display
configuration stable, but it is only a client hint and is not gameplay evidence.
`--network-mode` accepts `auto`, `lan`, or `wan` and is supported only by
Moonlight Embedded. LeagueBridge maps these values to Embedded's documented
`-remote auto`, `-remote no`, and `-remote yes` forms. Use `lan` for a local
network or `wan` across a routed path; this is a transport hint, not proof of
latency, packet delivery, or League gameplay.

The optional `--decoder` control accepts `auto`, `software`, or `hardware` and
is supported only by Moonlight Qt and the official Flatpak. It maps to Qt's
`-video-decoder` option and can help select a decoder explicitly on Linux/BSD
graphics stacks; Embedded clients reject it because their documented command
surface does not expose decoder selection. This remains a stream hint, not
evidence that the selected decoder or League gameplay works.

The optional `--display-mode` control accepts `fullscreen`, `windowed`, or
`borderless`. Qt and the official Flatpak support all three; Embedded supports
`windowed` through its documented `-windowed` option and uses fullscreen by
default, but does not support `borderless`. The setting controls the local
Moonlight window; it does not change the physical host's League window.

Moonlight Embedded also accepts `--platform auto|x11|x11_vdpau|sdl`. LeagueBridge
maps non-`auto` values to Embedded's documented `-platform` option, selecting
the local audio, video, and input backend. `auto` keeps the package default;
`sdl` can be useful when a Linux/BSD package provides SDL for the desktop
backend. This remains a selection hint: LeagueBridge does not claim that the
backend was compiled in or that it can decode video or deliver gameplay input.
Qt and Flatpak reject this Embedded-only option rather than silently ignoring
it.

The example above intentionally uses only options shared by Qt and Embedded,
so it works with the default flavor on every supported Linux/BSD target. Add
`--client moonlight-embedded` (or the `moonlight` alias on BSD) before using
`--platform`; add `--client moonlight-qt` or `--client flatpak` before using
the Qt-only `--decoder`, `--display-mode borderless`, or mouse-mode controls.
Clients reject unsupported controls rather than silently ignoring them.

Moonlight Qt also exposes `--absolute-mouse` and `--no-absolute-mouse` for its
remote-desktop optimized mouse mode. LeagueBridge exposes these as the bounded
`remote stream --absolute-mouse` and `remote stream --no-absolute-mouse`
controls for Qt and Flatpak clients; Embedded clients reject them because that
client does not document the same options. Try the mode that matches the
physical host and desktop, but treat it only as an input-mode choice: it does
not fix Riot/Vanguard compatibility or turn a remote handoff into local
Linux/BSD support. The option names are based on [Moonlight Qt's current
stream parser](https://raw.githubusercontent.com/moonlight-stream/moonlight-qt/master/app/cli/commandlineparser.cpp).

Known limitation: Riot's [open Moonlight/Sunshine mouse issue](https://github.com/RiotVanguard/Vanguard/issues/70)
still reports cursor-control failure after League starts. The Qt toggle cannot
repair Vanguard's host-side input filtering. If the physical host does not
accept input, stop the session or use input physically attached to that host;
do not use USB/IP, injected input, kernel interception, or another claimed
anti-cheat bypass.

[Configuration schema v2](../schemas/config.schema.json) stores one exact
`route_id` and one `remote_host`; it has no parallel Windows/macOS target
fields. Existing schema-v1 Windows configs are accepted strictly and normalized
in memory, while newly written configs always use v2. The Go runtime remains the
security authority for duplicate keys, byte limits, host syntax, and safe file
handling.

```sh
leaguebridge remote pair
leaguebridge remote list
leaguebridge remote stream --acknowledge-unverified-handoff
```

To verify the host has published the exact application before starting a
stream, add the bounded expectation to the live list operation:

```sh
leaguebridge remote list --require-app "League of Legends"
```

The listing is still forwarded to the terminal; the check only looks for the
validated application name in Moonlight's text response. It is a configuration
guard, not proof that League or Vanguard will accept streamed input.

To bind the check directly to the application that the current configuration
will launch, use:

```sh
leaguebridge remote list --require-configured-app
```

This avoids validating one advertised application while a later stream plan
targets another. `--require-configured-app` is live and cannot be combined with
`--dry-run`.

Every real stream performs that bounded application-list preflight
automatically. It checks the final application that the stream will launch and
does not start the stream if the physical host does not advertise it:

```sh
leaguebridge remote stream --acknowledge-unverified-handoff
```

`--require-app "League of Legends"` and `--require-configured-app` remain
available for explicit intent, but do not disable or weaken the automatic
stream check. The check is live and cannot be used with `--dry-run`. This
remains a physical-host handoff and does not validate streamed input, latency,
or Riot/Vanguard gameplay behavior.

`remote pair` and `remote list` are finite control-plane operations and have a
60-second execution deadline. `remote stream --dry-run` uses only those
control-plane prerequisites, so its fixed argv can be inspected from a
headless SSH session without contacting the host or starting Moonlight. A live
`remote stream` additionally requires an X11 or Wayland endpoint, or an
explicitly selected direct SDL/Qt backend with its device node, plus an
input-path indicator. For direct SDL KMS/DRM use, set
`SDL_VIDEODRIVER=kmsdrm`; for a Qt direct-display setup, set the appropriate
`QT_QPA_PLATFORM` value such as `eglfs` or `linuxfb`. A headless live stream is
intentionally blocked. These checks are only local endpoint indicators and do
not prove input delivery or gameplay. The stream keeps the caller's lifetime
and ends when Moonlight exits or the caller sends its normal interrupt/cancel
signal.

On BSD, current SDL documentation describes KMSDRM as supported on FreeBSD and
OpenBSD, usable on DragonFly BSD only with the required privileges, and
unsupported on NetBSD. LeagueBridge consequently fails closed when NetBSD is
asked to use `SDL_VIDEODRIVER=kmsdrm`; use X11 or Wayland there. OpenBSD's direct
video endpoint is normally `/dev/drm*`; other supported KMSDRM targets commonly
expose `/dev/dri/card*`. On OpenBSD, SDL's WSCONS input backend uses
`/dev/wskbd*` and `/dev/wsmouse`, and LeagueBridge recognizes those devices for
direct SDL preflight when the session can access them. FreeBSD and DragonFly
use their SDL evdev input path, so the preflight looks for `/dev/input/event*`
there.
See [SDL's KMSDRM/*BSD notes](https://github.com/libsdl-org/SDL/blob/main/docs/README-kmsbsd.md).

Stop immediately if Riot Client, Vanguard (on Windows), or other Riot software
reports an error. Do not try to hide the streaming software, patch input, or
work around an anti-cheat control. Validate first with a non-valuable account
and Practice Tool/custom game; public matchmaking remains a manual user
decision.
