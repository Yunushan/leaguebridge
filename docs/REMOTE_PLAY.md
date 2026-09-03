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
   interface safely, and publish an application with the exact name `League of
   Legends`. New LeagueBridge configurations target that game entry by default,
   so a stream cannot silently open Sunshine's generic `Desktop` entry. Use
   `--app` when the host intentionally publishes another exact application name
   for Riot Client/Vanguard setup.
4. Keep the host on a trusted LAN or private VPN. Do not expose Sunshine's web UI
   directly to the public internet.

Riot's June 2026 [Vanguard On-Demand update](https://www.riotgames.com/en/news/vanguard-on-demand)
describes an optional Windows-host Pre-Check, not a Linux/BSD or Wine exception.
If the physical host operator chooses that mode, Riot currently names Windows 11
25H2, UEFI/Secure Boot, TPM 2.0, VBS/HVCI, and IOMMU as its prerequisites.
Enable or review those settings only through the host's own vendor and Riot
instructions; LeagueBridge never changes them and a passing Pre-Check would
still not prove remote input or League gameplay acceptance.

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

### Experimental Sunshine Raw Input candidate

Current Sunshine documentation describes a separately installed LizardByte
Virtual HID Driver/libvirtualhid path that can expose keyboard and relative
mouse events through a host-side Raw Input device. This is a potentially useful
candidate for the known League/Vanguard mouse failure in software streaming,
but it is not a Riot authorization or a LeagueBridge-supported backend. The
current Sunshine documentation requires Virtual HID Driver
`2026.829.2338.54` or newer together with an active machine license for the
driver-backed input path. Keep Sunshine and the driver on the vendor-supported
version pair, and follow the vendor's current release and licensing
instructions rather than copying a driver into this repository.

The matching stable `libvirtualhid` release `v2026.829.2338.54` requires
Sunshine `v2026.830.44125` or newer. The current compatible candidate is
Sunshine `v2026.831.233010`, but that host release is still a prerelease; the
stable Sunshine release pinned by this repository, `v2026.516.143833`, is not
new enough for the driver. Therefore the overall Raw Input candidate remains
prerelease, unvalidated, and explicitly operator-accepted only. Evaluate it
only with an official, signature-verified compatible pair, or wait for a
compatible stable Sunshine release. If no compatible pair is installed, treat
the driver-backed path as unavailable and do not count Sunshine's `SendInput`
fallback as a League-capable result.

The separately pinned
[`sunshine-windows-amd64-raw-input-preview.lock.json`](../compatibility/sunshine-windows-amd64-raw-input-preview.lock.json)
records the official Windows AMD64 MSI metadata for the compatible Sunshine
prerelease `v2026.831.233010` and the stable `libvirtualhid` release
`v2026.829.2338.54`. This is a reproducibility record for an operator-approved
experiment only: it is not used by the stable inspector, does not authorize
download or installation, and does not promote the remote route.

If this candidate is evaluated, do it only on the physical Windows host:

1. Install Sunshine and the Virtual HID Driver only from the official LizardByte
   distribution, and verify the driver/broker/license state in Sunshine's own
   UI. Do not use a development build, an untrusted mirror, USB/IP, or another
   virtual-input product as a substitute.
2. Confirm that Sunshine reports the driver-backed Raw Input keyboard and mouse
   path. If it falls back to `SendInput`, treat the candidate as failed for
   League testing; a moving Windows desktop cursor is not proof that League
   receives the events. If the host is headless, keep a physical mouse attached
   during the experiment: Sunshine's current Raw Input troubleshooting reports
   that Raw Input games can fail when no physical mouse is present.
3. Keep Moonlight in relative pointer-capture mode. Do not select the Qt
   `--absolute-mouse` mode for this experiment, because Sunshine documents
   absolute positioning as an input-injection path. The Linux/BSD client can
   make the preference explicit with `--no-absolute-mouse`.
4. Test only Practice Tool or a custom game with a non-valuable account. Stop
   immediately on a Vanguard, Riot Client, or League error, unexpected input,
   or an account restriction. Record the exact Sunshine build, driver version,
   license state, host patch, client target, and input result without recording
   credentials or tokens.

LeagueBridge does not install, configure, license, or inspect this Windows
driver, and it does not claim that Vanguard accepts it. The vendor documents a
Raw Input delivery mechanism, not Riot permission. Until a current physical
run demonstrates stable League input and an appropriate authorization basis,
keep this route `unvalidated`; the hardware-KVM procedure in
[`HARDWARE_KVM.md`](HARDWARE_KVM.md) remains the separate fallback.

### Read-only Sunshine inspection

The repository pins the official Windows AMD64 asset metadata checked on 29
August 2026 in
[`compatibility/sunshine-windows-amd64.lock.json`](../compatibility/sunshine-windows-amd64.lock.json).
The official Sunshine release API and release page were rechecked on that date
and still report the pinned stable `v2026.516.143833` tag and locked asset
metadata; the public release page now also lists newer prereleases, which are
deliberately not added to this stable inspector lock without a separate asset
review. This does not re-download or independently rehash the locked assets.
The current Raw Input candidate pair reviewed on 1 September 2026 is recorded
separately in
[`compatibility/sunshine-windows-amd64-raw-input-preview.lock.json`](../compatibility/sunshine-windows-amd64-raw-input-preview.lock.json);
the inspector intentionally does not consume that prerelease lock.
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

The official Moonlight Flatpak is a Linux-only runtime. Do not use a Flatpak
installation as a BSD client fallback: LeagueBridge rejects that selection on
FreeBSD, OpenBSD, NetBSD, and DragonFly BSD, where a native signed Qt or
Embedded package is required.

The BSD package-source links and package names above were checked on 30 August
2026. None of these entries is a completed LeagueBridge native runtime
validation, so they are availability evidence—not support or gameplay claims.

After installation, run `leaguebridge doctor --profile client --json` and keep
the launcher on `PATH`. A passing package-discovery check only proves that a
Moonlight executable is present; it does not prove decoder, display, audio,
input, latency, or League/Vanguard behavior. Package names and availability can
change with the OS release, so use the package manager's signature and
repository policy and do not pipe an unverified download into a shell.

The client doctor can mirror a live stream's selected backend before any host
operation starts. Use `--client moonlight-qt` or `--client flatpak` with
`--qt-platform auto|xcb|wayland|eglfs|linuxfb`, or use
`--client moonlight-embedded` with
`--platform auto|x11|x11_vdpau|x11_vaapi|sdl`:

```sh
leaguebridge doctor --profile client --client moonlight-qt --qt-platform xcb
leaguebridge doctor --profile client --client moonlight-embedded --platform sdl
```

The backend flags are mutually exclusive and require the matching client
flavor; `--client auto` is narrowed to the matching flavor when one of these
flags is present. The checks remain local endpoint indicators and do not prove
Moonlight decoding, network quality, remote input acceptance, or League/Vanguard
gameplay.

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
Moonlight Embedded. Linux, OpenBSD, and NetBSD require the explicit
`moonlight-embedded` executable for that selection; FreeBSD and DragonFly also
accept the generic `moonlight` name because their package convention identifies
it as Embedded. Use the legacy `moonlight` selection only when a trusted
Embedded package deliberately installs its executable under that generic name.
Select `moonlight-qt` when a downstream Qt package uses the generic binary name.
On Linux, automatic discovery falls back to the trusted Flatpak launcher when
the native Moonlight candidates are unavailable. Set `client` to `flatpak` when
you want to pin that choice explicitly; LeagueBridge uses the fixed
`flatpak run com.moonlight_stream.Moonlight` prefix and does not execute a
shell. The client preflight honors this selection rather than accepting any
other installed Moonlight flavor: a Flatpak route requires both a
PATH-resolvable `flatpak` launcher and the installed
`com.moonlight_stream.Moonlight` app before pairing or listing can proceed.
The real-environment resolver repeats the app-presence check before constructing
an executable plan, so a launcher-only installation fails before handoff rather
than after Flatpak starts. On BSD, discovery skips Flatpak entirely and reports
the native package requirement instead.

### Host-free Linux/BSD client smoke

When no paired host is available, run the repository's host-free client smoke
helper first:

```sh
sh scripts/linux-bsd-client-smoke.sh ./leaguebridge ./client-evidence
```

It requires a regular executable LeagueBridge binary and a new evidence
directory. The helper records version, status, readiness, manifest, kernel,
and client-doctor output, then validates a `remote play` dry-run against the
reserved `example.invalid` name. The dry-run does not resolve or contact that
name; the helper never installs software, pairs a host, lists applications, or
starts a stream. It is therefore suitable for validating a Linux/BSD desktop
client before a physical Windows or macOS host is available.

The helper requires the platform, graphical-session, input, and Moonlight
client checks to pass. It writes `network=not-used` and
`gameplay=not-tested` deliberately: this smoke proves only local client
preflight and fixed League remote-plan construction, not Riot/Vanguard
authorization, streamed input, latency, or League gameplay. Use a new empty
evidence directory for every run; existing output files are never overwritten.

The latest route audit is recorded in
[`docs/research/2026-09-03-route-revalidation.md`](research/2026-09-03-route-revalidation.md).

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
physical host to advertise that application as well as the configured stream
application; it must match the configured application under the selected
Moonlight client's name-matching rules. Even without the fourth argument, the
helper always checks the configured application before recording a passing
remote-list check.

When the already-paired physical host is sleeping, pass its Wake-on-LAN MAC as
the fifth argument and optionally a bounded wait in seconds as the sixth
argument (15 by default, capped at 300). The optional seventh and eighth
arguments select a directed/unicast IPv4 destination and UDP port; they default
to `255.255.255.255` and `9`:

```sh
sh scripts/linux-bsd-remote-smoke.sh \
  ./leaguebridge ./remote-evidence "$HOME/.config/leaguebridge/config.json" \
  "League of Legends" 00:11:22:33:44:55 30
```

The helper sends one magic packet before `remote list`; it does not pair or
start League. The MAC is used only for that invocation and is not written to
the evidence directory. Use `""` as the fourth argument when wake support is
needed without requiring an exact application-name check. Wake-on-LAN only
wakes a physical host and does not establish Riot/Vanguard support. Include the
wait argument before a custom destination or port.

The helper requires the client preflight to pass, records the Linux/BSD client
readiness and kernel identity, exercises `remote list` on the configured
physical-host route, and records only a `remote play` dry-run plan using the
League shortcut's default quality profile. After reviewing the output, run
`leaguebridge remote play --acknowledge-unverified-handoff` yourself and
validate a local Practice Tool session on the physical host. The helper writes
`gameplay=not-tested` deliberately: a passing Linux/BSD client smoke cannot
prove Riot/Vanguard behavior, streamed input, latency, reconnects, or ordinary
match play.

If the paired host and client are ready and the goal is to start one real
interactive session, the repository also includes an explicit live-session
helper. `--start` is mandatory so a copied diagnostic command cannot launch a
stream accidentally. It validates the configuration, composes the fixed
1080p/60 FPS/H.264 stream plan, checks that the configured host advertises the
exact League application, and then starts the bounded League stream:

```sh
sh scripts/linux-bsd-remote-session.sh \
  ./leaguebridge "$HOME/.config/leaguebridge/config.json" --start
```

For a sleeping host, append the Wake-on-LAN values after `--start`, for
example `00:11:22:33:44:55 30`. The helper never installs or pairs software,
does not save session output, and returns Moonlight's exit status. A normal
exit is not gameplay evidence: verify Practice Tool keyboard/mouse input,
audio, reconnect behavior, and an ordinary match manually, and stop if Riot or
Vanguard reports an error. Use the direct `remote stream` command when a
different supported quality profile or client option is required.

The helper is shipped in portable Linux/BSD archives and installed under
`/usr/local/libexec/leaguebridge/`; native Debian/RPM packages use
`/usr/libexec/leaguebridge/`, while BSD packages use
`/usr/local/libexec/leaguebridge/`. Invoke it with the installed binary path
and the user's explicit configuration path.

The client doctor validates `DISPLAY` syntax and, when `WAYLAND_DISPLAY` can be
resolved through a safe `XDG_RUNTIME_DIR`, checks that the Wayland endpoint is
a Unix socket. A compositor-managed final link, such as WSLg's
`/run/user/1000/wayland-0`, may resolve to that socket for this display-only
check. A missing or stale Wayland socket blocks a live stream; X11 abstract
sockets and authentication still require runtime validation. This exception is
limited to environment-selected display endpoints: configuration, evidence,
device, and executable probes continue to reject final symlinks.

For an explicit Embedded `--platform` selection, live preflight checks that
backend's endpoint: X11/VDPAU and X11/VA-API require a valid `DISPLAY` and use
the display-backed X11 keyboard/mouse path; readable evdev access is required
only when `--input-device` explicitly adds a controller. SDL honors
`SDL_VIDEODRIVER`, and SDL KMS/DRM requires a real display device plus a
supported input endpoint. DragonFly's
SDL KMS/DRM path additionally requires an already-root process; LeagueBridge
does not elevate privileges. NetBSD's unsupported SDL KMS/DRM combination is
rejected before Moonlight starts, so a different available desktop session
cannot mask a bad backend selection.

Create a credential-free schema-v2 config for the intended host route, set the
host, and confirm `physical_host_confirmed` only when it truly is physical.
The default application is `League of Legends`; use `--app` or an exact custom
application name only when that entry is published by the host.

For an ad-hoc route switch, a Moonlight operation can be self-contained when
the command line supplies `--route`, `--host`, `--client`, and
`--confirm-physical-host`; a stream must also supply `--app`. In that case an
unrelated default configuration is not consulted. A named `--config` always
remains authoritative and its route must agree with `--route`:

```sh
leaguebridge remote stream --route macos --host gaming-mac.local \
  --client moonlight-qt --app "League of Legends" \
  --confirm-physical-host --acknowledge-unverified-handoff
```

```sh
# Choose one route. Record physicality only after checking the named machine.
# Windows host (the backward-compatible default)
leaguebridge config example --route windows
leaguebridge config init --route windows --host gaming-pc.local --confirm-physical-host

# Experimental, unvalidated macOS host
leaguebridge config example --route macos
leaguebridge config init --route macos --host gaming-mac.local --confirm-physical-host
```

The host field accepts DNS names, IPv4 literals, bare IPv6 literals, and
Moonlight endpoint forms `HOST:PORT` for DNS/IPv4 or `[IPv6]:PORT` for an
explicit non-default port. For example, use
`leaguebridge config init --host gaming-pc.local:47989` or
`leaguebridge config init --host '[2001:db8::10]:47989'`. Qt receives the
endpoint directly; Embedded receives the bare address plus its documented
separate `-port` argument. Quote bracketed endpoints in a POSIX shell. For a
link-local interface zone, URL-escape the zone delimiter inside the brackets,
for example `[fe80::10%25em0]:47989`; Embedded receives `fe80::10%em0`.

For a first pairing where the host-side flow requires a known four-digit code,
Moonlight Qt, Moonlight Embedded, and the official Qt-based Flatpak accept an
invocation-only predefined PIN:

```sh
leaguebridge remote pair --client moonlight-qt --host gaming-pc.local --pin 0427 --confirm-physical-host
```

The PIN must be exactly four ASCII digits and is forwarded to the selected
native client as `-pin`. It is never persisted or included in JSON dry-run
output; `--pin` is rejected for dry runs. The current Embedded parser accepts
the same action/options/host form even though the generated command reference
does not list it; see the [current Embedded parser](https://raw.githubusercontent.com/moonlight-stream/moonlight-embedded/master/src/config.c).
If omitted, the selected client uses its normal pairing flow. Treat the code
as short-lived pairing material and do not place it in evidence or support
records.

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

`--audio-on-host` keeps stream audio on the physical host. Embedded receives
its documented `-localaudio` flag, while Qt/Flatpak receives `-audio-on-host`.
This is useful when the host should retain local sound; it does not change the
client's own audio-device requirements.

With `--client moonlight-embedded`, `--audio-device` selects a bounded ALSA
output name such as `sysdefault` or `hw:0,0` and maps to Embedded's documented
`-audio` option. `--input-device` selects a documented evdev path such as
`/dev/input/event0` and maps to Embedded's `-input` option; repeat it to attach
multiple controllers, up to six devices (the current Moonlight Embedded input
limit). The paths are restricted to the
`/dev/input/eventN` family. Both are stream-only, Embedded-only device
selectors; leaving them unset preserves Moonlight's normal device discovery,
and neither option injects events or grants device permissions. A live stream
checks every explicit input path resolves to a character device and can be
opened read/write by the current user, using a nonblocking open before
Moonlight starts; dry runs only validate path shape. Moonlight Embedded opens
explicit evdev devices with read/write access. The same check applies to
`remote map`, whose upstream action performs an initial device setup before its
mapping read. On Linux this commonly
means granting the session access through the `input` group. BSD systems may
require their normal devfs/device permission rules. `--input-mapping` selects
an absolute local SDL gamecontroller database file and maps to Embedded's
documented `-mapping` option. The file
must already exist as a regular file on the Linux/BSD client, be no larger than
8 MiB, and is checked by LeagueBridge before a live stream starts. It is opened
by Moonlight; LeagueBridge does not execute, copy, or modify it. Dry runs only
validate the path shape. Current Moonlight Embedded also requires a readable
`gamecontrollerdb.txt` for a non-SDL stream. LeagueBridge checks Moonlight's
current-directory, home/config, and data-directory search paths before a live
Embedded launch and fails early with guidance if no mapping is available.
Install the Moonlight data package, pass `--input-mapping`, set
`SDL_GAMECONTROLLERCONFIG`, or select `--platform sdl`; Qt streams do not use
this Embedded mapping precondition. With no selectors, Moonlight still owns
its normal device discovery and mapping.

`--preserve-host-settings` asks the chosen client not to apply its game/settings
optimization path. It maps to Embedded's documented `-nosops` or Qt/Flatpak's
`-no-game-optimization` option. This can keep the physical host's League display
configuration stable, but it is only a client hint and is not gameplay evidence.
The optional `--quit-after` control asks Moonlight to request that the host
application stop when the streaming session ends. It maps to Embedded's
`-quitappafter` and Qt/Flatpak's `-quit-after` forms. This is useful after a
dropped session, but remains an opt-in cleanup hint and does not prove that the
host accepted the request.
When a transient network interruption makes Moonlight exit, the controller can
make bounded recovery attempts with `--reconnect-attempts N` and
`--reconnect-delay SECONDS`. `N` is the number of additional attempts and is
limited to five; the delay is context-aware and limited to 0–60 seconds. The
application-list guard runs before the first attempt and again before every
retry. Every attempt reuses the same discovered executable and fixed host/app
argument vector, and cancellation never retries. A retry may cause the
physical host to launch the application again, so this is a recovery aid only;
it does not preserve game state or prove that input, Riot/Vanguard behavior, or
ordinary gameplay survived a disconnect.
`--network-mode` accepts `auto`, `lan`, or `wan` and is supported only by
Moonlight Embedded. LeagueBridge maps these values to Embedded's documented
`-remote auto`, `-remote no`, and `-remote yes` forms. Use `lan` for a local
network or `wan` across a routed path; this is a transport hint, not proof of
latency, packet delivery, or League gameplay.
The optional `--frame-pacing auto|on|off` and `--keep-awake` controls are
supported only by Moonlight Qt/Flatpak. They map to Qt's `-frame-pacing`,
`-no-frame-pacing`, and `-keep-awake` toggles; the latter prevents the Linux/BSD
display from sleeping during a stream. These are session-stability hints, not
evidence of frame delivery, input, or League gameplay.
The optional `--vsync auto|on|off` control is also Qt/Flatpak-only and maps
non-`auto` values to Qt's `-vsync` or `-no-vsync` toggle. It can reduce local
display tearing, but the correct setting depends on the Linux/BSD compositor
and display refresh rate; it does not prove remote frame delivery.
The optional `--capture-system-keys auto|never|fullscreen|always` control is
also Qt/Flatpak-only. Non-`auto` values map to Qt's documented
`-capture-system-keys` mode. `always` can help deliver League modifier-key
shortcuts, but it can capture local window-management shortcuts too; it is an
input hint, not evidence that the physical host receives keyboard events.

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

Qt and Flatpak also expose bounded controls for `--multi-controller`,
`--background-gamepad`, `--mouse-buttons-swap`, `--touchscreen-trackpad`,
`--reverse-scroll-direction`, `--swap-gamepad-buttons`,
`--mute-on-focus-loss`, `--performance-overlay`, `--hdr`, and `--yuv444`.
They map to Moonlight Qt's documented toggles for multiple controllers,
background gamepad delivery, common mouse/controller mappings, diagnostics,
and optional display formats. Embedded instead exposes
`--disable-gamepad-mouse-emulation`, mapped to `-nomouseemulation`, to stop a
gamepad from unexpectedly emulating a local mouse. These are client controls,
not injected input or an anti-cheat workaround; unsupported flavor combinations
are rejected before execution.

Moonlight Embedded also accepts
`--platform auto|x11|x11_vdpau|x11_vaapi|sdl`. LeagueBridge maps non-`auto`
values to Embedded's documented `-platform` option, selecting the local audio,
video, and input backend. `auto` keeps the package default; `x11_vaapi` can
select Embedded's current X11/VA-API backend when the installed package was
built with VA-API support, and `sdl` can be useful when a Linux/BSD package
provides SDL for the desktop backend. This remains a selection hint:
LeagueBridge does not claim that the backend was compiled in or that it can
decode video or deliver gameplay input.
Qt and Flatpak reject this Embedded-only option rather than silently ignoring
it.

The example above intentionally uses only options shared by Qt and Embedded,
so it works with the default flavor on every supported Linux/BSD target. Add
`--platform` automatically narrows `--client auto` to Moonlight Embedded, and
`--qt-platform` automatically narrows it to Moonlight Qt. The same narrowing
applies to options that belong to only one flavor: Embedded-only controls
select Embedded, while Qt/Flatpak-only controls select a Qt surface (including
the official Linux Flatpak when no native Qt executable is available). `--hdr` is supported
by both current native surfaces and does not force a client flavor. Mixed
backend-specific options are rejected before discovery. Explicitly selecting
an incompatible client is also rejected, and the two backend selectors cannot
be combined. You may explicitly add `--client moonlight-embedded` (or the
`moonlight` alias on BSD) before using `--platform`, or select
`--client moonlight-qt`/`--client flatpak` to force the Qt route. Clients reject
unsupported controls rather than silently ignoring them.

For a live stream with `--client auto`, if the preferred local native Moonlight
choice fails the display/input preflight, LeagueBridge retries the other
installed native choices in its fixed order: Qt, Embedded, generic Moonlight,
then the official Flatpak on Linux. Flatpak is never considered on BSD. A
candidate is selected only after it passes local preflight and passive
discovery. If that selected client then fails the host application-list
preflight at the process/transport boundary, one additional bounded recovery
pass can select another installed native client before any stream process is
started. A successful list that does not advertise the requested application
is not retried, and an explicitly selected client is never replaced. This
recovery stays within native Moonlight clients; it never falls through to
Wine, Proton, a VM, or another compatibility-layer route. Dry-run remains a
plan check and does not probe alternate live endpoints. When a stream option
narrows automatic selection to one flavor, recovery remains constrained to that
flavor; Qt includes the official Linux Flatpak. The fallback improves client
selection but does not prove decoder behavior, remote input, or League/Vanguard
gameplay. If a bounded reconnect is requested and its repeated application-list
guard fails, the same single fallback may run before the next stream attempt.

When automatic recovery considers a generic `moonlight` executable, it applies
the same package convention as the initial `auto` resolver: Qt on Linux,
OpenBSD, and NetBSD, and Embedded on FreeBSD and DragonFly. The explicit legacy
`--client moonlight` alias remains an Embedded selection.

For `remote list --client auto`, the same bounded recovery applies to a failed
application-list process or transport operation. LeagueBridge retries with one
other supported client after excluding the failed executable, using only the
control-plane readiness gate. A successful listing that does not advertise a
required application still fails closed without switching clients, and an
explicit client selection is never replaced. This protects control-plane
discovery only; it does not make a Moonlight client a Riot-supported
Linux/BSD League runtime.

`remote pair --client auto` and `remote quit --client auto` also receive one
bounded recovery attempt when the preferred native client fails control
preflight or its process/transport operation. The failed executable is
excluded before the alternate client is passively discovered, cancellation
never starts a fallback, and explicit client choices are never replaced.
`remote unpair --client auto` remains Embedded-only and resolves directly to
Moonlight Embedded rather than trying Qt.

Moonlight Qt also exposes `--absolute-mouse` and `--no-absolute-mouse` for its
remote-desktop optimized mouse mode. LeagueBridge explicitly selects relative
pointer capture (`-no-absolute-mouse`) for Qt and Flatpak stream plans by
default, because that is the mode required for the documented physical-host
Raw Input experiment. `remote stream --absolute-mouse` opts into absolute mode,
while `remote stream --no-absolute-mouse` makes the default explicit. Embedded
clients reject both Qt-only controls. Treat this only as an input-mode choice:
it does not fix Riot/Vanguard compatibility or turn a remote handoff into local
Linux/BSD support. The option names are based on [Moonlight Qt's current
stream parser](https://raw.githubusercontent.com/moonlight-stream/moonlight-qt/master/app/cli/commandlineparser.cpp).

`--hdr` is the exception to the client-specific control split: current
Moonlight Embedded accepts `-hdr`, and Qt/Flatpak accept Qt's `-hdr`. The
request selects the stream format only; actual HDR output still depends on the
host codec, client decoder, display, and graphics driver. LeagueBridge does not
claim that HDR or any other stream option proves League/Vanguard gameplay. Do
not combine `--hdr` with `--codec h264`; LeagueBridge rejects that combination
because HDR requires a 10-bit HEVC or AV1-capable negotiation. Leave the codec
on `auto` or choose `hevc`/`av1` only when the host and Linux/BSD display stack
support it.

Known limitation: Riot's [open Moonlight/Sunshine mouse issue](https://github.com/RiotVanguard/Vanguard/issues/70)
still reports cursor-control failure after League starts. The Qt toggle cannot
repair Vanguard's host-side input filtering. If the physical host does not
accept input, stop the session or use input physically attached to that host;
do not use USB/IP, injected input, kernel interception, or another claimed
anti-cheat bypass.

If Linux/BSD must remain the active client while the physical host supplies the
League display and input, the separately managed hardware-KVM candidate is
described in [`HARDWARE_KVM.md`](HARDWARE_KVM.md). It requires HDMI capture and
USB HID hardware attached to the physical host, remains unvalidated, and is not
an authorized gameplay backend; the manifest records it as a deny/handoff-only
candidate until device-specific evidence exists.

LeagueBridge can open the KVM's web UI through an allowlisted desktop URL
opener or direct browser. This is a convenience launcher, not a KVM protocol
implementation:

```sh
leaguebridge remote kvm --url https://kvm.lan/ \
  --confirm-physical-host --acknowledge-unverified-handoff
```

For a KVM attached to a physical Mac, select the Mac handoff contract:

```sh
leaguebridge remote kvm --route macos --url https://kvm.lan/ \
  --confirm-physical-host --acknowledge-unverified-handoff
```

The endpoint can instead be stored without credentials in the normal
configuration:

```sh
leaguebridge config init --host gaming-pc.local \
  --kvm-url https://kvm.lan/ --confirm-physical-host
leaguebridge remote kvm --config ~/.config/leaguebridge/config.json \
  --acknowledge-unverified-handoff
```

`remote kvm --config` may reuse the stored endpoint and physical-host
confirmation, but the unverified-handoff acknowledgement is never persisted
and must be supplied for each operation. A direct `--url` or
`--confirm-physical-host=false` overrides the corresponding configured value.
The KVM route defaults to the configuration's `route_id`, then Windows. An
explicit `--route windows|macos` must agree with a supplied configuration and
selects which fresh physical-host handoff contract is checked.

### Optional Wake-on-LAN bootstrap

When the physical host's firmware, NIC, and LAN support Wake-on-LAN, the
Linux/BSD client can wake it before the normal Moonlight handoff:

```sh
leaguebridge remote wake --config ~/.config/leaguebridge/config.json \
  --mac 00:11:22:33:44:55 \
  --confirm-physical-host --acknowledge-unverified-handoff
leaguebridge remote pair
leaguebridge remote stream --acknowledge-unverified-handoff
```

The two steps can be combined when the host is already paired. `remote stream`
will send the packet once, wait for the bounded `--wake-wait` interval, and only
then run its normal host-application preflight. If the physical host or
Sunshine is still starting, the preflight can make up to three additional list
attempts by default, waiting five seconds between attempts:

```sh
leaguebridge remote stream --acknowledge-unverified-handoff \
  --wake-mac 00:11:22:33:44:55 --wake-wait 30
```

Tune that bounded startup recovery with `--wake-retries 0-5` and
`--wake-retry-delay 0-60`. The retry window applies to `remote list` and the
initial application-list preflight for `remote stream`; it retries only a
failed Moonlight list operation. A successful listing that does not advertise
the requested application fails closed without another attempt, and pairing
remains one normal Moonlight operation after the wake wait:

```sh
leaguebridge remote stream --acknowledge-unverified-handoff \
  --wake-mac 00:11:22:33:44:55 --wake-wait 15 \
  --wake-retries 5 --wake-retry-delay 10
```

For an initial Moonlight pairing after the physical host has powered off, use
the same opt-in bootstrap with `remote pair`:

```sh
leaguebridge remote pair --acknowledge-unverified-handoff \
  --wake-mac 00:11:22:33:44:55 --wake-wait 30
```

The packet is sent once and the normal pairing operation starts only after the
bounded wait. Physical-host confirmation still comes from the route
configuration or `--confirm-physical-host`; the unverified-handoff
acknowledgement is required for this combined operation. The MAC is
invocation-only. `--dry-run --json` includes both normalized plans without
network or Moonlight I/O.

The same flags can be used with `remote list` to wake the physical host before
checking its published applications:

```sh
leaguebridge remote list --acknowledge-unverified-handoff \
  --wake-mac 00:11:22:33:44:55 --wake-wait 30
```

Use `--wake-broadcast` and `--wake-port` with `--wake-mac` when the local
network needs a directed broadcast, unicast destination, or non-default UDP
port. The wait defaults to 15 seconds and is limited to 300 seconds. It is
performed only before the first host preflight; stream reconnect attempts do
not repeatedly wake the machine. The default three additional list attempts
and five-second retry delay are independently bounded; set
`--wake-retries 0` to disable startup list recovery. `--dry-run --json`
includes the normalized Wake-on-LAN and retry plans and never sends a packet.

The command sends one standard 102-byte magic packet to the default IPv4
limited broadcast `255.255.255.255:9`. Use `--broadcast` for a directed
broadcast or unicast destination and `--port` for a different UDP port. The
MAC is invocation-only; LeagueBridge does not store credentials or host wake
secrets. `--dry-run --json` validates the normalized MAC, destination, port,
and handoff contract without sending a packet.

Wake-on-LAN only powers or wakes the physical host. It does not start League,
authenticate to Riot, inspect Vanguard, establish gameplay evidence, or make
a Windows VM acceptable. Wait for the physical host to boot, then use the
normal pair/list/stream or hardware-KVM procedure.

The endpoint must be a clean HTTPS URL with no embedded credentials, query
parameters, or fragments. `--allow-http` is required for an unencrypted HTTP
bootstrap and should be limited to a trusted LAN. `--browser auto` selects the
first available `xdg-open`, `gio`, `sensible-browser`, or allowlisted direct
browser; an explicit launcher such as `--browser firefox` can be selected when
needed. `--dry-run --json` prints the fixed argument vector without opening
anything. LeagueBridge does not authenticate to or validate the KVM device,
and this command does not change the hardware-KVM
candidate's unvalidated status or readiness score.

[Configuration schema v2](../schemas/config.schema.json) stores one exact
`route_id` and one `remote_host`; it has no parallel Windows/macOS target
fields. Existing schema-v1 Windows configs are accepted strictly and normalized
in memory, while newly written configs always use v2. The Go runtime remains the
security authority for duplicate keys, byte limits, host syntax, and safe file
handling.

```sh
leaguebridge remote map --client moonlight-embedded --input-device /dev/input/event4
leaguebridge remote pair
leaguebridge remote list
leaguebridge remote stream --acknowledge-unverified-handoff
```

`remote map` is a local Linux/BSD controller-setup action for Moonlight
Embedded. It forwards the documented `map -input /dev/input/eventN` form, so
Moonlight reads one local evdev device and prints an SDL mapping; it does not
pair, contact, or start League on the physical host. Save the printed mapping
as a user-owned SDL gamecontroller database file and pass its absolute path to
`remote stream --input-mapping` later. The live action requires the selected
path to resolve to a character device with read/write access; `--dry-run --json` is available for
inspecting the fixed argv without opening the device. Qt and Flatpak do not
expose this Embedded action, and no input injection, permissions change, or
anti-cheat workaround is performed.
If `--client auto` is supplied, it resolves to Moonlight Embedded because Qt
does not expose this local mapping action; an explicitly selected incompatible
client is rejected.

If an Embedded client has a stale local pairing, remove that host record and
pair again:

```sh
leaguebridge remote unpair --client moonlight-embedded
leaguebridge remote pair --client moonlight-embedded
```

`remote unpair` forwards Embedded's documented `unpair HOST` operation. When
`--client auto` is used, LeagueBridge selects the Embedded surface before
preflight and discovery; an explicitly selected incompatible client is
rejected. The operation is not available through Moonlight Qt or the official
Flatpak, and it does not modify the physical host or uninstall any software.

If a previous host application is left running after a dropped session, use
the bounded recovery operation:

```sh
leaguebridge remote quit
```

This forwards Moonlight's `quit HOST` operation to the already-paired physical
host. It does not kill a local Linux/BSD process, handle credentials, or alter
Riot/Vanguard state.

To verify the host has published the exact application before starting a
stream, add the bounded expectation to the live list operation:

```sh
leaguebridge remote list --require-app "League of Legends"
```

The listing is still forwarded to the terminal; the check only looks for the
validated application name in Moonlight's text response. Qt treats application
names case-insensitively, matching its CLI launch behavior, while Embedded
keeps its exact-name lookup. It is a configuration guard, not proof that League
or Vanguard will accept streamed input.

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

After pairing, the League-oriented shortcut runs the same guarded physical-host
and exact-application preflight while applying a predictable 1080p/60 FPS/H.264
profile (20,000 Kbps and a 1392-byte packet size). Explicit quality flags
override the corresponding defaults:

```sh
leaguebridge remote play --acknowledge-unverified-handoff
```

The shortcut remains a remote handoff, not a local Linux/BSD League client. It
still requires physical-host confirmation and the explicit unverified-handoff
acknowledgement.

`--require-app "League of Legends"` and `--require-configured-app` remain
available for explicit intent, but do not disable or weaken the automatic
stream check. The check is live and cannot be used with `--dry-run`. This
remains a physical-host handoff and does not validate streamed input, latency,
or Riot/Vanguard gameplay behavior.

`remote pair`, `remote unpair`, `remote list`, and `remote quit` are finite control-plane
operations and have a 60-second execution deadline. `remote map` remains attached
to the caller because Moonlight may wait for controller input. `remote stream --dry-run` uses only those
control-plane prerequisites, so its fixed argv can be inspected from a
headless SSH session without contacting the host or starting Moonlight. A live
`remote stream` additionally requires an X11 or Wayland endpoint, or an
explicitly selected direct SDL/Qt backend with its device node, plus an
input-path indicator. X11/VDPAU/VA-API use the display-backed X11
keyboard/mouse path; an explicit Embedded `--input-device` still requires its
own readable evdev node. For direct SDL KMS/DRM use, set
`SDL_VIDEODRIVER=kmsdrm`; for a Qt direct-display setup, set the appropriate
`QT_QPA_PLATFORM` value such as `eglfs` or `linuxfb`, or pass
`--qt-platform auto|xcb|wayland|eglfs|linuxfb` to select the bounded value
and apply it only to the Moonlight child. For the official Flatpak, a concrete
value is placed before the app ID as
`flatpak run --env=QT_QPA_PLATFORM=VALUE com.moonlight_stream.Moonlight ...`,
so the sandbox receives the explicit selector rather than relying only on
inherited environment state. `auto` preserves the inherited environment, but
when Qt is selected the client preflight also inspects `QT_QPA_PLATFORM` so a
known headless or unsupported ambient backend cannot pass the live-stream
gate. The other values likewise select the matching desktop endpoint and
prevent a stale alternate display variable from winning. Qt's `linuxfb`
preflight recognizes both `/dev/fb0` and the plugin's `/dev/graphics/fb0`
fallback path and requires read/write access because Qt opens and maps the
framebuffer for live output.
Embedded's SDL backend discovers controllers and owns its audio path, so
`--platform sdl` cannot be combined with `--input-device` (including repeated
uses) or `--audio-device`; choose an X11/VA-API/VDPAU backend when a specific
device must be selected. LeagueBridge rejects those combinations before
Moonlight starts.
A headless live stream is
intentionally blocked. These checks are only local endpoint indicators and do
not prove input delivery or gameplay. The stream keeps the caller's lifetime
and ends when Moonlight exits or the caller sends its normal interrupt/cancel
signal.

On BSD, current SDL documentation describes KMSDRM as supported on FreeBSD and
OpenBSD, usable on DragonFly BSD only as root, and unsupported on NetBSD.
LeagueBridge consequently fails closed for a non-root DragonFly process using
`SDL_VIDEODRIVER=kmsdrm` and for NetBSD when it is asked to use that backend;
use X11 or Wayland there. OpenBSD's direct
video endpoint is normally `/dev/drm*`; other supported KMSDRM targets commonly
expose `/dev/dri/card*`. On OpenBSD, SDL's WSCONS input backend uses
`/dev/wskbd*` and `/dev/wsmouse`, and LeagueBridge recognizes those devices for
direct SDL preflight when the session can access them. FreeBSD and DragonFly
use their SDL evdev input path, so the preflight checks character devices under
`/dev/input/event*` there and, on a real system, performs a nonblocking
read/write-permission open to verify session access; the probe never writes to
the device. Regular files and directories at
those paths or at the DRM/framebuffer paths are rejected.
See [SDL's KMSDRM/*BSD notes](https://github.com/libsdl-org/SDL/blob/main/docs/README-kmsbsd.md).

Stop immediately if Riot Client, Vanguard (on Windows), or other Riot software
reports an error. Do not try to hide the streaming software, patch input, or
work around an anti-cheat control. Validate first with a non-valuable account
and Practice Tool/custom game; public matchmaking remains a manual user
decision.
