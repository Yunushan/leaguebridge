# Route revalidation — 2026-08-29

This follow-up rechecks the plausible Linux/BSD execution routes against
current primary documentation. It does not treat a client launch, a copied
file, or a community workaround as Riot authorization or gameplay evidence.

The current Riot system-requirements page lists retail Windows 10 version
19041 or newer and Windows 11 for the native x64 client. The pinned Sunshine
v2026.516.143833 documentation lists Windows 11+ for its host, so the
LeagueBridge Windows remote route uses the intersection and retains a Windows
11 baseline. The optional Vanguard Pre-Check's separate Windows 11 25H2
security requirements remain advisory; a registry check does not prove League,
Vanguard, GPU, or gameplay readiness.

The same first-party Riot support page explicitly states that League is
supported only on Windows and macOS and that Riot cannot provide support for
Linux, SteamOS, Bazzite, or other operating systems. That current product
support boundary is independent of the older Vanguard implementation details:
it is sufficient to keep Linux/BSD native gameplay unpromoted until Riot
publishes or authorizes a different client and anti-cheat path.

## 2026-08-30 source addendum

A fresh check of Riot's current Player Support requirements page still lists
League support only for Windows and macOS. Riot's Patch 25.S1.2 notes also
confirm that Mac anti-cheat was rolled out through Embedded Vanguard, without
an additional driver installation. This makes a physical Mac a legitimate
external host candidate for the optional remote handoff, but it does not make
Darling, a macOS virtual machine, Wine, Proton, or any other Linux/BSD user
space an authorized League runtime.

The current Riot Vanguard explanation continues to distinguish the Windows
boot/kernel trust boundary from Linux: Riot says Linux has never been
officially supported, that the Lutris/Wine implementation cannot satisfy the
Vanguard driver requirements, and that emulation creates an environment the
anti-cheat cannot reliably attest. The implementation and scorecard therefore
remain unchanged: native Linux/BSD gameplay is blocked, while physical
Windows or macOS hosts are external handoff routes only.

## 2026-08-31 official support recheck

Riot's current Player Support requirements article was rechecked on 31 August
2026. It still describes League support for Windows and macOS only and
explicitly excludes Linux, SteamOS, Bazzite, and other operating systems from
Riot support. The article also continues to describe native macOS support as a
separate platform requirement; it does not authorize a Linux compatibility
layer to run the Mac client.

Riot's Vanguard material was checked alongside that article. The Linux FAQ
still says the Lutris/Wine implementation cannot satisfy Vanguard's driver
requirements, while the current Vanguard On-Demand article describes added
Windows security prerequisites rather than a Linux, BSD, Wine, Proton, or VM
exception. No authoritative change therefore supports installing copied DLLs,
drivers, an anti-cheat package, or a virtualized Windows guest. LeagueBridge
continues to keep native Linux/BSD gameplay denied and the physical-host
Moonlight path explicitly external and unvalidated.

| Route | Current primary-source finding | LeagueBridge decision |
| --- | --- | --- |
| Wine, WineHQ, Lutris, or another Wine frontend | Riot says Linux has never been officially supported and that the current Lutris/Wine implementation cannot satisfy Vanguard's driver requirements. | Keep local Linux/BSD gameplay denied. |
| Community `wine-lol` / `kyechou/leagueoflegends` wrapper | Its upstream repository is archived and explicitly says Vanguard prevents the Wine route; it also warns that Linux play is unsupported and records ban reports. | Do not integrate or recommend this wrapper as a production path. |
| Experimental `nicolasdesenv/valorant-linux-compatibility` research | Its repository is a VALORANT investigation, not a League implementation or a claim that the game currently works on Linux; it explicitly stops at the Vanguard trust and kernel boundary. | Do not import its patches or treat Vanguard research as League support or Riot authorization. |
| Darling macOS compatibility layer | Darling's current upstream says GUI support is still in active development, while its known-nonfunctional-software documentation says complex GUI applications generally do not work. Its League issue remains open with no implementation or linked development work. Even a working macOS user-space layer would not be a physical Mac or a Riot-authorized Linux client. | Do not integrate Darling as a local League route; keep local Linux/BSD gameplay blocked and the physical-Mac handoff separate. |
| Proton or a Proton-capable launcher | Valve documents Proton anti-cheat support as publisher-configured and says kernel-space anti-cheat solutions are not currently supported or recommended. Riot has not published a League/Vanguard Proton authorization. | Do not add a Proton backend or anti-cheat workaround. |
| `dockur/windows`, QEMU/KVM, bhyve, or another VM | Dockur documents Windows running inside a Docker/KVM-backed virtual machine. Riot's Vanguard guidance treats virtual-device launches as an error route and does not turn a guest into an approved physical host. | Do not use a VM as the remote host or conceal its virtualization state. |
| WinBoat | Its upstream describes Windows as a VM inside a Docker/Podman container and requires KVM; its own issue tracker also records requests to hide virtualization from anti-cheat. | Treat WinBoat as the same non-certifying VM route; do not integrate virtualization concealment. |
| Vanguard On-Demand | Riot's June 2026 update describes an optional Vanguard Pre-Check for Windows hosts. Pre-Check requires at least Windows 11 25H2, UEFI/Secure Boot, TPM 2.0, VBS/HVCI, and IOMMU. It adds no Linux/BSD, Wine, Proton, or VM exception. | Treat it as a Windows-host attestation option, not a Linux/BSD runtime. |
| Public `RiotVanguard/Vanguard` source repository | Its page claims to provide Vanguard source, but the checked `main.c` is a Windows WDK kernel driver (`ntddk.h`) that looks up an existing `vgk.sys` export; the README also describes an unprotected, administrator-installed binary. It provides no Linux/BSD port, League authorization, or publisher-signed runtime. | Do not download, build, install, redistribute, or adapt this kernel artifact; it is not a Linux/BSD League path. |
| Copied DLLs, drivers, or anti-cheat packages | A copied proprietary component cannot reproduce the Windows boot, kernel, signing, and publisher trust boundary, and would not grant Riot authorization. | Never gather, redistribute, patch, inject, or hide Riot/Vanguard components. |

## Cloud-provider audit

Consumer cloud gaming was checked as a possible "something else" route. It
does not change the decision above:

| Provider class | Current primary-source finding | LeagueBridge decision |
| --- | --- | --- |
| NVIDIA GeForce NOW | NVIDIA's current pages document a native Linux client and its general games catalog still displays League, but NVIDIA's League-specific support answer still says League is unavailable because Vanguard does not support GeForce NOW virtual machines. The catalog and generic Linux-client pages do not state that this League-specific restriction was lifted. | Keep GeForce NOW denied for League. Do not advertise or automate it as a League route until NVIDIA publishes a current League-specific restoration statement and a real session is independently validated. |
| Shadow PC | Shadow's current incompatibility list says League cannot be played on Shadow because Riot Vanguard is incompatible with its virtual machines. | Reject Shadow and equivalent hosted VM services for certification. |
| Other hosted cloud PCs | This audit found no provider documentation granting a Riot/Vanguard exception or proving a physical, non-VM host. Marketing claims about device coverage are not gameplay authorization. | Require provider-specific primary evidence and Riot authorization before considering integration. |

Cloud clients can still be useful as ordinary viewers, but the hosted machine
must satisfy Riot's own runtime requirements. A browser, Linux client, or
streaming protocol does not change the anti-cheat boundary.

## 2026-08-31 cloud-status addendum

The current NVIDIA documentation is an important distinction: the GeForce NOW
download and system-requirements pages now describe a native Linux client, and
the general supported-games catalog still displays League. However, NVIDIA's
League-specific support answer remains explicit that League is unavailable on
GeForce NOW because Vanguard does not support its virtual machines. The current
release-highlights page documents Linux-client improvements and references
League in historical product notes, but it does not state that the League
restriction was lifted. This unresolved source conflict is not sufficient to
create a launch authorization or a reproducible Linux/BSD gameplay route, so
LeagueBridge keeps the provider-specific route blocked rather than guessing
from a generic catalog entry.

The current Linux client is also narrower than the project target: NVIDIA's
published requirements name Ubuntu 24.04 LTS, not FreeBSD, OpenBSD, NetBSD, or
DragonFly BSD. A browser or Linux cloud client therefore cannot be treated as
BSD support, and it cannot promote the separate native Linux/BSD hard gate.

## 2026-08-30 upstream runtime addendum

The current upstream scan also covered the Linux Wine runtimes that could
otherwise look like a new League path. GloriousEggroll's `wine-ge-custom`
repository is archived and its release index only exposes the old
`Wine-GE-Proton8-*-LoL` line; its README describes a general Wine/Lutris build
system, not a current Riot-approved League/Vanguard runtime. Open-Wine-Components'
`umu` is an active unified launcher for Windows games on Linux, and its
database supplies Proton fixes for launchers; neither project claims that
Riot has authorized League/Vanguard on Linux. A launcher, runtime container,
DLL override, or Proton fix cannot satisfy the missing Vanguard trust boundary.

The public `RiotVanguard/Vanguard` Linux issue remains an unassigned user
request with no linked implementation, branch, or pull request. It is useful
as a signal that the Linux support request remains unresolved, but it is not
an authorization or a reproducible runtime result. LeagueBridge therefore
does not add `umu`, Wine-GE, copied DLLs, or an issue-derived workaround to
the product route matrix.

The live public issue index rechecked on 2026-08-30 still lists the Linux
request (`#84`) as open, with no assignee or linked development work. The
newer open issues shown in that index concern Windows Vanguard driver behavior
(`#85` and `#86`), not a Linux client or a Linux/BSD authorization. No upstream
change therefore justifies promoting a native Linux/BSD route or adding a
Windows/macOS LeagueBridge product target.

The same index still contains Vanguard issue `#70`, an open report that the
mouse stops controlling the cursor after League starts through Moonlight/Sunshine
streaming. It has no assignee or linked development work. Sunshine's current
documentation now also describes a vendor-provided, driver-backed Raw Input
keyboard and relative-mouse path on Windows, requiring Virtual HID Driver
`2026.829.2338.54` or newer and an active license. That is a new experimental
host-side candidate worth testing,
but the Sunshine documentation is not Riot authorization and does not prove
that Vanguard accepts the device. Absolute positioning still uses Windows input
injection, so LeagueBridge must keep its remote-client preference in relative
pointer mode for this experiment. LeagueBridge must not add input interception,
driver injection, or an anti-cheat bypass; until Riot and the streaming stack
resolve this on a real host, remote gameplay remains unvalidated rather than a
guaranteed path.

The scan also checked the public `RiotVanguard/Vanguard` repository because its
name and README present it as Vanguard source. Its checked source is a
Windows-only WDK driver: `main.c` includes `ntddk.h`, references the Windows
kernel device namespace, and invokes an export from an already-installed
`vgk.sys`. The repository's own instructions describe an unprotected binary
installed as administrator. Even if the repository's claim were genuine, this
is not a Linux/BSD implementation or a Riot-authorized League distribution;
LeagueBridge does not fetch, compile, install, or adapt it.

## Local route inventory

On 2026-08-29, a read-only inventory of the current development host found the
Windows/AMD64 `wsl` and Docker launchers but no `wine`, `wine64`, `proton`,
`lutris`, `flatpak`, or QEMU launcher. A later host-permission recheck confirmed
that Debian and Ubuntu WSL2 distributions are installed and start as `x86_64`
Linux guests. The guests have no Go, Wine, Proton, Lutris, Flatpak, or
Linux-side QEMU installation, and the Docker check reported that Docker
integration is unavailable; the Windows Docker service is also stopped. A
current Linux amd64 LeagueBridge binary was cross-built with the pinned Go
toolchain and executed inside both guests: status and compatibility-doctor
commands completed in Ubuntu, while Debian also completed schema-v1 JSON
readiness. Both reports kept local gameplay blocked and found no authorized
Vanguard path. The WSL2 guests remain virtualized and therefore cannot serve as
Riot-approved physical gameplay hardware. This is host-specific evidence, not a
claim about every Linux/BSD installation; no League, Vanguard, Wine, Proton,
VM, or Docker workaround was installed or launched.

The Windows-host doctor run on the same date reported the native Windows
platform/version and a DirectX registration, plus a local Riot Client
executable. League itself was absent; the Vanguard installer was present but
the required services were not detected; and Sunshine was absent. Physicality,
hardware capability, active security state, signatures, and gameplay remain
unverified. This is preflight evidence only: no Riot or Sunshine installation,
repair, or launch was performed.

A fresh host-side recheck on 2026-08-30 could not enumerate the existing WSL
distributions (`Wsl/EnumerateDistros/Service/E_ACCESSDENIED`), so this pass
obtained no new Linux guest runtime evidence. That permission result does not
invalidate the earlier guest observations, but neither result establishes
physical Linux hardware or a Riot-authorized League/Vanguard runtime.

An elevated recheck later on 2026-08-30 started the installed Ubuntu WSL2
guest and executed a freshly cross-built, CGO-disabled Linux amd64
LeagueBridge binary. The binary's `version` command and both compatibility and
client doctor profiles completed; the compatibility profile found no
authorized Linux/BSD Vanguard integration, and the client profile found a
graphical/audio environment but no Moonlight executable. The repository's
Linux runtime smoke also passed for version, status, readiness, manifest
verification, and the expected blocked client preflight. Finally,
`scripts/verify-install.sh` passed its temporary-DESTDIR Linux lifecycle
smoke, including install, upgrade, command execution, symlink safety, and
exact uninstall, against the existing Linux release archive. These results
prove the LeagueBridge Linux binary and installer boundary, not League
gameplay: Ubuntu WSL2 is virtualized, no League or Vanguard was installed or
started, and no physical Linux/BSD or Riot-authorized session was available.

The same 2026-08-30 upstream recheck covered Darling's current project state.
Darling's repository documents an active AppKit/Metal development effort, but
the project's own known-nonfunctional-software page still says that complex
GUI applications generally do not work. The upstream League-of-Legends issue
is still open and has no implementation or linked development work. This does
not provide a route to the native Mac client: it is a Linux user-space
compatibility layer, not a physical macOS host, and it cannot supply Riot's
vendor authorization or a validated League session.

## Supported project boundary

The only implementable route remains an explicitly acknowledged Moonlight
handoff from Linux/BSD to a separately managed physical Windows host running
Riot's unmodified client and Vanguard. The physical macOS handoff remains
experimental and unvalidated. LeagueBridge continues to probe alternatives
read-only, fail closed, and avoid installing or launching them.

## Moonlight handoff command revalidation

The handoff implementation was checked against the current upstream command
parsers rather than relying on historical examples. Moonlight Embedded documents
`pair`, `list`, and `stream` actions, with streaming options such as `-720`,
`-1080`, `-4k`, `-width`, `-height`, `-fps`, `-bitrate`, and `-app`; its app
positional value follows the action options. Moonlight Qt's current parser
documents the same four fixed resolutions, accepts `-fps` and `-bitrate`, and
requires the stream positional order `stream HOST APP`. Its current CLI also
supports `pair HOST` and `list HOST`. The implementation keeps those forms
client-specific, rejects arbitrary flags, and uses the fixed
`flatpak run com.moonlight_stream.Moonlight` prefix when the official Flatpak
launcher is selected.

The current FreeBSD and DragonFly package recipes install the Qt executable as
`moonlight-qt`, so the resolver prefers that name on both platforms and treats
a generic `moonlight` name as Embedded there. Other supported BSD package
recipes may expose a Qt client under a generic name; an explicit
`--client moonlight-qt` selection is allowed to use that fallback only where
the platform convention does not reserve the generic name for Embedded. Embedded
can also be selected explicitly as `--client moonlight-embedded`; the resolver
accepts either that flavor-specific executable name or the generic `moonlight`
name. These are launcher and argument-compatibility checks only: they do not
prove decoder, input, latency, Sunshine, Vanguard, or League gameplay behavior.

The 2026-08-30 parser recheck also confirms the clients' MTU-sensitive packet
controls: Embedded uses `-packetsize` and requires a packet size below the path
MTU and aligned to a multiple of 16, while Qt uses `-packet-size` and accepts
values above its 1024-byte minimum. LeagueBridge exposes one bounded
`--packet-size` input, requiring 1024–9000 bytes and a multiple of 16 before it
is translated to the selected client. This is a network tuning control, not
evidence of decoder compatibility or League gameplay.

The 2026-08-30 parser recheck also confirms that Moonlight Qt exposes the
`-video-decoder` option with `auto`, `software`, and `hardware` values, while
the current Moonlight Embedded command reference does not document a decoder
selection control. LeagueBridge therefore exposes a normalized `--decoder`
input only for Qt/Flatpak and fails closed for Embedded. This permits an
explicit software-decoder choice on Linux/BSD graphics stacks without claiming
that the resulting stream, input path, Vanguard, or League session is working.

The official Sunshine release page was also checked on 2026-08-29. Its stable
release remains `v2026.516.143833`, matching the repository's pinned Windows
AMD64 release tag; no stable asset pin change is justified by this check. The
current public release list additionally shows `v2026.830.223700` and
`v2026.830.165455` as prereleases. The latest `libvirtualhid` release,
`v2026.829.2338.54`, requires Sunshine `v2026.830.44125` or newer, so the
driver-backed Raw Input candidate currently needs an explicitly accepted,
signature-verified compatible prerelease rather than the repository's stable
Sunshine pin. The pinned asset digests remain content values from the lock file
and were not refreshed by an unverified download. The official Windows AMD64 MSI
metadata for the matching `v2026.830.223700` prerelease is now recorded
separately in
[`compatibility/sunshine-windows-amd64-raw-input-preview.lock.json`](../../compatibility/sunshine-windows-amd64-raw-input-preview.lock.json)
with SHA-256
`00edf5f37c2a6351d9cd0e114565ef26710d14baafc43fa6c6b8fc671ef5953d`.
This preview lock is an operator-reviewed reproducibility record only; it is
not consumed by the stable inspector, does not authorize installation, and
does not change the unvalidated route state.

## 2026-08-31 remote-input addendum

Parsec's current support article, updated 30 March 2026, explicitly names
League of Legends and VALORANT as examples of multiplayer games whose Vanguard
anti-cheat can block Parsec's mouse and keyboard input. Parsec therefore does
not provide a demonstrated replacement for Moonlight, even though it has a
Linux client and Windows/macOS host support. LeagueBridge does not add a
Parsec backend or recommend its Virtual USB driver as a workaround.

The remaining non-invasive route worth documenting is a hardware KVM-over-IP
device. PiKVM's current handbook describes a device attached to the target
computer that presents keyboard and mouse USB devices while exposing the
captured display through a web UI. This can avoid the software streamer's
`SendInput` path, but PiKVM is not Riot authorization and its behavior with the
current Vanguard build is not established by these sources. It remains a
manual, route-bound candidate requiring a physical host and a Practice Tool
validation. Unapproved virtual-HID drivers, USB/IP forwarding, input
interception, VM concealment, and Riot component modification remain
unacceptable. Current Sunshine documentation describes its own official,
separately licensed Raw Input candidate; that path is recorded in
`docs/REMOTE_PLAY.md`, remains unvalidated, and must not be confused with a
Riot-approved anti-cheat bypass.

The project consequently keeps the Moonlight handoff as the only automated
streaming route and treats hardware KVM as an external operational fallback,
not as a new compatibility backend or a readiness promotion path. The detailed
operator and security procedure is in [`docs/HARDWARE_KVM.md`](../HARDWARE_KVM.md).

## 2026-09-01 upstream input-path recheck

The official Sunshine release page still identifies `v2026.516.143833` as the
latest stable release while `v2026.830.223700` remains a prerelease. The latter
is the operator-reviewed preview recorded in the repository's separate raw-input
lock file; no compatible stable release was found to replace the stable pin.

Sunshine's current Windows troubleshooting guidance describes the separately
installed Virtual HID Driver as the path that delivers keyboard transitions and
relative mouse events through Raw Input, while stating that an unavailable
driver, broker, or license falls back to `SendInput`. This makes the preview a
concrete physical-Windows input experiment worth retaining, but it does not
establish Riot authorization, native Linux/BSD support, or successful League
gameplay. The project must continue to stop on Riot/Vanguard errors and must not
copy the driver, alter Vanguard, or treat a moving desktop cursor as proof of
in-game input.

The current recheck therefore changes no compatibility verdict: native Linux/BSD
remains blocked, the Sunshine route remains an unvalidated physical-host
handoff, and hardware KVM remains the separate manual fallback.

The same current Moonlight Embedded source audit found one client-side backend
gap that can be handled without changing the League/Vanguard boundary:
`platform.c` recognizes the `x11_vaapi` selector, and the current CMake file
enables it when the X11 VA-API dependencies are available. LeagueBridge now
accepts that bounded selector, forwards it as `-platform x11_vaapi`, and
preflights the matching X11 display endpoint. This improves Linux/BSD decoder
selection where the installed Embedded package was built with VA-API support;
it remains a local client capability hint and is not evidence of Riot
authorization, remote input acceptance, or League gameplay.

## 2026-09-01 driver-preview update

LizardByte published a newer signed `libvirtualhid` Windows AMD64 driver
preview, `v2026.901.116.32`, on 1 September 2026. Its official release
metadata lists the driver MSI and digest
`f48a6d7632b6d86ab0ad9f8dc98e12e4367552f4b058e62eaff74e20fd0b69b5`; the
release remains a prerelease and still requires an active machine license.
The existing Sunshine Raw Input preview remains the separately pinned
`v2026.830.223700` MSI, whose digest is unchanged. The combined lock file now
records both official assets and the vendor's minimum Sunshine version.

This is a fresher reproducibility candidate for the physical-Windows Raw Input
experiment, not a Linux/BSD runtime or Riot authorization. LeagueBridge still
does not download, install, bundle, or alter the driver, and the route remains
unvalidated until a current physical Practice Tool run demonstrates stable
League input.

## 2026-09-01 compatible-pair refresh

The official release APIs were rechecked again on 1 September 2026. Sunshine's
current compatible candidate is the Windows AMD64 prerelease
`v2026.831.233010`; the stable `libvirtualhid` Windows AMD64 driver release is
`v2026.829.2338.54`. The driver requires Sunshine `v2026.830.44125` or newer,
so this pair satisfies the vendor version boundary, but the host component is
still a prerelease and the route remains an operator-approved experiment.

The separate raw-input lock file now records the exact official MSI URLs,
sizes, and release digests for this pair. The older Sunshine
`v2026.830.223700` and libvirtualhid preview records are superseded. This does
not change the compatibility verdict: LeagueBridge does not install, license,
bundle, or modify either Windows component; no Riot authorization or physical
League gameplay evidence exists; and the candidate cannot promote native
Linux/BSD support.

## 2026-09-01 native pairing-option recheck

The current Moonlight Embedded parser was rechecked after the command-reference
comparison above. Its `long_options` table includes `pin` for a four-digit
predefined pairing code, and the parser accepts it for the `pair` action. The
current Qt parser exposes the same `pair --pin PIN HOST` shape. LeagueBridge now
forwards a validated, invocation-only `--pin` to either native client (or the
Qt-based Flatpak), while still rejecting dry-run use and never persisting the
code. This improves first-pairing usability on BSD packages that install
Moonlight Embedded, but it does not authenticate a host, alter Vanguard, or
provide League gameplay support.

## Primary sources

- [Riot — Vanguard x LoL](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/)
- [Riot Player Support — minimum and recommended system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends)
- [Riot — Patch 25.S1.2 notes and Embedded Vanguard on Mac](https://www.leagueoflegends.com/en-us/news/game-updates/patch-25-s1-2-notes/)
- [Riot — Vanguard On-Demand](https://www.riotgames.com/en/news/vanguard-on-demand)
- [Riot — Vanguard FAQ for third-party applications](https://www.riotgames.com/en/DevRel/vanguard-faq)
- [Riot Player Support — Vanguard error codes](https://support.riotgames.com/en-us/riot/performance/vanguard-error-codes)
- [Valve — Steam Hardware and Proton](https://partner.steamgames.com/doc/steamhardware/proton)
- [Moonlight Qt — current command-line parser](https://raw.githubusercontent.com/moonlight-stream/moonlight-qt/master/app/cli/commandlineparser.cpp)
- [Moonlight Embedded — current command-line documentation](https://github.com/moonlight-stream/moonlight-embedded/blob/master/docs/README.pod)
- [Moonlight Embedded — current option parser](https://raw.githubusercontent.com/moonlight-stream/moonlight-embedded/master/src/config.c)
- [Moonlight Embedded — current platform selector](https://raw.githubusercontent.com/moonlight-stream/moonlight-embedded/master/src/platform.c)
- [Moonlight Embedded — current backend detection/build options](https://raw.githubusercontent.com/moonlight-stream/moonlight-embedded/master/CMakeLists.txt)
- [FreeBSD ports — Moonlight Qt package recipe](https://cgit.freebsd.org/ports/tree/games/moonlight-qt/Makefile)
- [DragonFly DPorts — Moonlight Qt package recipe](https://github.com/DragonFlyBSD/DPorts/blob/master/games/moonlight-qt/Makefile)
- [dockur/windows — README](https://github.com/dockur/windows/blob/master/readme.md)
- [TibixDev/WinBoat — README and architecture](https://github.com/TibixDev/winboat)
- [kyechou/leagueoflegends — archived Linux wrapper](https://github.com/kyechou/leagueoflegends)
- [GloriousEggroll/wine-ge-custom — archived Wine-GE builds and LoL release index](https://github.com/GloriousEggroll/wine-ge-custom)
- [Open-Wine-Components/umu — unified Proton/Wine launcher for Linux](https://github.com/Open-Wine-Components/umu-launcher)
- [Open-Wine-Components/umu-database — Proton-fix database](https://github.com/Open-Wine-Components/ULWGL-database)
- [RiotVanguard/Vanguard — public source repository claim](https://github.com/RiotVanguard/Vanguard)
- [RiotVanguard/Vanguard — checked Windows kernel source](https://github.com/RiotVanguard/Vanguard/blob/main/main.c)
- [RiotVanguard/Vanguard issue #84 — unresolved Linux support request](https://github.com/RiotVanguard/Vanguard/issues/84)
- [RiotVanguard/Vanguard issue #70 — Moonlight/Sunshine mouse report](https://github.com/RiotVanguard/Vanguard/issues/70)
- [RiotVanguard/Vanguard — live public issue index](https://github.com/RiotVanguard/Vanguard/issues)
- [Sunshine — current input configuration](https://github.com/LizardByte/Sunshine/blob/master/docs/configuration.md)
- [Sunshine — current Windows Raw Input troubleshooting](https://docs.lizardbyte.dev/projects/sunshine/master/md_docs_2troubleshooting.html?lng=en-US)
- [LizardByte — libvirtualhid and Virtual HID Driver announcement](https://app.lizardbyte.dev/2026-08-16-introducing-libvirtualhid-and-virtual-hid-driver/)
- [LizardByte — libvirtualhid capabilities and license boundary](https://github.com/LizardByte/libvirtualhid)
- [LizardByte — current Sunshine release list](https://github.com/LizardByte/Sunshine/releases)
- [Sunshine — current Windows Raw Input troubleshooting](https://docs.lizardbyte.dev/projects/sunshine/master/md_docs_2troubleshooting.html?lng=en-US)
- [Parsec — anti-cheat input limitations](https://support.parsec.app/hc/en-us/articles/32381827815188-Mouse-and-Keyboard-Isn-t-Working-Correctly-When-Connected)
- [PiKVM — USB configuration](https://docs.pikvm.org/usb/)
- [nicolasdesenv/valorant-linux-compatibility — research repository](https://github.com/nicolasdesenv/valorant-linux-compatibility)
- [Darling — current upstream runtime](https://github.com/darlinghq/darling)
- [Darling — known non-functional software](https://docs.darlinghq.org/known-nonfunctional-software.html)
- [Darling — League of Legends issue #1467](https://github.com/darlinghq/darling/issues/1467)
- [Sunshine — current system requirements](https://docs.lizardbyte.dev/projects/sunshine/latest/)
- [Sunshine — current public releases](https://github.com/LizardByte/Sunshine/releases)
- [LizardByte — libvirtualhid release v2026.829.2338.54](https://github.com/LizardByte/libvirtualhid/releases/tag/v2026.829.2338.54)
- [NVIDIA — Is League of Legends available on GeForce NOW?](https://nvidia.custhelp.com/app/answers/detail/a_id/5539/kw/surround%20setup)
- [NVIDIA — GeForce NOW download and Linux client](https://www.nvidia.com/en-us/geforce-now/download/)
- [NVIDIA — GeForce NOW system requirements](https://www.nvidia.com/en-us/geforce-now/system-reqs/)
- [NVIDIA — GeForce NOW supported games](https://www.nvidia.com/en-in/geforce/products/geforce-now/supported-games/)
- [NVIDIA — current GeForce NOW release highlights](https://www.nvidia.com/en-us/geforce-now/release-highlights/)
- [NVIDIA — Vanguard removal announcement for GeForce NOW](https://blogs.nvidia.com/blog/geforce-now-thursday-may-games-list/)
- [Shadow — Games incompatible with Shadow PC](https://support.shadow.tech/hc/en-us/articles/32731823908625-Games-Incompatible-with-Shadow-PC)
