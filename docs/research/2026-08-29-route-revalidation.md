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
| NVIDIA GeForce NOW | NVIDIA currently documents a Linux client and Linux system requirements, but its official Vanguard-era announcement says League was removed from GeForce NOW because Vanguard does not support its virtual machines. The current Linux-client documentation does not reverse that League-specific removal. | Do not advertise or automate GeForce NOW as a League route; a Linux cloud client is not evidence that League is available there. |
| Shadow PC | Shadow's current incompatibility list says League cannot be played on Shadow because Riot Vanguard is incompatible with its virtual machines. | Reject Shadow and equivalent hosted VM services for certification. |
| Other hosted cloud PCs | This audit found no provider documentation granting a Riot/Vanguard exception or proving a physical, non-VM host. Marketing claims about device coverage are not gameplay authorization. | Require provider-specific primary evidence and Riot authorization before considering integration. |

Cloud clients can still be useful as ordinary viewers, but the hosted machine
must satisfy Riot's own runtime requirements. A browser, Linux client, or
streaming protocol does not change the anti-cheat boundary.

The current NVIDIA documentation is an important distinction: the GeForce NOW
download and system-requirements pages now describe a Linux beta client, while
the company's Vanguard announcement says League was taken off GeForce NOW after
the Vanguard rollout because the service uses virtual machines. The current
release-highlights page documents Linux-client improvements but does not state
that League was restored. This is therefore a provider-specific blocked route,
not a missing Linux frontend that LeagueBridge should install or automate.

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
input documentation only exposes ordinary keyboard and mouse enablement, and
Moonlight Qt's documented absolute-mouse toggle is a client preference rather
than a Riot fix. LeagueBridge must not add input interception, driver injection,
or an anti-cheat bypass; until Riot and the streaming stack resolve this on a
real host, remote gameplay remains unvalidated rather than a guaranteed path.

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

The official Sunshine release page was also checked on 2026-08-29. Its latest
release remains `v2026.516.143833`, matching the repository's pinned Windows
AMD64 release tag; no asset pin change is justified by this check. The pinned
asset digests remain content values from the lock file and were not refreshed by
an unverified download.

## Primary sources

- [Riot — Vanguard x LoL](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/)
- [Riot Player Support — minimum and recommended system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends)
- [Riot — Patch 25.S1.2 notes and Embedded Vanguard on Mac](https://www.leagueoflegends.com/en-us/news/game-updates/patch-25-s1-2-notes/)
- [Riot — Vanguard On-Demand](https://www.riotgames.com/en/news/vanguard-on-demand)
- [Riot Player Support — Vanguard error codes](https://support.riotgames.com/en-us/riot/performance/vanguard-error-codes)
- [Valve — Steam Hardware and Proton](https://partner.steamgames.com/doc/steamhardware/proton)
- [Moonlight Qt — current command-line parser](https://raw.githubusercontent.com/moonlight-stream/moonlight-qt/master/app/cli/commandlineparser.cpp)
- [Moonlight Embedded — current command-line documentation](https://github.com/moonlight-stream/moonlight-embedded/blob/master/docs/README.pod)
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
- [nicolasdesenv/valorant-linux-compatibility — research repository](https://github.com/nicolasdesenv/valorant-linux-compatibility)
- [Darling — current upstream runtime](https://github.com/darlinghq/darling)
- [Darling — known non-functional software](https://docs.darlinghq.org/known-nonfunctional-software.html)
- [Darling — League of Legends issue #1467](https://github.com/darlinghq/darling/issues/1467)
- [Sunshine — current system requirements](https://docs.lizardbyte.dev/projects/sunshine/latest/)
- [NVIDIA — Is League of Legends available on GeForce NOW?](https://nvidia.custhelp.com/app/answers/detail/a_id/5539/kw/surround%20setup)
- [NVIDIA — GeForce NOW download and Linux client](https://www.nvidia.com/en-us/geforce-now/download/)
- [NVIDIA — GeForce NOW system requirements](https://www.nvidia.com/en-us/geforce-now/system-reqs/)
- [NVIDIA — current GeForce NOW release highlights](https://www.nvidia.com/en-us/geforce-now/release-highlights/)
- [NVIDIA — Vanguard removal announcement for GeForce NOW](https://blogs.nvidia.com/blog/geforce-now-thursday-may-games-list/)
- [Shadow — Games incompatible with Shadow PC](https://support.shadow.tech/hc/en-us/articles/32731823908625-Games-Incompatible-with-Shadow-PC)
