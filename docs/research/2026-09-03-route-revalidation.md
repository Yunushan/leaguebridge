# Route revalidation — 2026-09-03

This audit rechecks the requested Linux/BSD League routes against current
upstream material. It is a route-selection record, not gameplay evidence. A
successful client launch, copied Windows file, compatibility-layer prefix, or
virtual machine does not establish Riot authorization or Vanguard acceptance.

## Current result

No authorized local Linux or BSD League runtime was found. Riot's current
Vanguard FAQ still says that Linux has never been officially supported and
that the Lutris/Wine implementation cannot satisfy Vanguard's driver
requirements. It also explains that emulation creates a trust problem because
the host can inspect or manipulate the guest. This is a publisher constraint,
not a missing LeagueBridge DLL or Go implementation detail.

The public RiotVanguard issue index still contains an open Linux-support
request, but an open user issue is not an authorization, implementation, or
signed runtime. It does not justify importing a driver, DLL, kernel module, or
anti-cheat workaround into this project.

Riot's current [League system-requirements page](https://support-leagueoflegends.riotgames.com/hc/en-us/articles/201752654-Minimum-and-Recommended-System-Requirements)
was updated on 2026-05-28 and states that League is supported only on Windows
and macOS; it explicitly names Linux, SteamOS, and Bazzite among operating
systems Riot cannot support. This is the current platform contract and keeps
the local Linux/BSD gameplay gate separate from the Linux/BSD client handoff.

## 2026-09-04 upstream status recheck

The public [RiotVanguard/Vanguard issue tracker](https://github.com/RiotVanguard/Vanguard/issues)
still lists [issue #84](https://github.com/RiotVanguard/Vanguard/issues/84),
"still not working with linux," as open; it was opened on 2026-05-04 and has
no assignee, milestone, branch, or pull request. This is a user report rather
than a Riot support commitment, implementation, or authorization. It therefore
does not change the local Linux/BSD decision or justify importing a driver,
DLL, kernel module, or compatibility workaround. A future Riot-published
client, Vanguard path, or explicit authorization would require a new dated
review and a separate end-to-end validation before any backend promotion.

## Option audit

| Option | Current finding | Project decision |
| --- | --- | --- |
| Wine, WineHQ, Lutris, Bottles, or PlayOnLinux | Riot's own Linux statement says the Wine/Lutris implementation cannot satisfy Vanguard's driver requirements. | Keep local Linux/BSD gameplay denied; do not add DLL overrides or patches. |
| Proton or a Proton launcher | Proton can translate Windows games, but no Riot authorization for League/Vanguard on Linux or BSD was found. This is an authorization gap, not a missing launch flag. | Do not add a Proton backend or anti-cheat bypass. |
| `dockur/windows`, QEMU/KVM, bhyve, WinBoat, or another VM | Dockur's current project describes Windows inside a Docker container and requires KVM for its accelerated path. The guest remains a virtual machine, so packaging it differently does not create the physical trust boundary Riot requires. | Keep VM routes denied; do not hide virtualization or alter boot/device identity. |
| Copied Riot/Vanguard DLLs, drivers, or public source claims | A copied proprietary component cannot recreate signed boot state, kernel trust, machine identity, or publisher authorization. | Never download, redistribute, inject, patch, or conceal these components. |
| USB/IP, VirtualHere, software virtual-HID, or input interception | Community comments on the still-open RiotVanguard/Vanguard mouse-input issue describe software USB or virtual-device workarounds, but those comments are not Riot guidance or authorization and do not establish account safety. | Reject these paths; use only the physical host's ordinary input or an authenticated hardware-KVM path, and stop if Riot/Vanguard reports an error. |
| Official Moonlight client on Linux/BSD | The Linux Flatpak and native BSD client packages provide a legitimate viewer/control client for a separately managed physical host. They do not run League locally. | Keep the client preflight and explicit physical-host handoff. |

## Darling/macOS-client recheck

Darling's current upstream README describes GUI support as active development and
warns that most GUI applications do not run yet. Its current known-nonfunctional
software page is more specific: complex GUI applications generally do not work,
with only simple GUI examples expected to run. The dedicated Darling League issue
(`darlinghq/darling#1467`) remains an open information request with no assignee,
linked branch, or pull request, and it explicitly says no immediate maintainer
action is expected. Therefore there is no current executable League-on-Darling
implementation to integrate or validate. This route remains denied/unvalidated;
LeagueBridge must not import a macOS client, proprietary frameworks, or copied
Riot assets to manufacture one.

## Local validation performed

The WSL2 Linux client was checked with the repository's scorecard-bound binary
after installing the official Moonlight Flatpak. Platform, display, input,
audio, and Moonlight checks passed; the only warning concerned optional
decoder-diagnostic utilities. The host-free client smoke and `remote play`
dry-run passed with the reserved `example.invalid` host, and recorded
`network=not-used` and `gameplay=not-tested`. No host was contacted, no
credentials were handled, and no League or Vanguard process was started.

On 2026-09-03, the same smoke was rerun against a freshly cross-built Linux
amd64 binary stamped with the current scorecard digest. It passed with
`doctor_exit=0`, `client_preflight=pass`, and `remote_play_dry_run_exit=0`.
The headless branch was then rerun with the desktop session variables removed;
it passed with `doctor_exit=3` and `client_preflight=blocked`. This validates
both supported diagnostic states and the non-network handoff plan, not League
gameplay.

The follow-up WSL package check installed Debian's Moonlight Flatpak 6.1.0,
`vainfo`, and FFmpeg. The client smoke still passed, but `vainfo` could not
initialize VA-API: this WSL instance exposes `/dev/dxg` but no `/dev/dri`
device. Therefore the available decoder-tool check is only an availability
signal; it is not evidence that hardware decoding, streamed video, or League
gameplay works on a physical Linux desktop.

The same current source tree also cross-built all nine supported Linux/BSD
targets with vendored dependencies, CGO disabled, and the release toolchain
settings: Linux amd64/arm64, FreeBSD amd64/arm64, OpenBSD amd64/arm64, NetBSD
amd64/arm64, and DragonFly BSD amd64. Cross-build success confirms portable
artifacts only; no native BSD desktop, physical host, Vanguard session, or
League gameplay was executed.

The current Windows development machine still does not provide a validated
physical gameplay host: Riot Client is present, but League, Vanguard's active
service, and Sunshine were not available during the read-only audit. No
installation or login was attempted.

The official package trees were also rechecked on 2026-09-03. FreeBSD and
DragonFly provide both `games/moonlight-qt` (the `moonlight-qt` executable) and
`games/moonlight-embedded` (the generic `moonlight` executable). OpenBSD and
NetBSD provide `games/moonlight-qt`, whose packaged executable is named
`moonlight`. This matches LeagueBridge's target-aware discovery order and its
OpenBSD/NetBSD Qt fallback; no binary is copied, repackaged, or downloaded by
the project.

RiotVanguard/Vanguard issue #70 remains open and continues to track Moonlight /
Sunshine cursor-input failures. Its recent community comments mention
software USB or virtual-device forwarding, but they are unverified user reports
and do not authorize bypassing Vanguard's input boundary. LeagueBridge therefore
continues to reject USB/IP, VirtualHere, software virtual-HID, and input
interception; the only acceptable remote input candidates remain the physical
host's ordinary device path and an authenticated hardware-KVM path.

The official Sunshine release list was also rechecked on 2026-09-03. It still
marks `v2026.516.143833` as the latest stable release; the newer September
entries are explicitly marked prerelease. The stable Windows AMD64 lock was
therefore not changed. The prerelease channel is not a production-safe reason
to replace a content-addressed stable pin, and neither channel provides Riot
authorization or local Linux/BSD gameplay support.

The pinned official Sunshine Windows AMD64 installer was independently
rechecked on 2026-09-03 before inspection: its 24,465,408-byte payload matched
the lock-file SHA-256
`e7208b11a4ab9dd89871133a054bbb8dc55dfbba408227b0eccab22c60b273a2`, and
Windows reported a valid Authenticode signature. The read-only MSI inspection
found Sunshine PowerShell install/uninstall custom actions and no declarative
service tables, so it returned `review-required` and did not execute them.
Against a current staged-source Windows binary, the host doctor then passed
the platform, Windows-version, DirectX, and Riot Client checks but reported
League, the Vanguard service, and Sunshine as missing. This is host evidence,
not authorization or gameplay evidence.

## Required condition for the requested end state

The local Linux/BSD score can move beyond its hard blocked state only after
Riot publishes or authorizes a Linux/BSD client and anti-cheat path, followed
by a real route-bound Practice Tool and ordinary-game validation. Until then,
LeagueBridge can improve the Linux/BSD client, package lifecycle, diagnostics,
and physical-host handoff, but it must not claim that League runs locally or
that a compatibility layer is safe for a player account.

## Primary sources

- [Riot — Vanguard x LoL](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/)
- [Riot — current League system requirements](https://support-leagueoflegends.riotgames.com/hc/en-us/articles/201752654-Minimum-and-Recommended-System-Requirements)
- [RiotVanguard/Vanguard — live issue index](https://github.com/RiotVanguard/Vanguard/issues)
- [RiotVanguard/Vanguard issue #84 — Linux support request](https://github.com/RiotVanguard/Vanguard/issues/84)
- [RiotVanguard/Vanguard issue #70 — Moonlight/Sunshine mouse input](https://github.com/RiotVanguard/Vanguard/issues/70)
- [Valve — Steam Hardware and Proton](https://partner.steamgames.com/doc/steamhardware/proton)
- [dockur/windows — current README](https://github.com/dockur/windows/blob/master/readme.md)
- [Darling — current README](https://github.com/darlinghq/darling)
- [Darling — known non-functional software](https://docs.darlinghq.org/known-nonfunctional-software.html)
- [Darling issue #1467 — League of Legends on Darling](https://github.com/darlinghq/darling/issues/1467)
- [FreeBSD ports — Moonlight Qt](https://github.com/freebsd/freebsd-ports/tree/main/games/moonlight-qt)
- [FreeBSD ports — Moonlight Embedded](https://github.com/freebsd/freebsd-ports/tree/main/games/moonlight-embedded)
- [OpenBSD ports — Moonlight Qt](https://github.com/openbsd/ports/tree/master/games/moonlight-qt)
- [NetBSD pkgsrc — Moonlight Qt](https://github.com/NetBSD/pkgsrc/tree/trunk/games/moonlight-qt)
- [DragonFly DPorts — Moonlight Qt](https://github.com/DragonFlyBSD/DPorts/tree/master/games/moonlight-qt)
- [DragonFly DPorts — Moonlight Embedded](https://github.com/DragonFlyBSD/DPorts/tree/master/games/moonlight-embedded)
- [LizardByte — current Sunshine release list](https://github.com/LizardByte/Sunshine/releases)
