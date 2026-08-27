# Platform feasibility — 2026-08-26

Reviewed on 26 August 2026, with the Darling, CrossOver, WinBoat, Waydroid,
and cloud-gaming routes supplemented on 27 August 2026. This record expires
after 30 days or immediately after a material Riot/Vanguard requirement
change. Every linked source below was checked on the date of the corresponding
review.

| Route | Result | Why |
| --- | --- | --- |
| Wine / WineHQ / Lutris | Blocked | Riot states Wine/Lutris cannot meet Vanguard's driver requirements. |
| Proton | Blocked | Proton cannot provide required kernel-space anti-cheat support without publisher enablement; Riot's Wine statement controls. |
| CrossOver | Blocked / limited | CodeWeavers' current League entry rates CrossOver Linux as **Limited Functionality** (last tested 26.3.0) and CrossOver Mac as **Will Not Install**; CrossOver remains a Wine-based compatibility layer and cannot satisfy Riot's Vanguard driver requirement. |
| Bottles, PlayOnLinux, and other Wine frontends | Blocked | These projects manage Wine prefixes/runners; Bottles' own documentation describes the Wine runner as the execution layer, so the same Vanguard driver restriction applies. |
| Copied DLLs or Vanguard files | Rejected | User-mode files cannot create Windows boot/kernel attestation; redistribution and tampering create legal and safety risk. |
| Dockur Windows | Blocked | It runs QEMU/KVM Windows in a VM despite Docker packaging. |
| WinBoat | Blocked | WinBoat's own documentation says Windows runs as a VM inside a Docker/Podman container and requires KVM; its seamless desktop integration does not change the VM boundary. |
| libvirt/QEMU/KVM/VFIO and desktop hypervisors (VirtualBox, VMware, Hyper-V, Parallels, UTM) | Blocked | GPU passthrough, vTPM, and Secure Boot do not make a VM a Riot-supported physical host. |
| bhyve | Blocked | Same VM policy; missing parity does not improve the result. |
| OpenBSD vmm | Not viable | It is not a suitable supported Windows gaming platform. |
| Waydroid and Android containers/emulators | Not the PC route | Waydroid boots an Android system in a Linux container. It does not provide the Windows Riot Client or PC Vanguard driver, so an Android runtime cannot satisfy this project's League-of-Legends-PC gate. |
| GeForce NOW | Blocked | NVIDIA's support answer, updated 1 May 2024 and still current at review, says League is unavailable for the foreseeable future because Vanguard does not support GeForce NOW virtual machines. |
| Shadow PC | Blocked | Shadow's incompatibility list, updated 11 August 2026, says League cannot run because Vanguard does not support virtual machines. |
| Other third-party cloud gaming (for example Boosteroid) | Unvalidated / outside project control | These services stream games from provider infrastructure, but a Linux client cannot establish that the provider host is a Riot-supported physical Vanguard host. No route-bound League/Vanguard evidence is available to LeagueBridge. |
| Dual-boot Windows | Viable escape hatch | League runs on supported bare-metal Windows, not Linux/BSD. |
| Physical Windows remote streaming | Handoff candidate | The game and Vanguard remain on supported hardware; streaming/input still require responsible validation. |
| Native macOS | Officially supported | Separate Riot client/Embedded Vanguard architecture; not portable to Linux/BSD by LeagueBridge. |
| Darling (macOS compatibility layer on Linux) | Not viable / unvalidated | Darling documents only basic experimental GUI support and says complex GUI applications generally do not work; its open League issue has no validated playable route. |
| Physical macOS remote streaming | Implemented experimental handoff; unvalidated | Riot supports the native macOS client and Sunshine lists macOS 14.2+ as an experimental host. LeagueBridge now binds Moonlight planning to an explicit physical-macOS route and provides a non-certifying read-only host probe, but gamepads are unavailable and capture, audio, keyboard/mouse, session quality, and gameplay remain unvalidated. |

## Vanguard On-Demand does not change the blocked routes

Riot's 24 June 2026 Vanguard On-Demand option changes when the Windows kernel
driver starts, not whether it is required during play. On a PC that passes
Vanguard Pre-Check, the driver can launch with a Riot title and remain active
only while playing instead of starting at boot. The optional path requires at
least Windows 11 25H2 plus UEFI Secure Boot, TPM 2.0, VBS/HVCI, and IOMMU.

This improves the operating model for a qualifying physical Windows dual-boot
or remote host. It does not introduce a native Linux/BSD client, make Wine or
Proton able to load Vanguard, or authorize a virtual machine.

## Darling does not provide a supported macOS route

Darling is a macOS compatibility layer that runs macOS software on Linux, but
its official project page describes GUI support as basic and experimental. The
project documentation says that complex GUI applications generally do not work,
and the open League of Legends issue contains no implementation or validated
playable result. LeagueBridge therefore keeps Darling outside both the native
Linux/BSD gameplay gate and the physical-macOS remote route: a compatibility
layer is not the separately managed physical Mac required by Riot's supported
client.

## There is no standalone Vanguard or DLL route

Riot's current Client FAQ, updated 13 February 2026, says Vanguard is added only
when a user installs a Riot game that needs it and is not included in the Riot
Client by default. Riot does not publish a standalone Vanguard package that can
be gathered and moved into Wine, Proton, or a BSD compatibility layer. Copying
user-mode DLLs also cannot reproduce the required Windows kernel driver,
measured boot, or hardware trust chain. LeagueBridge must not acquire,
redistribute, or load such files.

## Primary evidence

- Riot: [Vanguard x LoL](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/)
- Riot: [minimum and recommended requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends)
- Riot: [Vanguard errors, including VM error VAN 138](https://support-leagueoflegends.riotgames.com/hc/en-us/articles/26932165816851-Vanguard-Error-Codes-and-Solutions-LoL)
- Riot: [Vanguard On-Demand](https://www.riotgames.com/en/news/vanguard-on-demand)
- Riot: [Patch 25.S1.2 Embedded Vanguard on Mac](https://www.leagueoflegends.com/en-ph/news/game-updates/patch-25-s1-2-notes/)
- Riot: [Riot Client FAQ](https://support.riotgames.com/en-us/riot/client/riot-client-faq)
- Valve: [Proton anti-cheat guidance](https://partner.steamgames.com/doc/steamhardware/proton)
- CodeWeavers: [League of Legends CrossOver compatibility](https://www.codeweavers.com/compatibility/crossover/league-of-legends)
- Bottles: [official Wine-runner documentation](https://docs.usebottles.com/components/runners)
- Dockur: [Windows project](https://github.com/dockur/windows) and [environment options](https://github.com/dockur/windows/blob/master/docs/environment.md)
- WinBoat: [official project and VM architecture](https://github.com/winboat-org/winboat/blob/main/README.md)
- Waydroid: [official Android-container project](https://github.com/waydroid/waydroid)
- Microsoft: [memory integrity in virtual machines](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- Microsoft: [BCDBoot dual-boot configuration](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di?view=windows-11)
- NVIDIA: [League unavailable on GeForce NOW because Vanguard does not support VMs](https://nvidia.custhelp.com/app/answers/detail/a_id/5539/)
- Shadow: [games incompatible with Shadow PC](https://support.shadow.tech/hc/en-us/articles/32731823908625-Games-Incompatible-with-Shadow-PC)
- Boosteroid: [official cloud-gaming service](https://boosteroid.com/)
- Darling: [official project](https://www.darlinghq.org/), [GUI/software limitations](https://docs.darlinghq.org/known-nonfunctional-software.html), and [League of Legends issue #1467](https://github.com/darlinghq/darling/issues/1467)
- Moonlight: [official PC client](https://github.com/moonlight-stream/moonlight-qt)
- Sunshine: [official documentation](https://docs.lizardbyte.dev/projects/sunshine/latest/)
- FreeBSD: [Moonlight Qt port](https://cgit.freebsd.org/ports/tree/games/moonlight-qt)
- OpenBSD: [Moonlight Qt port](https://cvsweb.openbsd.org/ports/games/moonlight-qt)
- NetBSD: [Moonlight Qt pkgsrc package](https://cdn.netbsd.org/pub/pkgsrc/current/pkgsrc/games/moonlight-qt/index.html)
- DragonFly BSD: [Moonlight Qt DPort](https://github.com/DragonFlyBSD/DPorts/tree/master/games/moonlight-qt)

## Decision

The embedded policy remains fail-closed for local execution. LeagueBridge may
offer an explicitly acknowledged Moonlight handoff to a user-confirmed physical
Windows PC or an explicitly selected physical Mac. The macOS route remains
handoff-only, denied by default policy, experimentally hosted by Sunshine, and
outside validation-evidence schema v1. Readiness schema v3 represents it as a
separate hard-zero route pending a future authenticated route-bound evidence
schema v2. The project must never describe remote play as League running on
Linux/BSD.
