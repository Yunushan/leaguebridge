# Current support check — 2026-08-27

This short addendum re-checks the execution routes that could plausibly change
the Linux/BSD outcome. It supplements the broader
[`2026-08-26-platform-feasibility.md`](2026-08-26-platform-feasibility.md)
record and the newer
[`2026-08-29-route-revalidation.md`](2026-08-29-route-revalidation.md); it
expires with that record or sooner if Riot changes a requirement.

## Findings

| Question | Current evidence-backed result |
| --- | --- |
| Does Riot provide a native Linux or BSD League client? | No. Riot Player Support's current system-requirements page lists Windows and macOS support and says it cannot provide support for Linux, SteamOS, Bazzite, or other operating systems. |
| Can Wine, WineHQ, Lutris, or Proton satisfy Vanguard? | No supported path was added. Riot's Vanguard explanation still says the Wine/Lutris implementation cannot meet the Vanguard driver requirements; Proton remains a Wine-based compatibility layer whose anti-cheat operation requires publisher support. |
| Can a VM provide a supported host? | No. Riot's current Vanguard error guidance identifies VAN 138 as Vanguard or the game starting from a virtual device and directs installation in a normal Windows instance. `dockur/windows`, WinBoat, QEMU/KVM, bhyve, VFIO, and desktop hypervisors remain virtual-machine routes. |
| Did Vanguard On-Demand add a Linux/BSD route? | No. Riot's 24 June 2026 update changes when the Windows driver starts on qualifying secured Windows PCs; it does not provide a Linux/BSD client, a Wine exception, or VM authorization. |
| Can copied DLLs, drivers, or an anti-cheat package fill the gap? | No. Riot does not publish a standalone Vanguard package for this purpose, and copying or modifying proprietary components would not recreate the required Windows trust boundary or provide authorization. |
| Can cloud gaming solve the gate? | Not as a project-controlled local route. NVIDIA, Shadow, and AirGPU document League/Vanguard incompatibility with their virtual machines; any other provider would require fresh, route-bound evidence of a supported host and remains outside LeagueBridge's control. |

## Experimental lead triage — 2026-08-27

A recent public forum post describes a patched Wine build reaching Vanguard's
`DriverEntry` while investigating **VALORANT**, but the author explicitly says
that VALORANT still does not work. It is not League evidence, not a Riot
authorization, and not an end-to-end gameplay result. Reproducing or extending
kernel-driver emulation would also cross LeagueBridge's safety boundary: it
would attempt to recreate an anti-cheat trust boundary inside Wine rather than
use an authorized host. The lead is therefore recorded for awareness only and
does not change the deny verdict for Wine, Proton, or BSD.

See the [experimental report](https://plus.diolinux.com.br/t/tentando-fazer-o-riot-vanguard-funcionar-no-linux-via-wine-proton-procurando-ajuda/83922)
for the author's stated scope and limitations.

## Decision

No compatibility-manifest backend is promoted or added. The project continues to
deny local Linux/BSD execution and to offer only an explicitly acknowledged
handoff to a separately managed physical Windows or experimental physical Mac
host. It does not download, redistribute, or attempt to hide Vanguard, and it
does not treat a community report or a successful client launch as Riot
authorization.

## Local execution audit — 2026-08-27

The available workspace host was checked without installing software, starting
services, changing security settings, or opening a network listener:

| Capability | Read-only result | Interpretation |
| --- | --- | --- |
| Wine/Wine64, Proton, Lutris, Flatpak, Moonlight/Moonlight Qt, Sunshine, and QEMU | No executable was found on `PATH` | No local translation layer, streaming client/host, or VM runtime was available to test. |
| Docker | Docker CLI 29.7.2 was present; the Docker service was stopped and the engine pipe was unavailable | `dockur/windows` could not be started without a service mutation; even a running instance would remain a VM route rejected by Riot. |
| WSL | `wsl --status` returned `E_ACCESSDENIED` while enumerating distributions | WSL state is unavailable; no claim that WSL is disabled or enabled is made. |
| Riot Client | A regular, Authenticode-valid Riot Client executable was present | This does not prove League or Vanguard installation. |
| League/Vanguard/Sunshine | League Client, `vgc`/`vgtray`, and Sunshine were absent at their standard Windows locations | There is no local physical Windows gameplay or Sunshine host to validate on this machine. |

No Riot/Vanguard DLL, driver, kernel module, installer, or anti-cheat package
was copied or modified. No VM-concealment, launch-flag bypass, process
injection, or other anti-cheat circumvention was attempted. Those actions would
not establish Riot authorization or the required Windows trust boundary.

## Upstream CI observation — 2026-08-27

The read-only [GitHub Actions run `33053034338`](https://github.com/Yunushan/leaguebridge/actions/runs/33053034338) for commit
`1d8fb2e8cd3f03d911bea1e834a1f97fe1257cf0` exposed a tracked formatting defect:
both the Ubuntu and Windows test jobs stopped at `gofmt` on
`internal/remote/coverage_test.go`. The release-smoke job, eight cross-build
jobs, four BSD-kernel guest jobs, and both hosted macOS lifecycle jobs completed
successfully; the hosted Linux job failed during runner setup before executing
its steps. The formatting defect is corrected in the current working tree, but
the fix still needs a pushed commit and a fresh CI run before it can count as
an authenticated CI attestation. These jobs validate the control plane only;
they do not test League, Vanguard, Sunshine, or gameplay.

## Primary sources checked

- [Riot Player Support — minimum and recommended system requirements](https://support-leagueoflegends.riotgames.com/hc/en-us/articles/201752654-Minimum-and-Recommended-System-Requirements-League-of-Legends)
- [Riot — Vanguard x LoL](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/)
- [Riot Player Support — Vanguard error codes](https://support-leagueoflegends.riotgames.com/hc/en-us/articles/26932165816851-Vanguard-Error-Codes-and-Solutions-LoL)
- [Riot — Vanguard On-Demand](https://www.riotgames.com/en/news/vanguard-on-demand)
- [Valve — Proton anti-cheat guidance](https://partner.steamgames.com/doc/steamhardware/proton)
- [dockur/windows](https://github.com/dockur/windows)
- [NVIDIA — League unavailable on GeForce NOW](https://nvidia.custhelp.com/app/answers/detail/a_id/5539/)
- [Shadow — games incompatible with Shadow PC](https://support.shadow.tech/hc/en-us/articles/32731823908625-Games-Incompatible-with-Shadow-PC)
- [AirGPU — League of Legends compatibility](https://help.airgpu.com/games/league-of-legends)
