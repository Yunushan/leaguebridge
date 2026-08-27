# Current support check — 2026-08-27

This short addendum re-checks the execution routes that could plausibly change
the Linux/BSD outcome. It supplements the broader
[`2026-08-26-platform-feasibility.md`](2026-08-26-platform-feasibility.md)
record and expires with that record or sooner if Riot changes a requirement.

## Findings

| Question | Current evidence-backed result |
| --- | --- |
| Does Riot provide a native Linux or BSD League client? | No. Riot Player Support's current system-requirements page lists Windows and macOS support and says it cannot provide support for Linux, SteamOS, Bazzite, or other operating systems. |
| Can Wine, WineHQ, Lutris, or Proton satisfy Vanguard? | No supported path was added. Riot's Vanguard explanation still says the Wine/Lutris implementation cannot meet the Vanguard driver requirements; Proton remains a Wine-based compatibility layer whose anti-cheat operation requires publisher support. |
| Can a VM provide a supported host? | No. Riot's current Vanguard error guidance identifies VAN 138 as Vanguard or the game starting from a virtual device and directs installation in a normal Windows instance. `dockur/windows`, WinBoat, QEMU/KVM, bhyve, VFIO, and desktop hypervisors remain virtual-machine routes. |
| Did Vanguard On-Demand add a Linux/BSD route? | No. Riot's 24 June 2026 update changes when the Windows driver starts on qualifying secured Windows PCs; it does not provide a Linux/BSD client, a Wine exception, or VM authorization. |
| Can copied DLLs, drivers, or an anti-cheat package fill the gap? | No. Riot does not publish a standalone Vanguard package for this purpose, and copying or modifying proprietary components would not recreate the required Windows trust boundary or provide authorization. |
| Can cloud gaming solve the gate? | Not as a project-controlled local route. NVIDIA, Shadow, and AirGPU document League/Vanguard incompatibility with their virtual machines; any other provider would require fresh, route-bound evidence of a supported host and remains outside LeagueBridge's control. |

## Decision

No compatibility-manifest backend is promoted or added. The project continues to
deny local Linux/BSD execution and to offer only an explicitly acknowledged
handoff to a separately managed physical Windows or experimental physical Mac
host. It does not download, redistribute, or attempt to hide Vanguard, and it
does not treat a community report or a successful client launch as Riot
authorization.

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
