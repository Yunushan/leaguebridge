# Route revalidation — 2026-09-23

This record updates the [2026-09-03 route audit](2026-09-03-route-revalidation.md)
against publisher pages observed on 2026-09-23. It assesses published support
and authorization, not whether LeagueBridge or League ran on any host. No new
physical-host, streaming, Vanguard, or gameplay test was performed.

## Riot platform and anti-cheat status

Riot's [League system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends),
dated **2026-09-22**, still list only Windows and macOS. They explicitly exclude
support for other operating systems, including Linux, SteamOS, and Bazzite.
BSD is likewise outside the stated Windows/macOS support set. The page lists
retail Windows 10 build 19041 or newer and Windows 11 on x64, with TPM 2.0
required for Windows 11. The project keeps the separate, stricter Windows 11
host baseline in [Sunshine's host requirements](https://docs.lizardbyte.dev/projects/sunshine/latest/).

The same Riot page now lists macOS **12**, Apple M1, and Metal-capable graphics
in its Mac minimum-specification table. Its architecture prose is inconsistent:
an introductory sentence says native support is Intel-only, while the table
names M1 and a later note says Intel Macs may continue to play but receive
less troubleshooting support than Apple Silicon. This page cannot establish a
single unambiguous Intel-versus-Apple-Silicon support boundary. Each proposed
physical Mac must be checked against Riot's current requirements and tested
directly; this wording grants no readiness credit. Independently,
[Sunshine's current host requirements](https://docs.lizardbyte.dev/projects/sunshine/latest/)
list macOS **14.2 or newer**, and its
[Mac setup guide](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2getting__started.html)
still calls the host experimental and says gamepads do not work. That higher
Sunshine minimum remains the handoff's practical OS floor.

Riot's [Vanguard explanation](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/),
published 2024-04-11 and still available on 2026-09-23, says Linux was never
officially supported and that the Lutris/Wine League implementation cannot
satisfy the Vanguard driver requirements. It also describes why a VM cannot
provide the same anti-cheat trust boundary. Riot's
[VAN 138 guidance](https://support.riotgames.com/en-us/riot/performance/error-van-138),
dated 2026-07-14, explicitly says Vanguard is unsupported in virtual-machine
environments and directs players to a regular Windows installation. The newer
[VAN 9100 guidance](https://support.riotgames.com/en-us/riot/client/error-van-9100)
also rejects unsupported virtualized environments. Riot's
sources reviewed here grant no exception to Wine, Proton, or a Windows VM for
local Linux/BSD League play.

Riot's [Vanguard FAQ](https://support.riotgames.com/en-us/league-of-legends/performance/riot-vanguard-faq-league-of-legends),
dated 2026-06-02, requires Vanguard while League and its client are active.
The [2026-06-24 Vanguard On-Demand announcement](https://www.riotgames.com/en/news/vanguard-on-demand)
offers an optional driver-startup mode only for sufficiently secured Windows
PCs; its Pre-Check requires at least Windows 11 25H2 and the specified UEFI,
Secure Boot, TPM 2.0, VBS/HVCI, and IOMMU features. It supplies no Linux/BSD,
Wine, or VM exception. For Mac, Riot's
[Patch 25.S1.2 notes](https://www.leagueoflegends.com/en-us/news/game-updates/patch-25-s1-2-notes/)
identify Embedded Vanguard inside the native Mac client. Those Mac notes do
not authorize a Mac client or anti-cheat port to Linux/BSD.

Riot's [Developer Portal](https://developer.riotgames.com/docs/portal) is a
channel for product registration and Developer Relations contact. Its
[League developer guidance](https://developer.riotgames.com/docs/lol) requires
registration for player-serving products even without API use, but the
[API Terms](https://developer.riotgames.com/terms) expressly state that
registration or a production key is not Riot endorsement, certification, or
approval. Portal access cannot satisfy this project's two-point upstream
authorization criterion. Scope-specific written authorization would have to
be independently authenticated and current.

## Sunshine Windows input and release change

Sunshine's [2026-09-15 release](https://github.com/LizardByte/Sunshine/releases/tag/v2026.914.233613),
`v2026.914.233613`, is now marked latest stable. The repository's
[Windows AMD64 inspection lock](../../compatibility/sunshine-windows-amd64.lock.json)
now records that release and the compatible stable Virtual HID Driver
`v2026.914.1218.10`. Their downloaded MSI sizes and SHA-256 digests matched
the official release assets on 2026-09-23, and both MSI Authenticode signatures
were valid. The Sunshine lite ZIP digest was also verified. This was a
read-only asset inspection, with no installation or gameplay test. The
intermediate
[2026-09-06 release](https://github.com/LizardByte/Sunshine/releases/tag/v2026.906.222525)
announced critical security updates and urged an upgrade. For example,
[GHSA-6w33-pjh7-p77c](https://github.com/LizardByte/Sunshine/security/advisories/GHSA-6w33-pjh7-p77c)
rates its input-packet flaw high severity, lists the formerly pinned
`v2026.516.143833` among affected versions, and names `v2026.906.222525` as
patched. The old pin is retired; the historical Raw Input preview release link
also no longer resolves and is not an active candidate.

Sunshine's current [Windows setup documentation](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2getting__started.html)
says its separately installed Virtual HID Driver can deliver normal key
transitions and relative mouse movement, buttons, and scrolling to Raw Input
applications. With this Sunshine release the driver must be version
`2026.914.1218.10` or newer and have an active paid machine license; that
version is an [official stable driver release](https://github.com/LizardByte/libvirtualhid/releases/tag/v2026.914.1218.10).
Unicode and unsupported keys, absolute mouse positioning, and a missing or
unlicensed driver still use Windows input injection or `SendInput`. These are
LizardByte delivery claims, not a Riot statement that League/Vanguard accepts
the input. They supersede the earlier audit's broad rejection of every
software virtual-HID path only as a candidate for separately governed physical
Windows testing. No Riot authorization, physical test, League input result,
or remote-readiness promotion was established here.

## Decision and scorecard effect

The current primary sources reviewed here contain no Riot-published Linux/BSD
client, Vanguard path, or express authorization for this project's proposed
native integration. The local Linux/BSD gameplay gate remains blocked; the
physical Windows and Mac streaming routes remain unvalidated. The 2026-09-22
Riot page warrants this dated research and scorecard refresh, and the Mac
wording warrants explicit manual review.
It does **not** justify a policy, backend, authorization, or score promotion.
Any later Riot support change would need a new source review followed by the
separate evidence required by the readiness contract.
