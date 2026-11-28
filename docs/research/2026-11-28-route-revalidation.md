# Route revalidation — 2026-11-28

This record updates the [2026-09-23 route revalidation](2026-09-23-route-revalidation.md)
against publisher pages observed on 2026-11-28. It assesses published support
and authorization, not whether LeagueBridge or League ran on any host. No new
physical-host, streaming, Vanguard, or gameplay test was performed.

## Riot platform and anti-cheat status

Riot's [League system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends)
still carry the **2026-09-22** date and still say League is supported only on
Windows and macOS, naming Linux, SteamOS, and Bazzite as unsupported. The
Windows table is unchanged: retail Windows 10 build 19041 or newer or
Windows 11 on x64, TPM 2.0 for Windows 11, and no ARM support.

The Mac table still lists macOS 12, Apple M1, and a Metal-capable GPU, and the
architecture prose remains inconsistent between an Intel-only sentence and a
note that Intel Macs receive reduced troubleshooting. The page now also
announces that **from 2027-01-05 League will require macOS 13 or later**. That
upcoming Riot floor stays below Sunshine's current macOS 14.2 host minimum, so
the handoff's practical OS floor is unchanged. Each proposed physical Mac must
still be checked against Riot's then-current requirements; this wording grants
no readiness credit.

Riot's [VAN 138 guidance](https://support.riotgames.com/en-us/riot/performance/error-van-138)
(dated 2026-07-14) and [VAN 9100 guidance](https://support.riotgames.com/en-us/riot/client/error-van-9100)
(dated 2026-07-16) still state that Vanguard is not supported in virtual
machines or unsupported virtualized environments and direct players to a
regular Windows installation. The [Vanguard FAQ](https://support.riotgames.com/en-us/league-of-legends/performance/riot-vanguard-faq-league-of-legends)
(dated 2026-06-02) still requires Vanguard to be running to play League. The
[Vanguard On-Demand announcement](https://www.riotgames.com/en/news/vanguard-on-demand)
(2026-06-24), the [Vanguard x LoL explanation](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/)
(2024-04-11), [Patch 14.9 notes](https://www.leagueoflegends.com/en-us/news/game-updates/patch-14-9-notes/),
[Patch 25.S1.2 notes](https://www.leagueoflegends.com/en-ph/news/game-updates/patch-25-s1-2-notes/),
and the [third-party Vanguard FAQ](https://www.riotgames.com/en/DevRel/vanguard-faq)
all remain available with the dates previously recorded. None of these
sources grants a Linux/BSD, Wine, Proton, or VM exception.

Riot's [Developer Portal](https://developer.riotgames.com/docs/portal),
[League developer guidance](https://developer.riotgames.com/docs/lol), and
[API Terms](https://developer.riotgames.com/terms) remain available; the terms
still contain their "No Partnership or Endorsement" section. Portal
registration therefore still cannot satisfy the upstream authorization
criterion.

## Sunshine, Moonlight, and other sources

Sunshine's latest stable release remains
[`v2026.914.233613`](https://github.com/LizardByte/Sunshine/releases/tag/v2026.914.233613),
and the libvirtualhid driver remains
[`v2026.914.1218.10`](https://github.com/LizardByte/libvirtualhid/releases/tag/v2026.914.1218.10).
The LizardByte release URLs now redirect to the `SunshineStream/Sunshine`
repository. GitHub's published SHA-256 digests for the Windows AMD64 Sunshine
MSI, Sunshine lite ZIP, and driver MSI matched the
[Windows AMD64 inspection lock](../../compatibility/sunshine-windows-amd64.lock.json)
on 2026-11-28. This was a metadata comparison only: no asset was downloaded,
no Authenticode signature was re-inspected, and the lock's own
`source_checked_at` date is intentionally unchanged.

[GHSA-fp6g-27w5-489j](https://github.com/LizardByte/Sunshine/security/advisories/GHSA-fp6g-27w5-489j),
a high-severity Linux capability escalation published 2026-09-15, lists
`v2026.914.233613` as the patched version, so the pinned release is not
affected.

Sunshine's stable
[getting-started documentation](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2getting__started.html)
still calls the macOS host experimental and says gamepads do not work, and
the [stable overview](https://docs.lizardbyte.dev/projects/sunshine/latest/)
still lists macOS 14.2 or newer. Its Windows section still describes the paid,
licensed Virtual HID Driver (version 2026.914.1218.10 or newer) for Raw Input
keyboard and mouse delivery, with `SendInput` fallback. The unreleased
[`master` documentation](https://docs.lizardbyte.dev/projects/sunshine/master/md_docs_2getting__started.html?lng=en-US)
renames the component to "Virtual HID Broker", describes licensed macOS
virtual gamepads through it, and says prebuilt macOS DMGs will require
macOS 15.0. Those statements describe unreleased work and do not change the
reviewed stable route. They should be rechecked when a new stable Sunshine
release ships.

Moonlight Qt has a newer
[v6.2.0 release](https://github.com/moonlight-stream/moonlight-qt) (2026-10-04);
the project pins no Moonlight version, so this changes no recorded claim.
The [Proton](https://partner.steamgames.com/doc/steamhardware/proton),
[dockur/windows environment](https://github.com/dockur/windows/blob/master/docs/environment.md),
[Microsoft BCDBoot](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di?view=windows-11),
[FreeBSD bhyve](https://docs.freebsd.org/en/books/handbook/virtualization/#virtualization-host-bhyve),
and PiKVM [API](https://docs.pikvm.org/api/), [USB](https://docs.pikvm.org/usb/),
[authentication](https://docs.pikvm.org/auth/), and
[audio](https://docs.pikvm.org/audio/) pages all remain available.

## Decision and scorecard effect

The current primary sources reviewed here contain no Riot-published Linux/BSD
client, Vanguard path, or express authorization for this project's proposed
native integration. The local Linux/BSD gameplay gate remains blocked; the
physical Windows and Mac streaming routes remain unvalidated. This review
renews the compatibility manifest's dated sources and warrants a scorecard
validity refresh. It does **not** justify a policy, backend, authorization, or
score promotion, and the six externally evidenced engineering rows remain at
zero.
