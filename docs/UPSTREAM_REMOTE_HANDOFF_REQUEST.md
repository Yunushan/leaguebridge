# Riot inquiry: physical Windows remote handoff to Linux and BSD

**Status: draft; not submitted; not authorization.** This asks Riot for a
scope-specific written determination. It does not claim that a physical test
host exists or that Riot permits streamed play.

Riot's current [League system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends)
support Windows and macOS, not Linux or BSD. Riot's [Vanguard third-party FAQ](https://www.riotgames.com/en/DevRel/vanguard-faq)
says Developer Relations cannot grant a Vanguard allowlist or exception.
Register the product through the [Developer Portal](https://developer.riotgames.com/docs/portal)
and use the signed-in [Developer Relations request form](https://support-developer.riotgames.com/hc/en-us/requests/new)
for this inquiry. A portal registration or support reply alone is not
authorization for any scope Riot has not expressly approved.

## Facts to confirm before sending

- Confirm the maintainer's name and registered Developer Portal product ID.
- Confirm whether an eligible physical retail Windows 11 PC is actually
  available, its Windows version and hardware, and which Riot/Vanguard checks
  it passes. Do not describe a proposed host as an observed one.
- Confirm whether a physical Fedora 44 viewer exists and record a privacy-safe
  machine pseudonym, CPU architecture, kernel, desktop/display path, and
  installed Moonlight version. Fedora 44 is a proposed first Linux client,
  not a tested result in this document.
- Confirm which BSD client machines, OS versions, and architectures actually
  exist. The nine shipped targets listed below are a release inventory, not
  nine observed physical installations.
- Confirm the Sunshine version and input method on any proposed Windows host,
  including whether its separately licensed Virtual HID Driver is installed.
  Remove the conditional Raw Input question if it is outside the planned test.
- Confirm which shipped viewer-side controls the first test will use. Pairing,
  application listing, streaming, and normal stream exit are proposed; optional
  Wake-on-LAN, unpairing, and host-application quit controls need separate scope.

## Copy-ready inquiry

**Subject:** LeagueBridge: written policy determination for physical Windows
host streaming to Fedora/Linux and BSD viewers

Hello Riot Developer Relations,

I maintain LeagueBridge (https://github.com/Yunushan/leaguebridge), an
open-source Linux/BSD diagnostic and remote-handoff tool. This inquiry concerns
its public [`v0.1.0` release](https://github.com/Yunushan/leaguebridge/releases/tag/v0.1.0).
I seek a written determination on the proposed topology
below before claiming that Riot permits it. If Developer Relations cannot
decide this scope, please direct this request to the Riot team that can.

We propose an operator-owned **physical**, supported retail Windows 11 PC as
the game host. The operator would obtain and update Riot Client, League of
Legends, and Vanguard directly from Riot and keep them unmodified. Sunshine,
installed separately from its publisher, would stream video and audio over a
trusted LAN or private VPN to a separately installed Moonlight client on
Linux/BSD; Moonlight would convey the player's keyboard, mouse, and optional
controller input back to the physical Windows host. LeagueBridge runs only on
the Linux/BSD viewer. Its shipped controls perform diagnostics, pass fixed
pair, application-list, stream, unpair, and quit operations to the installed
Moonlight client, and can send an opt-in standard Wake-on-LAN packet to the
physical host. A live stream first lists Sunshine-published applications and
refuses to start unless the configured League entry is present. Unpairing is
available only with Moonlight Embedded; `remote quit` asks Moonlight to stop
the host application, and opt-in `--quit-after` asks it to stop that application
when the stream ends. The first proposed test would use pairing, listing, a
stream, and normal stream exit. Wake-on-LAN, unpairing, `remote quit`, and
`--quit-after` are outside that first test pending Riot guidance. No specific
Windows host, Fedora 44 viewer, or end-to-end League session is asserted to
exist or work by this request.

The first proposed viewer is Fedora 44 on **[confirm actual physical hardware,
OS build, architecture, and Moonlight version]**. The release also targets
Linux amd64 and arm64; FreeBSD, OpenBSD, and NetBSD on amd64 and arm64; and
DragonFly BSD on amd64. Please assess each BSD OS separately rather than
interpreting a Linux answer as BSD approval. This request covers only the
physical Windows host route; local Linux/BSD League or Vanguard, Windows VMs,
cloud hosts, and the separate macOS handoff are outside it.

LeagueBridge's proposed distribution contains its source, Linux/BSD
executables, native packages, licensed dependencies, and required notices. It
does not bundle Riot Client, League, Vanguard, Riot assets, Sunshine,
Moonlight, credentials, or API keys. We do not propose modifying or bypassing
Riot software, hiding virtualization, reading game memory, intercepting Riot
traffic, scripting play, or calling Riot/League Client/Game Client APIs in this
route. If any implementation detail changes, we will disclose it before
testing or publishing.

Could Riot please determine:

1. Whether this physical-host video/audio/input arrangement is permitted for
   the proposed Fedora/Linux viewer and, separately, each BSD target. What
   host, viewer, account, network, and input constraints apply?
2. Whether ordinary Sunshine/Moonlight user-input forwarding is permitted.
   If we separately propose Sunshine's licensed host-side Virtual HID
   Driver/Raw Input path, is that method permitted, prohibited, or subject to
   additional review? We would identify its exact version before any test and
   would not treat working input as permission.
3. Whether limited, operator-controlled integration tests in Practice Tool
   or a custom game on the physical Windows host are permitted, with an
   independent observer and no automated gameplay. Which test modes, stop
   conditions, and reporting path apply if Riot Client, League, or Vanguard
   rejects the stream or input?
4. Whether we may publish the described LeagueBridge-only binaries and native
   packages, and what product registration, attribution, trademark, or other
   conditions apply. We will not copy, modify, or redistribute Riot software
   or assets without a separate express signed Riot agreement.
5. Whether the shipped viewer-side Wake-on-LAN, Moonlight pairing/unpairing,
   Sunshine application listing, and host-application quit/`--quit-after`
   controls may be used in this physical-host route, and whether any require
   separate review before a later test.

Please state the permitted or disallowed OS/architecture scope, host and
Vanguard prerequisites, input and test methods, distribution terms, effective
date, and any limits or withdrawal process. We would appreciate a response
on a Riot-controlled channel that an independent reviewer can authenticate
and recheck for continued validity. Please indicate whether it may be cited
publicly; if confidential, please identify a way for an independent reviewer
to verify its authenticity and current status without publishing private
correspondence. A clear “not permitted” answer is useful and will keep the
route blocked.

We will not include account identifiers, passwords, tokens, machine secrets,
or private diagnostic bundles in this inquiry.

Thank you,

**[Maintainer name; registered Developer Portal product ID]**

## Review boundary

This draft concerns the remote physical-host route only. The separate
[local Linux/BSD runtime request](UPSTREAM_LINUX_BSD_REQUEST.md) remains a
different question. Riot's [Terms of Service](https://www.riotgames.com/en/terms-of-service)
require an express signed written contract for distribution of Riot Services
or code. The [Developer Portal FAQ](https://developer.riotgames.com/docs/faqs)
says new inquiries should use its support site. Riot's
[Vanguard third-party FAQ](https://www.riotgames.com/en/DevRel/vanguard-faq)
states that Developer Relations cannot grant Vanguard exceptions. A support
ticket, product approval, working
stream, or signed reply outside its explicit scope must not be counted as
authorization.
