# Hardware KVM fallback for Linux and BSD

LeagueBridge's Moonlight route is a software streaming handoff. Riot Vanguard
can reject mouse events arriving through that software input path even when
the physical Windows host, Sunshine, and Moonlight are otherwise healthy. The
current Riot/Moonlight report remains open, and Parsec's own support guidance
now names League of Legends as an example of an anti-cheat that can block its
inputs. A different streaming client is therefore not a demonstrated fix.

When Linux or BSD must remain the active client operating system, the practical
fallback to investigate is a hardware KVM-over-IP device. A KVM with HDMI
capture and USB keyboard/mouse emulation is attached to the **physical** host;
the Linux/BSD user operates the KVM's browser interface. The host still runs
Riot Client, League, and Vanguard locally and unmodified. This is a hardware
access path, not a LeagueBridge Windows/macOS package or a native Linux/BSD
League runtime.

## Safe topology

```text
Linux / FreeBSD / OpenBSD / NetBSD / DragonFly BSD
       trusted browser session
                  |
             private LAN/VPN
                  |
       hardware KVM-over-IP device
       HDMI capture/audio + USB HID
          v
       physical Windows PC or physical Mac
          Riot Client + League + Vanguard
```

PiKVM is one example of this device class. Its documentation describes the
keyboard and mouse as USB devices presented to the target host and its web UI
as the control surface. Some PiKVM V3/V4 models also document HDMI audio in
WebRTC mode; VNC and DIY capture variants may not provide audio. Other
hardware KVMs must be reviewed against their own vendor documentation;
LeagueBridge does not assume that one device behaves like another.

The compatibility manifest records this candidate as
`hardware-kvm-remote`. That entry is deliberately `handoff-only`, denied, and
unverified: it makes the route auditable without treating a KVM device as an
authorized League backend. `leaguebridge remote kvm` checks that manifest
entry and the selected physical-host handoff contract before opening the
device UI. The selected route comes from the configuration, or from
`--route windows|macos` when no configuration route is being used.

To avoid repeating the device endpoint, store only its clean URL (never a
login or session token) in the normal credential-free configuration:

```sh
leaguebridge config init --host gaming-pc.local \
  --kvm-url https://kvm.lan/ --confirm-physical-host
leaguebridge remote kvm --config ~/.config/leaguebridge/config.json \
  --acknowledge-unverified-handoff
```

The acknowledgement is intentionally per-operation and is never stored.

`remote kvm` discovers `xdg-open`, `gio`, or `sensible-browser` first. If a BSD
desktop does not provide one of those helpers, select an installed allowlisted
browser directly, for example:

```sh
leaguebridge remote kvm --browser firefox --url https://kvm.lan/ \
  --confirm-physical-host --acknowledge-unverified-handoff
```

Direct-browser mode passes only the clean KVM URL; it does not accept profile,
extension, script, or arbitrary command arguments.

The command remains attached while a newly started browser is running, with no
60-second session deadline. Close the browser or interrupt the command when
finished. An opener that hands the URL to an existing browser may exit sooner.

If the physical host supports Wake-on-LAN, the wake and browser launch can be
combined after the endpoint is configured:

```sh
leaguebridge remote kvm --config ~/.config/leaguebridge/config.json \
  --wake-mac 00:11:22:33:44:55 --wake-wait 30 \
  --acknowledge-unverified-handoff
```

The packet is sent once before the browser is opened, and the wait defaults to
15 seconds with a 300-second maximum. `--wake-broadcast` and `--wake-port`
select a directed/unicast destination or non-default UDP port. The MAC remains
invocation-only; `--dry-run --json` shows the normalized wake plan without
opening the KVM UI or sending network traffic.

## Operator procedure

1. On the physical host, install League and complete a direct local Practice
   Tool session first. Do not use a VM, Dockur, QEMU/KVM guest, bhyve guest, or
   a host with virtualization concealed.
2. Connect the KVM's HDMI capture/audio input to the host's display output and
   its USB HID link to a host USB port. If the device supports audio, select
   its documented WebRTC/multimedia mode and configure the physical host to
   send stereo audio to the KVM HDMI sink. Use the device's normal keyboard
   and mouse functions; do not install a custom Windows kernel driver or patch
   Vanguard.
3. Put the KVM management UI on a private, access-controlled LAN or VPN. Use
   HTTPS where the device supports it, change default credentials, update the
   device from its signed vendor channel, and never expose its management UI
   directly to the public Internet.
4. From the Linux/BSD desktop, open the KVM UI in a trusted browser and confirm
   that the captured display, keyboard, mouse, and audio are all working in the
   host desktop. For PiKVM, use WebRTC with multimedia enabled and a non-zero
   volume; do not treat VNC or a DIY capture path as an audio-capable result.
   Keep the KVM and host input sessions single-user; do not run a second
   software input injector at the same time.
5. Start League on the physical host and validate only a non-valuable account
   in Practice Tool or a custom game. Stop if Vanguard, Riot Client, or League
   reports an error, or if input behavior is unexpected. A working desktop
   cursor is not proof that in-game input is accepted.
6. If the KVM route is stable, record the exact device firmware, host patch,
   client OS/architecture, video mode, audio path, and observed input/latency
   results as route-bound evidence. Do not copy credentials, PINs, session
   tokens, or private KVM URLs into a support bundle.

## Scope and prohibited workarounds

This fallback avoids the known `SendInput`-style software streamer path, but it
does **not** establish Riot authorization or guarantee Vanguard acceptance. It
must remain a manually validated candidate until current, route-bound evidence
exists. The project must not advertise it as a supported League backend merely
because the KVM presents a USB HID descriptor.

Do not use USB/IP, an unapproved software virtual-HID driver, kernel input
interception, mouse-event rewriting, Vanguard service changes, DLL overrides,
VM concealment, or copied Riot components. Those actions change the anti-cheat
trust boundary and are outside LeagueBridge's safety policy. The official
Sunshine Raw Input candidate is documented separately in
[`REMOTE_PLAY.md`](REMOTE_PLAY.md); it is not part of this hardware-KVM route
and is not Riot authorization. If the physical host requires a real locally
attached mouse or keyboard, use that hardware or stop the session; do not
attempt to make software input look physical.

The existing `remote stream` command remains useful for video/audio and for
non-Vanguard applications, but do not assume that its mouse or keyboard path
will provide League gameplay. Keep the hardware-KVM browser session separate
from Moonlight input, and use the KVM's own video when it is the selected
input/control path.

## References

- [Riot Vanguard third-party application FAQ](https://www.riotgames.com/en/DevRel/vanguard-faq)
- [RiotVanguard/Vanguard issue #70: Moonlight/Sunshine mouse input](https://github.com/RiotVanguard/Vanguard/issues/70)
- [Parsec: mouse and keyboard issues with anti-cheats](https://support.parsec.app/hc/en-us/articles/32381827815188-Mouse-and-Keyboard-Isn-t-Working-Correctly-When-Connected)
- [PiKVM USB configuration](https://docs.pikvm.org/usb/)
- [PiKVM two-way audio](https://docs.pikvm.org/audio/)
- [PiKVM V4 quickstart](https://docs.pikvm.org/v4/)
