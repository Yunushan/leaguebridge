# Platform scope

LeagueBridge is a Linux/BSD client project. Its supported installation and
runtime targets are Linux, FreeBSD, OpenBSD, NetBSD, and DragonFly BSD on
amd64.

Windows and macOS are not LeagueBridge gameplay targets. League, Riot Client,
and Vanguard remain vendor-managed software on those operating systems. The
repository must not install, redistribute, patch, or emulate them, and a
Windows or macOS build of the LeagueBridge CLI must not be presented as
League support.

The only reason those operating systems may appear in the repository is as an
explicitly external host in the optional Moonlight handoff model: the
Linux/BSD machine is the client, while the user separately owns and validates
the physical host with Riot's unmodified software. That handoff is not local
Linux/BSD gameplay, does not raise the local support score, and is not a
substitute for an authorized native Linux/BSD runtime.

Accordingly:

- Linux/BSD builds, installers, diagnostics, and client runtime evidence are
  product work.
- Windows/macOS package installation and native gameplay validation are out of
  scope for LeagueBridge.
- Portable code or route-contract checks that mention Windows/macOS are
  non-support safety checks only; they must never be counted as Linux/BSD
  gameplay evidence.
- Wine, Proton, copied DLLs, VM concealment, and anti-cheat workarounds remain
  denied regardless of host operating system.
