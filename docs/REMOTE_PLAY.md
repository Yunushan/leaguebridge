# Remote play from Linux and BSD

LeagueBridge implements two remote handoff routes from Linux/BSD clients: a
physical Windows host and an explicitly unvalidated physical Mac host. Neither
route is local Linux/BSD compatibility, and neither is a Riot endorsement of
remote play.

## Topology

```text
Linux / FreeBSD / OpenBSD
NetBSD / DragonFly BSD (runtime unverified)
        Moonlight client
            |
       trusted LAN or VPN
            |
physical Windows 11 gaming PC
   Sunshine + official Riot software + Vanguard

                    or

physical Intel or Apple-silicon Mac
   Sunshine (experimental host) + Riot's native macOS client
```

Do not use a cloud VM, Dockur, QEMU/KVM, bhyve, or another virtualized host.
For the Windows route, do not use Windows Server or Windows Enterprise. Riot's
current Windows requirements call for ordinary supported Windows, and Vanguard
reports a VM-specific error. The macOS route likewise requires a user-confirmed
physical Mac; LeagueBridge does not attempt to hide or spoof virtualization.

## Physical Windows host preparation

1. Use an activated physical Windows PC that satisfies Riot's current
   [system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends).
2. Install League only from Riot and confirm a direct local Practice Tool session
   works before adding streaming.
3. Install Sunshine from its
   [official project](https://github.com/LizardByte/Sunshine), bind its management
   interface safely, and add either Desktop or a League launcher entry.
4. Keep the host on a trusted LAN or private VPN. Do not expose Sunshine's web UI
   directly to the public internet.

Run `leaguebridge doctor --profile windows-host` as a bounded checklist, but do
not expect certification from it. The alpha doctor deliberately exits with
blocked code 3 whenever physicality, hardware, TPM/IOMMU, or active Vanguard
state remains unprovable; today at least one of those manual gates is always
unverified. Complete Vanguard's own per-machine pre-check and the local Practice
Tool validation instead of treating probe output as Riot or hardware approval.

### Read-only Sunshine inspection

The repository pins the official Windows AMD64 asset metadata checked on 26
August 2026 in
[`compatibility/sunshine-windows-amd64.lock.json`](../compatibility/sunshine-windows-amd64.lock.json).
The supported inspector path is the MSI that Sunshine documents as its preferred
Windows package. The portable ZIP is recorded only as an integrity reference;
Sunshine describes that package as a reduced-performance, unsupported lite
option, so it is not accepted by this workflow.

From a trusted source checkout on the physical Windows host, run the inspector
only after verifying the outer Windows release ZIP and `checksums.txt` as
described in [Packaging and release process](PACKAGING.md). Then read the
`leaguebridge.exe` payload SHA-256 from the verified ZIP's inner
`PACKAGE-MANIFEST.json`: require the sole payload entry whose `archive_path` is
exactly `leaguebridge.exe`, `role` is exactly `executable`, and `mode` is exactly
`0755`; independently confirm that the extracted executable's size and SHA-256
match that entry, then pass its lowercase digest to the inspector. The outer
`checksums.txt` contains archive digests, not the executable digest. Place the
MSI and executable on a fixed local drive in
directories whose entire ancestor chain is non-reparse and not writable by
untrusted users; do not use a network share, junction, symlink, or shared
download directory:

```powershell
powershell -NoProfile -File .\scripts\inspect-sunshine-host.ps1 `
  -ConsentToReadOnlyInspection `
  -ArtifactPath 'C:\LeagueBridge-Inspection\Sunshine-Windows-AMD64-installer.msi' `
  -LeagueBridgePath 'C:\LeagueBridge-Inspection\leaguebridge.exe' `
  -ExpectedLeagueBridgeSha256 '<lowercase leaguebridge.exe SHA-256 from PACKAGE-MANIFEST.json>' `
  -Json
```

The consent applies only to reading the two files, computing their hashes,
checking the MSI's Windows Authenticode status, and invoking the fixed
`doctor --profile windows-host --json` probe. The script neither downloads nor
executes Sunshine and never installs software, starts or changes a service,
opens a firewall port, changes security settings, or handles credentials. It
always reports `installation_authorized: false` and `launch_authorized: false`
and exits blocked (3), even when artifact integrity succeeds. Review the output
before retaining it as a validation artifact; it is not proof of a physical
machine or permission to proceed.

The inspector rejects UNC paths, mapped/network and non-fixed drives, and
reparse points in either file's full ancestor chain. It holds each verified leaf open with write/delete sharing
denied throughout all path-based inspections, and through LeagueBridge doctor
execution. Windows does not provide a security boundary between mutually
untrusted processes running as the same account: use a clean dedicated session
and ACL-restricted local directories if that threat is relevant.

The inspector also opens the MSI database in mode 0 (read-only) and reports the
`Property`, `CustomAction`, `ServiceInstall`, `ServiceControl`, `Registry`, and
`Environment` tables. Treat custom-action targets as inert data; the inspector
does not invoke them. For the pinned MSI, service tables are absent and service
or firewall work is delegated to Sunshine's setup custom action, so the MSI
tables alone cannot enumerate every machine change. The reported uninstall and
rollback action names are a review aid, not permission to execute them. The
supported rollback route remains Windows Installed Apps/Apps & features using
Sunshine's signed uninstaller, after a separate user decision and after
credentials or evidence have been retained or removed as intended.

For the pinned v2026.516.143833 MSI, the read-only inventory currently reports
14 properties, 9 custom actions, 5 registry rows, and no `ServiceInstall`,
`ServiceControl`, or `Environment` table. `ALLUSERS=1` requests a per-machine
installation. The custom actions explicitly call the packaged
`scripts\sunshine-setup.ps1` with `install`, `uninstall`, and silent variants;
the registry rows target `Software\LizardByte\Sunshine`, while the WiX actions
create and roll back internet shortcuts. Because the setup script—not the
declarative service tables—owns additional setup, a reviewer must treat service,
firewall, and optional driver effects as unresolved until they inspect the
selected installer options and vendor setup implementation. Do not infer safety
from the empty service tables.

Installation is a separate, user-authorized operation. Before granting that
authorization, recheck the pinned tag and digest against Sunshine's official
release page, confirm the machine is physical and supported, review every MSI
option, and decide the required private-network firewall scope. Configure
Sunshine credentials and Moonlight pairing directly in those applications;
never place passwords, PINs, account identifiers, or pairing material in
LeagueBridge output or evidence.

## Physical macOS host preparation (experimental and unvalidated)

The `physical-macos-remote` route is implemented only as a Moonlight handoff.
League itself must run unmodified through Riot's native macOS client on a
user-owned physical Mac. Sunshine documents macOS 14.2 or newer as an
experimental host, with gamepad hosting unavailable. LeagueBridge has no real
Mac evidence for capture, audio, keyboard/mouse, session quality, or gameplay,
so this route remains `handoff-only`, `deny`, and `unverified` in the embedded
manifest.

Before separately authorizing any installation or launch on the Mac:

1. Confirm the physical Intel or Apple-silicon Mac meets Riot's current native
   macOS requirements.
2. Install Riot Client and League only from Riot, then complete a direct local
   Practice Tool session.
3. Review Sunshine's current official macOS documentation, experimental limits,
   permissions, and rollback instructions. Configure credentials and pairing
   only inside Sunshine and Moonlight.
4. Keep the host on a trusted LAN or private VPN; do not expose Sunshine's web
   interface directly to the public internet.

`leaguebridge doctor --profile macos-host` is intended to run on the Mac, not on
the Linux/BSD client. It performs only passive application-directory and PATH
discovery; it runs no subprocesses and does not read credentials or application
contents. It accepts Darwin `amd64` and `arm64`, but always exits blocked because
physicality, macOS version, hardware, permissions, Sunshine behavior, and a
local Practice Tool session require manual evidence.

No Darwin release archive has yet been published. The release contract now
defines deterministic Darwin amd64 and arm64 diagnostic archives and hosted
native lifecycle jobs. Until an attested tagged release exists, a reviewer can
build the current checkout natively on the Mac with a supported Go toolchain,
or cross-build a diagnostic binary for transfer to the Mac:

```sh
GOOS=darwin GOARCH=amd64 go build -mod=vendor -o leaguebridge-darwin-amd64 ./cmd/leaguebridge
GOOS=darwin GOARCH=arm64 go build -mod=vendor -o leaguebridge-darwin-arm64 ./cmd/leaguebridge
```

Cross-compilation and hosted CI prove only their exact build and lifecycle
observations. They do not validate a physical Mac, Sunshine, League, or remote
gameplay; those gates require separate authenticated physical-host evidence.

## Client preparation

- Linux: use Moonlight Qt from the project's documented Flatpak, Snap, AppImage,
  or trusted distribution package.
- FreeBSD: `pkg install moonlight-qt` or `pkg install moonlight-embedded`; the
  official ports tree contains [Moonlight Qt](https://cgit.freebsd.org/ports/tree/games/moonlight-qt).
- OpenBSD: install the `games/moonlight-qt` package/port from the
  [official ports tree](https://cvsweb.openbsd.org/ports/games/moonlight-qt).
- NetBSD: current pkgsrc contains
  [`games/moonlight-qt`](https://cdn.netbsd.org/pub/pkgsrc/current/pkgsrc/games/moonlight-qt/index.html)
  at source version 4.3.1nb23 and publishes x86_64 binary packages.
- DragonFly BSD: current DPorts contains
  [`games/moonlight-qt`](https://github.com/DragonFlyBSD/DPorts/tree/master/games/moonlight-qt)
  at version 6.1.0.

NetBSD and DragonFly BSD package availability was checked on 26 August 2026.
Neither platform has a completed LeagueBridge native runtime validation, so the
entries above are availability evidence—not support or gameplay claims.

LeagueBridge discovery uses `LookPath` only and never starts a candidate client.
The executable path is normalized and checked as a regular executable, and the
production handoff binds its private plan provenance to that discovery result;
hand-built or replayed JSON plans cannot substitute a launcher.
`auto` treats a generic `moonlight` executable as Embedded on FreeBSD and
DragonFly BSD, and as Qt elsewhere. On Linux, explicitly set `client` to
`moonlight` for Moonlight Embedded; select `moonlight-qt` when a downstream Qt
package uses the generic binary name. When only the trusted Flatpak launcher is
available, set `client` to `flatpak`; LeagueBridge uses the fixed
`flatpak run com.moonlight_stream.Moonlight` prefix and does not execute a
shell.

Create a credential-free schema-v2 config for the intended host route, set the
host, and confirm `physical_host_confirmed` only when it truly is physical.

```sh
# Choose one route. Record physicality only after checking the named machine.
# Windows host (the backward-compatible default)
leaguebridge config example --route windows
leaguebridge config init --route windows --host gaming-pc.local --confirm-physical-host

# Experimental, unvalidated macOS host
leaguebridge config example --route macos
leaguebridge config init --route macos --host gaming-mac.local --confirm-physical-host
```

[Configuration schema v2](../schemas/config.schema.json) stores one exact
`route_id` and one `remote_host`; it has no parallel Windows/macOS target
fields. Existing schema-v1 Windows configs are accepted strictly and normalized
in memory, while newly written configs always use v2. The Go runtime remains the
security authority for duplicate keys, byte limits, host syntax, and safe file
handling.

```sh
leaguebridge remote pair
leaguebridge remote list
leaguebridge remote stream --acknowledge-unverified-handoff
```

Stop immediately if Riot Client, Vanguard (on Windows), or other Riot software
reports an error. Do not try to hide the streaming software, patch input, or
work around an anti-cheat control. Validate first with a non-valuable account
and Practice Tool/custom game; public matchmaking remains a manual user
decision.
