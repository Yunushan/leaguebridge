# Privacy

LeagueBridge has no telemetry, HTTP client, or upload path during `status`,
`doctor`, default `readiness`, or support-bundle creation. Read-only file metadata checks
can still traverse a user-mounted or network-backed filesystem; LeagueBridge
therefore does not promise zero operating-system network I/O. Remote Moonlight
handoffs intentionally use the network.

The explicit `readiness verify-release` command makes read-only GitHub API and
attestation requests through the selected GitHub CLI executable. It uses that
executable's existing authentication and trust configuration. GitHub receives
the repository, release, workflow, and artifact identities being verified;
local release archives and CI evidence are not uploaded. Use a trusted `gh`
executable. The command creates a temporary local copy of release files for
verification and removes it when the invocation ends. Its output contains
public source and run identities, scores, and observation timestamps; it is
not a reusable authorization record.

The project never asks for or stores Riot credentials, session cookies, MFA
codes, Moonlight pairing keys, or Sunshine passwords. A Moonlight pairing PIN
may be passed to one live `remote pair` invocation when explicitly supplied,
but it is never persisted or emitted in dry-run JSON. Pairing and
authentication remain inside those applications. A bounded `remote
stream --qt-platform` value may
set `QT_QPA_PLATFORM` for the child Moonlight process only; it is not persisted
and does not modify the parent shell environment.

Validation-evidence records are user-authored local files. LeagueBridge reads
them only when explicitly named, requires regular non-symlink bounded files,
and never uploads them. Record only redacted environment descriptions and
artifact references. Do not put account names, Riot IDs, hostnames, network
addresses, device serials, pairing PINs, tokens, screenshots containing private
data, or credentials into a record or its review artifacts.

Diagnostic reports are generated from an allowlist of non-sensitive capability
facts. Raw environment dumps, process lists, registry exports, Riot logs, browser
data, and home-directory contents are not collected. Defense-in-depth redaction
removes common tokens, email addresses, user paths, and network identifiers.

Bundles are written only on explicit request, are size-bounded, and refuse to
overwrite an existing file. Unix builds request mode 0600; Windows builds inherit
the destination directory's DACL and do not claim owner-only access. Always
preview a bundle and inspect both its contents and access controls before sharing
it. Exclusive no-overwrite publication requires hard-link support. If a USB,
network, or cloud filesystem does not provide it, create the bundle on a local
supported filesystem and copy it only after inspection. Sharing is a manual user
action; LeagueBridge does not upload bundles.
