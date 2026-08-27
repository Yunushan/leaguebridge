# Privacy

LeagueBridge has no telemetry, HTTP client, or upload path during `status`,
`doctor`, `readiness`, or support-bundle creation. Read-only file metadata checks
can still traverse a user-mounted or network-backed filesystem; LeagueBridge
therefore does not promise zero operating-system network I/O. Remote Moonlight
handoffs intentionally use the network.

The project never asks for or stores Riot credentials, session cookies, MFA
codes, Moonlight pairing keys, or Sunshine passwords. Pairing and authentication
remain inside those applications.

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
