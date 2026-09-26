# Stable-release native package candidates

This workflow builds **score-free package candidates** for the fixed eleven
native package cells. It does not sign or publish them and does not award either
native package readiness row. The published GitHub release still has exactly
nine portable archives and `checksums.txt`; native packages belong in a
separately approved channel.

## Prepare release inputs on a connected verifier

Use a trusted `nativepackagestage` binary from this checkout and a trusted,
authenticated `gh`. Run from the directory containing the downloaded CI
attestation subjects required by `releaseassessment.VerifyForProduction`:

```sh
nativepackagestage release-set \
  --version v0.1.0 --release-dir /path/to/ten-release-files \
  --output /path/to/new-release-set --gh /path/to/trusted-gh
```

`release-set` rechecks the live release and writes eleven complete staging
trees. Its JSON plan is a locator and records every package as `unbuilt`.
Transfer the complete ten-file release directory and eleven-cell staging set
to each build guest through a controlled channel. The native guest treats those
copies as local, untrusted inputs; the final connected verifier authenticates
them again.

## Build on matching native hosts

Use the matching Linux amd64/arm64 host or a disposable FreeBSD, OpenBSD,
NetBSD, or DragonFly BSD guest. The trusted checkout named by `--repo` must
contain the reviewed smoke scripts. The binary itself must run natively on the
host. Linux needs the repository's Go toolchain, package tools, and
passwordless `sudo -n` for private package-manager install tests. BSD needs a
native Go toolchain or a native `versioncheck` executable passed via
`--version-checker`.

```sh
nativepackagestage candidate-host \
  --version v0.1.0 --release-dir /guest/ten-release-files \
  --inputs /guest/release-set --repo /guest/leaguebridge \
  --output /guest/new-host-output
```

For BSD, add `--disposable-guest` and, if Go is absent, `--version-checker
/guest/versioncheck`. The BSD smoke builders install and remove files under
`/usr/local` and may require root. Run them only in a fresh disposable guest.
`candidate-host` verifies local archive and staging consistency, runs the
existing package builder and install/uninstall smoke, checks the resulting
package file inventory and hashes, and publishes a complete host output in a
new directory. It **does not authenticate the live release** or inspect all
native package payload formats.

## Verify the exact eleven-package set

Collect only the `native-package-output` directories from successful host
outputs into a fresh merged directory. Preserve the paths
`native-package-output/<family>/<goarch>/<package filename>` and do not
overwrite a previously copied file. Do not include the host install logs or
completion markers in this merged package directory. The verifier rejects
missing, duplicate-path, symlinked, unexpected, or non-regular package files.
Run on a connected trusted verifier from the CI evidence directory:

```sh
nativepackagestage candidate-set \
  --version v0.1.0 --release-dir /path/to/ten-release-files \
  --inputs /path/to/release-set --packages /path/to/merged \
  --output /path/to/new-candidate-set.json --gh /path/to/trusted-gh
```

The command authenticates the live release, rechecks every release-set cell,
derives ephemeral candidate metadata from the exact package bytes, calls
`productionpackage.VerifyPayloadSet` for all eleven cells, then rechecks the
release and package digests. It writes an exclusive canonical JSON record of
the observed release identity and eleven SHA-256 package digests. This record
is score-free descriptive data, not a reusable authentication token. A future
publisher must independently bind the exact
bytes it signs and uploads to approved package-family signing keys and live
index records, and must observe installation and withdrawal through that
channel. Green candidate verification alone does not establish any of those
facts.
