# Release packaging contract

LeagueBridge publishes exactly eight target-native executable archives: Linux,
FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and Windows on amd64, plus Darwin on
amd64 and arm64. The Linux, BSD, and Darwin archives are portable tarballs with
an unprivileged staging interface; they are not represented as
distribution-owned Debian, RPM, FreeBSD ports, OpenBSD ports, pkgsrc, dports,
or macOS installer packages.

## Canonical package manifest

Every archive contains a schema-version 2 `PACKAGE-MANIFEST.json`, conforming to
`schemas/package-manifest.schema.json`. It binds the archive to:

- the exact release version, target operating system, architecture, required
  kernel, archive filename, and format;
- the exact release source commit and tree object IDs, `SOURCE_DATE_EPOCH`,
  production Go builder, and fixed build-affecting Go environment;
- every non-manifest payload member by role, mode, size, and SHA-256; and
- the default Unix install prefix and exact installed paths.

The manifest declares `validation_scope: artifact-integrity-only`. It cannot be
used as evidence that League gameplay, remote input, a native kernel, or a
package manager was tested. Top-level release checksums bind the manifest itself
to its containing archive, avoiding a self-hash cycle.

`tools/releasecheck` reconstructs the expected manifest from the
archive bytes and rejects any mismatch. It also rejects missing, additional,
duplicate, reordered, oversized, symlink, special-file, mode, owner, timestamp,
target, SBOM, provenance, build-ID, and checksum deviations. Executable
container identity is target-bound: exact ELF class/data/type/machine/OSABI,
PE machine/PE32+/executable/subsystem, and thin Mach-O magic/CPU/type fields are
checked independently of Go build information.

## Reproducible production builder

Production releases require Go `go1.27.0` exactly. Go 1.24 remains the minimum
source-compatibility test and is not an authorized release builder. The builder
version is checked in three places:

1. `scripts/release.sh` refuses another toolchain before changing `dist`.
2. The structured Go build-ID v4 contract binds the exact builder version,
   commit, tree, target, epoch, architecture tuning (`GOAMD64=v1` or
   `GOARM64=v8.0`), and approved compiled dependency identity.
3. `tools/releasecheck` checks Go build information and the package manifest.

The release process disables persistent Go configuration with `GOENV=off`,
`GOWORK=off`, empty `GOFLAGS`, `GOEXPERIMENT`, `GOCACHEPROG`, `GONOPROXY`,
and `GONOSUMDB`, fixed `GOFIPS140=off`, `GO_EXTLINK_ENABLED=0`, and
`GOTOOLCHAIN=local`; module proxy, checksum-database, and VCS fetching are
disabled with `GOPROXY=off`, `GOSUMDB=off`, and `GOVCS=*:off`. Every release
`go build` and `go run` explicitly use `-mod=vendor` against the committed
vendor tree. Before any other snapshot-local Go command, `tools/vendorcheck`
validates the exact `go.mod`, `go.sum`, `vendor/modules.txt`, directory set, and
path/size/SHA-256 inventory beneath `vendor/`; any drift fails the release.
The release executable has exactly one approved compiled external
module: `filippo.io/edwards25519` v1.2.0, without a replacement. The v4 build
identity binds its exact module checksum token from `go.sum` as well as the
source tree containing the vendor bytes. Go's vendored build information
records the dependency path and version but not its checksum, so the binary
verifier requires that exact path and version with an empty build-information
sum and rejects replacements or additional compiled modules. Other modules in
`go.mod` and the vendor tree support repository schema tests and are not
compiled into the release executable. The release process checks a clean
`HEAD`, rejects gitlinks, symlinks, and archive-affecting
`export-ignore`/`export-subst` attributes. It rejects every `.gitmodules` path
except the exact inert file generated at
`vendor/github.com/santhosh-tekuri/jsonschema/v6/.gitmodules`; that exception is
accepted only because the complete vendor lock verifies its path and bytes.
The process then exports the exact commit with `git archive` into a private
temporary snapshot. Builds use that snapshot with `-buildvcs=false`; compiled binaries
must contain no VCS settings, unexpected build settings, dependency other than
the exact approved module, or module replacement. Only completed archives and
`checksums.txt` are written to the original absolute `dist` directory.

Every release Git command disables replacement objects both through
`GIT_NO_REPLACE_OBJECTS` and Git's `--no-replace-objects` option. System and
global Git configuration and attributes are replaced with private empty files,
system attributes are disabled, ambient command-scope configuration and
attribute-source overrides are cleared, and `core.attributesFile` is overridden
for each command. Because Git has no switch that disables
`$GIT_DIR/info/attributes`, the release refuses to run when that path exists
(including as a symlink). These controls ensure that only attributes committed
in the bound tree can influence the exported snapshot. The reproducibility
driver establishes the same boundary before deriving its default epoch, commit,
or tree, so a replacement commit cannot silently supply different metadata even
when it points to the same tree.

Before replacing `dist`, `tools/readinesscheck` validates the snapshot's public
and embedded readiness scorecards and hashes every awarded repository-evidence
file. The builder then injects a value bound to the exact verified scorecard.
Every shipped binary must contain both those exact scorecard bytes and the
matching build-time verification value, or `tools/releasecheck` rejects it. Ad
hoc/dev builds omit the value and user-facing commands report zero
repository-backed points. This is a production verification state, not a
publisher signature or substitute for the outer GitHub artifact attestation.

`scripts/verify-release-reproducible.sh` builds the complete release twice,
strictly verifies both builds, exercises the Linux installation lifecycle, and
requires byte-identical archive checksums.

The Windows ZIP is emitted by `tools/canonicalzip` with exact Deflate, DOS-time,
mode, version, flag, and header rules. Linux, BSD, and Darwin tarballs are
emitted by `tools/canonicaltar` with exact USTAR metadata and a canonical gzip
header. Release generation therefore does not depend on host-specific archive
utilities or their changing defaults. `tools/releasecheck` reconstructs the
canonical ZIP and tar.gz bytes and rejects alternate compression streams,
headers, or metadata.

`SBOM.spdx.json` is a canonical SPDX 2.3 build inventory derived from the exact
binary's embedded Go build information. It inventories the executable, exact
Go toolchain, main module, and every compiled module or effective replacement,
with deterministic relationships. License and copyright fields remain
`NOASSERTION` because the SBOM generator does not perform source-license
analysis.

## Unix lifecycle and native-kernel scope

The Linux, BSD, and Darwin tarballs install under `/usr/local` by default,
support `PREFIX` and `DESTDIR`, and own only these paths:

- `bin/leaguebridge`
- `share/doc/leaguebridge/{README.md,LICENSE,SBOM.spdx.json,PACKAGE-MANIFEST.json}`
- `libexec/leaguebridge/uninstall.sh`

The lifecycle smoke test verifies exact-file installation, deterministic
upgrade/repair, modes, manifest preservation, command execution, symlink
refusal, unrelated-file preservation, and exact-file uninstall. CI runs that
same shipped-archive lifecycle on Linux and, in separate VM jobs, on actual
FreeBSD, OpenBSD, NetBSD, and DragonFly BSD kernels. Hosted macOS runners execute
the matching Darwin archive and lifecycle for their native architecture. The
runtime kernel and machine architecture must both match the archive target.

The installed uninstaller has no implicit target. Both `PREFIX` and `DESTDIR`
must be explicitly present in its environment before it inspects or changes a
path; `DESTDIR` may be the explicit empty string. The installer always prints
an uninstall command containing both variables.

A locally generated cross-target archive proves packaging structure and binary
identity only. Native execution evidence exists only after the corresponding CI
job completes and retains its evidence artifact.

Release consumers must verify the repository's documented release attestation
identity, workflow, source ref, and hosted-runner policy before extraction, then
validate `checksums.txt` against the downloaded archives. Package manifests and
SBOMs supplement that outer attestation; they do not replace it.

`checksums.txt` uses the canonical binary-mode `sha256sum` form
`<64 lowercase hex> *./<archive>`. The `*` is required so verification never
opens an archive in a platform's text mode; a two-space text marker is rejected.

Release publication also has an external GitHub administration prerequisite:
maintainers must configure an immutable protected ruleset for `v*` tags. The
public repository does not currently provide that ruleset, so the release
workflow fails closed unless GitHub reports the triggering tag as protected;
it rechecks the tag after provenance attestation before publishing. Repository
code cannot satisfy or self-award this prerequisite.

For a tag stored in `release_tag`, verify both the checksum manifest and chosen
archive before reading or extracting either payload:

```sh
for subject in checksums.txt "$artifact"; do
  gh attestation verify "$subject" \
    --repo Yunushan/leaguebridge \
    --signer-workflow Yunushan/leaguebridge/.github/workflows/release.yml \
    --source-ref "refs/tags/$release_tag" \
    --deny-self-hosted-runners
done
```

After that succeeds, require the archive's exact `./filename` entry in
`checksums.txt` and compare its SHA-256 before extraction. A valid inner
checksum without the required GitHub/Sigstore attestation is insufficient.
