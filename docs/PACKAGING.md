# Release packaging contract

LeagueBridge publishes exactly nine target-native executable archives: Linux,
FreeBSD, OpenBSD, and NetBSD on amd64 and arm64, plus DragonFly BSD on amd64. Each release is a
portable tarball with an unprivileged staging interface; releases are not
represented as distribution-owned Debian, RPM, FreeBSD ports, OpenBSD ports,
pkgsrc, or dports packages.

## Canonical package manifest

Every archive contains a schema-version 3 `PACKAGE-MANIFEST.json`, conforming to
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
container identity is target-bound: exact ELF class/data/type/machine/OSABI
fields are checked independently of Go build information.

## Optional native package staging

The repository now provides a deterministic staging boundary for native package
builders without changing the nine-archive release contract. The command
`tools/nativepackagestage` accepts one Unix release tarball after its embedded
package manifest and payload have been checked, then creates a new directory
containing:

- `root/`, with the executable, host-free client-smoke and remote-session
  helpers, documentation, SBOM, and package manifest;
- `NATIVE-PACKAGE-MANIFEST.json`, a content-addressed staging inventory; and
- no portable installer or uninstaller scripts.

The supported family-to-target mapping is deliberately explicit. Linux native
packages remain amd64-only; the three BSD package families also cover the
arm64 release archives.

| Family | Target | Package root |
| --- | --- | --- |
| `debian` | Linux amd64 | `/` (`/usr/local` is rewritten to `/usr`) |
| `rpm` | Linux amd64 | `/` (`/usr/local` is rewritten to `/usr`) |
| `freebsd-pkg` | FreeBSD amd64 | `/usr/local` |
| `freebsd-pkg` | FreeBSD arm64 (`aarch64` package architecture) | `/usr/local` |
| `openbsd-pkg` | OpenBSD amd64 | `/usr/local` |
| `openbsd-pkg` | OpenBSD arm64 | `/usr/local` |
| `pkgsrc` | NetBSD amd64 | `/usr/local` |
| `pkgsrc` | NetBSD arm64 (`aarch64` package architecture) | `/usr/local` |
| `dports` | DragonFly BSD amd64 | `/usr/local` |

For example:

```sh
go run -mod=vendor ./tools/nativepackagestage \
  -archive ./leaguebridge_1.2.3_linux_amd64.tar.gz \
  -family debian \
  -output ./native-stage-debian
```

The staging command rejects non-regular archive inputs, symlinked parent
directories, unsafe tar members, duplicate or unexpected files, non-canonical
modes and timestamps, manifest payload mismatches, and cross-target package
families. It never invokes a package manager, installs files, signs output,
fetches dependencies, or claims
that a native package exists. The repository includes CI-only reference smoke
builders in `scripts/native-package-linux-smoke.sh` and
`scripts/native-package-bsd-smoke.sh`. They turn the staged tree into
temporary unsigned package-manager artifacts, install and uninstall them on
the target runner or guest, and retain the logs; they do not publish those
artifacts or provide package-manager signatures. Before writing, each script
rejects symlinked output/evidence directories and pre-existing package or
evidence paths, preventing a smoke run from redirecting artifacts outside its
workspace. Each script validates its version with the repository's
`tools/versioncheck` before constructing package output paths. On BSD guests, CI
cross-builds that validator for the guest
kernel and passes it as `VERSION_CHECKER`, so the package smoke does not
silently depend on an unprovisioned Go toolchain in the VM image. A production
builder must
still turn the staging root into authorized `.deb`, `.rpm`, BSD package/port,
or `.pkg` bytes and retain the builder's exact package attestation. The
staging manifest is therefore `staging-integrity-only` evidence and cannot
promote the native-package or native-runtime readiness rows.

FreeBSD and DragonFly package creation supplies an explicit packing list for
the seven staged payload files and the two owned directories. The `pkg create
-r` argument only selects the source root; the packing list determines which
files enter the package. CI creates each family staging parent before the
exclusive staging command and preserves executable modes across artifact
upload/download using the fixed-inventory `tools/ciartifact` tar transport.

`tools/nativepackagecheck` reopens an existing staging directory and verifies
the manifest with exact field names, duplicate-key rejection, canonical JSON,
the expected `root/` layout, regular non-symlink files, payload sizes, modes
where the host filesystem exposes POSIX modes, and SHA-256 digests. The release
builder and the CI reference package jobs run this check after each staging
mapping. This protects the handoff between LeagueBridge and a native package
builder; it does not
replace that builder's package signature, installation test, or runtime
attestation.

The CI reference jobs and an external production builder can use
`tools/nativepackageattestation` after producing package bytes and a native
install-test log. The generated, score-free subject hashes the package, every
file in the verified staging tree, and the install log, and binds all of them
to the exact CI source and run. Its verifier requires the complete Debian/RPM
and BSD-family package set. It accepts hosted Linux and
virtualized BSD builder claims only; it rejects physical claims because a
hosted GitHub attestation cannot prove physical hardware. Package-manager
signatures, publication authorization, target-kernel installation, and
Riot/League runtime behavior remain independently governed evidence. The
install log is capped at 1 MiB and must include exactly one package-family,
version, package-filename, target, install-pass, and uninstall-pass marker,
matching the subject; this semantic check does not turn a self-authored log
into a package-manager signature.

The hermetic release builder exercises all nine target/architecture-family
mappings in its private work directory after `tools/releasecheck` succeeds.
This catches mapping drift during release smoke tests while leaving `dist/`
limited to the nine executable archives and `checksums.txt`.

## Reproducible production builder

Production releases require Go `go1.27.1` exactly. Go `go1.25.12` remains the
minimum source-compatibility test and is not an authorized release builder.
The builder version is checked in three places:

1. `scripts/release.sh` refuses another toolchain before changing `dist`.
2. The structured Go build-ID v4 contract binds the exact builder version,
   commit, tree, target, epoch, amd64 tuning (`GOAMD64=v1`), and approved
   compiled dependency identity.
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
Both release scripts also pin `GOPATH`, `GOMODCACHE`, `GOCACHE`, and `GOTMPDIR`
inside their private scratch workspace before the first Go invocation, keeping
managed-host cache and temporary-directory policy from affecting the build.
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
the exact approved module, or module replacement. Archives and `checksums.txt`
are created in a private same-filesystem staging directory. Only after the
complete archive, checksum, release, and native-package staging checks pass is
that directory moved into the original absolute `dist` path; an existing
`dist` is kept in a private sibling backup until publication succeeds and can
be restored if the final move is interrupted.

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

Linux and BSD tarballs are emitted by `tools/canonicaltar` with exact USTAR
metadata and a canonical gzip header. Release generation therefore does not
depend on host-specific archive utilities or their changing defaults.
`tools/releasecheck` reconstructs the canonical tar.gz bytes and rejects
alternate compression streams, headers, or metadata.

`SBOM.spdx.json` is a canonical SPDX 2.3 build inventory derived from the exact
binary's embedded Go build information. It inventories the executable, exact
Go toolchain, main module, and every compiled module or effective replacement,
with deterministic relationships. License and copyright fields remain
`NOASSERTION` because the SBOM generator does not perform source-license
analysis.

## Unix lifecycle and native-kernel scope

The Linux and BSD tarballs install under `/usr/local` by default,
support `PREFIX` and `DESTDIR`, and own only these paths:

- `bin/leaguebridge`
- `libexec/leaguebridge/{linux-bsd-client-smoke.sh,linux-bsd-remote-session.sh}`
- `share/doc/leaguebridge/{README.md,LICENSE,SBOM.spdx.json,PACKAGE-MANIFEST.json}`
- `libexec/leaguebridge/uninstall.sh`

The lifecycle smoke test verifies exact-file installation, deterministic
upgrade/repair, modes, manifest preservation, command execution, symlink
refusal, unrelated-file preservation, and exact-file uninstall. CI runs that
same shipped-archive lifecycle on Linux and, in separate VM jobs, on actual
FreeBSD, OpenBSD, NetBSD, and DragonFly BSD kernels. The
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
validate `checksums.txt` against the downloaded archives. The release workflow
checks the exact archive set and checksums, then runs
`tools/ciattestation -verify -kind release` after signing and before its final
protected-tag recheck and publication. That verifier performs the same
per-subject attestation verification with bounded retries. Package manifests
and SBOMs supplement that outer attestation; they do not replace it.

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
