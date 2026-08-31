# Native package staging

LeagueBridge's release artifact is a target-native executable archive. The
optional staging command converts one verified Unix archive into a clean package
root for a platform-owned builder:

```sh
go run -mod=vendor ./tools/nativepackagestage \
  -archive ./leaguebridge_1.2.3_linux_amd64.tar.gz \
  -family debian \
  -output ./native-stage-debian
```

Supported families are `debian`, `rpm`, `freebsd-pkg`, `openbsd-pkg`, `pkgsrc`,
and `dports`. The command writes `root/` plus
`NATIVE-PACKAGE-MANIFEST.json`; it does not build, sign, install, or publish a
native package. It also omits the portable `install.sh` and `uninstall.sh`
scripts because native package managers own their own lifecycle.

Re-check a staging directory before handing it to a package builder:

```sh
go run -mod=vendor ./tools/nativepackagecheck \
  -staging ./native-stage-debian
```

The checker validates the canonical manifest, exact `root/` contents, regular
non-symlink files, payload sizes, hashes, and POSIX modes when the host
filesystem exposes them. It remains a staging-integrity check; the package
builder still owns package metadata, signing, installation, and runtime tests.

The non-PR CI workflow includes reference smoke builders for the six supported
package mappings. The Linux and BSD scripts under `scripts/` build temporary
package-manager artifacts and test install/uninstall on the target runner or
guest. These artifacts are unsigned CI outputs and are not published
release packages; the workflow retains them only as inputs to the score-free
GitHub artifact-attestation contract.

After a platform-owned builder has produced and installed a package, it can
create a score-free, source-bound subject with:

```sh
go run -mod=vendor ./tools/nativepackageattestation \
  -target-goos linux -target-goarch amd64 -family debian -format deb \
  -package packages/leaguebridge-1.2.3.deb \
  -staging-dir native-stage-debian \
  -install-evidence package-evidence/debian/install.txt \
  -output package-evidence/debian/native-package.json \
  -command 'package build; package-manager install; native install smoke'
```

The subject hashes the package bytes, all six staging files, and the install
log. Its verifier requires the complete six-package Linux/BSD set and GitHub
artifact attestations; it does not add package-manager signatures or publish
packages.

Native package bytes require the target operating system's package toolchain,
policy metadata, signing process, and independent attestation. Those tools are
not downloaded or run by this repository's release builder. See
[`docs/PACKAGING.md`](../docs/PACKAGING.md) for the mapping and evidence
boundary.
