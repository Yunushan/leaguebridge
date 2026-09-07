# Live release engineering assessment

`leaguebridge readiness verify-release` answers whether a named published
release currently has the repository, CI, and publication evidence required
by the fixed engineering contract. The command performs verification itself.
It accepts no caller-provided score, pass flag, source identity, run identity,
policy file, or saved verification report.

## Inputs and invocation

Use a trusted GitHub CLI and its normal authentication and Sigstore trust
configuration. Download the release's nine archives plus `checksums.txt` to
one directory. Separately retain the matching complete main-branch CI
race/vet and cross-build artifacts. The latter must have this layout:

```text
ci-evidence/
  ci-attestation/
    race-vet-linux.json
    cross-build-linux-amd64.json
    cross-build-linux-arm64.json
    cross-build-freebsd-amd64.json
    cross-build-freebsd-arm64.json
    cross-build-openbsd-amd64.json
    cross-build-openbsd-arm64.json
    cross-build-netbsd-amd64.json
    cross-build-netbsd-arm64.json
    cross-build-dragonfly-amd64.json
  ci-build/
    leaguebridge-linux-amd64
    leaguebridge-linux-arm64
    leaguebridge-freebsd-amd64
    leaguebridge-freebsd-arm64
    leaguebridge-openbsd-amd64
    leaguebridge-openbsd-arm64
    leaguebridge-netbsd-amd64
    leaguebridge-netbsd-arm64
    leaguebridge-dragonfly-amd64
```

Run from `ci-evidence/`, because the signed CI documents identify their binary
subjects relative to that directory:

```sh
cd /absolute/path/to/ci-evidence
/absolute/path/to/leaguebridge readiness verify-release \
  --version v0.1.0 \
  --release-dir /absolute/path/to/published-v0.1.0/assets \
  --gh /absolute/path/to/gh \
  --json
```

The command reads the supplied files and GitHub state. It does not publish,
upload, change repository settings, run downloaded binaries, install software,
or alter the embedded readiness card. Missing, stale, mismatched, or
unauthenticated inputs fail the assessment rather than awarding partial
external credit. Authentication failures never become a lower assurance mode.

## Evidence requirements

The assessor independently resolves the stable published release, its
protected tag, exact commit/tree, reviewed CI and Release workflows, and
complete successful run attempts. It requires the release's own main-branch
CI; newer main commits cannot supply evidence for an older release. Current
main need not still point at the release commit.

The released scorecard is read through its authenticated Git source objects.
Every referenced repository file must exist as a regular Git blob and match
its recorded digest. The score is derived from the fixed criterion contract,
not from a stored total. An explicitly pinned historical policy preserves
the reviewed v0.1.0 contract when the assessor's current evidence inventory
changes. That compatibility pin identifies policy bytes, not evidence of a
run or release; all live and cryptographic checks remain mandatory. The
released scorecard's assessed/expiry bounds are checked throughout.

The complete race/vet and nine-target cross-build sets must authenticate for
the exact source, workflow, run, attempt, and hosted-runner policy. For
publication, all nine archives and the canonical checksum file must match
the actual GitHub asset names, sizes, and SHA-256 digests. The full archive
checker independently validates payloads, binary/source identities, SBOMs,
manifests, the released scorecard's exact bytes, and its matching build-time
verification marker. All ten release files must authenticate against the
exact Release workflow run and protected tag.

Before returning a result, the assessor checks the latest matching CI and
Release attempts, publication state, tag/protection, and local evidence bytes
again. GitHub's APIs do not offer one atomic snapshot: the observation describes
completed checks and detected stability during the call, not a guarantee
about a subsequent state. The operation timeout is not a freshness policy.

## Derived credit and remaining requirements

The live result adds only these four independently established rows to the
authenticated released repository baseline:

| Criterion | Points |
| --- | ---: |
| Linux race and vet | 3 |
| Complete nine-target cross-build | 3 |
| Nine published Linux/BSD release archives | 2 |
| Release publication and attestation | 1 |

For the released 74-point repository baseline, successful authentication of
all four yields **83/100**. The following requirements still account for the
remaining 17 points; the command does not award them:

| Criterion | Points | Required evidence |
| --- | ---: | --- |
| Authorized upstream extension contract | 2 | Authentic Riot authorization for the specified native integration |
| Native validated platform integration | 3 | Authenticated complete native integration results with their actual prerequisites satisfied |
| Native BSD and physical-hardware smoke tests | 5 | Genuine authenticated physical hardware results; hosted/QEMU observations cannot substitute |
| Closed independent audit findings | 2 | Authenticated independent review and closure evidence |
| Native OS packages | 3 | Authenticated production package artifacts and their required publication/signing evidence |
| Install/uninstall and native smoke evidence | 2 | Authenticated production-candidate lifecycle and native runtime results |

The separate local Linux/BSD gameplay gate remains blocked. Both physical
remote-host routes remain unvalidated until their route-specific evidence and
reviewer trust requirements are met. A live engineering score does not change
those outcomes or any execution permission.

## Output contract

Successful JSON output uses the normal application envelope with command
`readiness verify-release`; its `data` follows
[`release-assessment.schema.json`](../schemas/release-assessment.schema.json).
It records the named release and source, exact CI/Release run attempts,
observation time, released scorecard expiry, derived baseline/total, and four
fixed earned criteria. It is output only. Saving or editing that JSON does
not create an acceptable verification input.

Usage errors return exit 2. An unsuccessful live assessment returns exit 3
without score data. Output failures return exit 4. Re-run the command for a
later assessment; neither this document nor the output grants a durable or
offline readiness status.
