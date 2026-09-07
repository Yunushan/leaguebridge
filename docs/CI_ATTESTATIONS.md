# CI attestation subjects

The readiness scorecard keeps CI execution in a separate evidence class. The
repository therefore emits a small, score-free JSON subject after successful
GitHub-hosted jobs; it does not turn a workflow definition or a local run into
readiness credit.

`schemas/ci-attestation.schema.json` defines
`leaguebridge.ci-attestation.v1`. `tools/ciattestation` binds each subject to:

- the exact commit and tree object IDs;
- the workflow path, workflow revision, ref, job, run ID, and attempt;
- the runner and Go toolchain identity;
- the exact race/vet command or cross-build target; and
- the size and SHA-256 of a cross-build binary when one exists.

The JSON itself is the subject of GitHub's artifact-attestation service. The
attesting jobs grant `id-token: write`, `attestations: write`, and
`artifact-metadata: write`, which are required by that service. The
`-verify` mode of `tools/ciattestation` is the operator-side authenticity gate:
it requires the exact expected checkout, the complete Linux/BSD target set,
and invokes `gh attestation verify` separately for every
JSON subject and cross-build binary. It pins the repository, workflow, ref,
source commit, SLSA predicate, GitHub OIDC issuer, and hosted-runner policy;
then it checks the signed certificate, verified timestamp, subject digest, and
post-verification file hash. The subject's fields are still claims and hashes,
not signatures; no copied JSON, uploaded artifact, or verifier output can
promote a scorecard row by itself.

Go callers can use `internal/ciattestation.VerifySet` with a typed
`VerifyRequest` instead of invoking the command and interpreting its printed
output. The package applies the same complete-set, source/run identity,
GitHub authentication, and post-verification digest checks. The existing CLI
remains the workflow interface and retains its flags and output.

A successful return verifies the supplied set against the caller's expected
identity. It is not an awardable readiness receipt, proof of release
publication, or a source-selection policy. A future engineering assessment
must independently establish its authoritative checkout or release, expected
run/attempt, freshness, and the relevant production trust rules. The repository
score, external-evidence restrictions, and physical/gameplay gates remain
unchanged.

### Observe the current main CI evidence

`tools/currentci` connects live GitHub source and run selection to the typed
attestation verifier. The caller supplies the trusted GitHub CLI executable,
one race/vet JSON subject, and the nine cross-build JSON subjects. The command
derives the repository, main commit and tree, workflow revision, run ID and
attempt through live GitHub reads. It rejects an incomplete or unsuccessful
latest CI attempt even when older or feature-branch checks passed.

The source resolver walks the exact Git tree to the CI workflow, verifies its
blob identity and a reviewed SHA-256 workflow pin, and requires the fixed full
CI job contract. This supports the reviewed non-reusable push and dispatch
workflow. Workflow changes require reviewing the pin alongside the job and
attestation contracts. Subject documents cannot select their own expected
source or workflow policy.

Build the verifier from reviewed source and place it outside the evidence
directory:

```sh
go build -mod=vendor -o /absolute/path/currentci ./tools/currentci
```

Arrange the retained CI JSON files under `ci-attestation/` and the nine
`ci-build/leaguebridge-GOOS-GOARCH` binaries at the paths declared in those documents.
Run from that evidence directory, using a trusted `gh` installation configured
for GitHub access:

```sh
set --
for cell in linux-amd64 linux-arm64 freebsd-amd64 freebsd-arm64 \
  openbsd-amd64 openbsd-arm64 netbsd-amd64 netbsd-arm64 dragonfly-amd64
do
  set -- "$@" -cross-build-subject "ci-attestation/cross-build-$cell.json"
done
/absolute/path/currentci \
  -race-vet-subject ci-attestation/race-vet-linux.json "$@"
```

The command verifies the JSON signatures and the cross-build binary signatures
through GitHub CLI. It then rechecks the source and full CI gate, and rereads
main after the final gate. A changed commit, source tree, workflow, latest run
or attempt fails verification. The package applies a 15-minute timeout, and
interruption/cancellation reaches the signature-verification
subprocesses. `internal/ciattestation.VerifySetContext` also exposes that
cancellation support to other callers; `VerifySet` preserves its existing
background-context behavior.

Success prints the observed commit, tree, run, attempt and UTC observation
time. Exit status 0 means verification completed, 1 means verification or output
failed, and 2 means command usage was invalid. No output file is accepted as
a substitute for another live invocation.

The observation does not establish an atomic snapshot across GitHub's APIs,
a maximum acceptable evidence age, release publication, physical execution,
or readiness points. A production assessment must bind evidence to its
independently selected release or source and its reviewed freshness policy;
it cannot borrow credit from a different main commit.

Non-PR CI runs also execute `tools/ciattestation` in the `Verify signed CI attestations`
job after the test and cross-build matrices complete. That job downloads the
retained subjects and binaries, arranges the exact one-run set, and verifies
the Linux race/vet subject and all nine Linux/BSD cross-build targets with the same
repository, commit, tree, ref, exact workflow revision, exact run ID and
attempt, certificate, and post-verification digest checks described above.

The workflow also emits `leaguebridge.native-runtime-attestation.v2` subjects
for the native Linux/BSD runtime jobs. `tools/nativeattestation` inventories
the exact runtime executable and every smoke/install evidence file, records
their size and SHA-256, and keeps the document score-free. The Linux amd64 and
arm64 jobs are hosted runners; seven BSD target jobs run in explicitly `virtualized`
BSD guests on a hosted runner: amd64 and arm64 for FreeBSD, OpenBSD, and NetBSD,
plus amd64 for DragonFly BSD. The native verifier requires the
complete target set, the exact commit/tree/workflow revision/run identity, and
the same GitHub artifact-attestation check for each JSON subject and listed
runtime file. A virtualized BSD result is not physical-BSD evidence and none
of these smoke jobs establishes local League/Vanguard compatibility. The
GitHub-hosted verifier rejects an `expected-host-class physical` request because
that artifact-attestation channel cannot establish physical hardware; physical
promotion requires a separate independently governed attestation path.

Native package builders use `schemas/native-package-attestation.schema.json` and
`tools/nativepackageattestation`. A package subject binds the exact package
bytes, the verified staging manifest and seven staged payload files, and the
package-manager install-test log to the same repository, tree, workflow
revision, ref, run, and attempt. The verifier requires the complete nine-package
Linux/BSD set: Debian and RPM on Linux amd64, FreeBSD/OpenBSD/NetBSD packages
on amd64 and arm64, and DragonFly BSD on amd64. The Linux package job is
hosted; BSD package jobs are explicitly virtualized. Package subjects are
score-free and cannot claim that
League/Vanguard ran, that a package was published, or that a host was physical.
The install log is bounded to 1 MiB and must contain exactly one line for each
of `package`, `version`, `filename`, `target`, `install=pass`, and
`uninstall=pass`, all matching the attested package subject; the remaining log
text is diagnostic evidence only.
The non-PR CI workflow now runs reference builders for the nine Linux/BSD
target/architecture mappings: Debian/RPM on hosted Linux, FreeBSD/OpenBSD/
NetBSD package tools in virtualized amd64 and arm64 BSD guests, and DragonFly
package tools in a virtualized amd64 guest. They install and uninstall the
generated bytes and retain the package-manager evidence before creating the
score-free subjects. GitHub artifact attestation is not a Debian, RPM, or BSD
package signature. A production builder must still produce
authorized, signed, publishable package bytes and retain the trusted package
attestation before the native-package or install-smoke rows can receive
credit.

CI transports executable evidence and package staging trees in canonical tar
containers because GitHub's ZIP artifact transport removes executable modes.
`tools/ciartifact` defines the exact runtime or native-package inventory for
each target. It rejects missing, duplicate, extra, reordered, oversized,
non-regular, linked, or noncanonical members before creating any output, then
restores files exclusively beneath a new directory with their expected modes.
Runtime artifacts also retain the individual files consumed by the separate
attestation jobs; the verification jobs restore the tar container and verify
those same bytes against their individual signatures. The tar container adds
no trust or readiness credit. Native-package artifacts contain the tar
containers after the original package, staging, and evidence files are signed.

Release publication uses the same executable verifier in `-kind release` mode.
It derives exactly ten subjects from the v-prefixed release version: the nine
Linux/BSD target archives and `checksums.txt`. It rejects extra or missing files,
recomputes every archive digest, checks the canonical binary-mode checksum
manifest, and verifies each subject's GitHub/Sigstore certificate against the
release workflow, tag ref, tested commit, workflow revision, run, and hosted
runner policy. The preceding `tools/releasecheck` step binds each archive's
embedded package manifest to the tested source tree; publication still remains
unverified until an actual tagged run produces retained external evidence.

Immediately before publication, `tools/cireleasegate -commit SHA` also requires
a completed, successful main-branch CI run for the exact tested source commit,
including every required target runtime, package, and attestation verification
job. The publish token therefore includes read access to Actions. A successful
Linux release build alone cannot authorize publication while target CI is
missing, running, skipped, or failing.

Go callers can invoke `internal/cireleasegate.Verify` with a context and a
`VerifyRequest` containing the exact commit and trusted GitHub CLI executable.
The package retains the CLI's fixed repository, main-branch workflow, complete
job inventory, latest-attempt selection, bounded API reads, and final state
recheck. It returns the observed run ID, attempt, and commit without accepting a
caller-supplied API client or job allowlist. This result does not authenticate
artifact bytes, select a production source, establish publication, or award
readiness points; later publication decisions must rerun the live gate.

The release-mode invocation has the following shape inside the publish job:

```sh
go run -mod=vendor ./tools/ciattestation \
  -verify -kind release \
  -release-dir dist -release-version "$GITHUB_REF_NAME" \
  -expected-repository "$GITHUB_REPOSITORY" \
  -expected-workflow .github/workflows/release.yml \
  -expected-commit "$EXPECTED_COMMIT" \
  -expected-ref "$GITHUB_REF" \
  -expected-workflow-sha "$EXPECTED_WORKFLOW_SHA" \
  -run-id "$EXPECTED_RUN_ID" -run-attempt "$EXPECTED_RUN_ATTEMPT"
```

For a checked-out commit, first derive the exact commit and tree and then
verify the Linux race/vet subject:

```sh
commit=$(git rev-parse --verify HEAD)
tree=$(git rev-parse --verify HEAD^{tree})
workflow_sha=<the-GitHub-workflow-revision-from-the-signed-run>
run_id=<the-GitHub-actions-run-id>
run_attempt=<the-GitHub-actions-run-attempt>
go run -mod=vendor ./tools/ciattestation \
  -verify -kind race-vet \
  -expected-commit "$commit" \
  -expected-tree "$tree" \
  -expected-ref refs/heads/main \
  -expected-workflow-sha "$workflow_sha" \
  -run-id "$run_id" \
  -run-attempt "$run_attempt" \
  -verify-subject ci-attestation/race-vet-linux.json
```

The cross-build invocation takes the nine `ci-attestation/cross-build-*.json`
subjects from one workflow run. It also verifies the binary named inside every
subject, so the JSON cannot be detached from the artifact it describes. The
command contacts GitHub through the locally installed `gh` executable; it
does not accept a JSON receipt as a substitute for that cryptographic check.
For offline bundles, use the documented `gh attestation verify --bundle`
workflow directly with a securely obtained trusted root, then retain the
result for an independent review.

The generator rejects symlinked or non-regular binary subjects, symlinked
parent directories, unsafe paths, unexpected targets, target/path mismatches,
duplicate subject paths, missing workflow identity, and non-canonical
timestamps. The workflow also refuses preexisting symlinked `ci-build` or
`ci-attestation` directories and compares the checked-out commit with
`GITHUB_SHA` before producing a subject. It has no network access, does not
invoke a compiler, and never handles credentials or private signing keys.

An external repository-settings audit on 2026-08-29 reported read-only default
workflow token permissions, but no branch protection on `main`; GitHub's public
repository Actions policy also allows all actions and does not require SHA
pinning. The workflow source still uses immutable action commit references, but
that source property is not the same as repository-level enforcement. Enabling
branch protection, narrowing the allowed-action policy, and requiring pinned
actions are separate owner-authorized hardening tasks and are not claimed by
the readiness scorecard.
