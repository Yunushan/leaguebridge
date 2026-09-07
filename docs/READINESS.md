# Production-readiness score

The score is evidence, not branding. `leaguebridge readiness` reports each
dimension independently and never converts engineering work into gameplay
compatibility.

The latest Wine, Proton, VM/Dockur, anti-cheat, and cloud-provider route audit
is recorded in [`docs/research/2026-09-03-route-revalidation.md`](research/2026-09-03-route-revalidation.md).

## Engineering readiness (100 points)

Readiness schema version 3 fixes 30 ordered, binary subcriteria and their
weights. The scorecard cannot supply `earned` points or a `passed` flag. The
runtime derives each category score and the 100-point total from the evidence
class required by the fixed contract.

Repository-backed credit requires the exact ordered file inventory for that
subcriterion. Every reference records a lowercase SHA-256 digest, and tests
require the target to be a regular file and every traversed path component to
be non-symlink. A different, additional, missing, reordered, or modified file
fails closed.

User-facing commands award those repository-backed points only when the build
contains the exact build-time verification value for its embedded scorecard.
The production builder creates that value after `tools/readinesscheck` hashes
every referenced file in the immutable source snapshot; `tools/releasecheck`
then requires both the exact embedded scorecard bytes and verification value in
every binary. A development or ad hoc build has no value and reports **0/100 —
repository evidence unverified**, including zero category scores. This marker
records build-time verification; it is not a publisher signature or substitute
for the separately required release attestation.

CI execution, release publication, native runtime results, native packages,
vendor authorization, and independent audit are different evidence classes.
Their mere scripts, workflows, self-authored notes, or arbitrary files do not
count. The embedded schema-v3 evaluation keeps those criteria at zero and
does not import external observations. The explicit live release assessment
described below authenticates a named release's evidence and derives its
eligible CI and publication criteria without modifying the embedded card.

The CI workflow includes hosted Ubuntu Linux amd64 and arm64 runtime/install
smokes and native BSD guest lifecycle jobs for amd64 and arm64 where the guest
supports it. These jobs deliberately capture their
observations as artifacts and keep headless or unsupported client states
blocked; a workflow definition or an unauthenticated artifact cannot promote a
scorecard row. Non-PR CI emits score-free native-runtime v2 subjects that hash
the exact executable and smoke/install files, labels Linux as hosted and BSD as
virtualized, and verifies the complete Linux/BSD set against the exact commit,
tree, workflow revision, run ID, and attempt. The BSD guest results are not
physical-BSD evidence, and the GitHub-hosted verifier rejects physical-host
promotion without a separate physical attestation. No native runtime job claims
local League/Vanguard support. The corresponding rows remain zero until an
actual run's externally authenticated evidence is retained for a scorecard
assessment. Native package builders now have the same score-free boundary via
`tools/nativepackageattestation`: it verifies the complete nine-target/architecture
Linux/BSD package set, exact package/staging/install-log digests, and source/run identity,
but it does not create package bytes or promote runtime support. The shared
`tools/ciattestation` verifier also has a strict release mode that checks the
exact nine Linux/BSD archives, `checksums.txt`, and each publication attestation
against the release workflow, tag, tested commit, workflow revision, run, and
hosted-runner policy. The live release assessment requires an actual published
tagged run and verifies both the external attestations and the downloaded bytes.

The current verified source tree derives 74 points from the following binary
subcriteria; no row receives partial credit:

| ID | Subcriterion | Points | Earned | Required evidence/status |
| --- | --- | ---: | ---: | --- |
| `scope-support-matrix` | Support matrix | 4 | 4 | Exact content-addressed `README.md` |
| `scope-explicit-limitations` | Explicit limitations | 3 | 3 | Exact content-addressed `docs/SUPPORT_POLICY.md` |
| `scope-primary-source-research` | Dated primary-source research | 3 | 3 | Exact content-addressed dated research |
| `governance-policy-conduct` | Governance and conduct | 3 | 3 | Exact governance and conduct files |
| `governance-security-policy` | Security policy | 3 | 3 | Exact content-addressed `SECURITY.md` |
| `governance-legal-privacy` | Legal and privacy boundaries | 4 | 4 | Exact legal and privacy files |
| `architecture-versioned-schemas` | Versioned schemas | 5 | 5 | Exact compatibility, config, package, readiness, readiness-promotion-v4, validation-evidence, signature-envelope, and trust-policy schemas |
| `architecture-fail-closed-policy` | Fail-closed policy | 5 | 5 | Exact policy implementation and negative tests |
| `architecture-reason-codes-adrs` | Stable reason codes and ADRs | 3 | 3 | Exact five ADRs and manifest implementation |
| `architecture-upstream-authorization` | Authorized upstream extension contract | 2 | 0 | Authenticated Riot authorization absent |
| `implementation-cli-controller` | CLI/controller | 5 | 5 | Exact CLI and application controller files |
| `implementation-strict-config-fixed-argv` | Strict config and fixed remote argv | 4 | 4 | Exact config, Moonlight, and hardware-KVM launcher implementation files |
| `implementation-bounded-diagnostics-redaction` | Bounded diagnostics and redaction | 4 | 4 | Exact diagnostics and redaction implementation files |
| `implementation-read-only-probes` | Read-only host/client probes | 4 | 4 | Exact Linux/BSD client and consent-gated external-host inspection files |
| `implementation-native-validated-integration` | Native validated platform integration | 3 | 0 | CI runtime subjects do not establish working native client integration |
| `tests-unit-negative` | Unit and negative tests | 5 | 5 | Exact core negative-test inventory, including authenticated-evidence, external-host, and KVM URL/launcher coverage |
| `tests-coverage-80` | 80% aggregate core coverage gate | 4 | 4 | Exact versioned coverage gate and tests |
| `tests-race-vet-linux` | Linux race and vet | 3 | 0 | Authenticated by the explicit live release assessment; not imported into v3 |
| `tests-nine-target-cross-build` | Nine-target Linux/BSD cross-build | 3 | 0 | Authenticated by the explicit live release assessment; not imported into v3 |
| `tests-native-bsd-physical-smoke` | Native BSD and physical-hardware smoke tests | 5 | 0 | Hosted and virtualized subjects do not establish physical-hardware validation |
| `security-threat-model` | Threat model and scope | 4 | 4 | Exact threat-model and security-policy files |
| `security-injection-bounds-redaction` | Injection, bounds, and redaction tests | 4 | 4 | Exact security negative-test inventory, including KVM endpoint and fixed-argv checks |
| `security-pinned-least-privilege-ci` | Pinned least-privilege CI | 3 | 3 | Exact reviewed workflow definitions; not an execution claim |
| `security-sbom-checksum-provenance` | SBOM, checksum, and provenance tooling | 2 | 2 | Exact LF-normalization, lifecycle-script, deterministic archive, package-manifest, readiness-integrity, checksum, provenance, and SBOM tooling; not native-host or publication evidence |
| `security-independent-audit-closed` | Closed independent audit findings | 2 | 0 | Authenticated independent-audit closure absent |
| `packaging-nine-release-archives` | Nine published Linux/BSD release archives | 2 | 0 | Authenticated by the explicit live release assessment; not imported into v3 |
| `packaging-version-sbom-checksums` | Version metadata, SBOMs, and checksums tooling | 2 | 2 | Exact version/SBOM/release-check tooling |
| `packaging-publication-attestation` | Release publication and attestation | 1 | 0 | Authenticated by the explicit live release assessment; not imported into v3 |
| `packaging-native-os-packages` | Native OS packages | 3 | 0 | CI package subjects do not establish production package publication and signing |
| `packaging-install-uninstall-native-smoke` | Install/uninstall and native smoke evidence | 2 | 0 | CI lifecycle subjects do not establish validation of the published production version |

After build-time repository verification, the derived category totals are
10/10, 10/10, 13/15, 17/20, 9/20, 13/15, and 2/10, for **74/100**. Workflow
source code earns only the narrowly defined repository-control points above.
It does not prove that CI ran, that an archive was published, or that software
worked on physical hardware.

The scorecard has a bounded validity interval. Its public and embedded copies
must be semantically identical and conform to the public Draft 2020-12 schema.

## Live assessment of a published release

`leaguebridge readiness verify-release` separately assesses one named release
through live GitHub metadata and cryptographic verification. It derives the
release's repository baseline from the authenticated released scorecard and
every referenced source file, then requires complete matching CI and release
evidence before awarding the four fixed CI/publication criteria above. It
does not use the assessor binary's newer embedded card as an older release's
baseline. The released card's own validity interval still applies.

The current contract can derive nine additional points: three for race/vet,
three for all nine cross-builds, two for the complete published archive set,
and one for publication attestation. A release whose authenticated repository
baseline is 74 can therefore receive a live engineering assessment of 83/100.
Failure produces no assessment; the command does not fall back to an embedded
or cached score. Existing v3 files and their hard-zero external/remote arrays
remain unchanged.

This result describes the named release at observation time. It is not a
signed receipt, a validity promise until a chosen time, an assessment of later
main commits, or a gameplay authorization. Re-run the command to assess later
state. The output schema is [`release-assessment.schema.json`](../schemas/release-assessment.schema.json).
The input layout, exact checks, and remaining 17-point evidence requirements
are documented in [`RELEASE_ASSESSMENT.md`](RELEASE_ASSESSMENT.md).

## Local gameplay readiness (hard gate)

Local Linux/BSD gameplay remains **0/100 — blocked**. Riot does not provide a
supported or expressly authorized Linux/BSD League/Vanguard route. Wine,
Proton, copied DLLs, anti-cheat redistribution, VMs, and VM concealment cannot
earn engineering points toward this separate hard gate. Schema version 3 fixes
the outcome at `0/blocked`; changing it requires a new reviewed schema version,
current primary-source authorization, and native end-to-end evidence.

## Remote handoff readiness

Schema version 3 fixes two independent, ordered handoff routes:

1. `physical-windows-remote`: League and Vanguard stay on a user-owned,
   supported physical Windows PC.
2. `physical-macos-remote`: League stays on a user-owned physical Mac through
   Riot's native macOS client. Sunshine's macOS host support is experimental,
   gamepad hosting is unavailable, and capture, audio, keyboard/mouse, session
   quality, and gameplay remain unvalidated.

For each route, Linux, FreeBSD, OpenBSD, and NetBSD on `amd64` or `arm64`, plus
DragonFly BSD on `amd64`, is only the Moonlight viewer/controller. Each of the
18 route/client cells has
the same four derived 25-point gates. The route-specific physical-host gate is
deliberately different:

| Route | `physical-host` gate requirements |
| --- | --- |
| `physical-windows-remote` | Supported physical Windows hardware; current Windows/Riot/League/Vanguard state; direct local Practice Tool; reviewed Sunshine host; no VM or VM concealment |
| `physical-macos-remote` | Supported physical Intel or Apple-silicon Mac; current Riot native macOS client, Embedded Vanguard, and League; direct local Practice Tool; reviewed experimental Sunshine host; explicit no-gamepad limitation |

The other gates are route-bound and cannot borrow evidence from the other
host:

| Gate | Required evidence |
| --- | --- |
| `client-runtime` | Exact native Linux/BSD client OS, Moonlight, display, audio, decoder, and input behavior against the named host route |
| `session-quality` | Route-bound pairing, discovery, video/audio stability, and bounded versioned latency measurements |
| `gameplay-interaction` | Route-bound keyboard/mouse interaction, streamed Practice Tool, current League patch, and no relevant Riot/anti-cheat error |

Both routes and all nine target combinations per route currently score **0/100 —
unvalidated**. They are reported independently; there is no aggregate remote
score and no zero or candidate state for one route implies anything about the
other. “Experimental” describes Sunshine's macOS host implementation, not a
positive readiness state or Riot support for a Linux/BSD client.

The existing validation-evidence schema is version 1 and explicitly evaluates
`promotion_safe=false`; its reviewer text is unauthenticated. It now binds the
host to the selected Windows or macOS route and architecture. A separate
schema-v2 signed-set verifier defines strict Ed25519, reviewer-scope, freshness,
record-linkage, and exact artifact-verification rules for either route's record
chain. Its application-controlled production trust policy is intentionally
unprovisioned: no reviewer public keys or signed physical-run sets are accepted
by this release.

Readiness schema v3 deliberately remains the hard-zero contract and still
rejects every nonempty `evidence_sets` array for both routes. It contains no
stored remote score, state, gate, or pass field. Runtime output derives both
zero matrices.

The repository now includes a readiness-schema-v4 output contract and the
`evidencev2.PromoteRemoteSetAt` evaluator. It accepts only the opaque
`VerifiedSet` returned by the authenticated v2 verifier, rechecks its validity
and route/client cell, and derives the fixed four 25-point remote gates. The
result is not itself a trust root and is not wired into the current v3 CLI
scorecard: the production reviewer policy remains unprovisioned, and no signed
physical-run evidence exists. Production promotion still needs
root-authorized reviewer keys, release/readiness/challenge binding, and
route-specific physical evidence for every client cell. No arbitrary repository
file, user-supplied key, schema-v1 manual record, filename, signature, or
SHA-256 alone can promote a gate.
