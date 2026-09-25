# Design: a full production-readiness assessment

**Status: initial composer implemented; external verification proposed.** This
document defines the remaining review target. It is not an accepted external
trust policy or production evidence. The
current embedded scorecard remains schema v3 and derives 74 repository points
after build-time verification. `readiness verify-release` can derive nine more
points for a named published release. `readiness verify-production` now
composes that live verification with all six external rows and a final live
recheck. Its current output is capped at 83 because no production trust roots
or independent external verifiers are provisioned. The existing remote
promotion schema v4 is a separate route-specific contract.

## Composition and score boundary

The initial assessor selects a stable release tag and local artifact
directories. It calls the live `internal/releaseassessment.VerifyForProduction`
logic in the same assessment and never accepts its JSON output as proof. That verifier
authenticates the protected tag, Git source tree, released scorecard and every
repository reference, exact CI and Release runs, signed CI and publication
subjects, and the ten published release files. Its result establishes a named
release's repository baseline and the four fixed CI/publication criteria.

For production composition, the release verifier now exposes an opaque
verified release identity whose zero value is invalid. It retains the version,
commit, tree, release ID, CI/Release run and attempt, released scorecard digest
and expiry, exact release asset digests, full publication state, and local
evidence digests. Only the verifier may construct it. The full assessor must
pass this opaque identity to future external verifiers alongside a copied
release binding, so a package candidate can be checked against the authenticated
release rather than an assessment JSON document. The full assessor must
call its final live recheck after all additional verification, because the
release verifier's own final check happens before the extra evidence would be
inspected. It also rechecks mutable external state after that live release
recheck, since authorization or package publication can change while the
release check runs. A saved release-assessment result or caller-supplied commit
is never an input.

The live release verifier checks that the six rows below occur exactly once in the released
fixed contract with their reviewed IDs, weights, evidence types, and verifier
IDs. The composer currently emits all six rows as missing evidence with zero
points. Future verifiers must derive each row's points from successful authenticated checks; inputs
cannot contain `score`, `earned`, `passed`, or a new trust key. Missing evidence
leaves that whole row at zero and states what is missing. Present but invalid,
conflicting, revoked, expired, or unbound evidence fails the assessment rather
than falling back to a weaker interpretation. The final total is the
authenticated release result plus independently earned rows and must not
exceed 100. Local Linux/BSD gameplay and the two remote handoff matrices remain
separate; a full engineering score does not promote either gameplay gate.

Every new proof must identify the same release version, commit and tree, and
the exact binary or package digests it covers. The assessor pins a reviewed
evidence schema and a production trust policy in application-controlled code
or an authenticated source revision. A file, flag, environment variable,
record, or signer cannot supply its own acceptance policy. Policies need
validity windows, key scope, revocation, and a reviewed rotation path. Signed
statements also bind a verifier-issued or governance-issued challenge and a
short observation window where replay would otherwise be possible. Mutable
publication and revocation state is checked again before output. The output
is an observation at that time, not a durable certificate.

## The six external rows

| Fixed criterion | Points | Required verifier and complete evidence | Production trust root |
| --- | ---: | --- | --- |
| `architecture-upstream-authorization` | 2 | Fetch a current Riot-controlled publication or authenticate a written Riot authorization through an independently verified Riot signatory channel. Check the exact Linux and BSD platform/architecture scope, client and Vanguard distribution, permitted integration and test methods, redistribution, validity, and withdrawal state. A developer-portal registration or third-party report cannot satisfy this row. | Riot-controlled official publication origin or a separately established Riot signing identity and current authorization status; neither a user-supplied document nor a project key is sufficient. |
| `implementation-native-validated-integration` | 3 | Authenticate a complete reviewed target inventory of native client integration runs against the assessed release binary, its dependencies, and an actually usable physical host route. The proposed inventory is the nine shipped Linux/BSD target cells. Verify native OS/architecture, Moonlight installation and execution, display/audio/input behavior, exact release digests, the host route's prerequisites, complete artifacts, and fresh signed observations. A cross-build, headless CLI smoke, or self-authored log is insufficient. | A separately governed physical-run lab observer and independent reviewer policy, scoped to each target and release; publisher CI identity alone is insufficient. |
| `tests-native-bsd-physical-smoke` | 5 | Authenticate native-kernel execution and install/smoke results on physical hardware for the seven shipped BSD cells: FreeBSD, OpenBSD, and NetBSD on amd64/arm64, plus DragonFly BSD on amd64. Bind the exact release binary, target, machine/run pseudonym, challenge, raw result artifacts, reviewer observations, and expiry. Verify physical presence through independently witnessed machine and boot evidence; a `host_class: physical` string, VM, QEMU guest, or hosted runner cannot qualify. | Provisioned physical-lab keys with distinct observer and independent-reviewer principals and organizations, rooted in a reviewed policy and checked for revocation. |
| `security-independent-audit-closed` | 2 | Authenticate an independent auditor's engagement scope for the exact release source and artifacts, signed findings inventory, severity and disposition, and signed closure/retest evidence for every finding required by the reviewed closure policy. Recheck report version and withdrawal status. A project-authored threat model or its own security scan is insufficient. | Reviewed independent auditor identity/key and independence policy, separate from project publisher and physical-lab keys. |
| `packaging-native-os-packages` | 3 | Define and verify a reviewed 11-cell package family/target inventory: Debian and RPM on Linux amd64/arm64; FreeBSD, OpenBSD, and NetBSD on amd64/arm64; DragonFly BSD on amd64. Match each published package's bytes to a signed native-package build subject for the assessed release, its staging manifest, exact assessed release binary, package metadata, and authoritative index. Verify the approved package-manager signature or signed repository metadata and live publication/withdrawal state. CI now builds and smoke-tests all eleven cells with synthetic `v0.0.0-ci` archives. Those subjects still do not establish stable-release provenance, package-manager signatures, or publication. | Reviewed package publisher keys and separately authenticated repository/index roots for each package family, with key scope, revocation, and rotation. GitHub OIDC/Sigstore authenticates CI subjects only. |
| `packaging-install-uninstall-native-smoke` | 2 | Verify an independently authenticated install, upgrade/repair, native CLI smoke, and uninstall run for the exact published production package in every reviewed package target cell. Confirm native OS/kernel and architecture, package-manager status, installed file digests and modes, unrelated-file preservation, cleanup, and link to the package signature and publication proof above. A CI VM install log or staged but unpublished package cannot qualify. | The provisioned physical/native-run reviewer policy plus authenticated package publisher identity; the observer must be independent of a self-authored CI log. |

The proposed target inventories and test profile are review decisions, not
backdated interpretations of schema v3. They must be fixed in a reviewed
versioned contract before any row can earn points. If one target remains
unsupported, its all-or-nothing row remains zero rather than shrinking the
inventory to the targets that happen to pass.

## Existing verifiers and required new boundaries

`internal/ciattestation` already provides a typed, context-aware verifier for
the release assessor's signed CI and release sets. The score-free verifiers in
`internal/nativeattestation` and `internal/nativepackageattestation` check
complete target sets, source/run identity, subject digests, and GitHub artifact
attestations. Their CLI wrappers remain in `tools/`; the internal verifiers
return opaque, score-free results. The assessor supplies expected
source and run identity from the verified release; artifact JSON does not get
to select its own release. A verifier should return an opaque result whose zero
value is invalid, or an error, never a caller-constructed boolean.

These existing verifiers remain prerequisite checks only. The native runtime
verifier explicitly rejects physical-host promotion from GitHub-hosted
attestations. The native runtime v2 schema fixes the BSD CI jobs to
`virtualized`, so physical BSD evidence needs a new, separately governed
schema and verifier. The native package v1 schema permits hosted/virtualized
builders and has no native signature or publication proof; a production
package verifier must add those checks. Its bounded install log remains an
observation, not proof that the package manager accepted a signed published
package. `internal/evidencev2` demonstrates an opaque verified-set and strict
reviewer quorum pattern, but its production policy is unprovisioned and its
records describe remote route cells, not these six engineering rows. The
current worktree factors out its strict Ed25519 reviewer-key check and
length-framed signature preimage into `internal/reviewercrypto` for future
independently governed evidence formats; that primitive does not provision
keys or prove physical hardware.

`internal/productionpackage` adds a score-free candidate verifier for the
proposed 11-cell inventory. It binds candidate metadata and package bytes to
the authenticated released archive and verified staging tree, including the
exact released executable digest. The candidate is not a production package
attestation: package-manager payload parsing, approved publisher signatures,
authoritative index state, and native installation remain separate checks.
`VerifySet` requires the opaque authenticated release and verifies exactly one
candidate for each of the eleven fixed cells. It returns a score-free complete
inventory for those later production checks.
`nativepackagestage release-set` prepares those eleven staging inputs from an
opaque authenticated stable release and records package building, signing,
publication, and lifecycle verification as outstanding. It does not build
production packages or award points.

The existing release assessor requires exactly nine archives and
`checksums.txt` in the GitHub release. Publishing native packages as additional
assets there would invalidate that reviewed ten-file release contract. A
separate approved native package channel, or a reviewed new release contract,
must be chosen before the package publication verifier is implemented. The
project must also approve package-family-specific signing and index mechanisms
and pin their trust roots; a generic GitHub attestation cannot be renamed a
native package-manager signature.

The current CI native package subjects use the synthetic `v0.0.0-ci` smoke
version and binary. They cannot be reused as provenance for a stable release,
even if their package formats and target cells match. The production package
build must originate from the exact assessed release and bind its published
package bytes to that release's authenticated source and binary digests.

## Implementation order and acceptance gates

1. Review and freeze the six criterion profiles: exact target inventories,
   physical-run and lifecycle commands, audit closure threshold, evidence
   freshness, package publication channel, issuer scope, and key governance.
   Until those decisions and keys are provisioned, all six rows remain zero.
2. Completed in the current worktree: native runtime and package verification
   now use context-aware internal packages with opaque, score-free results.
   The hosted/virtualized limits, complete-set checks, source/run binding,
   GitHub/Sigstore checks, post-read digests, and CLI behavior remain enforced.
   This implementation creates no external credit by itself.
3. Completed as a zero-external-credit composer in the current worktree: the
   live release verifier captures an opaque identity with scorecard and
   published asset digests. The full assessment checks all six released rows,
   derives the fixed 74/83 baseline, emits explicit missing-evidence reasons,
   and performs a final live recheck. It never ingests a saved `verify-release`
   JSON result. The versioned output schema alone cannot authenticate or award
   a row.
4. Implement separate vendor, physical/native, independent-audit, and native
   package publication/signature verifiers with provisioned trust roots. Each
   needs fixtures for valid proof and negative cases: wrong release/digest,
   incomplete inventory, substituted key, duplicate signer, same principal or
   organization, revoked/expired authorization, VM presented as physical,
   unsigned/unpublished package, stale challenge, and changed live state.
5. Exercise a real full assessment for a named, unexpired release. Inspect
   each authenticated proof, verifier result, and final live state. Only then
   may the output derive 100. A test fixture, example JSON, proposed schema,
   or this document cannot raise the current score.

Current external blockers are Riot authorization, governed physical Linux/BSD
test results, an independent audit and closure, and signed/published native
packages with production lifecycle evidence. No test credential, hosted guest,
or self-authored report may be used to fill those gaps.
