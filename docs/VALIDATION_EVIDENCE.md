# Validation evidence contract

LeagueBridge validation evidence is a versioned record of observations made on
a physical Windows streaming host, a native Linux/BSD client, or an end-to-end
remote session. Every schema-v1 record is scoped to the single
`physical-windows-remote` route and the `remote-play-v1` test profile. It is an
input to readiness evaluation. It is **not** an authorization token, a launcher
bypass, or proof that Riot supports Linux or BSD.

The public Draft 2020-12 schema is
[`schemas/validation-evidence.schema.json`](../schemas/validation-evidence.schema.json).
The checked-in examples are deliberately unverified templates:

- [`host-windows-unverified.json`](evidence/examples/host-windows-unverified.json)
- [`client-linux-unverified.json`](evidence/examples/client-linux-unverified.json)
- [`session-linux-unverified.json`](evidence/examples/session-linux-unverified.json)

Their deterministic IDs, empty observations, and zero measurements are sample
data only. Do not cite them as gameplay, hardware, latency, anti-cheat, or
platform-support evidence.

## Record types

Every schema-v1 record has `route_id: "physical-windows-remote"`,
`test_profile_id: "remote-play-v1"`, a privacy-safe `validation_run_id` of
`run-` plus 32 lowercase hexadecimal digits, a type-specific ID prefix and
subject, and an exact check inventory. The host, client, and session in a set
must use the same run ID; it is a random correlation value, not an account,
machine, or reviewer identifier. `manifest_sha256` binds each record to the validated embedded
compatibility manifest's canonical JSON content corresponding to
`manifest_as_of`. The canonical representation normalizes the known schema URI,
so whitespace and checkout line endings do not change the digest. Array order
remains content-significant. Check order is conventional rather than semantic;
no required ID may be missing, duplicated, or replaced.

| Type | Allowed subject | Required checks |
| --- | --- | --- |
| `host` | Physical Windows `amd64` only | `host.physical-machine`, `host.supported-os`, `host.hardware-requirements`, `host.security-requirements`, `host.riot-installation`, `host.local-practice-tool`, `host.streaming-server` |
| `client` | Linux, FreeBSD, OpenBSD, NetBSD, or DragonFly BSD on `amd64` | `client.platform`, `client.moonlight`, `client.display`, `client.audio`, `client.decoder` |
| `session` | Linux, FreeBSD, OpenBSD, NetBSD, or DragonFly BSD on `amd64` | `session.pair`, `session.app-list`, `session.video`, `session.keyboard-mouse`, `session.audio`, `session.latency`, `session.practice-tool`, `session.vanguard-errors`, `session.patch-current` |

Only session records contain `bindings`. Both
`host_record_sha256` and `client_record_sha256` remain empty in a template and
must be lowercase SHA-256 digests when set. They are intended to identify the
exact host/client record bytes; the schema and single-record evaluator check only
their shape and presence. A consumer accepting a session must recompute both
digests against the supplied records. A digest is not a signature or a trust
decision.

## Recording checks

Each check uses one status and one observation method:

- Status: `unverified`, `pass`, `fail`, or `not-applicable`.
- Method: `manual`, `automatic`, or `external`.

An `unverified` check must have an empty `observed_at` and no artifacts. Any
decided status (`pass`, `fail`, or `not-applicable`) requires an RFC 3339
`observed_at` and at least one artifact descriptor. Reviewed attestations also
require at least one descriptor. Each descriptor contains:

- a safe basename-like `name` of at most 128 characters;
- the lowercase SHA-256 of the exact external artifact bytes;
- `size_bytes` between 1 byte and 1 GiB; and
- a canonical lowercase `media_type` without parameters.

Artifact names are globally unique within a record under ASCII case folding,
including check and attestation artifacts, and their declared sizes may total
at most 4 GiB. The record contains metadata, not the artifact itself. Without an
artifact directory, the evaluator checks only these claims and can report at
most `claims-complete`.

Supplying an artifact directory makes the CLI require that it contain exactly
the declared names: no missing or unexpected entries, subdirectories, symbolic
links, junction-like non-regular entries, or other non-regular files. Each file
must have the exact declared size and SHA-256. Hashing is streamed with bounded
reads, and the resulting verification token is bound to the exact parsed
record. `artifacts_verified` is always emitted explicitly.

Artifact directories and every ancestor must be trusted and not writable by an
attacker while verification runs. The verifier holds the directory open while
enumerating it and rechecks files, but path-based lookup cannot make a hostile
directory-replacement race impossible on every supported operating system.
Never put passwords, pairing PINs, tokens, account identifiers, machine IDs, or
other secrets in a record or its artifacts.

`not-applicable` is still incomplete for readiness evaluation. Completion
requires every exact check to be `pass`.

Host/client measurements are optional. A session must contain one of each of
the following measurements (additional bounded measurements are allowed):

| Measurement | Unit | Completion acceptance profile |
| --- | --- | --- |
| `session-duration` | `seconds` | 1800 through 28800 seconds; equals the capture interval within 1 ms |
| `average-frame-rate` | `fps` | Arithmetic mean, at least 55 FPS and at most 240 FPS |
| `encode-latency` | `ms` | Greater than 0 and at most 30 ms |
| `network-latency` | `ms` | Greater than 0 and at most 80 ms |
| `decode-latency` | `ms` | Greater than 0 and at most 30 ms |
| `end-to-end-latency` | `ms` | Greater than 0 and at most 150 ms |
| `dropped-frames` | `percent` | Dropped/attempted frame ratio as a percentage, at most 1% |

Measurement IDs may not repeat. All four latency values are p95 values over the
same capture and common observation count; `average-frame-rate` is the
arithmetic mean over that capture. `end-to-end-latency` must be at least each
component p95. Component p95 values are not added because percentiles are not
generally additive. Structural validation permits non-negative values and caps
`dropped-frames` at 100%; the tighter table above is applied by evaluation. The
seven zeros in an unverified template are placeholders, not observations, and
keep a session pending.

Each session has a `measurement_methodology` object. Version
`session-metrics-v1` defines one shared capture interval for every required
metric, its common `sample_count`, a bounded collector ID and version, and the
SHA-256 of the capture artifact. A populated capture must be inside the record
lifetime, end no later than review, last at most eight hours, and provide from
one through 1000 common observations per capture second (with an absolute cap
of 10,000,000). Its digest must match an artifact declared by
`session.latency`. The capture timestamps determine `session-duration`; a
separately typed duration claim cannot extend or shorten the interval. The
empty methodology in a template is deliberately unverified and remains
pending.

Every session also has a `stream_profile`. Structural validation permits widths
and heights from 0 through 8192, target frame rates from 0 through 240, codecs
`unverified`, `h264`, `hevc`, or `av1`, and transports `unverified`, `wired-lan`,
`wifi`, or `wan`. Completion requires at least 1920x1080, a target of at least
60 FPS, and a verified codec and transport. Average frame rate must be at least
90% of the recorded target frame rate.

## Attestation and promotion

Attestation levels intentionally separate observation from review:

| Level | Required fields | Evaluation effect |
| --- | --- | --- |
| `self-attested` | `reviewer`, `reviewed_at`, and review `artifacts` must be empty | Always pending and never promotion-safe |
| `lab-observed` | Bounded reviewer ID, RFC 3339 review time, and at least one artifact | May reach `claims-complete` or artifact-verified `complete`; never promotion-safe |
| `independent-review` | Bounded reviewer ID, RFC 3339 review time, and at least one artifact | May reach `claims-complete` or artifact-verified `complete`; the manual identity claim is unauthenticated and never promotion-safe |

Schema v1 has no embedded trust root, public-key identity, or signature
verification for a reviewer. Consequently `promotion_safe` is always `false`,
including for `independent-review` records and correctly hash-bound sets. A
`claims-complete` state means the descriptor claims and acceptance profile
passed without verifying the artifact bytes. `complete` additionally means an
exact artifact bundle was re-hashed successfully. Neither state authenticates
the reviewer, promotes readiness, authorizes local gameplay, or proves Riot
support.

## Freshness and evaluation

Structural validation requires:

- schema ID `https://leaguebridge.dev/schemas/validation-evidence.schema.json`;
- `schema_version` 1;
- route ID `physical-windows-remote`, test profile `remote-play-v1`, and a
  physical Windows `amd64` host;
- a lowercase SHA-256 binding to the embedded compatibility manifest's
  canonical JSON content;
- RFC 3339 creation/expiry timestamps and a `YYYY-MM-DD` manifest date;
- expiry after creation, with no more than 30 days of validity;
- exact subject, attestation, binding, check, and measurement shapes.

Evaluation additionally requires non-future creation and review timestamps,
non-future observation timestamps for every decided status (including `fail`
and `not-applicable`), non-future capture timestamps, an unexpired record, the
current and fresh embedded compatibility manifest, matching manifest content,
reviewed attestation, every check passing, and both bindings for a session.
Creation cannot predate the manifest date; observations, capture, and review
must fall within the record lifetime, and review must be at or after every
decided observation. A session must meet the methodology, stream profile, and
every duration, frame-rate, consistency, latency, and dropped-frame threshold
above. An expired record remains readable but cannot be completed or used for
promotion.

Set evaluation also requires one shared `validation_run_id`, exact host/client
raw-file digest bindings, and matching client platform and architecture. Host
and client review must finish strictly before the session capture starts, and
the session may not expire after either bound record. These constraints prevent
a session from borrowing records reviewed after the capture or outliving its
supporting evidence.

`leaguebridge evidence validate --file RECORD.json` validates and evaluates one
record. Add `--artifacts DIRECTORY` to verify that record's exact artifact
bundle. For a session, single-record evaluation checks that binding values are
present and well formed, but it does **not** prove they match host/client files.
Only `leaguebridge evidence verify-set --host HOST.json --client CLIENT.json
--session SESSION.json` recomputes the SHA-256 digests of the supplied raw
record files, checks run/order/expiry and client subject invariants, and
evaluates the exact three-record chain. Add all of `--host-artifacts`,
`--client-artifacts`, and `--session-artifacts` to verify every bundle; supplying
only some directories is an error. This authenticates content linkage and
artifact bytes, not the claimed reviewer. Use `--json` on either command for
machine-readable output, including explicit `artifacts_verified`.

Both `evidence validate` and `evidence verify-set` exit with code 3 (blocked)
even when they report `state=claims-complete` or artifact-verified
`state=complete`, because schema-v1 manual attestations cannot produce
`promotion_safe=true`. Automation must check the exit code,
`artifacts_verified`, and the structured state; it must not reinterpret either
completion state as authorization.

## Authenticated set verifier (schema v2)

LeagueBridge also defines a separate signed-set schema v2. It wraps the exact
raw bytes of one complete, artifact-verified schema-v1 Windows host/client/
session chain in a bounded set payload and authenticates that payload with
Ed25519 signatures. The payload binds one route, one Linux/BSD client cell, the
shared run and profile, current compatibility-manifest identity, expiry, and
the SHA-256 of all three raw records. It never carries a score, mutable gate,
or `passed` field.

`leaguebridge evidence v2 verify` requires the signed envelope, all three raw
records, all three exact artifact directories, and an expected route/client
cell. The verifier strictly decodes the envelope and payload, re-evaluates the
v1 records, re-hashes every artifact, checks all cross-record bindings, and
then verifies every signature against the application-controlled reviewer
policy. Signatures must include both a lab observer and an independent reviewer
from distinct principals and organizations. A key supplied by a record, file,
flag, or environment variable is never a production trust root.

Before a provisioned policy is accepted, every reviewer public key must decode
to its exact canonical Edwards25519 encoding, must not be the identity, and must
belong to the prime-order subgroup. This rejects both small-order keys and
otherwise valid-looking mixed-order keys with a torsion component. These curve
constraints are enforced by the Go verifier because JSON Schema can validate
the 32-byte encoding's shape but cannot prove group membership.

The v2 payload, signature, and trust-policy timestamps are canonical
whole-second UTC RFC 3339 values. Wrapped schema-v1 records keep the broader
RFC 3339 syntax already accepted by v1, including numeric UTC offsets and
fractional seconds. Session validity and reviewer ordering are compared as
instants; the verifier never rewrites those record bytes, and their exact
original representations remain authenticated through the record SHA-256
bindings.

The production reviewer policy is deliberately **unprovisioned** in this
release: it contains no reviewer public keys. Consequently the command remains
blocked even for otherwise well-formed input. Test keys exist only in Go test
files. Readiness schema v3 still rejects every nonempty `evidence_sets` array
and derives a zero remote matrix. Production promotion requires a separately
reviewed readiness schema v4, embedded/root-authorized reviewer keys, and real
signed physical-run evidence. The current v2 slice is Windows-route and
schema-v1-record backed; it does not validate the experimental macOS route.

If a provisioned-policy build successfully verifies a set, its output describes
only that verification: `authenticated=true`, `artifacts_verified=true`, and
`readiness_promotable=false`, with `readiness-schema-v4` named as the promotion
boundary. It does not emit `promotion_safe` or authorize readiness schema v3 to
consume the result.

The signature proves that trusted key holders approved the exact evidence
bytes. It does not by itself prove that the observations were honest, make a
virtual machine physical, grant Riot authorization, or make League execute
locally on Linux/BSD. Those claims remain outside the cryptographic boundary.

The Go parser adds safeguards that JSON Schema alone cannot completely express:
a 1 MiB input limit, regular non-symlink file input, duplicate-key rejection,
one JSON value only, a 64-level nesting limit, exact cross-field time arithmetic,
canonical media-type parsing, globally duplicate artifact-name and
measurement-ID rejection, bounded capture sampling, and several
cross-measurement consistency checks. Optional artifact verification adds exact
directory membership, regular-file, size, and digest checks. Consumers making
readiness decisions must use the LeagueBridge parser/evaluator rather than
treating schema validation alone as a pass.

## Collection workflow

1. Generate the host template first with `leaguebridge evidence template --type
   host --platform windows --arch amd64`. Save its generated
   `validation_run_id`, then pass the same value with `--run-id ID` when
   generating the client and session templates. Save each JSON output to a new
   file; do not reuse the deterministic example IDs.
2. Work on a non-valuable test account and a supported physical host. Observe
   every check directly; retain redacted artifacts outside the JSON record and
   record their exact digest, byte length, and media type.
3. Change a check only after observation. Record failures honestly; never mark a
   blocked or skipped check as passing.
4. Validate the host and client records with their artifact directories, bind
   the SHA-256 digests of their exact raw file bytes into the session record,
   and only then begin the shared end-to-end measurement capture. Record the
   collector, common sample count, interval, capture artifact digest, and
   aggregation methods defined by `session-metrics-v1`.
5. Request lab or independent review. The reviewer records only a bounded
   identifier, review time, artifact descriptors, and non-sensitive notes.
6. Run `evidence verify-set` with all three final files and all three trusted,
   non-writable artifact directories. A standalone session validation is not a
   substitute for this set verification.
7. Repeat after material League, Vanguard, operating-system, driver, Sunshine,
   Moonlight, kernel, or network changes, and before the record expires.

The consent-gated `scripts/inspect-sunshine-host.ps1` output may be retained as
one input artifact for the host review. Its `artifact.integrity_verified` field
means only that the inspected MSI matched the repository-pinned official asset
digest and had a locally valid Authenticode signature. Its embedded doctor
report remains a bounded preflight. Its MSI-table inventory is inert metadata;
custom actions are not executed, and the absence of declarative service tables
does not prove that setup will avoid service or firewall changes. The script
always denies installation and launch authorization, and neither its output nor
a passing hash is sufficient to mark `host.physical-machine`,
`host.hardware-requirements`, `host.security-requirements`,
`host.local-practice-tool`, or `host.streaming-server` as passed.

This contract is intentionally fail-closed. Missing, malformed, stale,
self-attested, partially passing, or unbound session evidence cannot promote a
route.
