# ADR 0005: Authenticated validation-evidence v2 foundation

Status: accepted as non-promoting foundation — 2026-08-26

## Context

Validation-evidence schema v1 strictly binds a route-matching Windows or native
macOS host, Linux/BSD client, session, and artifact observations, but its
reviewer identity is a manual string. Even complete, artifact-verified v1
evidence is therefore intentionally not promotion-safe. Readiness schema v3
anticipates authenticated evidence version 2, rejects every nonempty
remote-evidence reference, and keeps both remote routes at zero.

Treating a public key supplied beside evidence as trusted would only replace a
self-attested name with a self-attested key. Re-serializing JSON before signing
would also make the authenticated bytes dependent on parser and serializer
behavior.

## Decision

LeagueBridge defines a deliberately bounded authenticated-evidence foundation:

- `validation-evidence-v2.schema.json` is one flat, score-free set payload. It
  binds a `physical-windows-remote` or `physical-macos-remote` /
  `remote-play-v1` run, its exact route-matching Windows `amd64` or macOS
  `amd64`/`arm64` host and Linux/BSD `amd64`/`arm64` client cell, the compatibility
  manifest, three raw schema-v1 record SHA-256 digests, and one trust-policy ID.
- `evidence-signature-envelope.schema.json` carries those exact payload bytes as
  canonical RFC 4648 base64url without padding and two to eight Ed25519
  signatures. Signature entries are strictly ordered by key ID. Timestamps in
  the v2 payload, envelope signatures, and trust policy use canonical
  whole-second UTC RFC 3339.
- `evidence-trust-policy.schema.json` documents the policy injected into an
  official verifier. A provisioned policy needs at least one lab observer and
  one independent reviewer, using distinct keys, principals, and organizations.
  Reviewer public keys must be canonical Edwards25519 encodings of non-identity
  points in the prime-order subgroup; low-order and mixed-order points are
  rejected before the policy is accepted. Keys are time-bounded,
  route/platform/architecture/profile scoped, and may be revoked.

The verifier decodes `payload` once, requires raw base64url decode followed by
identical re-encoding, and strictly parses the decoded bytes without duplicate
or unknown fields. Each signature verifies this exact byte sequence:

```text
ASCII("LeagueBridge/validation-evidence-set/v2\x00")
|| uint64be(len(payload_type)) || UTF8(payload_type)
|| uint64be(len(key_id))       || ASCII(key_id)
|| uint64be(len(signed_at))    || ASCII(signed_at)
|| uint64be(len(payload))      || exact decoded payload bytes
```

The verifier never signs or verifies a JSON reconstruction. Whitespace,
object-member order, escaping, or a trailing-newline change therefore
invalidates the signature even if another JSON parser would produce equivalent
values. A key ID is `lbk1-` followed by lowercase hexadecimal SHA-256 over
`ASCII("LeagueBridge/reviewer-key/v1\x00") || raw_public_key`.

The payload's `policy_id` must select the production policy already injected
into the running verifier. No command-line key, environment key, repository
file, or policy shipped beside an evidence envelope can become a production
trust root. The verifier—not JSON Schema—enforces ordering, uniqueness,
canonical prime-subgroup reviewer keys, validity intervals, revocation, exact
scope, and the distinct lab-plus-independent quorum. Point decoding and
subgroup validation use the pinned, vendored `filippo.io/edwards25519` v1.2.0
module rather than local curve arithmetic. Release builds accept that exact
compiled dependency without replacements or additional compiled modules.

The production policy is intentionally `unprovisioned`: it has no keys or
validity interval. This allows the verifier and negative trust behavior to ship
without inventing reviewer identities or embedding private keys. It also means
no current v2 envelope can authenticate under the production policy or promote
readiness.

## Compatibility and boundaries

Schema v1 and its CLI behavior remain unchanged. Schema v2 authenticates the
hashes of the three raw v1 records; it does not reinterpret v1 as trusted, infer
missing observations, or accept a v1 signature through fallback. Readiness
schema v3 also remains unchanged and rejects v2 evidence references.

Schema-v1 timestamps retain their existing RFC 3339 contract, including valid
numeric UTC offsets and fractional seconds. The v2 verifier compares session
validity and reviewer ordering as time instants, not timestamp spellings. The
signed v2 payload stays canonical, and its record digests bind every original
v1 byte, so compatibility does not require rewriting or normalizing a record.

The v2 slice is route-aware and v1-record-backed. Artifact bundles are
enumerated and hashed beneath one pinned `os.Root`, with exact membership,
regular-file, identity, size, and digest checks before an opaque verification
token can be used. It does not yet provide a signed collection challenge,
source/release or package-manifest binding, replay registry, or full scorecard
integration. A valid signature establishes that a
policy-recognized reviewer authenticated exact bytes; it does not by itself
prove physical hardware, honest observation, general platform support, Riot
authorization, or safe local Linux/BSD gameplay. The payload therefore contains
no `passed`, gate, score, support, or launch-authorization field.

A successful verifier result means the exact set is authenticated and its
artifacts were verified. Its machine-readable result explicitly reports
`authenticated=true`, `artifacts_verified=true`, and
`readiness_promotable=false`, with `readiness-schema-v4` as the promotion
boundary. It never reports the set as promotion-safe under readiness schema v3.

The CLI also provides `evidence v2 prepare`. It re-verifies the exact v1
records and artifact bundles, derives a fresh set ID and canonical validity
instants, and emits the exact score-free payload bytes for external reviewers
to sign. It has no key, policy, or signing input and refuses to overwrite an
existing payload file. Preparation is a collection aid only; it does not
change the unprovisioned production policy or create promotion evidence.

Reviewer private keys never belong in this repository, application process, or
ordinary CI. Test keys may exist only in tests. A locally modified binary may
replace its own trust policy and is not an authoritative official-release
verifier.

## Next decision

The repository now contains a derived readiness-schema-v4 output contract, an
opaque `PromoteRemoteSetAt` evaluator, and an `evidence v2 promote` CLI path.
Before v3 or an overall release score can consume that result, a separate
reviewed change must provision independently governed production public keys;
add signed challenge, exact release/package, patch, and artifact bindings;
connect those bindings to the evaluator; and retain replay-safe evidence for
exactly one route/platform run. Only real physical runs signed under that
policy may populate readiness references. Until then, both remote routes
remain unvalidated at zero and local gameplay remains blocked.
