# Native production observations

`internal/productionnative` is a score-free verifier for retained, signed
native-run observations. It is preparatory work for three external rows in the
[full production assessment](PRODUCTION_ASSESSMENT_V4_DESIGN.md): integration
on all nine shipped Linux/BSD targets, physical BSD smoke on seven targets,
and native package lifecycle on eleven package targets. Each row remains
all-or-nothing.

The verifier fixes those inventories in application code. An observation must
match the expected release version, source commit and tree, release ID,
published archive digest, executable digest, target cell, and a
caller-selected challenge. A production issuer must establish its freshness
and prevent replay. A package lifecycle observation also needs the
expected digest of the exact published package. It binds bounded raw artifact
bytes and requires signatures from separately governed lab observer and
independent reviewer identities with distinct principals and organizations.
The record cannot introduce its own trust key, policy, release identity, or
target cell.

These checks authenticate what reviewers signed and which artifact bytes they
reviewed. They do not by themselves establish that a machine was physical,
that a streamed game worked, or that a package was signed and published. Those
facts require an approved evidence profile, independent witness procedures,
release-derived executable digests, publisher signatures, live package index
and withdrawal checks, and a final recheck of mutable state. The current
production reviewer policy has no trusted keys; no native observation earns
readiness points.

The host-free Fedora 44 x86_64 client smoke is useful preflight evidence. Its
pass result does not cover a paired physical game host, video, audio, input,
gameplay, an independent witness, or the complete target inventories, so it
cannot satisfy any of these production rows.
