# External evidence needed for a 100-point production assessment

This is an intake checklist for a named, unexpired LeagueBridge release. It is
not an approved trust policy and does not award points. The last authenticated
assessment of `v0.1.0` was 83/100 on 2026-09-23; its released scorecard expires
at 2026-10-06T00:00:00Z. A later assessment must reauthenticate the release and
every mutable evidence source.

Before submitting records, identify the separately approved verifier principals,
their organization and role, key fingerprints, independently authenticated key
distribution channel, validity, revocation, and rotation process. A key or policy
embedded only in the submitted record cannot establish its own authority.

| Criterion | Points | Evidence to provide for the exact assessed release |
| --- | ---: | --- |
| Riot authorization | 2 | Riot-controlled publication or independently authenticated written authorization, with current withdrawal status and explicit Linux/BSD platform, client/Vanguard, integration, test, and redistribution scope. [Riot's system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends), checked 2026-09-25, list Windows/macOS; they do not authorize this Linux/BSD scope. |
| Native validated integration | 3 | Independently observed runs for all nine shipped Linux/BSD target cells, each bound to the released binary and dependencies, physical host route, native Moonlight execution, display/audio/input behavior, challenge, raw artifacts, and expiry. |
| Physical BSD smoke | 5 | Independently witnessed native-kernel and physical-machine/boot evidence for the seven BSD cells, with exact release digests, installation/smoke artifacts, distinct observer and reviewer principals, challenge, and expiry. |
| Independent audit closure | 2 | Auditor engagement and independence, exact release/source scope, signed findings inventory, closure/retest for every finding required by the approved policy, and current report/withdrawal status. |
| Native OS packages | 3 | Approved publication channel and authenticated index roots; publisher signing keys for each family; eleven release-bound package files and signed build subjects; package-manager metadata, staged and published payload digests, signatures, live index membership, and withdrawal state. |
| Package lifecycle smoke | 2 | Independent install, upgrade/repair, native CLI smoke, and uninstall observations for every published package cell, with native OS/kernel and architecture, installed file digests/modes, unrelated-file preservation, cleanup, and links to the signed published package. |

A [draft remote-handoff Riot inquiry](UPSTREAM_REMOTE_HANDOFF_REQUEST.md) is ready for maintainer review; it has not been submitted and does not establish authorization.

For each record, supply its location, immutable digest, producer and independent
witness, creation and expiry times, exact release version/commit/tree and binary
or package digests, and the authoritative way to recheck its current state.
Please also supply the governance decisions that freeze target inventories,
reviewer independence and quorum, freshness and challenge rules, audit closure
threshold, package channel, and signature/index mechanisms. Records must not
contain a caller-selected readiness score.

The detailed proposed acceptance contract is in
[PRODUCTION_ASSESSMENT_V4_DESIGN.md](PRODUCTION_ASSESSMENT_V4_DESIGN.md).
