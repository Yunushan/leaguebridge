# Governance

LeagueBridge is currently maintainer-led. Maintainers review changes, releases,
compatibility evidence, security reports, and project scope.

No single data update may enable executable behavior. A new runtime backend needs
all of the following:

1. An ADR and threat-model update.
2. Evidence of official Riot support or express written authorization.
3. Code review of a fixed, non-shell adapter.
4. Automated negative/security tests and current manual end-to-end evidence.
5. A documented rollback/demotion plan.

## Release integrity

Stable release tags must be immutable and protected against deletion or force
updates in repository settings. The release workflow independently resolves
lightweight or annotated tags and refuses publication unless the peeled commit
still equals the tested workflow commit. Maintainers must also respond to the
daily compatibility-evidence freshness gate before its 30-day review window
expires.

Compatibility may be demoted immediately when evidence expires or an upstream
patch breaks a gate. Promotion requires a reviewed change; popularity is not
evidence.

Project decisions and conflicts are recorded in public issues/ADRs unless they
contain a responsibly disclosed vulnerability or private legal correspondence.
