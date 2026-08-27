# Security policy

## Reporting a LeagueBridge vulnerability

Use GitHub's private vulnerability reporting for this repository. If it is not
available, open an issue containing only the words “private security contact
needed”; do not include vulnerability details, logs, account data, or proof of
concepts in public.

Maintainers should acknowledge a complete private report within three business
days, provide an initial assessment within seven, and coordinate disclosure after
a fix is available. These targets are best effort for a volunteer project.

Supported security fixes apply to the latest release and the current default
branch. There are no stable releases yet.

## Scope

In scope: LeagueBridge command/config injection, unsafe file handling, policy
bypass, secret leakage, package/update integrity, vendored-source or SBOM
contract bypass, unsafe use of a dependency, or privilege escalation.

Out of scope here: Riot Client, League, Vanguard, Moonlight, Sunshine, Windows,
Wine, hypervisors, or defects solely within an upstream third-party package.
Reports that LeagueBridge pins a vulnerable version or invokes an upstream API
unsafely remain in scope here; report the underlying package defect upstream as
well. Report Riot vulnerabilities through
[Riot's security process](https://www.riotgames.com/en/reporting-a-security-vulnerability).

Do not test with another person's account, public matchmaking, service
disruption, anti-cheat evasion, credential access, or destructive payloads.
