# Upstream request: official Linux/BSD League support

**Status: draft; not submitted and not authorization.**

LeagueBridge cannot create a legitimate Linux or BSD League runtime by copying
Riot files, emulating or hiding Vanguard, or weakening the host kernel. The
remaining path to local gameplay is an explicit Riot-supported or Riot-
authorized runtime contract.

Riot's current [Vanguard x LoL explanation](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol/)
says that Linux has not been officially supported and that the Wine/Lutris
implementation cannot satisfy Vanguard's driver requirements. The public
[Linux support request](https://github.com/RiotVanguard/Vanguard/issues/84)
remains open as of 3 September 2026, with no assignee, linked branch, or pull
request. This document provides a respectful, non-exploit request for a
supported solution; it does not claim that one exists.

## Copy/paste request

**Subject:** Request for an official League of Legends Linux/BSD support contract

Hello Riot Games,

I maintain an open-source Linux/BSD client project for League of Legends users.
We are not asking for a Vanguard bypass, copied DLLs, a concealed VM, input
injection, or any reverse-engineered proprietary component. We want to use only
a route Riot explicitly supports and can verify.

Could Riot please clarify the following?

1. Is Riot planning or willing to authorize League of Legends on Linux? If so,
   which distributions, kernels, architectures, graphics stacks, and desktop
   sessions are in scope?
2. Can Riot publish the supported Vanguard trust/attestation contract for that
   route, including Secure Boot, TPM, kernel-module signing, boot-state checks,
   privacy boundaries, and update/rollback behavior?
3. Is a native client required, or could Riot authorize a defined Wine/Proton
   integration with publisher-controlled anti-cheat support? Please identify
   the exact launcher, runtime, and anti-cheat versions that would be allowed.
4. Is any BSD operating system in scope? If not, please state that explicitly
   so BSD projects do not misrepresent Linux authorization as BSD support.
5. What test and reporting process would let an independent open-source project
   validate installation, patching, sign-in, Practice Tool, reconnect, input,
   audio, networking, and ordinary game queues without automating public play?

We will keep Riot Client, League, and Vanguard unmodified; obtain all software
from Riot; avoid credentials in diagnostics; and stop distributing or invoking
any route that Riot does not authorize. A written platform/anti-cheat support
statement and a documented validation path would be sufficient to start a
reviewed implementation.

Thank you.

## What an acceptable answer must contain

For LeagueBridge to consider a local route, the response must be attributable
to Riot and specific enough to review:

- the exact supported OS/runtime and architecture, including whether BSD is
  included separately from Linux;
- the allowed Riot client and Vanguard distribution/update mechanism;
- the host trust and kernel requirements, with no requirement to conceal or
  spoof virtualization;
- redistribution, licensing, security-reporting, and support boundaries; and
- a current, repeatable end-to-end validation procedure.

An informal forum comment, a working launcher window, a downloaded DLL, a
third-party patch, or an unsigned kernel experiment is not authorization.

## Repository policy while awaiting a response

Until a qualifying response exists, the embedded compatibility policy keeps
local Linux/BSD gameplay blocked. The project may continue improving its
Linux/BSD Moonlight client and its explicitly separate physical-host handoff,
but no user-supplied reply, issue comment, or local experiment can promote a
native League/Vanguard backend. Do not send account identifiers, credentials,
machine secrets, or private diagnostic bundles with an upstream request.

Relevant references:

- [Riot system requirements](https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends)
- [Riot Vanguard error codes](https://support.riotgames.com/en-us/riot/performance/vanguard-error-codes)
- [LeagueBridge legal and authorization gates](LEGAL-AND-AUTHORIZATION.md)
