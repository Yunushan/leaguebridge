# Contributing

Contributions must preserve the fail-closed policy and the boundaries in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

LeagueBridge's native product targets are Linux, FreeBSD, OpenBSD, and NetBSD
on amd64 or arm64, plus DragonFly BSD on amd64. Do not add Windows or macOS build, installation, or
gameplay targets: those operating systems are vendor-managed League hosts and
may appear here only for the explicitly external physical-host handoff safety
contract described in [`docs/PLATFORM_SCOPE.md`](docs/PLATFORM_SCOPE.md).

Before submitting a change:

```sh
go run -mod=vendor ./tools/vendorcheck -root .
go test -mod=vendor -race ./...
go vet -mod=vendor ./...
go run -mod=vendor ./tools/coverage -minimum 80
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
go build -mod=vendor ./cmd/leaguebridge
```

## Recovering from a stale Git index lock

If Git reports that `.git/index.lock` already exists, close GitHub Desktop,
editors, and other operations that may be changing this checkout first. In
PowerShell, inspect the exact repository lock and active Git processes:

```powershell
Get-Process git,git-remote-https,git-lfs -ErrorAction SilentlyContinue
Test-Path -LiteralPath .git\index.lock
```

Only when no Git process is active and the lock belongs to this checkout, remove
that exact file and retry:

```powershell
Remove-Item -LiteralPath .git\index.lock
git status
```

Never remove the lock while another Git process is running; it protects the
index from concurrent writes.

The vulnerability scan uses the live Go vulnerability database and fails only
for known vulnerabilities reachable from LeagueBridge symbols. Release builds
must use the exact supported Go toolchain pinned by the release workflow; the
minimum Go job proves source compatibility and is not a production builder.

Dependency changes require explicit security and license review. Regenerate
`go.mod`, `go.sum`, the complete `vendor/` tree, and the reviewed vendor lock
with the production Go toolchain; update the release dependency allowlist and
build-contract version when the compiled dependency identity changes. Do not
hand-edit vendored source or weaken `vendorcheck` to make drift pass.

New compatibility claims need a primary source, retrieval/review/expiry dates,
and a test. Cross-building is not evidence that an OS works.

Do not submit Riot binaries/assets, credentials, copied DLLs, Vanguard files,
client injection, VM concealment, hardware spoofing, security-disablement,
gameplay automation, bots, cheats, or private-protocol reverse engineering.

Large changes should begin with an issue or ADR. Commits should be focused and
must include tests for changed behavior. By contributing, you agree that your
work may be distributed under the repository's 0BSD license.
