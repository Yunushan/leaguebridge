# Contributing

Contributions must preserve the fail-closed policy and the boundaries in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

Before submitting a change:

```sh
go run -mod=vendor ./tools/vendorcheck -root .
go test -mod=vendor -race ./...
go vet -mod=vendor ./...
go run -mod=vendor ./tools/coverage -minimum 80
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
go build -mod=vendor ./cmd/leaguebridge
```

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
