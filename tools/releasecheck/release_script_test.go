package main

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestReleaseScriptPinsHermeticSnapshotContract(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "release.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"export GIT_NO_REPLACE_OBJECTS=1",
		"export GIT_CONFIG_NOSYSTEM=1",
		"export GIT_ATTR_NOSYSTEM=1",
		"export GIT_CONFIG_COUNT=0",
		"unset GIT_ATTR_SOURCE GIT_CONFIG_PARAMETERS",
		"git --no-replace-objects -c core.attributesFile=\"$release_git_attributes\"",
		"release_git rev-parse --git-path info/attributes",
		`[[ -e "$info_attributes" || -L "$info_attributes" ]]`,
		"export GOENV=off",
		"export GOWORK=off",
		"export GOFLAGS=",
		"export GOEXPERIMENT=",
		"export GOFIPS140=off",
		"export GOCACHEPROG=",
		"export GO_EXTLINK_ENABLED=0",
		"export GOTOOLCHAIN=local",
		"export GOPROXY=off",
		"export GONOPROXY=",
		"export GOSUMDB=off",
		"export GONOSUMDB=",
		"export GOVCS='*:off'",
		"export GOAMD64=v1",
		"export GOARM64=v8.0",
		"export GOTMPDIR=",
		`! "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$`,
		`release_git rev-parse --verify "${GITHUB_SHA}^{commit}"`,
		"release_git archive --format=tar --output=\"$snapshot_archive\" \"$commit\"",
		"go run -mod=vendor ./tools/vendorcheck -root .",
		"go run -mod=vendor ./tools/versioncheck",
		"go run -mod=vendor ./tools/readinesscheck -root .",
		`readiness_scorecard_sha256="$(sha256sum "$snapshot_root/readiness/scorecard.json")"`,
		"repository_evidence_verification=\"leaguebridge-repository-evidence-v1:$readiness_scorecard_sha256\"",
		"internal/version.RepositoryEvidenceVerification=$repository_evidence_verification",
		"go build -mod=vendor -trimpath -buildvcs=false",
		"go run -mod=vendor ./tools/sbom",
		"go run -mod=vendor ./tools/packagemanifest",
		"-tree \"$tree\"",
		"go run -mod=vendor ./tools/canonicaltar",
		"go run -mod=vendor ./tools/releasecheck",
		"go run -mod=vendor ./tools/nativepackagestage",
		"go run -mod=vendor ./tools/nativepackagecheck",
		`cp "$snapshot_root/scripts/install.sh" "$snapshot_root/scripts/linux-bsd-client-smoke.sh" "$snapshot_root/scripts/linux-bsd-remote-session.sh" "$snapshot_root/scripts/uninstall.sh" "$pack_stage/"`,
		`chmod 0755 "$pack_stage/install.sh" "$pack_stage/linux-bsd-client-smoke.sh" "$pack_stage/linux-bsd-remote-session.sh" "$pack_stage/uninstall.sh"`,
		"native_stage_root=",
		"native_stage_families=(",
		"native_stage_archives=(",
		"created and verified nine Linux/BSD release archives",
		"leaguebridge-release-contract-v4|",
		"leaguebridge-build-v4-",
		"filippo.io/edwards25519@v1.2.0#h1:crnVqOiS4jqYleHd9vaKZ+HKtHfllngJIiOpNpoJsjo=",
		"sha256sum --binary ./*.tar.gz > checksums.txt",
		"export-(ignore|subst)",
		"160000)",
		"vendor/github.com/santhosh-tekuri/jsonschema/v6/.gitmodules)",
		".gitmodules|*/.gitmodules)",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("release.sh is missing production contract fragment %q", required)
		}
	}
	for _, forbidden := range []string{"-buildvcs=true", "release-contract-v2", "leaguebridge-build-v2", "release-contract-v3", "leaguebridge-build-v3", "tar --sort=name"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("release.sh contains obsolete or non-hermetic fragment %q", forbidden)
		}
	}
	for lineNumber, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "go run ") && !strings.Contains(line, "go run -mod=vendor ") {
			t.Errorf("release.sh line %d runs a Go release tool without -mod=vendor: %s", lineNumber+1, line)
		}
		if strings.Contains(line, "go build ") && !strings.Contains(line, "go build -mod=vendor ") {
			t.Errorf("release.sh line %d builds without -mod=vendor: %s", lineNumber+1, line)
		}
	}
	assertGoEnvironmentPinnedBeforeUse(t, "release.sh", script)
	assertCanonicalSourceDateEpochGuard(t, script)
	assertGitmodulesGuard(t, script)
	bareGitCommand := regexp.MustCompile(`(^|[[:space:]$(;&|])git[[:space:]]`)
	for lineNumber, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.Contains(line, `command git --no-replace-objects -c core.attributesFile="$release_git_attributes"`) {
			continue
		}
		if bareGitCommand.MatchString(line) {
			t.Errorf("release.sh line %d bypasses release_git: %s", lineNumber+1, line)
		}
	}
}

func TestReleaseScriptPublishesOnlyAfterCompleteVerification(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "release.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)

	if !strings.Contains(script, `release_staging_dir="$(mktemp -d "$repository_root/.dist-staging.XXXXXX")"`) {
		t.Fatal("release.sh does not create a same-filesystem private dist staging directory")
	}
	if strings.Contains(script, `rm -rf -- "$release_output_dir"`) {
		t.Fatal("release.sh can delete dist before the replacement release is ready")
	}
	for _, forbidden := range []string{
		`-output "$release_output_dir/`,
		`-dir "$release_output_dir"`,
		`(cd "$release_output_dir"`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("release.sh writes or verifies against the publish path before commit: %q", forbidden)
		}
	}
	verification := strings.LastIndex(script, `go run -mod=vendor ./tools/nativepackagecheck -staging "$native_output")`)
	publish := strings.Index(script, `if [[ -e "$release_output_dir" || -L "$release_output_dir" ]]; then`)
	if verification < 0 || publish < 0 || verification > publish {
		t.Fatal("release.sh publishes before the final native-package staging verification")
	}
	for _, required := range []string{
		`release_backup_parent="$(mktemp -d "$repository_root/.dist-backup.XXXXXX")"`,
		`mv -- "$release_output_dir" "$release_backup_parent/dist"`,
		`mv -- "$release_staging_dir" "$release_output_dir"`,
		`mv -- "$release_backup_parent/dist" "$release_output_dir" || :`,
		`! -L "$work_root"`,
		`! -L "$release_backup_parent"`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("release.sh is missing rollback-safe publication fragment %q", required)
		}
	}
}

func TestNativePackageSmokeCleanupRejectsSymlinkScratch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		path  string
		guard string
		trap  string
	}{
		{
			name:  "linux",
			path:  filepath.Join("..", "..", "scripts", "native-package-linux-smoke.sh"),
			guard: `if [[ -n "${temporary_root:-}" && -e "$temporary_root" && ! -L "$temporary_root" ]]; then`,
			trap:  "trap cleanup EXIT",
		},
		{
			name:  "bsd",
			path:  filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"),
			guard: `if [ -n "${temporary_root:-}" ] && [ -e "$temporary_root" ] && [ ! -L "$temporary_root" ]; then`,
			trap:  "trap cleanup EXIT HUP INT TERM",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			for _, required := range []string{`temporary_root=$(mktemp`, "cleanup() {", test.guard, `rm -rf -- "$temporary_root"`, test.trap} {
				if !strings.Contains(script, required) {
					t.Errorf("%s is missing scratch cleanup contract fragment %q", test.path, required)
				}
			}
		})
	}
}

func TestNativePackageSmokeGuardsWorkspaceOutputDirectories(t *testing.T) {
	for _, test := range []struct {
		name     string
		path     string
		required []string
	}{
		{
			name: "linux",
			path: filepath.Join("..", "..", "scripts", "native-package-linux-smoke.sh"),
			required: []string{
				"ensure_directory native-package-staging",
				"ensure_directory native-package-output",
				"ensure_directory native-package-evidence",
				"ensure_directory native-package-output/debian",
				"ensure_directory native-package-output/rpm",
				"ensure_directory native-package-evidence/debian",
				"ensure_directory native-package-evidence/rpm",
				"debian_evidence=\"native-package-evidence/debian/install.txt\"",
				"rpm_evidence=\"native-package-evidence/rpm/install.txt\"",
				"for evidence in \"$debian_evidence\" \"$rpm_evidence\"; do",
				"evidence output already exists",
				"path changed into a non-directory after creation",
			},
		},
		{
			name: "bsd",
			path: filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"),
			required: []string{
				"ensure_directory native-package-staging",
				"ensure_directory native-package-output",
				"ensure_directory native-package-evidence",
				"ensure_directory \"$package_dir\"",
				"ensure_directory \"$evidence_dir\"",
				"if [ -e \"$evidence\" ] || [ -L \"$evidence\" ]; then",
				"evidence output already exists",
				"path changed into a non-directory after creation",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			for _, required := range test.required {
				if !strings.Contains(script, required) {
					t.Errorf("%s is missing workspace-directory guard fragment %q", test.path, required)
				}
			}
		})
	}
}

func TestNativePackageSmokeUsesTargetPackageManagerContracts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		`pkg_command=`,
		`"$pkg_command" create -m "$metadata" -r "$staging/root" -o "$generated" -f txz -n`,
		`as_root "$pkg_command" add -f "$package"`,
		`as_root "$pkg_command" delete -y "$package_name"`,
		`pkg_create -A amd64 -B "$staging/root" -p /usr/local \`,
		`-f "$packlist" -d "$description" \`,
		`as_root pkg_add -D unsigned -I "$package"`,
		`as_root pkg_delete -I "$installed_package_name"`,
		`pkg_create \`,
		`-I /usr/local -p "$root_abs/usr/local" -F gzip \`,
		`-c "$comment" -d "$description" -f "$packlist" "$package"`,
		`as_root pkg_add "$package"`,
		`as_root pkg_delete -f "$package_name"`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("BSD package smoke script is missing target package-manager contract %q", required)
		}
	}
}

func assertGitmodulesGuard(t *testing.T, script string) {
	t.Helper()
	const approved = "vendor/github.com/santhosh-tekuri/jsonschema/v6/.gitmodules"
	approvedIndex := strings.Index(script, approved+")")
	if approvedIndex < 0 {
		t.Fatalf("release.sh does not name the sole approved vendored .gitmodules path %q", approved)
	}
	caseStart := strings.LastIndex(script[:approvedIndex], `case "$tree_path" in`)
	if caseStart < 0 {
		t.Fatal("release.sh .gitmodules exception is outside a tree-path case guard")
	}
	caseTail := script[caseStart:]
	caseEnd := strings.Index(caseTail, "\n  esac")
	if caseEnd < 0 {
		t.Fatal("release.sh .gitmodules tree-path case guard is unterminated")
	}
	guard := caseTail[:caseEnd+len("\n  esac")]
	bash := bashForReleaseTest(t)
	for _, test := range []struct {
		path   string
		accept bool
	}{
		{path: approved, accept: true},
		{path: ".gitmodules"},
		{path: "nested/.gitmodules"},
		{path: "vendor/github.com/santhosh-tekuri/jsonschema/v6/other/.gitmodules"},
	} {
		t.Run("gitmodules "+strings.ReplaceAll(test.path, "/", "_"), func(t *testing.T) {
			command := exec.Command(bash, "-c", "set -euo pipefail\ntree_path=\"$1\"\n"+guard+"\nprintf accepted", "gitmodules-guard", test.path)
			output, err := command.CombinedOutput()
			if test.accept {
				if err != nil || string(output) != "accepted" {
					t.Fatalf("approved vendored .gitmodules rejected: %v\n%s", err, output)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), "contains .gitmodules") {
				t.Fatalf("unapproved .gitmodules %q was not rejected by the tree guard: %v\n%s", test.path, err, output)
			}
		})
	}
}

func assertCanonicalSourceDateEpochGuard(t *testing.T, script string) {
	t.Helper()
	guardStart := strings.Index(script, `if [[ -z "${SOURCE_DATE_EPOCH:-}" || ! "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]]; then`)
	guardEndMarker := "export SOURCE_DATE_EPOCH"
	guardEnd := strings.Index(script, guardEndMarker)
	distMutation := strings.Index(script, `release_output_dir="$repository_root/dist"`)
	if guardStart < 0 || guardEnd < guardStart || distMutation < 0 || guardStart > distMutation {
		t.Fatal("release.sh does not validate a canonical SOURCE_DATE_EPOCH before dist mutation")
	}
	guard := script[guardStart : guardEnd+len(guardEndMarker)]
	bash := bashForReleaseTest(t)
	command := exec.Command(bash, "-c", "set -euo pipefail\n"+guard)
	command.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=01787702400")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("release.sh epoch guard accepted a leading-zero value")
	}
	if !strings.Contains(string(output), "without leading zeros") {
		t.Fatalf("release.sh epoch guard failed for the wrong reason: %v\n%s", err, output)
	}
}

func TestVerifyReleaseScriptPinsHermeticGitInputs(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "verify-release-reproducible.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"export GIT_NO_REPLACE_OBJECTS=1",
		"export GIT_CONFIG_NOSYSTEM=1",
		"export GIT_ATTR_NOSYSTEM=1",
		"export GIT_CONFIG_COUNT=0",
		"unset GIT_ATTR_SOURCE GIT_CONFIG_PARAMETERS",
		"export GOFIPS140=off",
		"export GOCACHEPROG=",
		"export GO_EXTLINK_ENABLED=0",
		"export GONOPROXY=",
		"export GONOSUMDB=",
		"export GOVCS='*:off'",
		"git --no-replace-objects -c core.attributesFile=\"$release_git_attributes\"",
		"release_git rev-parse --git-path info/attributes",
		`[[ -e "$info_attributes" || -L "$info_attributes" ]]`,
		`SOURCE_DATE_EPOCH="$(release_git show -s --format=%ct HEAD)"`,
		`commit="$(release_git rev-parse HEAD)"`,
		`release_git rev-parse --verify "${GITHUB_SHA}^{commit}"`,
		`tree="$(release_git rev-parse "${commit}^{tree}")"`,
		"export GOPATH=\"$scratch/gopath\"",
		"export GOMODCACHE=\"$GOPATH/pkg/mod\"",
		"export GOCACHE=\"$scratch/gocache\"",
		"export GOTMPDIR=\"$scratch/go-tmp\"",
		"cleanup() {",
		`! -L "$scratch"`,
		"trap cleanup EXIT",
		"go run -mod=vendor ./tools/releasecheck",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("verify-release-reproducible.sh is missing Git contract fragment %q", required)
		}
	}
	assertGoEnvironmentPinnedBeforeUse(t, "verify-release-reproducible.sh", script)
	bareGitCommand := regexp.MustCompile(`(^|[[:space:]$(;&|])git[[:space:]]`)
	for lineNumber, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.Contains(line, `command git --no-replace-objects -c core.attributesFile="$release_git_attributes"`) {
			continue
		}
		if bareGitCommand.MatchString(line) {
			t.Errorf("verify-release-reproducible.sh line %d bypasses release_git: %s", lineNumber+1, line)
		}
	}
}

func TestReleaseWorkflowRecomputesExactBinaryChecksumManifest(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		`mapfile -t checksum_archives < <(printf '%s\n' "${archives[@]}" | LC_ALL=C sort)`,
		`checksum_paths+=("./$archive")`,
		`cmp --silent`,
		`sha256sum --binary "${checksum_paths[@]}"`,
		`dist/checksums.txt`,
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release workflow is missing exact checksum contract fragment %q", required)
		}
	}
	if strings.Contains(workflow, "mapfile -t manifest_lines") {
		t.Fatal("release workflow still parses checksum lines without byte-exact comparison")
	}
}

func assertGoEnvironmentPinnedBeforeUse(t *testing.T, name, script string) {
	t.Helper()
	fipsLine := "export GOFIPS140=off"
	cacheProgramLine := "export GOCACHEPROG="
	extlinkLine := "export GO_EXTLINK_ENABLED=0"
	noProxyLine := "export GONOPROXY="
	noSumDBLine := "export GONOSUMDB="
	vcsLine := "export GOVCS='*:off'"
	tmpDirLine := "export GOTMPDIR="
	firstGoUse := len(script)
	for _, marker := range []string{"$(go ", "\ngo "} {
		if index := strings.Index(script, marker); index >= 0 && index < firstGoUse {
			firstGoUse = index
		}
	}
	for _, line := range []string{fipsLine, cacheProgramLine, extlinkLine, noProxyLine, noSumDBLine, vcsLine, tmpDirLine} {
		index := strings.Index(script, line)
		if index < 0 {
			t.Fatalf("%s is missing %q", name, line)
		}
		if index > firstGoUse {
			t.Fatalf("%s pins %q only after its first Go invocation", name, line)
		}
	}

	bash := bashForReleaseTest(t)
	command := exec.Command(bash, "-c", strings.Join([]string{
		"set -euo pipefail",
		"export GOFIPS140=latest",
		"export GOCACHEPROG=/definitely-not-a-release-cache-helper",
		"export GO_EXTLINK_ENABLED=1",
		"export GONOPROXY=*",
		"export GONOSUMDB=*",
		"export GOVCS=*:all",
		fipsLine,
		cacheProgramLine,
		extlinkLine,
		noProxyLine,
		noSumDBLine,
		vcsLine,
		tmpDirLine,
		`printf '<%s>|<%s>|<%s>|<%s>|<%s>|<%s>|<%s>' "$GOFIPS140" "$GOCACHEPROG" "$GO_EXTLINK_ENABLED" "$GONOPROXY" "$GONOSUMDB" "$GOVCS" "$GOTMPDIR"`,
	}, "\n"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("execute %s Go-environment sanitization: %v\n%s", name, err, output)
	}
	if string(output) != "<off>|<>|<0>|<>|<>|<*:off>|<>" {
		t.Fatalf("%s sanitized Go environment = %q; want <off>|<>|<0>|<>|<>|<*:off>|<>", name, output)
	}
}

func TestGoModuleResolutionPolicyFailsClosedBeforeVCS(t *testing.T) {
	moduleDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDirectory, "go.mod"), []byte("module example.invalid/release-policy-probe\n\ngo 1.24.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fakeDirectory := t.TempDir()
	marker := filepath.Join(fakeDirectory, "git-invoked")
	fakeName := "git"
	fakeBody := "#!/bin/sh\nprintf invoked >\"$LEAGUEBRIDGE_FAKE_GIT_MARKER\"\nexit 99\n"
	if runtime.GOOS == "windows" {
		fakeName = "git.bat"
		fakeBody = "@echo off\r\n>\"%LEAGUEBRIDGE_FAKE_GIT_MARKER%\" echo invoked\r\nexit /b 99\r\n"
	}
	if err := os.WriteFile(filepath.Join(fakeDirectory, fakeName), []byte(fakeBody), 0o755); err != nil {
		t.Fatal(err)
	}

	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	goExecutable := filepath.Join(runtime.GOROOT(), "bin", goName)
	workspace := t.TempDir()
	base := map[string]string{
		"GOENV":                        "off",
		"GOTOOLCHAIN":                  "local",
		"GOWORK":                       "off",
		"GOPATH":                       filepath.Join(workspace, "gopath"),
		"GOMODCACHE":                   filepath.Join(workspace, "modules"),
		"GOCACHE":                      filepath.Join(workspace, "cache"),
		"GOPROXY":                      "off",
		"GONOPROXY":                    "",
		"GOSUMDB":                      "off",
		"GONOSUMDB":                    "",
		"GOVCS":                        "*:off",
		"GOPRIVATE":                    "",
		"GIT_TERMINAL_PROMPT":          "0",
		"LEAGUEBRIDGE_FAKE_GIT_MARKER": marker,
		"PATH":                         fakeDirectory + string(os.PathListSeparator) + os.Getenv("PATH"),
	}

	run := func(name, noProxy, wanted string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			overrides := make(map[string]string, len(base))
			for key, value := range base {
				overrides[key] = value
			}
			overrides["GONOPROXY"] = noProxy
			commandContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(commandContext, goExecutable, "mod", "download", "example.invalid/unresolved.git@v0.0.0")
			command.Dir = moduleDirectory
			command.Env = testEnvironment(overrides)
			output, err := command.CombinedOutput()
			if commandContext.Err() != nil {
				t.Fatalf("Go module policy command timed out: %v; output = %s", commandContext.Err(), output)
			}
			if err == nil || !strings.Contains(string(output), wanted) {
				t.Fatalf("Go module policy error = %v, output = %s; want %q", err, output, wanted)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("Go module policy invoked the fake git helper")
			} else if !os.IsNotExist(err) {
				t.Fatalf("inspect fake git marker: %v", err)
			}
		})
	}

	run("proxy off has no direct bypass", "", "module lookup disabled by GOPROXY=off")
	run("valid GOVCS policy blocks forced direct VCS", "*", "GOVCS disallows using git")
}

func testEnvironment(overrides map[string]string) []string {
	blocked := make(map[string]struct{}, len(overrides))
	for name := range overrides {
		blocked[strings.ToUpper(name)] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, assignment := range os.Environ() {
		name := assignment
		if separator := strings.IndexByte(assignment, '='); separator >= 0 {
			name = assignment[:separator]
		}
		if _, skip := blocked[strings.ToUpper(name)]; !skip {
			environment = append(environment, assignment)
		}
	}
	for name, value := range overrides {
		environment = append(environment, name+"="+value)
	}
	return environment
}

func TestVerifyReproducibleUsesRealHeadEpochWithSameTreeReplacement(t *testing.T) {
	repository := t.TempDir()
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "LeagueBridge Release Test")
	runGit(t, repository, "config", "user.email", "release-test@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "source"), []byte("same tree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", "source")
	realDate := "2024-01-02T03:04:05Z"
	replacementDate := "2034-05-06T07:08:09Z"
	realCommit := runGitWithEnvironment(t, repository, map[string]string{
		"GIT_AUTHOR_DATE":    realDate,
		"GIT_COMMITTER_DATE": realDate,
	}, nil, "commit", "--quiet", "--no-gpg-sign", "-m", "real head")
	if realCommit != "" {
		t.Fatalf("quiet commit unexpectedly printed %q", realCommit)
	}
	realCommit = runGit(t, repository, "rev-parse", "HEAD")
	realTree := runGit(t, repository, "rev-parse", realCommit+"^{tree}")
	realEpoch := runGitWithEnvironment(t, repository, nil, releaseGitUnsetEnvironment(),
		"--no-replace-objects", "show", "-s", "--format=%ct", realCommit)

	replacementCommit := runGitWithEnvironment(t, repository, map[string]string{
		"GIT_AUTHOR_DATE":    replacementDate,
		"GIT_COMMITTER_DATE": replacementDate,
	}, nil, "commit-tree", realTree, "-m", "replacement head")
	replacementTree := runGit(t, repository, "rev-parse", replacementCommit+"^{tree}")
	if replacementTree != realTree {
		t.Fatalf("replacement tree = %q; want same tree %q", replacementTree, realTree)
	}
	runGit(t, repository, "replace", realCommit, replacementCommit)

	replacementEpoch := runGitWithEnvironment(t, repository, nil, releaseGitUnsetEnvironment(),
		"show", "-s", "--format=%ct", "HEAD")
	if replacementEpoch == realEpoch {
		t.Fatal("replacement fixture did not change the unprotected HEAD epoch")
	}
	emptyConfig, emptyAttributes := emptyGitPolicyFiles(t)
	derivedEpoch := runGitWithEnvironment(t, repository, releaseGitEnvironment(emptyConfig), releaseGitUnsetEnvironment(),
		"--no-replace-objects", "-c", "core.attributesFile="+emptyAttributes,
		"show", "-s", "--format=%ct", "HEAD")
	if derivedEpoch != realEpoch {
		t.Fatalf("hardened derived HEAD epoch = %q; want real commit epoch %q (replacement supplied %q)", derivedEpoch, realEpoch, replacementEpoch)
	}
}

func TestReleaseGitDisablesReplacementObjects(t *testing.T) {
	repository := t.TempDir()
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "LeagueBridge Release Test")
	runGit(t, repository, "config", "user.email", "release-test@example.invalid")
	sourcePath := filepath.Join(repository, "source")
	if err := os.WriteFile(sourcePath, []byte("bound tree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", "source")
	runGit(t, repository, "commit", "--quiet", "--no-gpg-sign", "-m", "bound source")
	boundCommit := runGit(t, repository, "rev-parse", "HEAD")

	if err := os.WriteFile(sourcePath, []byte("replacement tree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", "source")
	runGit(t, repository, "commit", "--quiet", "--no-gpg-sign", "-m", "replacement source")
	replacementCommit := runGit(t, repository, "rev-parse", "HEAD")
	replacementTree := runGit(t, repository, "rev-parse", replacementCommit+"^{tree}")
	runGit(t, repository, "replace", boundCommit, replacementCommit)

	unprotectedTree := runGitWithEnvironment(t, repository, nil, nil, "rev-parse", boundCommit+"^{tree}")
	if unprotectedTree != replacementTree {
		t.Fatalf("replacement-ref fixture is inactive: got tree %q; want %q", unprotectedTree, replacementTree)
	}

	emptyConfig, emptyAttributes := emptyGitPolicyFiles(t)
	hardenedEnvironment := releaseGitEnvironment(emptyConfig)
	boundTree := runGitWithEnvironment(t, repository, hardenedEnvironment, releaseGitUnsetEnvironment(),
		"--no-replace-objects", "-c", "core.attributesFile="+emptyAttributes,
		"rev-parse", boundCommit+"^{tree}")
	if boundTree == replacementTree {
		t.Fatal("hardened Git resolved the replacement tree")
	}

	archivePath := filepath.Join(t.TempDir(), "source.tar")
	runGitWithEnvironment(t, repository, hardenedEnvironment, releaseGitUnsetEnvironment(),
		"--no-replace-objects", "-c", "core.attributesFile="+emptyAttributes,
		"archive", "--format=tar", "--output="+archivePath, boundCommit)
	content, found := readTarMember(t, archivePath, "source")
	if !found || string(content) != "bound tree\n" {
		t.Fatalf("hardened archive source = %q, found %t; want bound tree", content, found)
	}
}

func TestReleaseGitIgnoresConfiguredOutOfTreeAttributes(t *testing.T) {
	repository := releaseAttributeFixture(t)
	externalAttributes := filepath.Join(t.TempDir(), "external-attributes")
	if err := os.WriteFile(externalAttributes, []byte("source export-ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	globalConfig := filepath.Join(t.TempDir(), "global-config")
	configData := "[core]\n\tattributesFile = " + filepath.ToSlash(externalAttributes) + "\n"
	if err := os.WriteFile(globalConfig, []byte(configData), 0o644); err != nil {
		t.Fatal(err)
	}

	globalArchive := filepath.Join(t.TempDir(), "global.tar")
	runGitWithEnvironment(t, repository, map[string]string{
		"GIT_CONFIG_GLOBAL":   globalConfig,
		"GIT_CONFIG_NOSYSTEM": "1",
	}, releaseGitUnsetEnvironment(), "archive", "--format=tar", "--output="+globalArchive, "HEAD")
	if _, found := readTarMember(t, globalArchive, "source"); found {
		t.Fatal("global attributes fixture did not affect the unprotected archive")
	}

	runGit(t, repository, "config", "core.attributesFile", filepath.ToSlash(externalAttributes))
	localArchive := filepath.Join(t.TempDir(), "local.tar")
	runGitWithEnvironment(t, repository, nil, releaseGitUnsetEnvironment(),
		"archive", "--format=tar", "--output="+localArchive, "HEAD")
	if _, found := readTarMember(t, localArchive, "source"); found {
		t.Fatal("repository-local core.attributesFile fixture did not affect the unprotected archive")
	}

	emptyConfig, emptyAttributes := emptyGitPolicyFiles(t)
	hardenedArchive := filepath.Join(t.TempDir(), "hardened.tar")
	runGitWithEnvironment(t, repository, releaseGitEnvironment(emptyConfig), releaseGitUnsetEnvironment(),
		"--no-replace-objects", "-c", "core.attributesFile="+emptyAttributes,
		"archive", "--format=tar", "--output="+hardenedArchive, "HEAD")
	content, found := readTarMember(t, hardenedArchive, "source")
	if !found || string(content) != "committed source\n" {
		t.Fatalf("hardened archive source = %q, found %t; want committed source", content, found)
	}
}

func TestReleaseScriptRefusesInfoAttributes(t *testing.T) {
	repository := releaseAttributeFixture(t)
	writeInfoAttributes(t, repository)
	unprotectedArchive := filepath.Join(t.TempDir(), "info.tar")
	runGitWithEnvironment(t, repository, nil, releaseGitUnsetEnvironment(),
		"archive", "--format=tar", "--output="+unprotectedArchive, "HEAD")
	if _, found := readTarMember(t, unprotectedArchive, "source"); found {
		t.Fatal("info/attributes fixture did not affect the unprotected archive")
	}

	runBashScriptExpectFailure(t, repository, "release.sh", "release builds refuse out-of-tree Git attributes")
}

func TestVerifyReleaseScriptRefusesInfoAttributes(t *testing.T) {
	repository := releaseAttributeFixture(t)
	writeInfoAttributes(t, repository)
	runBashScriptExpectFailure(t, repository, "verify-release-reproducible.sh", "reproducibility checks refuse out-of-tree Git attributes")
}

func writeInfoAttributes(t *testing.T, repository string) {
	t.Helper()
	infoAttributes := runGit(t, repository, "rev-parse", "--git-path", "info/attributes")
	if !filepath.IsAbs(infoAttributes) {
		infoAttributes = filepath.Join(repository, filepath.FromSlash(infoAttributes))
	}
	if err := os.MkdirAll(filepath.Dir(infoAttributes), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoAttributes, []byte("source export-ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runBashScriptExpectFailure(t *testing.T, repository, scriptName, wantedMessage string) {
	t.Helper()
	bash := bashForReleaseTest(t)
	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "scripts", scriptName))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(bash, filepath.ToSlash(scriptPath))
	command.Dir = repository
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("%s accepted repository info/attributes", scriptName)
	}
	if !strings.Contains(string(output), wantedMessage) {
		t.Fatalf("%s failed for the wrong reason: %v\n%s", scriptName, err, output)
	}
}

func bashForReleaseTest(t *testing.T) string {
	t.Helper()
	var candidates []string
	if runtime.GOOS == "windows" {
		if gitExecutable, err := exec.LookPath("git"); err == nil {
			gitRoot := filepath.Clean(filepath.Join(filepath.Dir(gitExecutable), ".."))
			candidates = append(candidates,
				filepath.Join(gitRoot, "bin", "bash.exe"),
				filepath.Join(gitRoot, "usr", "bin", "bash.exe"),
			)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		candidates = append(candidates, bash)
	}
	for _, candidate := range candidates {
		command := exec.Command(candidate, "--version")
		if output, err := command.CombinedOutput(); err == nil && strings.Contains(string(output), "GNU bash") {
			return candidate
		}
	}
	t.Skip("a working GNU bash is unavailable")
	return ""
}

func releaseAttributeFixture(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "LeagueBridge Release Test")
	runGit(t, repository, "config", "user.email", "release-test@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "source"), []byte("committed source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", "source")
	runGit(t, repository, "commit", "--quiet", "--no-gpg-sign", "-m", "source")
	return repository
}

func emptyGitPolicyFiles(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	config := filepath.Join(directory, "empty-config")
	attributes := filepath.Join(directory, "empty-attributes")
	for _, path := range []string{config, attributes} {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return config, attributes
}

func releaseGitEnvironment(emptyConfig string) map[string]string {
	return map[string]string{
		"GIT_NO_REPLACE_OBJECTS": "1",
		"GIT_CONFIG_NOSYSTEM":    "1",
		"GIT_ATTR_NOSYSTEM":      "1",
		"GIT_CONFIG_COUNT":       "0",
		"GIT_CONFIG_SYSTEM":      emptyConfig,
		"GIT_CONFIG_GLOBAL":      emptyConfig,
	}
}

func releaseGitUnsetEnvironment() []string {
	return []string{"GIT_ATTR_SOURCE", "GIT_CONFIG_PARAMETERS"}
}

func runGitWithEnvironment(t *testing.T, repository string, overrides map[string]string, unset []string, arguments ...string) string {
	t.Helper()
	blocked := make(map[string]struct{}, len(overrides)+len(unset))
	for name := range overrides {
		blocked[strings.ToUpper(name)] = struct{}{}
	}
	for _, name := range unset {
		blocked[strings.ToUpper(name)] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides)+2)
	for _, assignment := range os.Environ() {
		name := assignment
		if separator := strings.IndexByte(assignment, '='); separator >= 0 {
			name = assignment[:separator]
		}
		if _, skip := blocked[strings.ToUpper(name)]; !skip {
			environment = append(environment, assignment)
		}
	}
	for name, value := range overrides {
		environment = append(environment, name+"="+value)
	}
	if _, overridden := overrides["GIT_AUTHOR_DATE"]; !overridden {
		environment = append(environment, "GIT_AUTHOR_DATE=2026-08-26T00:00:00Z")
	}
	if _, overridden := overrides["GIT_COMMITTER_DATE"]; !overridden {
		environment = append(environment, "GIT_COMMITTER_DATE=2026-08-26T00:00:00Z")
	}
	command := exec.Command("git", arguments...)
	command.Dir = repository
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func readTarMember(t *testing.T, archivePath, member string) ([]byte, bool) {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil, false
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == member {
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			return data, true
		}
	}
}

func TestUninstallerRequiresExplicitRootsBeforePathConstruction(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "uninstall.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	prefixGuard := strings.Index(script, `if [ "${PREFIX+x}" != x ]`)
	destdirGuard := strings.Index(script, `if [ "${DESTDIR+x}" != x ]`)
	pathConstruction := strings.Index(script, "install_root=$destdir$prefix")
	if prefixGuard < 0 || destdirGuard < 0 || pathConstruction < 0 || prefixGuard > pathConstruction || destdirGuard > pathConstruction {
		t.Fatal("uninstall.sh does not require explicit PREFIX and DESTDIR before constructing owned paths")
	}
	if strings.Contains(script, "prefix=/usr/local") || strings.Contains(script, "destdir=${DESTDIR-") {
		t.Fatal("uninstall.sh still contains an implicit removal target")
	}
}

func TestAnnotatedTagObjectPeelsToBoundCommitAndTree(t *testing.T) {
	repository := t.TempDir()
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "LeagueBridge Release Test")
	runGit(t, repository, "config", "user.email", "release-test@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "source"), []byte("bound tree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", "source")
	runGit(t, repository, "commit", "--quiet", "--no-gpg-sign", "-m", "source")
	commit := runGit(t, repository, "rev-parse", "HEAD")
	runGit(t, repository, "tag", "--annotate", "--no-sign", "--message", "release", "v1.2.3")
	tagObject := runGit(t, repository, "rev-parse", "refs/tags/v1.2.3")
	if tagObject == commit {
		t.Fatal("fixture tag is not annotated")
	}
	peeled := runGit(t, repository, "rev-parse", "--verify", tagObject+"^{commit}")
	if peeled != commit {
		t.Fatalf("annotated tag peeled to %q; want commit %q", peeled, commit)
	}
	tree := runGit(t, repository, "rev-parse", peeled+"^{tree}")
	if err := validateTree(tree); err != nil {
		t.Fatalf("peeled commit tree is invalid: %v", err)
	}
}
