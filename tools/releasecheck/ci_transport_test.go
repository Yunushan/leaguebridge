package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBSDStagingWorkflowCreatesTheImmediateOutputParent(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Stage and verify native package input", "Stage and verify DragonFly native package input"} {
		t.Run(name, func(t *testing.T) {
			script := workflowRun(t, string(workflow), name)
			script = strings.NewReplacer("${{ matrix.family }}", "freebsd-pkg", "${{ matrix.goarch }}", "amd64", "${{ matrix.goos }}", "freebsd").Replace(script)
			// The actual staging command requires an existing immediate parent.
			// Execute the workflow shell with that filesystem contract enforced;
			// creating only native-package-staging fails this regression.
			mock := `go() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -output) shift; test -d "$(dirname "$1")" || exit 41; mkdir "$1" || exit 42 ;;
      -staging) shift; test -d "$1" || exit 43 ;;
    esac
    shift
  done
}
`
			runShellFixture(t, mock+script)
		})
	}
}

func TestFreeBSDPackageBuilderPassesTheCompletePayloadInventory(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "    metadata=\"$temporary_root/metadata\"")
	if start < 0 {
		t.Fatal("FreeBSD metadata builder absent")
	}
	end := strings.Index(script[start:], "    ;;\n  openbsd)")
	if end < 0 {
		t.Fatal("FreeBSD builder end absent")
	}
	// Exercise the real builder branch. The pkg stand-in consumes the -p
	// argument just as pkg does; a metadata-only invocation cannot pass.
	setup := `temporary_root="$PWD/work"
mkdir "$temporary_root"
staging="$temporary_root/staging"
mkdir -p "$staging/root"
package_version=0.0.0-ci
package="$temporary_root/result.pkg"
pkg_command=fixture_pkg
fail() { echo "$*" >&2; exit 44; }
fixture_pkg() {
  plist=
  while [ "$#" -gt 0 ]; do
    case "$1" in -p) shift; plist=$1;; esac
    shift
  done
  [ -n "$plist" ] && [ -f "$plist" ] || exit 45
  cp "$plist" "$temporary_root/observed-plist"
  printf 'fixture package\n' > "$generated/leaguebridge-test.pkg"
}
`
	dir := runShellFixture(t, setup+script[start:start+end])
	observed, err := os.ReadFile(filepath.Join(dir, "work", "observed-plist"))
	if err != nil {
		t.Fatal(err)
	}
	mode := ""
	files := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(observed)), "\n") {
		if strings.HasPrefix(line, "@mode ") {
			mode = strings.TrimPrefix(line, "@mode ")
			continue
		}
		if strings.HasPrefix(line, "@dir ") {
			if mode != "0755" {
				t.Fatalf("directory inherits non-searchable mode %s", mode)
			}
			continue
		}
		if strings.HasPrefix(line, "@") {
			continue
		}
		if _, duplicate := files[line]; duplicate {
			t.Fatalf("duplicate payload %s", line)
		}
		files[line] = mode
	}
	want := map[string]string{"bin/leaguebridge": "0755", "libexec/leaguebridge/linux-bsd-client-smoke.sh": "0755", "libexec/leaguebridge/linux-bsd-remote-session.sh": "0755", "share/doc/leaguebridge/LICENSE": "0644", "share/doc/leaguebridge/README.md": "0644", "share/doc/leaguebridge/SBOM.spdx.json": "0644", "share/doc/leaguebridge/PACKAGE-MANIFEST.json": "0644"}
	if len(files) != len(want) {
		t.Fatalf("payload inventory = %v", files)
	}
	for file, mode := range want {
		if files[file] != mode {
			t.Errorf("payload %s mode=%s want=%s", file, files[file], mode)
		}
	}
}

func TestVerificationRestoresPermissionPreservingTransport(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeRun := workflowRun(t, string(data), "Arrange exact native runtime set")
	packageRun := workflowRun(t, string(data), "Arrange exact native package set")
	for _, run := range []string{runtimeRun, packageRun} {
		if !strings.Contains(run, "./tools/ciartifact -unpack") {
			t.Fatal("attestation verification must restore the validated transport archive")
		}
	}
	if !strings.Contains(runtimeRun, `cp -p "$source_root/ci-bin/leaguebridge-linux-$arch"`) || !strings.Contains(runtimeRun, `cp -p "$source_root/bsd-ci/leaguebridge-${target}-${arch}"`) {
		t.Fatal("runtime verifier must retain executable modes after restoring")
	}
}

func workflowRun(t *testing.T, workflow, name string) string {
	t.Helper()
	marker := "      - name: " + name + "\n"
	start := strings.Index(workflow, marker)
	if start < 0 {
		t.Fatalf("workflow step %q absent", name)
	}
	step := workflow[start+len(marker):]
	if end := strings.Index(step, "      - name:"); end >= 0 {
		step = step[:end]
	}
	run := strings.Index(step, "        run: |\n")
	if run < 0 {
		t.Fatalf("step %q has no shell block", name)
	}
	lines := strings.Split(strings.TrimSuffix(step[run+len("        run: |\n"):], "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimPrefix(line, "          ")
	}
	return strings.Join(lines, "\n") + "\n"
}

func runShellFixture(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires a native Unix shell and filesystem")
	}
	shell, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	cmd := exec.Command(shell, "-eu", "-o", "pipefail", "-c", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("workflow/builder shell failed: %v\n%s", err, out)
	}
	return dir
}
