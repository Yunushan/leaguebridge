package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBSDPackageFailureDiagnosticsDoNotWriteIntoTheirInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a native Unix shell")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "temporary_root=$(mktemp -d ")
	end := strings.Index(script, "trap cleanup EXIT HUP INT TERM\n")
	if start < 0 || end < start {
		t.Fatal("BSD cleanup trap absent")
	}
	cleanup := script[start : end+len("trap cleanup EXIT HUP INT TERM\n")]
	dir := t.TempDir()
	evidence := bytes.Repeat([]byte("package tool failed\n"), 10000)
	if err := os.WriteFile(filepath.Join(dir, "evidence.log"), evidence, 0600); err != nil {
		t.Fatal(err)
	}
	setup := `export TMPDIR="$PWD"
evidence="$PWD/evidence.log"
expected_goos=openbsd
package_installed=0
`
	// ksh can retain a failing brace group's redirects when running EXIT.
	// Retain them explicitly to exercise that state on every Unix test host.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-eu", "-c", setup+cleanup+"exec >>\"$evidence\" 2>&1\nexit 17\n")
	cmd.Dir = dir
	output, _ := cmd.CombinedOutput()
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 17 {
		t.Fatalf("cleanup did not preserve failure status: %v", cmd.ProcessState)
	}
	want := append([]byte("native-package-bsd-smoke: command output before failure:\n"), evidence[:64*1024]...)
	if !bytes.Equal(output, want) {
		t.Fatalf("diagnostics must reach original stderr and be bounded: got %d bytes, want %d", len(output), len(want))
	}
	after, err := os.ReadFile(filepath.Join(dir, "evidence.log"))
	if err != nil || !bytes.Equal(after, evidence) {
		t.Fatalf("failure reporting changed its evidence input: %v", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, "leaguebridge-native-package.*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("cleanup left private scratch directories: %v, %v", leftovers, err)
	}
}

func TestNetBSDPackageBuildersIncludeRequiredPlatformMetadata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "  netbsd)\n    command -v pkg_add")
	end := strings.Index(script, "\n    ;;\nesac\n\nif [ -L \"$package\"")
	if start < 0 || end < start {
		t.Fatal("NetBSD builder absent")
	}
	body := script[start+len("  netbsd)\n") : end]
	for _, arch := range []string{"amd64", "arm64"} {
		for _, native := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/native=%t", arch, native), func(t *testing.T) {
				setup := fmt.Sprintf(`expected_goarch=%s
package_name=leaguebridge-0.0.0-ci
package=package.tgz
temporary_root="$PWD/work"
staging="$PWD/staging"
mkdir "$temporary_root"
mkdir -p "$staging/root/usr/local/bin" "$staging/root/usr/local/libexec/leaguebridge" "$staging/root/usr/local/share/doc/leaguebridge"
for relative in bin/leaguebridge libexec/leaguebridge/linux-bsd-client-smoke.sh libexec/leaguebridge/linux-bsd-remote-session.sh share/doc/leaguebridge/LICENSE share/doc/leaguebridge/README.md share/doc/leaguebridge/SBOM.spdx.json share/doc/leaguebridge/PACKAGE-MANIFEST.json; do
  printf 'payload\n' > "$staging/root/usr/local/$relative"
done
fail() { echo "$*" >&2; exit 41; }
assert_clean_install_paths() { :; }
as_root() { test "$#" -eq 9 && test "$1" = chown && test "$2" = root:wheel; }
pkg_add() { test "$1" = -V; echo 20260227; }
pkg_delete() { :; }
pkg_info() { return 1; }
uname() { test "$1" = -r; echo 11.0; }
command() {
  if [ "$1" = -v ] && [ "$2" = pkg_create ]; then %t; return; fi
  builtin command "$@"
}
pkg_create() {
  info=
  while [ "$#" -gt 0 ]; do
    case "$1" in -B) shift; info=$1;; esac
    shift
  done
  test -n "$info" && test -f "$info" || exit 42
  cp "$info" observed-build-info
}
`, arch, native)
				dir := runShellFixture(t, setup+body)
				var metadata []byte
				if native {
					metadata, err = os.ReadFile(filepath.Join(dir, "observed-build-info"))
				} else {
					metadata, err = exec.Command("tar", "-xOzf", filepath.Join(dir, "package.tgz"), "+BUILD_INFO").Output()
				}
				if err != nil {
					t.Fatalf("build metadata absent from builder output: %v", err)
				}
				packageArch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[arch]
				want := "OPSYS=NetBSD\nOS_VERSION=11.0\nMACHINE_ARCH=" + packageArch + "\nPKGTOOLS_VERSION=20260227\n"
				if string(metadata) != want {
					t.Fatalf("platform metadata=%q, want %q", metadata, want)
				}
			})
		}
	}
}

func TestLinuxPackageCleanupRemovesPrivilegedRootsAndPreservesFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a native Unix shell")
	}
	shell, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-linux-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "cleanup() {\n")
	end := strings.Index(script, "trap cleanup EXIT\n")
	if start < 0 || end < start {
		t.Fatal("package cleanup trap absent")
	}
	cleanup := script[start : end+len("trap cleanup EXIT\n")]
	for _, test := range []struct {
		name           string
		original, want int
		cleanupFails   bool
	}{
		{"success", 0, 0, false},
		{"preserve original failure", 17, 17, false},
		{"report cleanup failure", 0, 1, true},
		{"preserve failure when cleanup also fails", 17, 17, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			setup := fmt.Sprintf(`temporary_root="$PWD/private package roots"
mkdir "$temporary_root"
printf 'database' > "$temporary_root/root-owned-database"
debian_scratch="$temporary_root/debian"
rpm_scratch="$temporary_root/rpm"
rm() { echo 'unprivileged removal refused' >&2; return 81; }
sudo() {
  case "$1" in
    dpkg|rpm) return 0 ;;
    rm)
      test "$#" -eq 4 && test "$2" = -rf && test "$3" = -- && test "$4" = "$temporary_root" || return 82
      if %t; then return 83; fi
      shift
      command rm "$@"
      ;;
    *) return 84 ;;
  esac
}
`, test.cleanupFails)
			cmd := exec.Command(shell, "-eu", "-o", "pipefail", "-c", setup+cleanup+fmt.Sprintf("exit %d\n", test.original))
			cmd.Dir = dir
			output, _ := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != test.want {
				t.Fatalf("cleanup exit=%v, want %d: %s", cmd.ProcessState, test.want, output)
			}
			_, statErr := os.Stat(filepath.Join(dir, "private package roots"))
			if !test.cleanupFails && !os.IsNotExist(statErr) {
				t.Fatalf("privileged package roots remain after cleanup: %v", statErr)
			}
			if test.cleanupFails && !strings.Contains(string(output), "could not remove private package roots") {
				t.Fatalf("cleanup failure was not reported: %s", output)
			}
		})
	}
}

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
