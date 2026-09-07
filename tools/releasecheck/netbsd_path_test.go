package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNetBSDPackageToolsResolveWithNonLoginPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a native Unix shell")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	shell, err = filepath.Abs(shell)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "case \"$(uname -s):$expected_goos\" in\n")
	end := strings.Index(script, "runtime_machine=$(uname -m)\n")
	if start < 0 || end < start {
		t.Fatal("BSD kernel guard and environment setup are absent")
	}
	block := script[start:end]
	guardEnd := strings.Index(block, "esac\n")
	if guardEnd < 0 {
		t.Fatal("BSD kernel guard is incomplete")
	}
	// Retain the real guard as the pre-fix negative control. The current block
	// must additionally discover administrative tools through its PATH setup.
	originalGuard := block[:guardEnd+len("esac\n")]
	// All executable discovery stays inside the fixture. Replacing directory
	// literals leaves the actual production branch and PATH operations intact.
	block = strings.NewReplacer(
		"/usr/sbin", "\"$FIXTURE_USR_SBIN\"",
		"/sbin", "\"$FIXTURE_SBIN\"",
	).Replace(block)

	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	sbin := filepath.Join(root, "sbin")
	usrSbin := filepath.Join(root, "usr", "sbin")
	for _, directory := range []string{bin, sbin, usrSbin} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(filepath.Join(bin, "uname"), `test "$#" -eq 1 && test "$1" = -s || exit 31
printf '%s\n' "$FIXTURE_KERNEL"
`)
	writeExecutable(filepath.Join(usrSbin, "pkg_add"), `test "$#" -eq 1 && test "$1" = -V || exit 32
printf 'pkg_add executed\n' > "$FIXTURE_MARKER"
printf 'pkg_add fixture version\n'
`)

	for _, test := range []struct {
		name         string
		kernel       string
		goos         string
		block        string
		wantCode     int
		wantPATH     string
		wantExecuted bool
	}{
		{"netbsd", "NetBSD", "netbsd", block, 0, sbin + ":" + usrSbin + ":" + bin, true},
		{"original-guard", "NetBSD", "netbsd", originalGuard, 42, bin, false},
		{"freebsd-unchanged", "FreeBSD", "freebsd", block, 42, bin, false},
		{"wrong-kernel", "FreeBSD", "netbsd", block, 41, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(root, test.name+".executed")
			setup := `fail() { printf '%s\n' "$*" >&2; exit 41; }
`
			probe := `printf 'PATH=%s\n' "$PATH"
command -v pkg_add >/dev/null 2>&1 || exit 42
pkg_add -V
`
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, shell, "-eu", "-c", setup+test.block+probe)
			command.Dir = root
			command.Env = []string{
				"PATH=" + bin, "LC_ALL=C", "HOME=" + root,
				"expected_goos=" + test.goos, "FIXTURE_KERNEL=" + test.kernel,
				"FIXTURE_SBIN=" + sbin, "FIXTURE_USR_SBIN=" + usrSbin,
				"FIXTURE_MARKER=" + marker,
			}
			output, runErr := command.CombinedOutput()
			if command.ProcessState == nil || command.ProcessState.ExitCode() != test.wantCode {
				t.Fatalf("exit=%v error=%v output=%s; want exit %d", command.ProcessState, runErr, output, test.wantCode)
			}
			wantOutput := "package smoke is running on the wrong BSD kernel\n"
			if test.wantPATH != "" {
				wantOutput = "PATH=" + test.wantPATH + "\n"
			}
			if test.wantExecuted {
				wantOutput += "pkg_add fixture version\n"
			}
			if string(output) != wantOutput {
				t.Fatalf("output=%q; want %q", output, wantOutput)
			}
			markerData, markerErr := os.ReadFile(marker)
			if test.wantExecuted {
				if markerErr != nil || string(markerData) != "pkg_add executed\n" {
					t.Fatalf("administrative executable did not run: %q, %v", markerData, markerErr)
				}
			} else if !os.IsNotExist(markerErr) {
				t.Fatalf("administrative executable ran despite the failed lookup or guard: %q, %v", markerData, markerErr)
			}
		})
	}
}
