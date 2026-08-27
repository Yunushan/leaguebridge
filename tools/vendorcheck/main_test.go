package main

import (
	"bytes"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunVerifiesRepositorySnapshot(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-root", repositoryRoot(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "production dependency filippo.io/edwards25519 v1.2.0") || !strings.Contains(stdout.String(), "lock sha256:") {
		t.Fatalf("success output = %q", stdout.String())
	}
}

func TestRunRejectsMissingRootAndPositionalArguments(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		wantCode  int
		wantError string
	}{
		{name: "missing root", arguments: []string{"-root", filepath.Join(t.TempDir(), "missing")}, wantCode: 1, wantError: "inspect snapshot root"},
		{name: "positional", arguments: []string{"unexpected"}, wantCode: 2, wantError: "positional arguments are not accepted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := run(test.arguments, &stdout, &stderr); code != test.wantCode {
				t.Fatalf("run exit code = %d; want %d", code, test.wantCode)
			}
			if !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("stderr = %q; want substring %q", stderr.String(), test.wantError)
			}
			if stdout.Len() != 0 {
				t.Fatalf("failure stdout = %q", stdout.String())
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
