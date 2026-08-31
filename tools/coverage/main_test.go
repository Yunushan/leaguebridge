package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestRunningGoExecutableUsesCurrentToolchain(t *testing.T) {
	path, err := runningGoExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("Go executable path = %q, want absolute path", path)
	}
	wantName := "go"
	if runtime.GOOS == "windows" {
		wantName += ".exe"
	}
	if filepath.Base(path) != wantName {
		t.Fatalf("Go executable basename = %q, want %q", filepath.Base(path), wantName)
	}
	if !strings.Contains(filepath.Clean(path), filepath.Join("bin", wantName)) {
		t.Fatalf("Go executable path = %q, want the running toolchain bin directory", path)
	}
}

func TestCoverageTestArgumentsKeepProfilePathSeparate(t *testing.T) {
	t.Parallel()
	args := coverageTestArguments("coverage.out")
	want := []string{"test", "-covermode=atomic", "-coverprofile", "coverage.out", "./internal/..."}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("coverage test arguments = %#v, want %#v", args, want)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-coverprofile=") {
			t.Fatalf("coverage profile path was joined to its flag: %#v", args)
		}
	}
}

func TestParseProfile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "profile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("mode: atomic\nexample/a.go:1.1,2.2 3 1\nexample/b.go:3.1,4.2 2 0\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	covered, total, err := parseProfile(f)
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if covered != 3 || total != 5 {
		t.Fatalf("got %d/%d, want 3/5", covered, total)
	}
}

func TestParseProfileRejectsMalformed(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "profile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not a profile\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	_, _, parseErr := parseProfile(f)
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if parseErr == nil {
		t.Fatal("expected error")
	}
}
