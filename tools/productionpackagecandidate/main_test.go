package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReleaseRequestUsesCompleteCISubjectSet(t *testing.T) {
	request := releaseRequest(options{version: "v1.2.3", releaseDir: "release", gh: "trusted-gh"})
	if request.GHPath != "trusted-gh" || request.Version != "v1.2.3" || request.ReleaseDir != "release" || request.RaceVetSubject != "ci-attestation/race-vet-linux.json" {
		t.Fatalf("release request identity = %+v", request)
	}
	want := []string{
		"ci-attestation/cross-build-linux-amd64.json",
		"ci-attestation/cross-build-linux-arm64.json",
		"ci-attestation/cross-build-freebsd-amd64.json",
		"ci-attestation/cross-build-freebsd-arm64.json",
		"ci-attestation/cross-build-openbsd-amd64.json",
		"ci-attestation/cross-build-openbsd-arm64.json",
		"ci-attestation/cross-build-netbsd-amd64.json",
		"ci-attestation/cross-build-netbsd-arm64.json",
		"ci-attestation/cross-build-dragonfly-amd64.json",
	}
	if !reflect.DeepEqual(request.CrossBuildSubjects, want) {
		t.Fatalf("CI subject set = %v; want %v", request.CrossBuildSubjects, want)
	}
}

func TestParseRequiresOneCandidateModeAndAllSelectors(t *testing.T) {
	base := []string{"--version", "v1.2.3", "--release-dir", "release", "--archive", "source.tar.gz", "--staging", "staging", "--package", "package.deb"}
	for _, input := range []struct {
		name string
		args []string
	}{
		{"no command", base},
		{"no output", append([]string{"build"}, base...)},
		{"no candidate", append([]string{"verify"}, base...)},
		{"wrong output mode", append(append([]string{"verify"}, base...), "--output", "result.json")},
		{"wrong candidate mode", append(append([]string{"build"}, base...), "--candidate", "result.json")},
		{"saved score", append(append([]string{"build"}, base...), "--output", "result.json", "--score", "100")},
		{"prerelease", []string{"build", "--version", "v1.2.3-rc1", "--release-dir", "release", "--archive", "source.tar.gz", "--staging", "staging", "--package", "package.deb", "--output", "result.json"}},
		{"positional", append(append([]string{"build"}, base...), "--output", "result.json", "extra")},
	} {
		t.Run(input.name, func(t *testing.T) {
			if _, err := parse(input.args); err == nil {
				t.Fatal("parse accepted invalid candidate invocation")
			}
		})
	}
	if got, err := parse(append(append([]string{"build"}, base...), "--output", "result.json")); err != nil || got.command != "build" || got.output != "result.json" {
		t.Fatalf("parse build = %+v, %v", got, err)
	}
	if got, err := parse(append(append([]string{"verify"}, base...), "--candidate", "result.json")); err != nil || got.command != "verify" || got.candidate != "result.json" {
		t.Fatalf("parse verify = %+v, %v", got, err)
	}
}

func TestPublishNewCandidateRechecksBeforeExclusivePublication(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "candidate.json")
	data := []byte("candidate body\n")
	called := 0
	if err := publishNewCandidate(output, data, func(temporaryPath string) error {
		called++
		temporary, err := os.ReadFile(temporaryPath)
		if err != nil || !bytes.Equal(temporary, data) {
			t.Fatalf("temporary candidate = %q, %v; want %q", temporary, err, data)
		}
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output became visible before recheck: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("recheck calls = %d; want one", called)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("published bytes = %q, %v; want %q", got, err, data)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "candidate.json" {
		t.Fatalf("output directory = %v, %v", entries, err)
	}
}

func TestPublishNewCandidateFailsClosedAndPreservesExistingOutput(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "candidate.json")
	if err := publishNewCandidate(output, []byte("new"), func(string) error { return errors.New("release changed") }); err == nil || !strings.Contains(err.Error(), "release changed") {
		t.Fatalf("recheck failure = %v", err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("failure left output or temporary file: %v, %v", entries, err)
	}
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishNewCandidate(output, []byte("new"), func(string) error { return nil }); err == nil {
		t.Fatal("exclusive publication replaced an existing output")
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != "existing" {
		t.Fatalf("existing bytes changed to %q, %v", got, err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 {
		t.Fatalf("collision left temporary file: %v, %v", entries, err)
	}
}

func TestPublishNewCandidateRejectsChangedTemporaryBytes(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "mutate-in-place"
		if replacement {
			name = "replace-file"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			output := filepath.Join(directory, "candidate.json")
			err := publishNewCandidate(output, []byte("original\n"), func(temporaryPath string) error {
				if replacement {
					if err := os.Remove(temporaryPath); err != nil {
						return err
					}
				}
				return os.WriteFile(temporaryPath, []byte("modified\n"), 0o600)
			})
			if err == nil || !strings.Contains(err.Error(), "temporary candidate changed") {
				t.Fatalf("temporary mutation result = %v", err)
			}
			if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("changed candidate became visible: %v", err)
			}
		})
	}
}

func TestRunRejectsInvalidInvocationBeforeLiveReleaseAccess(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"verify", "--candidate", "saved.json"}, &output); err == nil {
		t.Fatal("run accepted missing live release selectors")
	}
	if output.Len() != 0 {
		t.Fatalf("invalid invocation wrote output %q", output.String())
	}
}
