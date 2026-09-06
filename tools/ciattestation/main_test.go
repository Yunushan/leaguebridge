package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
)

func TestCLIProcess(t *testing.T) {
	if os.Getenv("LEAGUEBRIDGE_CIATTESTATION_CLI_TEST") != "1" {
		return
	}
	for index, argument := range os.Args {
		if argument == "--" {
			os.Args = append([]string{"ciattestation"}, os.Args[index+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("CLI test arguments are missing")
}

func TestCLIGenerationMapsFlagsAndEnvironment(t *testing.T) {
	root := t.TempDir()
	input := ciattestation.GenerateRequest{
		Kind: "race-vet", GeneratedAt: "2026-08-28T12:00:00Z",
		Repository: "Yunushan/leaguebridge",
		Commit:     "0123456789abcdef0123456789abcdef01234567",
		Tree:       "89abcdef0123456789abcdef0123456789abcdef",
		Ref:        "refs/heads/main", Workflow: "CI",
		WorkflowRef: "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
		WorkflowSHA: "fedcba9876543210fedcba9876543210fedcba98",
		RunID:       "123456789", RunAttempt: "1", Job: "test",
		RunnerOS: "Linux", RunnerArchitecture: "X64", GoVersion: runtime.Version(),
		Command:    "go test -mod=vendor -race ./...; go vet -mod=vendor ./...",
		TargetGOOS: "linux", TargetGOARCH: "amd64",
	}
	environment := []string{
		"GITHUB_REPOSITORY=" + input.Repository, "GITHUB_SHA=" + input.Commit,
		"CI_ATTESTATION_TREE=" + input.Tree, "GITHUB_REF=" + input.Ref,
		"GITHUB_WORKFLOW=" + input.Workflow, "GITHUB_WORKFLOW_REF=" + input.WorkflowRef,
		"GITHUB_WORKFLOW_SHA=" + input.WorkflowSHA, "GITHUB_RUN_ID=" + input.RunID,
		"GITHUB_RUN_ATTEMPT=" + input.RunAttempt, "GITHUB_JOB=" + input.Job,
		"RUNNER_OS=" + input.RunnerOS, "RUNNER_ARCH=" + input.RunnerArchitecture,
	}
	output := filepath.Join(root, "actual.json")
	arguments := []string{
		"-kind", input.Kind, "-output", output, "-generated-at", input.GeneratedAt,
		"-target-goos", input.TargetGOOS, "-target-goarch", input.TargetGOARCH,
		"-command", input.Command,
	}
	code, stdout, stderr := runCLI(t, environment, arguments...)
	if code != 0 || stdout != "created CI attestation subject "+output+"\n" || stderr != "" {
		t.Fatalf("generation: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	expected := filepath.Join(root, "expected.json")
	if err := ciattestation.GenerateFile(expected, input); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(expected)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("CLI generation differs from explicitly supplied metadata:\ngot %s\nwant %s", got, want)
	}
	code, stdout, stderr = runCLI(t, environment, arguments...)
	if code != 2 || stdout != "" || stderr != "ciattestation: write CI attestation subject: output path already exists\n" {
		t.Fatalf("overwrite: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCLIFailureMessagesAndExitCodes(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments []string
		message   string
	}{
		{"missing output", nil, "-output is required"},
		{"generation flags while verifying", []string{"-verify", "-output", "subject.json"}, "generation flags cannot be used with -verify"},
		{"verification flags while generating", []string{"-verify-subject", "subject.json"}, "verification flags require -verify"},
		{"verifier error", []string{"-verify", "-kind", "unknown"}, "verify attestation set: kind must be race-vet or cross-build"},
		{"release dispatch", []string{"-verify", "-kind", "release"}, "verify attestation set: release directory is required"},
		{"default verifier executable", []string{"-verify", "-kind", "race-vet"}, "verify attestation set: at least one -verify-subject is required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, nil, test.arguments...)
			if code != 2 || stdout != "" || stderr != "ciattestation: "+test.message+"\n" {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCLIHelpRetainsVerificationDefaults(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil, "-h")
	if code != 0 || stdout != "" {
		t.Fatalf("help: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, expected := range []string{
		"Usage of ciattestation:",
		`expected GitHub owner/repository (default "Yunushan/leaguebridge")`,
		`expected workflow path relative to the repository (default ".github/workflows/ci.yml")`,
		`GitHub CLI executable used for verification (default "gh")`,
	} {
		if !strings.Contains(stderr, expected) {
			t.Fatalf("help is missing %q: %s", expected, stderr)
		}
	}
}

func runCLI(t *testing.T, environment []string, arguments ...string) (int, string, string) {
	t.Helper()
	command := exec.Command(os.Args[0], append([]string{"-test.run=^TestCLIProcess$", "--"}, arguments...)...)
	command.Env = append(os.Environ(), "LEAGUEBRIDGE_CIATTESTATION_CLI_TEST=1")
	command.Env = append(command.Env, environment...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), stdout.String(), stderr.String()
		}
		t.Fatal(err)
	}
	return 0, stdout.String(), stderr.String()
}
