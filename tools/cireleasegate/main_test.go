package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCIGateCLIProcess(t *testing.T) {
	if os.Getenv("LEAGUEBRIDGE_CI_GATE_CLI_TEST") != "1" {
		return
	}
	for index, argument := range os.Args {
		if argument == "--" {
			os.Args = append([]string{"cireleasegate"}, os.Args[index+1:]...)
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("CLI test arguments are missing")
}

func TestCLIUsageAndVerificationFailuresRemainDistinct(t *testing.T) {
	commit := strings.Repeat("a", 40)
	for _, test := range []struct {
		name      string
		arguments []string
	}{
		{"missing commit", nil},
		{"invalid commit", []string{"-commit", "main"}},
		{"positional argument", []string{"-commit", commit, "unexpected"}},
		{"empty executable", []string{"-commit", commit, "-gh", ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCIGateCLI(t, test.arguments...)
			want := "cireleasegate: a complete -commit SHA is required; positional arguments are not accepted\n"
			if code != 2 || stdout != "" || stderr != want {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	// The helper has an empty PATH, so the default gh cannot contact GitHub.
	code, stdout, stderr := runCIGateCLI(t, "-commit", commit)
	if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "cireleasegate: read CI workflow identity: GitHub API request failed:") || !strings.Contains(stderr, "gh") {
		t.Fatalf("verification failure: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCLIHelpPreservesDefaults(t *testing.T) {
	code, stdout, stderr := runCIGateCLI(t, "-h")
	if code != 0 || stdout != "" {
		t.Fatalf("help: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"Usage of cireleasegate:", "-commit string", "exact lowercase release commit SHA", "-gh string", `trusted GitHub CLI executable (default "gh")`} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("help is missing %q: %s", want, stderr)
		}
	}
}

func runCIGateCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCIGateCLIProcess$", "--"}, arguments...)...)
	command.Env = append(os.Environ(), "LEAGUEBRIDGE_CI_GATE_CLI_TEST=1", "PATH=")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), stdout.String(), stderr.String()
		}
		t.Fatal(err)
	}
	return 0, stdout.String(), stderr.String()
}
