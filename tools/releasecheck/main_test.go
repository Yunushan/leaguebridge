package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/releasecheck"
)

func TestReleasecheckCLIHelperProcess(t *testing.T) {
	if os.Getenv("LEAGUEBRIDGE_RELEASECHECK_CLI_HELPER") != "1" {
		return
	}
	for index, argument := range os.Args {
		if argument == "--" {
			os.Args = append([]string{"releasecheck"}, os.Args[index+1:]...)
			flag.CommandLine = flag.NewFlagSet("releasecheck", flag.ExitOnError)
			main()
			return
		}
	}
	t.Fatal("missing command separator")
}

func TestReleasecheckCLICompatibility(t *testing.T) {
	complete := []string{
		"-dir", filepath.Join(t.TempDir(), "absent"), "-version", "v1.2.3",
		"-source-date-epoch", "1787702400",
		"-commit", "0123456789abcdef0123456789abcdef01234567",
		"-tree", "89abcdef0123456789abcdef0123456789abcdef",
		"-builder-go-version", "go1.27.1",
	}
	for _, test := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"help", []string{"-h"}, 0, "release directory to validate (default \"dist\")"},
		{"missing epoch", nil, 2, "releasecheck: source-date-epoch is required"},
		{"positional argument", []string{"extra"}, 2, "releasecheck: positional arguments are not accepted"},
		{"unknown flag", []string{"-unknown"}, 2, "flag provided but not defined: -unknown"},
		{"missing commit", []string{"-source-date-epoch", "1787702400"}, 2, "releasecheck: commit must"},
		{"invalid builder", append(append([]string(nil), complete...), "-builder-go-version", "go1.99.0"), 2, "production releases require"},
		{"invalid version", append(append([]string(nil), complete...), "-version", "invalid"), 1, "releasecheck: version"},
		{"missing release", complete, 1, "releasecheck: release directory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestReleasecheckCLIHelperProcess$", "--"}, test.args...)
			command := exec.Command(os.Args[0], args...)
			command.Env = append(os.Environ(), "LEAGUEBRIDGE_RELEASECHECK_CLI_HELPER=1")
			output, err := command.CombinedOutput()
			code := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != test.code || !strings.Contains(string(output), test.want) {
				t.Fatalf("CLI exit=%d output=%q; want exit=%d containing %q", code, output, test.code, test.want)
			}
		})
	}
}

// Existing protected-tag script fixtures also validate the resolved tree.
func validateTree(tree string) error {
	return (releasecheck.CheckRequest{
		SourceDateEpoch: 1787702400, Commit: strings.Repeat("0", 40),
		Tree: tree, BuilderGoVersion: "go1.27.1",
	}).ValidateIdentity()
}

func runGit(t *testing.T, repository string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = repository
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2026-08-26T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-08-26T00:00:00Z",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}
