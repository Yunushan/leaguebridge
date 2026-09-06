// Command ciattestation generates unsigned CI attestation subjects and verifies
// complete sets of externally signed GitHub artifact attestations.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
)

const (
	defaultRepository   = "Yunushan/leaguebridge"
	defaultWorkflowPath = ".github/workflows/ci.yml"
)

func main() {
	set := flag.NewFlagSet("ciattestation", flag.ExitOnError)
	verify := set.Bool("verify", false, "verify signed GitHub artifact attestations for a complete CI set")
	kind := set.String("kind", "", "attestation kind: race-vet, cross-build, or release")
	output := set.String("output", "", "new JSON subject path")
	generatedAt := set.String("generated-at", "", "canonical UTC RFC3339 generation timestamp; defaults to current UTC time")
	targetGOOS := set.String("target-goos", "", "target GOOS")
	targetGOARCH := set.String("target-goarch", "", "target GOARCH")
	command := set.String("command", "", "exact command description")
	var subjects stringList
	set.Var(&subjects, "subject", "regular file to hash; may be repeated for cross-build")
	var verifySubjects stringList
	set.Var(&verifySubjects, "verify-subject", "CI attestation subject JSON to verify; may be repeated")
	expectedRepository := set.String("expected-repository", defaultRepository, "expected GitHub owner/repository")
	expectedWorkflow := set.String("expected-workflow", defaultWorkflowPath, "expected workflow path relative to the repository")
	expectedCommit := set.String("expected-commit", "", "expected source commit object ID (required when verifying)")
	expectedTree := set.String("expected-tree", "", "expected source tree object ID (required when verifying)")
	expectedRef := set.String("expected-ref", "", "expected source ref (required when verifying)")
	expectedWorkflowSHA := set.String("expected-workflow-sha", "", "expected workflow revision object ID (required when verifying)")
	runID := set.String("run-id", "", "GitHub Actions run ID (required when verifying)")
	runAttempt := set.String("run-attempt", "", "GitHub Actions run attempt (required when verifying)")
	releaseDir := set.String("release-dir", "", "release artifact directory (required for release verification)")
	releaseVersion := set.String("release-version", "", "v-prefixed release version (required for release verification)")
	ghPath := set.String("gh", "gh", "GitHub CLI executable used for verification")
	if err := set.Parse(os.Args[1:]); err != nil {
		return
	}
	if *verify {
		if *output != "" || len(subjects) != 0 || *generatedAt != "" || *targetGOOS != "" || *targetGOARCH != "" || *command != "" {
			fail("generation flags cannot be used with -verify")
		}
		if err := ciattestation.VerifySet(ciattestation.VerifyRequest{
			Kind: *kind, SubjectPaths: verifySubjects, ExpectedRepo: *expectedRepository,
			ExpectedWorkflow: *expectedWorkflow, ExpectedCommit: *expectedCommit,
			ExpectedTree: *expectedTree, ExpectedRef: *expectedRef, GHPath: *ghPath,
			ReleaseDir: *releaseDir, ReleaseVersion: *releaseVersion,
			WorkflowSHA: *expectedWorkflowSHA, RunID: *runID, RunAttempt: *runAttempt,
		}); err != nil {
			fail("verify attestation set: %v", err)
		}
		if *kind == "release" {
			fmt.Printf("verified GitHub release attestation set version=%s subjects=9 commit=%s\n", *releaseVersion, *expectedCommit)
		} else {
			fmt.Printf("verified GitHub CI attestation set kind=%s subjects=%d commit=%s\n", *kind, len(verifySubjects), *expectedCommit)
		}
		return
	}
	if len(verifySubjects) != 0 || *expectedCommit != "" || *expectedTree != "" || *expectedRef != "" || *expectedRepository != defaultRepository || *expectedWorkflow != defaultWorkflowPath || *expectedWorkflowSHA != "" || *runID != "" || *runAttempt != "" || *releaseDir != "" || *releaseVersion != "" || *ghPath != "gh" {
		fail("verification flags require -verify")
	}
	if *output == "" {
		fail("-output is required")
	}
	if *generatedAt == "" {
		*generatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	err := ciattestation.GenerateFile(*output, ciattestation.GenerateRequest{
		Kind:               *kind,
		GeneratedAt:        *generatedAt,
		Repository:         os.Getenv("GITHUB_REPOSITORY"),
		Commit:             os.Getenv("GITHUB_SHA"),
		Tree:               os.Getenv("CI_ATTESTATION_TREE"),
		Ref:                os.Getenv("GITHUB_REF"),
		Workflow:           os.Getenv("GITHUB_WORKFLOW"),
		WorkflowRef:        os.Getenv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA:        os.Getenv("GITHUB_WORKFLOW_SHA"),
		RunID:              os.Getenv("GITHUB_RUN_ID"),
		RunAttempt:         os.Getenv("GITHUB_RUN_ATTEMPT"),
		Job:                os.Getenv("GITHUB_JOB"),
		RunnerOS:           os.Getenv("RUNNER_OS"),
		RunnerArchitecture: os.Getenv("RUNNER_ARCH"),
		GoVersion:          runtime.Version(),
		Command:            *command,
		TargetGOOS:         *targetGOOS,
		TargetGOARCH:       *targetGOARCH,
		SubjectPaths:       subjects,
	})
	if err != nil {
		fail("%v", err)
	}
	fmt.Printf("created CI attestation subject %s\n", *output)
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("subject path must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "ciattestation: "+format+"\n", arguments...)
	os.Exit(2)
}
