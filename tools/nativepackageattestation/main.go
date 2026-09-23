// Command nativepackageattestation generates and verifies score-free evidence
// for native package builders. Signed subjects do not prove production package
// signing, publication, or independent native install results.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	attest "github.com/Yunushan/leaguebridge/internal/nativepackageattestation"
)

const (
	defaultRepository = "Yunushan/leaguebridge"
	defaultWorkflow   = ".github/workflows/ci.yml"
)

func main() {
	set := flag.NewFlagSet("nativepackageattestation", flag.ExitOnError)
	verify := set.Bool("verify", false, "verify signed native package attestations")
	output := set.String("output", "", "new JSON subject path")
	generatedAt := set.String("generated-at", "", "canonical UTC RFC3339 generation timestamp; defaults to current UTC time")
	targetGOOS := set.String("target-goos", "", "target GOOS")
	targetGOARCH := set.String("target-goarch", "", "target GOARCH")
	family := set.String("family", "", "native package family")
	format := set.String("format", "", "native package byte format")
	packagePath := set.String("package", "", "new native package path")
	stagingDir := set.String("staging-dir", "", "verified native package staging directory")
	installEvidence := set.String("install-evidence", "", "native package install-test evidence path")
	command := set.String("command", "", "bounded description of the package build and install test")
	var verifySubjects stringList
	set.Var(&verifySubjects, "verify-subject", "native package attestation subject JSON to verify; may be repeated")
	expectedRepository := set.String("expected-repository", defaultRepository, "expected GitHub owner/repository")
	expectedWorkflow := set.String("expected-workflow", defaultWorkflow, "expected workflow path relative to the repository")
	expectedCommit := set.String("expected-commit", "", "expected source commit object ID (required when verifying)")
	expectedTree := set.String("expected-tree", "", "expected source tree object ID (required when verifying)")
	expectedRef := set.String("expected-ref", "", "expected source ref (required when verifying)")
	expectedWorkflowSHA := set.String("expected-workflow-sha", "", "expected workflow revision object ID (required when verifying)")
	runID := set.String("run-id", "", "GitHub Actions run ID (required when verifying)")
	runAttempt := set.String("run-attempt", "", "GitHub Actions run attempt (required when verifying)")
	ghPath := set.String("gh", "gh", "GitHub CLI executable used for verification")
	if err := set.Parse(os.Args[1:]); err != nil {
		return
	}
	if *verify {
		if *output != "" || *generatedAt != "" || *targetGOOS != "" || *targetGOARCH != "" || *family != "" || *format != "" || *packagePath != "" || *stagingDir != "" || *installEvidence != "" || *command != "" {
			fail("generation flags cannot be used with -verify")
		}
		if _, err := attest.Verify(context.Background(), attest.VerifyRequest{
			SubjectPaths: verifySubjects, ExpectedRepo: *expectedRepository,
			ExpectedWorkflow: *expectedWorkflow, ExpectedCommit: *expectedCommit,
			ExpectedTree: *expectedTree, ExpectedRef: *expectedRef,
			WorkflowSHA: *expectedWorkflowSHA, RunID: *runID, RunAttempt: *runAttempt,
			GHPath: *ghPath,
		}); err != nil {
			fail("verify native package attestations: %v", err)
		}
		fmt.Printf("verified GitHub native package attestation set subjects=%d commit=%s\n", len(verifySubjects), *expectedCommit)
		return
	}
	if len(verifySubjects) != 0 || *expectedCommit != "" || *expectedTree != "" || *expectedRef != "" || *expectedRepository != defaultRepository || *expectedWorkflow != defaultWorkflow || *expectedWorkflowSHA != "" || *runID != "" || *runAttempt != "" || *ghPath != "gh" {
		fail("verification flags require -verify")
	}
	if *output == "" || *targetGOOS == "" || *targetGOARCH == "" || *family == "" || *format == "" || *packagePath == "" || *stagingDir == "" || *installEvidence == "" || *command == "" {
		fail("output, target, family, format, package, staging-dir, install-evidence, and command are required")
	}
	if *generatedAt == "" {
		*generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	outputPath, err := attest.NormalizeRelativePath(*output)
	if err != nil {
		fail("output path: %v", err)
	}
	document, err := attest.Build(attest.BuildRequest{
		GeneratedAt: *generatedAt,
		Repository:  os.Getenv("GITHUB_REPOSITORY"), Commit: os.Getenv("GITHUB_SHA"),
		Tree: os.Getenv("CI_ATTESTATION_TREE"), Ref: os.Getenv("GITHUB_REF"),
		Workflow: os.Getenv("GITHUB_WORKFLOW"), WorkflowRef: os.Getenv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA: os.Getenv("GITHUB_WORKFLOW_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"),
		RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Job: os.Getenv("GITHUB_JOB"),
		RunnerOS: os.Getenv("RUNNER_OS"), RunnerArchitecture: os.Getenv("RUNNER_ARCH"),
		HostClass: attest.ExpectedHostClass(*family), GoVersion: runtime.Version(), Command: *command,
		TargetGOOS: *targetGOOS, TargetGOARCH: *targetGOARCH, Family: *family, Format: *format,
		PackagePath: *packagePath, StagingDir: *stagingDir, InstallEvidence: *installEvidence,
		OutputPath: outputPath,
	})
	if err != nil {
		fail("build native package attestation subject: %v", err)
	}
	data, err := attest.Marshal(document)
	if err != nil {
		fail("marshal native package attestation subject: %v", err)
	}
	if err := attest.WriteNew(*output, data); err != nil {
		fail("write native package attestation subject: %v", err)
	}
	fmt.Printf("created native package attestation subject %s\n", *output)
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("verification subject path must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "nativepackageattestation: "+format+"\n", arguments...)
	os.Exit(2)
}
