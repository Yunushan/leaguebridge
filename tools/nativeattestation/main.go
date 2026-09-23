// Command nativeattestation creates and verifies score-free native runtime
// evidence. The JSON document is a subject for GitHub's artifact-attestation
// service; it is not an attestation and it never contains a readiness score or
// a gameplay-support claim.
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

	"github.com/Yunushan/leaguebridge/internal/nativeattestation"
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("subject path must not be empty")
	}
	*values = append(*values, value)
	return nil
}

// Keep the bounded subprocess output test at the CLI boundary while using
// the exact buffer type used by the internal verifier.
type boundedBuffer = nativeattestation.BoundedBuffer

func main() {
	set := flag.NewFlagSet("nativeattestation", flag.ExitOnError)
	verify := set.Bool("verify", false, "verify signed native runtime attestations")
	kind := set.String("kind", "", "attestation kind: linux-runtime or bsd-runtime")
	output := set.String("output", "", "new JSON subject path")
	evidenceDir := set.String("evidence-dir", "", "runtime evidence directory to inventory")
	generatedAt := set.String("generated-at", "", "canonical UTC RFC3339 generation timestamp; defaults to current UTC time")
	targetGOOS := set.String("target-goos", "", "target GOOS")
	targetGOARCH := set.String("target-goarch", "", "target GOARCH")
	hostClass := set.String("host-class", "", "runtime host class: hosted, virtualized, or physical")
	command := set.String("command", "", "bounded description of the runtime test command")
	var subjects stringList
	set.Var(&subjects, "subject", "regular file executed or consumed by the runtime test; may be repeated")
	var verifySubjects stringList
	set.Var(&verifySubjects, "verify-subject", "native runtime attestation subject JSON to verify; may be repeated")
	expectedRepository := set.String("expected-repository", nativeattestation.DefaultRepository, "expected GitHub owner/repository")
	expectedWorkflow := set.String("expected-workflow", nativeattestation.DefaultWorkflow, "expected workflow path relative to the repository")
	expectedCommit := set.String("expected-commit", "", "expected source commit object ID (required when verifying)")
	expectedTree := set.String("expected-tree", "", "expected source tree object ID (required when verifying)")
	expectedRef := set.String("expected-ref", "", "expected source ref (required when verifying)")
	expectedWorkflowSHA := set.String("expected-workflow-sha", "", "expected workflow revision object ID (required when verifying)")
	runID := set.String("run-id", "", "GitHub Actions run ID (required when verifying)")
	runAttempt := set.String("run-attempt", "", "GitHub Actions run attempt (required when verifying)")
	expectedHostClass := set.String("expected-host-class", "", "expected host class (required when verifying)")
	ghPath := set.String("gh", "gh", "GitHub CLI executable used for verification")
	if err := set.Parse(os.Args[1:]); err != nil {
		return
	}
	if *verify {
		if *output != "" || *evidenceDir != "" || len(subjects) != 0 || *generatedAt != "" || *targetGOOS != "" || *targetGOARCH != "" || *hostClass != "" || *command != "" {
			fail("generation flags cannot be used with -verify")
		}
		if _, err := nativeattestation.VerifySet(context.Background(), nativeattestation.VerifyRequest{
			Kind: *kind, SubjectPaths: verifySubjects, ExpectedRepo: *expectedRepository,
			ExpectedWorkflow: *expectedWorkflow, ExpectedCommit: *expectedCommit,
			ExpectedTree: *expectedTree, ExpectedRef: *expectedRef,
			WorkflowSHA: *expectedWorkflowSHA, RunID: *runID, RunAttempt: *runAttempt,
			ExpectedHostClass: *expectedHostClass, GHPath: *ghPath,
		}); err != nil {
			fail("verify native runtime attestations: %v", err)
		}
		fmt.Printf("verified GitHub native runtime attestation set kind=%s subjects=%d commit=%s\n", *kind, len(verifySubjects), *expectedCommit)
		return
	}
	if len(verifySubjects) != 0 || *expectedCommit != "" || *expectedTree != "" || *expectedRef != "" || *expectedRepository != nativeattestation.DefaultRepository || *expectedWorkflow != nativeattestation.DefaultWorkflow || *expectedWorkflowSHA != "" || *runID != "" || *runAttempt != "" || *expectedHostClass != "" || *ghPath != "gh" {
		fail("verification flags require -verify")
	}
	if *output == "" || *evidenceDir == "" || *kind == "" || *targetGOOS == "" || *targetGOARCH == "" || *hostClass == "" || *command == "" {
		fail("kind, output, evidence-dir, target, host-class, and command are required")
	}
	if *generatedAt == "" {
		*generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	outputPath, err := nativeattestation.NormalizeRelativePath(*output)
	if err != nil {
		fail("output path: %v", err)
	}
	document, err := nativeattestation.Build(nativeattestation.BuildRequest{
		Kind: *kind, GeneratedAt: *generatedAt,
		Repository: os.Getenv("GITHUB_REPOSITORY"), Commit: os.Getenv("GITHUB_SHA"),
		Tree: os.Getenv("CI_ATTESTATION_TREE"), Ref: os.Getenv("GITHUB_REF"),
		Workflow: os.Getenv("GITHUB_WORKFLOW"), WorkflowRef: os.Getenv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA: os.Getenv("GITHUB_WORKFLOW_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"),
		RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Job: os.Getenv("GITHUB_JOB"),
		RunnerOS: os.Getenv("RUNNER_OS"), RunnerArchitecture: os.Getenv("RUNNER_ARCH"),
		HostClass: *hostClass, GoVersion: runtime.Version(), Command: *command,
		TargetGOOS: *targetGOOS, TargetGOARCH: *targetGOARCH,
		EvidenceDir: *evidenceDir, OutputPath: outputPath, SubjectPaths: subjects,
	})
	if err != nil {
		fail("build native runtime attestation subject: %v", err)
	}
	data, err := nativeattestation.Marshal(document)
	if err != nil {
		fail("marshal native runtime attestation subject: %v", err)
	}
	if err := nativeattestation.WriteNew(*output, data); err != nil {
		fail("write native runtime attestation subject: %v", err)
	}
	fmt.Printf("created native runtime attestation subject %s\n", *output)
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "nativeattestation: "+format+"\n", arguments...)
	os.Exit(2)
}
