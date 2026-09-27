package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

func TestParseVerifyCandidateAttestationsRequiresOnlyLocatorsAndInputs(t *testing.T) {
	artifact := []string{
		"verify-candidate-attestations", "--version", "v0.1.0",
		"--release-dir", "/release", "--inputs", "/staging",
		"--artifact", "/artifact/eleven-score-free-candidates.tar",
		"--run-id", "123", "--run-attempt", "2",
	}
	artifactOptions, err := parseCandidateWorkflow(artifact)
	if err != nil || artifactOptions.artifact == "" || artifactOptions.packages != "" || artifactOptions.record != "" {
		t.Fatalf("safe artifact options = %+v, %v", artifactOptions, err)
	}
	valid := []string{
		"verify-candidate-attestations", "--version", "v0.1.0",
		"--release-dir", "/release", "--inputs", "/staging", "--packages", "/merged",
		"--record", "/artifact/CANDIDATE-SET.json", "--run-id", "123", "--run-attempt", "2",
	}
	opts, err := parseCandidateWorkflow(valid)
	if err != nil || opts.command != "verify-candidate-attestations" || opts.runID != 123 || opts.runAttempt != 2 {
		t.Fatalf("parsed candidate attestation options = %+v, %v", opts, err)
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing record", valid[:len(valid)-6]},
		{"output replacement", append(append([]string(nil), valid...), "--output", "/tmp/result")},
		{"caller trust key", append(append([]string(nil), valid...), "--signing-key", "/tmp/key")},
		{"host source option", append(append([]string(nil), valid...), "--repo", "/tmp/other")},
		{"zero attempt", append(append([]string(nil), valid[:len(valid)-1]...), "0")},
		{"artifact mixed with extracted paths", append(append([]string(nil), artifact...), "--packages", "/merged")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseCandidateWorkflow(test.args); err == nil {
				t.Fatal("invalid candidate attestation command accepted")
			}
		})
	}
}

func TestVerifyCandidateAttestationCLIRejectsOverlappingRootsBeforeLiveChecks(t *testing.T) {
	opts := candidateWorkflowOptions{
		command: "verify-candidate-attestations", version: "v0.1.0",
		releaseDir: "/tmp/shared", inputs: "/tmp/staging", packages: "/tmp/shared",
		record: "/tmp/artifact/CANDIDATE-SET.json", gh: "gh", runID: 123, runAttempt: 2,
	}
	err := verifyCandidateWorkflowAttestations(context.Background(), opts, releaseassessment.VerifiedRelease{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must be separate") {
		t.Fatalf("overlapping CLI inputs were accepted: %v", err)
	}
}
