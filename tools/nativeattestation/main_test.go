package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBuildNativeRuntimeSubjectInventoriesExecutableAndEvidence(t *testing.T) {
	directory, cleanup := testDirectory(t)
	defer cleanup()
	evidenceDirectory := filepath.ToSlash(filepath.Join(directory, "linux-evidence"))
	if err := os.Mkdir(evidenceDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kernel.txt", "doctor.json", "result.txt"} {
		if err := os.WriteFile(filepath.Join(evidenceDirectory, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	binaryName := "leaguebridge"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.ToSlash(filepath.Join(directory, binaryName))
	if err := os.WriteFile(binaryPath, []byte("native runtime binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.ToSlash(filepath.Join(evidenceDirectory, "native-runtime.json"))

	value, err := build(request{
		Kind:               "linux-runtime",
		GeneratedAt:        "2026-08-29T00:00:00Z",
		Repository:         "Yunushan/leaguebridge",
		Commit:             strings.Repeat("a", 40),
		Tree:               strings.Repeat("b", 40),
		Ref:                "refs/heads/main",
		Workflow:           "CI",
		WorkflowRef:        "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
		WorkflowSHA:        strings.Repeat("c", 40),
		RunID:              "1234",
		RunAttempt:         "1",
		Job:                "linux-runtime",
		RunnerOS:           "Linux",
		RunnerArchitecture: "X64",
		HostClass:          "hosted",
		GoVersion:          "go1.27.0",
		Command:            "native runtime smoke",
		TargetGOOS:         "linux",
		TargetGOARCH:       "amd64",
		EvidenceDir:        evidenceDirectory,
		OutputPath:         outputPath,
		SubjectPaths:       []string{binaryPath},
	})
	if err != nil {
		t.Fatalf("build native runtime subject: %v", err)
	}
	if len(value.Subjects) != 4 {
		t.Fatalf("subject count = %d, want executable plus three evidence files", len(value.Subjects))
	}
	if value.Subjects[0].Path == "" || value.Subjects[0].Path > value.Subjects[len(value.Subjects)-1].Path {
		t.Fatal("subjects are not sorted")
	}
	var binaries, evidence int
	for _, item := range value.Subjects {
		switch item.Role {
		case "runtime-binary":
			binaries++
		case "runtime-evidence":
			evidence++
		default:
			t.Fatalf("unexpected subject role %q", item.Role)
		}
	}
	if binaries != 1 || evidence != 3 {
		t.Fatalf("subject roles = binary %d/evidence %d, want 1/3", binaries, evidence)
	}
	data, err := marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) || bytes.Contains(data, []byte(`"score"`)) || bytes.Contains(data, []byte(`"passed"`)) {
		t.Fatalf("subject is not canonical and score-free: %s", data)
	}
	if err := writeNew(outputPath, data); err != nil {
		t.Fatalf("write subject: %v", err)
	}
	loaded, err := loadDocument(outputPath)
	if err != nil {
		t.Fatalf("reload subject: %v", err)
	}
	if !bytes.Equal(loaded.Data, data) || loaded.Value.Kind != "linux-runtime" {
		t.Fatal("written subject did not round-trip exactly")
	}
}

func TestLoadDocumentRejectsRuntimePromotionFields(t *testing.T) {
	value := document{
		Schema: schemaID, SchemaVersion: schemaVersion, AttestationType: attestationType,
		Kind: "linux-runtime", GeneratedAt: "2026-08-29T00:00:00Z",
		Source: source{
			Repository: "Yunushan/leaguebridge", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40),
			Ref: "refs/heads/main", Workflow: "CI", WorkflowRef: "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
			WorkflowSHA: strings.Repeat("c", 40), RunID: "1234", RunAttempt: "1",
		},
		Execution: execution{
			Job: "linux-runtime", RunnerOS: "Linux", RunnerArchitecture: "X64", HostClass: "hosted",
			GoVersion: "go1.27.0", Command: "native runtime smoke", Target: target{GOOS: "linux", GOARCH: "amd64"},
		},
		Subjects: []subject{
			{Path: "ci-bin/leaguebridge", Role: "runtime-binary", SizeBytes: 1, SHA256: strings.Repeat("d", 64)},
			{Path: "linux-evidence/result.txt", Role: "runtime-evidence", SizeBytes: 1, SHA256: strings.Repeat("e", 64)},
		},
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	t.Chdir(directory)
	for _, field := range []string{"score", "passed", "launch_authorization"} {
		fields[field] = json.RawMessage(`true`)
		candidate, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("native-runtime.json", candidate, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadDocument("native-runtime.json"); err == nil {
			t.Fatalf("loadDocument accepted promotion field %q", field)
		}
		delete(fields, field)
	}
	if err := validateDocument(value); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	value.Execution.HostClass = "physical"
	if err := validateDocument(value); err != nil {
		t.Fatalf("physical host class should remain structurally representable: %v", err)
	}
	value.Execution.HostClass = "not-a-host-class"
	if err := validateDocument(value); err == nil {
		t.Fatal("invalid host class accepted")
	}
}

func TestValidateSetShapeRequiresCompleteNativeRuntimeSet(t *testing.T) {
	value := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64")
	if err := validateSetShape("linux-runtime", []loadedDocument{{Path: "linux-evidence/native-runtime.json", Value: value}}); err != nil {
		t.Fatalf("complete Linux set rejected: %v", err)
	}
	value.Execution.Target.GOOS = "freebsd"
	if err := validateSetShape("linux-runtime", []loadedDocument{{Path: "linux-evidence/native-runtime.json", Value: value}}); err == nil {
		t.Fatal("wrong target accepted for Linux runtime set")
	}
}

func TestVerifySetRejectsUnprovenPhysicalClaim(t *testing.T) {
	input := verifyRequest{
		Kind: "linux-runtime", SubjectPaths: []string{"linux-evidence/native-runtime.json"},
		ExpectedRepo: "Yunushan/leaguebridge", ExpectedWorkflow: ".github/workflows/ci.yml",
		ExpectedCommit: strings.Repeat("a", 40), ExpectedTree: strings.Repeat("b", 40),
		ExpectedRef: "refs/heads/main", WorkflowSHA: strings.Repeat("c", 40),
		RunID: "1234", RunAttempt: "1", ExpectedHostClass: "physical", GHPath: "stub",
	}
	if err := verifySet(input); err == nil || !strings.Contains(err.Error(), "physical host claims") {
		t.Fatalf("physical claim verification error = %v; want explicit independent-attestation rejection", err)
	}
}

func TestVerifySetAuthenticatesAndRehashesCompleteLinuxSet(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, "linux-evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "ci-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "linux-evidence", "result.txt"), []byte("runtime smoke passed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binaryName := "leaguebridge"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.ToSlash(filepath.Join("ci-bin", binaryName))
	if err := os.WriteFile(filepath.FromSlash(binaryPath), []byte("native runtime binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.FromSlash(binaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	request := request{
		Kind: "linux-runtime", GeneratedAt: "2026-08-29T00:00:00Z",
		Repository: "Yunushan/leaguebridge", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40),
		Ref: "refs/heads/main", Workflow: "CI", WorkflowRef: "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
		WorkflowSHA: strings.Repeat("c", 40), RunID: "1234", RunAttempt: "1", Job: "linux-runtime",
		RunnerOS: "Linux", RunnerArchitecture: "X64", HostClass: "hosted", GoVersion: "go1.27.0",
		Command: "native runtime smoke", TargetGOOS: "linux", TargetGOARCH: "amd64",
		EvidenceDir: "linux-evidence", OutputPath: "linux-evidence/native-runtime.json", SubjectPaths: []string{binaryPath},
	}
	value, err := build(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNew(request.OutputPath, data); err != nil {
		t.Fatal(err)
	}

	originalRunner := runGitHubAttestation
	t.Cleanup(func() { runGitHubAttestation = originalRunner })
	runGitHubAttestation = func(_ context.Context, _ string, artifactPath string, sourceValue source) ([]byte, error) {
		artifact, err := hashPath(artifactPath, "verified-artifact")
		if err != nil {
			return nil, err
		}
		return json.Marshal([]ghVerification{validNativeGHVerification(sourceValue, artifact.SHA256)})
	}
	if err := verifySet(verifyRequest{
		Kind: "linux-runtime", SubjectPaths: []string{"linux-evidence/native-runtime.json"},
		ExpectedRepo: request.Repository, ExpectedWorkflow: ".github/workflows/ci.yml",
		ExpectedCommit: request.Commit, ExpectedTree: request.Tree, ExpectedRef: request.Ref,
		WorkflowSHA: request.WorkflowSHA, RunID: request.RunID, RunAttempt: request.RunAttempt,
		ExpectedHostClass: "hosted", GHPath: "stub",
	}); err != nil {
		t.Fatalf("complete Linux native runtime set rejected: %v", err)
	}
}

func validNativeGHVerification(value source, digest string) ghVerification {
	repositoryURI := "https://github.com/" + value.Repository
	workflowURI := "https://github.com/" + value.WorkflowRef
	runURI := repositoryURI + "/actions/runs/" + value.RunID + "/attempts/" + value.RunAttempt
	certificate := make(map[string]json.RawMessage)
	for name, text := range map[string]string{
		"issuer": githubOIDCIssuer, "subjectAlternativeName": workflowURI,
		"githubWorkflowRepository": value.Repository, "githubWorkflowRef": value.Ref,
		"githubWorkflowSHA": value.WorkflowSHA, "buildSignerURI": workflowURI,
		"buildSignerDigest": value.WorkflowSHA, "buildConfigURI": workflowURI,
		"buildConfigDigest": value.WorkflowSHA, "runnerEnvironment": "github-hosted",
		"sourceRepositoryURI": repositoryURI, "sourceRepositoryDigest": value.Commit,
		"sourceRepositoryRef": value.Ref, "runInvocationURI": runURI,
	} {
		encoded, _ := json.Marshal(text)
		certificate[name] = encoded
	}
	return ghVerification{VerificationResult: ghVerificationResult{
		Statement: ghStatement{PredicateType: slsaPredicateType, Subjects: []ghSubject{{Name: "artifact", Digest: map[string]string{"sha256": digest}}}},
		Signature: ghSignature{Certificate: certificate}, VerifiedTimestamps: []json.RawMessage{json.RawMessage(`{}`)},
	}}
}

func makeDocumentForSet(kind, goos, goarch, hostClass, runnerOS, runnerArch string) document {
	return document{
		Schema: schemaID, SchemaVersion: schemaVersion, AttestationType: attestationType,
		Kind: kind, GeneratedAt: time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Source:    source{Repository: "Yunushan/leaguebridge", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), Ref: "refs/heads/main", Workflow: "CI", WorkflowRef: "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main", WorkflowSHA: strings.Repeat("c", 40), RunID: "1234", RunAttempt: "1"},
		Execution: execution{Job: kind, RunnerOS: runnerOS, RunnerArchitecture: runnerArch, HostClass: hostClass, GoVersion: "go1.27.0", Command: "native runtime smoke", Target: target{GOOS: goos, GOARCH: goarch}},
		Subjects:  []subject{{Path: "ci-bin/leaguebridge", Role: "runtime-binary", SizeBytes: 1, SHA256: strings.Repeat("d", 64)}, {Path: "linux-evidence/result.txt", Role: "runtime-evidence", SizeBytes: 1, SHA256: strings.Repeat("e", 64)}},
	}
}

func testDirectory(t *testing.T) (string, func()) {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".nativeattestation-test-")
	if err != nil {
		t.Fatal(err)
	}
	return directory, func() { _ = os.RemoveAll(directory) }
}
