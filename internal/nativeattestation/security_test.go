package nativeattestation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGitHubOutputRequiresPinnedSignerAndSubject(t *testing.T) {
	sourceValue := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64").Source
	digest := strings.Repeat("d", 64)
	encode := func(value ghVerification) []byte {
		t.Helper()
		data, err := json.Marshal([]ghVerification{value})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := verifyGitHubOutput(encode(validNativeGHVerification(sourceValue, digest)), digest, sourceValue); err != nil {
		t.Fatalf("valid GitHub result rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*ghVerification)
		want   string
	}{
		{"wrong predicate", func(value *ghVerification) { value.VerificationResult.Statement.PredicateType = "wrong" }, "predicate type"},
		{"unsigned timestamp", func(value *ghVerification) { value.VerificationResult.VerifiedTimestamps = nil }, "verified timestamp"},
		{"wrong subject digest", func(value *ghVerification) {
			value.VerificationResult.Statement.Subjects[0].Digest["sha256"] = strings.Repeat("e", 64)
		}, "signed subject"},
		{"missing certificate", func(value *ghVerification) { value.VerificationResult.Signature.Certificate = nil }, "verified certificate is missing"},
		{"wrong issuer", func(value *ghVerification) {
			value.VerificationResult.Signature.Certificate["issuer"] = json.RawMessage(`"https://other.example"`)
		}, "issuer"},
		{"wrong run", func(value *ghVerification) {
			value.VerificationResult.Signature.Certificate["runInvocationURI"] = json.RawMessage(`"https://github.com/Yunushan/leaguebridge/actions/runs/999/attempts/1"`)
		}, "runInvocationURI"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validNativeGHVerification(sourceValue, digest)
			test.change(&candidate)
			if err := verifyGitHubOutput(encode(candidate), digest, sourceValue); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GitHub output error = %v; want %q", err, test.want)
			}
		})
	}
	for _, test := range []struct {
		name, output, want string
	}{
		{"invalid JSON", "{", "decode GitHub verification result"},
		{"no attestations", "[]", "no attestations"},
		{"trailing value", "[] {}", "multiple JSON values"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyGitHubOutput([]byte(test.output), digest, sourceValue); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GitHub output error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestGitHubSignerWorkflowRejectsRepositoryAndPathSubstitution(t *testing.T) {
	sourceValue := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64").Source
	want := sourceValue.Repository + "/.github/workflows/ci.yml"
	if got, err := githubSignerWorkflow(sourceValue); err != nil || got != want {
		t.Fatalf("signer workflow = %q, %v; want %q", got, err, want)
	}
	for _, test := range []struct{ name, workflowRef, want string }{
		{"different repository", "Other/repository/.github/workflows/ci.yml@refs/heads/main", "expected repository"},
		{"missing ref", sourceValue.Repository + "/.github/workflows/ci.yml", "workflow path and ref"},
		{"unsafe workflow path", sourceValue.Repository + "/../ci.yml@refs/heads/main", "invalid workflow path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := sourceValue
			candidate.WorkflowRef = test.workflowRef
			if _, err := githubSignerWorkflow(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("signer workflow error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestVerificationBindsExpectedSourceAndRun(t *testing.T) {
	value := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64")
	input := VerifyRequest{
		ExpectedRepo: value.Source.Repository, ExpectedWorkflow: defaultWorkflow,
		ExpectedCommit: value.Source.Commit, ExpectedTree: value.Source.Tree,
		ExpectedRef: value.Source.Ref, WorkflowSHA: value.Source.WorkflowSHA,
		RunID: value.Source.RunID, RunAttempt: value.Source.RunAttempt,
	}
	if err := validateExpectedSource(value, input, defaultWorkflow); err != nil {
		t.Fatalf("matching source rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*VerifyRequest)
		want   string
	}{
		{"repository", func(value *VerifyRequest) { value.ExpectedRepo = "Other/repository" }, "repository"},
		{"commit", func(value *VerifyRequest) { value.ExpectedCommit = strings.Repeat("f", 40) }, "commit, tree, or ref"},
		{"tree", func(value *VerifyRequest) { value.ExpectedTree = strings.Repeat("f", 40) }, "commit, tree, or ref"},
		{"ref", func(value *VerifyRequest) { value.ExpectedRef = "refs/heads/other" }, "commit, tree, or ref"},
		{"workflow SHA", func(value *VerifyRequest) { value.WorkflowSHA = strings.Repeat("f", 40) }, "workflow_sha"},
		{"run ID", func(value *VerifyRequest) { value.RunID = "999" }, "run ID or attempt"},
		{"run attempt", func(value *VerifyRequest) { value.RunAttempt = "2" }, "run ID or attempt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			test.change(&candidate)
			if err := validateExpectedSource(value, candidate, defaultWorkflow); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("source binding error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestLoadDocumentRejectsAmbiguousOrExtraJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	value := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64")
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, data, want string }{
		{"duplicate kind", strings.Replace(string(canonical), `"kind":"linux-runtime"`, `"kind":"linux-runtime","kind":"linux-runtime"`, 1), "duplicate key"},
		{"case variant", strings.Replace(string(canonical), `"kind":"linux-runtime"`, `"Kind":"linux-runtime"`, 1), "non-exact field"},
		{"trailing value", string(canonical) + ` {}`, "multiple JSON values"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile("native-runtime.json", []byte(test.data), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadDocument("native-runtime.json"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadDocument error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestGitHubVerificationRechecksArtifactAfterAttestation(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("artifact.txt", []byte("original runtime evidence\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	item, err := hashPath("artifact.txt", "runtime-evidence")
	if err != nil {
		t.Fatal(err)
	}
	sourceValue := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64").Source
	originalRunner := runGitHubAttestation
	t.Cleanup(func() { runGitHubAttestation = originalRunner })
	runGitHubAttestation = func(_ context.Context, _, _ string, sourceValue source) ([]byte, error) {
		if err := os.WriteFile("artifact.txt", []byte("substituted runtime data\n"), 0o644); err != nil {
			return nil, err
		}
		return json.Marshal([]ghVerification{validNativeGHVerification(sourceValue, item.SHA256)})
	}
	err = verifyGitHubArtifact(context.Background(), verifiedArtifact{Path: item.Path, Digest: item.SHA256, Size: item.SizeBytes}, sourceValue, "stub")
	if err == nil || !strings.Contains(err.Error(), "changed during GitHub verification") {
		t.Fatalf("changed artifact verification error = %v", err)
	}
}

func TestBoundedGitHubOutputCannotGrowThroughIOCopy(t *testing.T) {
	output := &boundedBuffer{Maximum: 32}
	reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 33))}
	if _, exposed := any(output).(io.ReaderFrom); exposed {
		t.Fatal("bounded output exposes an unbounded ReaderFrom fast path")
	}
	if _, err := io.Copy(output, reader); err == nil || !output.Oversized || output.Len() > 32 {
		t.Fatalf("bounded copy = length %d, oversized %v, error %v", output.Len(), output.Oversized, err)
	}
	if len(output.Bytes()) != output.Len() {
		t.Fatal("bounded output copy does not match retained bytes")
	}
	if output.String() != "" {
		t.Fatal("oversized output retained data")
	}
}

func TestBuildRejectsIncompleteAndDuplicateEvidence(t *testing.T) {
	makeFixture := func(t *testing.T) BuildRequest {
		t.Helper()
		t.Chdir(t.TempDir())
		if err := os.MkdirAll(filepath.FromSlash("linux-evidence/amd64"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir("ci-bin", 0o755); err != nil {
			t.Fatal(err)
		}
		binary := "ci-bin/leaguebridge"
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}
		if err := os.WriteFile(filepath.FromSlash(binary), []byte("binary\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.FromSlash(binary), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.FromSlash("linux-evidence/amd64/result.txt"), []byte("observed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		fixture := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64")
		return BuildRequest{
			Kind: fixture.Kind, GeneratedAt: fixture.GeneratedAt,
			Repository: fixture.Source.Repository, Commit: fixture.Source.Commit, Tree: fixture.Source.Tree,
			Ref: fixture.Source.Ref, Workflow: fixture.Source.Workflow, WorkflowRef: fixture.Source.WorkflowRef,
			WorkflowSHA: fixture.Source.WorkflowSHA, RunID: fixture.Source.RunID, RunAttempt: fixture.Source.RunAttempt,
			Job: fixture.Execution.Job, RunnerOS: fixture.Execution.RunnerOS, RunnerArchitecture: fixture.Execution.RunnerArchitecture,
			HostClass: fixture.Execution.HostClass, GoVersion: fixture.Execution.GoVersion, Command: fixture.Execution.Command,
			TargetGOOS: fixture.Execution.Target.GOOS, TargetGOARCH: fixture.Execution.Target.GOARCH,
			EvidenceDir: "linux-evidence/amd64", OutputPath: "linux-evidence/amd64/native-runtime.json", SubjectPaths: []string{binary},
		}
	}
	t.Run("empty evidence", func(t *testing.T) {
		input := makeFixture(t)
		if err := os.Remove(filepath.FromSlash("linux-evidence/amd64/result.txt")); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "contains no regular files") {
			t.Fatalf("Build empty evidence error = %v", err)
		}
	})
	t.Run("duplicate binary", func(t *testing.T) {
		input := makeFixture(t)
		input.SubjectPaths = append(input.SubjectPaths, input.SubjectPaths[0])
		if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "duplicated") {
			t.Fatalf("Build duplicate binary error = %v", err)
		}
	})
	t.Run("more than bounded evidence files", func(t *testing.T) {
		input := makeFixture(t)
		for index := 1; index <= maxEvidenceFiles; index++ {
			name := filepath.Join("linux-evidence", "amd64", "extra-"+strings.Repeat("x", index/100)+strings.Repeat("y", index%100))
			if err := os.WriteFile(name, []byte("observed\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "more than 128 files") {
			t.Fatalf("Build oversized evidence inventory error = %v", err)
		}
	})
}

func TestVerifySetRejectsMalformedExpectedIdentity(t *testing.T) {
	base := VerifyRequest{
		Kind: "linux-runtime", SubjectPaths: []string{"native-runtime.json"},
		ExpectedRepo: defaultRepository, ExpectedWorkflow: defaultWorkflow,
		ExpectedCommit: strings.Repeat("a", 40), ExpectedTree: strings.Repeat("b", 40),
		ExpectedRef: "refs/heads/main", WorkflowSHA: strings.Repeat("c", 40),
		RunID: "1234", RunAttempt: "1", ExpectedHostClass: "hosted", GHPath: "stub",
	}
	for _, test := range []struct {
		name   string
		change func(*VerifyRequest)
		want   string
	}{
		{"missing CLI", func(value *VerifyRequest) { value.GHPath = "" }, "GitHub CLI path"},
		{"missing subjects", func(value *VerifyRequest) { value.SubjectPaths = nil }, "verify-subject"},
		{"malformed repository", func(value *VerifyRequest) { value.ExpectedRepo = "other" }, "expected repository"},
		{"dot-only repository owner", func(value *VerifyRequest) { value.ExpectedRepo = "../other" }, "expected repository"},
		{"wrong workflow", func(value *VerifyRequest) { value.ExpectedWorkflow = "other.yml" }, "expected workflow path"},
		{"malformed commit", func(value *VerifyRequest) { value.ExpectedCommit = "not-a-commit" }, "expected commit, tree"},
		{"malformed run", func(value *VerifyRequest) { value.RunID = "0" }, "expected ref, run ID"},
		{"host-class spoof", func(value *VerifyRequest) { value.ExpectedHostClass = "physical" }, "physical host claims"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.change(&candidate)
			result, err := VerifySet(context.Background(), candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) || result.Valid() {
				t.Fatalf("VerifySet result = (%+v, %v); want %q", result, err, test.want)
			}
		})
	}
	if result, err := VerifySet(nil, base); err == nil || !strings.Contains(err.Error(), "context is required") || result.Valid() {
		t.Fatalf("nil-context VerifySet = (%+v, %v)", result, err)
	}
}

func TestContextReaderStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := contextReader{ctx: ctx, reader: strings.NewReader("data")}
	cancel()
	var data [4]byte
	if count, err := reader.Read(data[:]); count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read = %d, %v", count, err)
	}
}

func TestDocumentValidationRejectsPromotionAndMalformedSubjects(t *testing.T) {
	base := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64")
	if err := validateDocument(base); err != nil {
		t.Fatalf("valid base document rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*document)
		want   string
	}{
		{"wrong schema", func(value *document) { value.Schema = "other" }, "identity"},
		{"wrong kind", func(value *document) { value.Kind = "physical-runtime" }, "kind must be"},
		{"non-UTC timestamp", func(value *document) { value.GeneratedAt = "2026-08-29T03:00:00+03:00" }, "canonical"},
		{"wrong source", func(value *document) { value.Source.Commit = "not-an-object-id" }, "source:"},
		{"wrong job", func(value *document) { value.Execution.Job = "bsd-runtime" }, "execution:"},
		{"missing evidence", func(value *document) { value.Subjects = value.Subjects[:1] }, "binary and at least one evidence"},
		{"unsorted subjects", func(value *document) { value.Subjects[0], value.Subjects[1] = value.Subjects[1], value.Subjects[0] }, "strictly sorted"},
		{"unsupported role", func(value *document) { value.Subjects[0].Role = "physical-host-proof" }, "unsupported role"},
		{"wrong digest", func(value *document) { value.Subjects[0].SHA256 = "bad" }, "invalid size or SHA-256"},
		{"no binary", func(value *document) { value.Subjects[0].Role = "runtime-evidence" }, "both runtime-binary and runtime-evidence"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Subjects = append([]subject(nil), base.Subjects...)
			test.change(&candidate)
			if err := validateDocument(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("document validation error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestExecutionAndSourceRejectForgedCIIdentity(t *testing.T) {
	base := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64")
	for _, test := range []struct {
		name   string
		change func(*source)
		want   string
	}{
		{"malformed repository", func(value *source) { value.Repository = "other" }, "repository"},
		{"dot-only repository owner", func(value *source) { value.Repository = "../other" }, "repository"},
		{"invalid tree", func(value *source) { value.Tree = "bad" }, "tree"},
		{"invalid ref", func(value *source) { value.Ref = "main" }, "ref"},
		{"missing workflow", func(value *source) { value.Workflow = "" }, "workflow identity"},
		{"invalid run", func(value *source) { value.RunAttempt = "0" }, "run_id and run_attempt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base.Source
			test.change(&candidate)
			if err := validateSource(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("source validation error = %v; want %q", err, test.want)
			}
		})
	}
	for _, test := range []struct {
		name   string
		change func(*execution)
		want   string
	}{
		{"unsupported runner OS", func(value *execution) { value.RunnerOS = "Windows" }, "unsupported runner OS"},
		{"unsupported architecture", func(value *execution) { value.RunnerArchitecture = "X86" }, "runner architecture"},
		{"malformed Go version", func(value *execution) { value.GoVersion = "go1.27" }, "go version"},
		{"control character in command", func(value *execution) { value.Command = "smoke\nfailed" }, "command"},
		{"wrong target", func(value *execution) { value.Target.GOOS = "windows" }, "linux runtime target"},
		{"wrong job", func(value *execution) { value.Job = "bsd-runtime" }, "execution identity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base.Execution
			test.change(&candidate)
			if err := validateExecution(candidate, base.Kind); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("execution validation error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestPublicSubjectAPIRejectsOverwriteAndUnsafePaths(t *testing.T) {
	t.Chdir(t.TempDir())
	value := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64")
	data, err := Marshal(value)
	if err != nil || len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("Marshal = %d bytes, %v; want newline-terminated document", len(data), err)
	}
	if err := WriteNew("native-runtime.json", data); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew("native-runtime.json", data); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("WriteNew overwrite error = %v", err)
	}
	for _, test := range []struct{ path, want string }{
		{"", "non-empty relative path"},
		{"../outside.json", "unsafe"},
		{"dir\\evidence.json", "non-empty relative path"},
		{"C:/absolute.json", "path"},
		{"evidence\n.json", "unsafe"},
	} {
		t.Run(test.path, func(t *testing.T) {
			if _, err := NormalizeRelativePath(test.path); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NormalizeRelativePath(%q) error = %v; want %q", test.path, err, test.want)
			}
		})
	}
}

func TestGitHubCLIInvocationFailsClosedWithoutVerifier(t *testing.T) {
	sourceValue := makeDocumentForSet("linux-runtime", "linux", "amd64", "hosted", "Linux", "X64").Source
	output, err := runGitHubAttestationCommand(context.Background(), "leaguebridge-no-such-gh-executable", "artifact.txt", sourceValue)
	if err == nil || !strings.Contains(err.Error(), "GitHub CLI verification failed") || len(output) != 0 {
		t.Fatalf("missing GitHub CLI invocation = %q, %v; want failure without output", output, err)
	}
}
