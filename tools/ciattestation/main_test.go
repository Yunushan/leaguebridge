package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestBuildRaceVetSubjectIsScoreFreeAndCanonical(t *testing.T) {
	document, err := build(testRequest("race-vet"))
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Subjects) != 0 || document.AttestationType != attestationType || document.SchemaVersion != schemaVersion {
		t.Fatalf("unexpected race-vet document: %+v", document)
	}
	data, err := marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") || strings.Contains(string(data), "score") || strings.Contains(string(data), "passed") {
		t.Fatalf("race-vet document is not canonical and score-free: %s", data)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["kind"] != "race-vet" {
		t.Fatalf("decoded kind = %#v", decoded["kind"])
	}
}

func TestBuildCrossBuildHashesRegularSubject(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ci-build", "leaguebridge-linux-amd64")
	body := []byte("cross-target binary fixture\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	input := testRequest("cross-build")
	input.SubjectPaths = []string{"ci-build/leaguebridge-linux-amd64"}
	document, err := build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Subjects) != 1 || document.Subjects[0].SizeBytes != int64(len(body)) {
		t.Fatalf("unexpected subject: %+v", document.Subjects)
	}
	if document.Subjects[0].Path != "ci-build/leaguebridge-linux-amd64" {
		t.Fatalf("subject path = %q", document.Subjects[0].Path)
	}
	if document.Subjects[0].SHA256 == "" || !sha256Pattern(document.Subjects[0].SHA256) {
		t.Fatalf("subject digest = %q", document.Subjects[0].SHA256)
	}
}

func TestValidateSubjectAfterHashRejectsPathReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "subject")
	if err := os.WriteFile(path, []byte("original subject\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	expected, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	replaced := filepath.Join(root, "subject.original")
	if err := os.Rename(path, replaced); err != nil {
		t.Skipf("renaming an open subject is unavailable: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement subject\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateSubjectAfterHash(path, expected, file); err == nil || !strings.Contains(err.Error(), "changed while hashing") {
		t.Fatalf("validateSubjectAfterHash() error = %v; want path-replacement rejection", err)
	}
}

func TestBuildRejectsUnsafeOrMismatchedSubjects(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(fixture, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Dir(fixture))
	tests := []struct {
		name   string
		mutate func(*request)
		want   string
	}{
		{name: "race subject", mutate: func(input *request) { input.SubjectPaths = []string{"binary"} }, want: "race-vet subjects"},
		{name: "missing cross subject", mutate: func(input *request) { input.Kind = "cross-build" }, want: "exactly one"},
		{name: "wrong race target", mutate: func(input *request) { input.TargetGOOS = "freebsd" }, want: "race-vet target"},
		{name: "unsafe subject", mutate: func(input *request) { input.Kind = "cross-build"; input.SubjectPaths = []string{"../binary"} }, want: "unsafe"},
		{name: "backslash subject", mutate: func(input *request) {
			input.Kind = "cross-build"
			input.SubjectPaths = []string{"ci-build\\leaguebridge-linux-amd64"}
		}, want: "non-empty relative"},
		{name: "mismatched subject", mutate: func(input *request) { input.Kind = "cross-build"; input.SubjectPaths = []string{"binary"} }, want: "not bound to target"},
		{name: "symlink subject", mutate: func(input *request) { input.Kind = "cross-build"; input.SubjectPaths = []string{"link"} }, want: "regular file"},
	}
	if err := os.Symlink("binary", "link"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := testRequest("race-vet")
			test.mutate(&input)
			_, err := build(input)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("build error = %v; want %q", err, test.want)
			}
		})
	}
	subjectTarget := filepath.Join(filepath.Dir(fixture), "subject-target")
	if err := os.Mkdir(subjectTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	subjectFile := filepath.Join(subjectTarget, "leaguebridge-linux-amd64")
	if err := os.WriteFile(subjectFile, []byte("subject fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("subject-target", "ci-build"); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	input := testRequest("cross-build")
	input.SubjectPaths = []string{"ci-build/leaguebridge-linux-amd64"}
	if _, err := build(input); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("build parent-symlink error = %v; want parent rejection", err)
	}
}

func TestMarshalRevalidatesNestedIdentityAndTargetBinding(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ci-build", "leaguebridge-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	input := testRequest("cross-build")
	input.SubjectPaths = []string{"ci-build/leaguebridge-linux-amd64"}
	doc, err := build(input)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*document){
		"invalid source commit":  func(value *document) { value.Source.Commit = "not-a-commit" },
		"invalid execution job":  func(value *document) { value.Execution.Job = strings.Repeat("a", maxJobLength+1) },
		"mismatched target path": func(value *document) { value.Subjects[0].Path = "ci-build/leaguebridge-freebsd-amd64" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := doc
			copy.Subjects = append([]subject(nil), doc.Subjects...)
			mutate(&copy)
			if _, err := marshal(copy); err == nil {
				t.Fatal("marshal accepted a malformed nested document")
			}
		})
	}
}

func TestWriteNewRefusesOverwriteAndSymlink(t *testing.T) {
	directory := t.TempDir()
	created := filepath.Join(directory, "created.json")
	contents := []byte("subject\n")
	if err := writeNew(created, contents); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(created); err != nil || string(got) != string(contents) {
		t.Fatalf("created subject = %q, %v; want %q", got, err, contents)
	}
	existing := filepath.Join(directory, "existing.json")
	if err := os.WriteFile(existing, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(existing, []byte("new")); err == nil {
		t.Fatal("writeNew overwrote an existing file")
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(existing, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeNew(link, []byte("new")); err == nil {
		t.Fatal("writeNew accepted a symlink")
	}
	parentTarget := filepath.Join(directory, "parent-target")
	if err := os.Mkdir(parentTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(directory, "parent-link")
	if err := os.Symlink(parentTarget, parentLink); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if err := writeNew(filepath.Join(parentLink, "redirected.json"), []byte("new")); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("writeNew parent-symlink error = %v; want parent rejection", err)
	}
}

func TestVerifyGitHubOutputRequiresBoundCertificateAndSubject(t *testing.T) {
	input := testRequest("race-vet")
	value := source{
		Repository: input.Repository, Commit: input.Commit, Tree: input.Tree, Ref: input.Ref,
		Workflow: input.Workflow, WorkflowRef: input.WorkflowRef, WorkflowSHA: input.WorkflowSHA,
		RunID: input.RunID, RunAttempt: input.RunAttempt,
	}
	digest := strings.Repeat("a", 64)
	tests := map[string]func(*ghVerification){
		"missing timestamp": func(result *ghVerification) {
			result.VerificationResult.VerifiedTimestamps = nil
		},
		"wrong predicate": func(result *ghVerification) {
			result.VerificationResult.Statement.PredicateType = "https://example.invalid/predicate"
		},
		"wrong certificate": func(result *ghVerification) {
			delete(result.VerificationResult.Signature.Certificate, "runnerEnvironment")
		},
		"wrong subject": func(result *ghVerification) {
			result.VerificationResult.Statement.Subjects[0].Digest["sha256"] = strings.Repeat("b", 64)
		},
	}
	valid, err := json.Marshal([]ghVerification{validGHVerification(value, digest)})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGitHubOutput(valid, digest, value); err != nil {
		t.Fatalf("valid GitHub verification result rejected: %v", err)
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validGHVerification(value, digest)
			mutate(&result)
			data, err := json.Marshal([]ghVerification{result})
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyGitHubOutput(data, digest, value); err == nil {
				t.Fatal("verifyGitHubOutput accepted an invalid GitHub verification result")
			}
		})
	}
}

func TestGitHubSignerWorkflowUsesPathWithoutRefSuffix(t *testing.T) {
	input := testRequest("race-vet")
	got, err := githubSignerWorkflow(source{
		Repository:  input.Repository,
		WorkflowRef: input.WorkflowRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := input.Repository + "/.github/workflows/ci.yml"
	if got != want {
		t.Fatalf("githubSignerWorkflow() = %q; want %q", got, want)
	}
	for name, value := range map[string]source{
		"foreign repository": {Repository: input.Repository, WorkflowRef: "other/repo/.github/workflows/ci.yml@refs/heads/main"},
		"missing ref":        {Repository: input.Repository, WorkflowRef: input.Repository + "/.github/workflows/ci.yml"},
		"missing path":       {Repository: input.Repository, WorkflowRef: input.Repository + "/@refs/heads/main"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := githubSignerWorkflow(value); err == nil {
				t.Fatal("githubSignerWorkflow accepted malformed workflow identity")
			}
		})
	}
}

func TestVerifySetRequiresCompleteCrossBuildSet(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	targets := []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"linux", "arm64"},
		{"freebsd", "amd64"}, {"freebsd", "arm64"},
		{"openbsd", "amd64"}, {"openbsd", "arm64"},
		{"netbsd", "amd64"}, {"netbsd", "arm64"},
		{"dragonfly", "amd64"},
	}
	request := testRequest("cross-build")
	request.Job = "cross-build"
	paths := make([]string, 0, len(targets))
	for _, target := range targets {
		binaryPath := "ci-build/leaguebridge-" + target.goos + "-" + target.goarch
		if err := os.MkdirAll(filepath.FromSlash(filepath.Dir(binaryPath)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.FromSlash(binaryPath), []byte("binary fixture "+target.goos+"/"+target.goarch+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		request.TargetGOOS = target.goos
		request.TargetGOARCH = target.goarch
		request.SubjectPaths = []string{binaryPath}
		value, err := build(request)
		if err != nil {
			t.Fatal(err)
		}
		data, err := marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		jsonPath := "ci-attestation/cross-build-" + target.goos + "-" + target.goarch + ".json"
		if err := os.MkdirAll(filepath.FromSlash(filepath.Dir(jsonPath)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.FromSlash(jsonPath), data, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, jsonPath)
	}
	oldRunner := runGitHubAttestation
	defer func() { runGitHubAttestation = oldRunner }()
	var calls int
	runGitHubAttestation = func(_ context.Context, _ string, artifact string, value source) ([]byte, error) {
		calls++
		actual, err := hashSubject(artifact)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal([]ghVerification{validGHVerification(value, actual.SHA256)})
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	input := verifyRequest{
		Kind: "cross-build", SubjectPaths: paths, ExpectedRepo: request.Repository,
		ExpectedWorkflow: ".github/workflows/ci.yml", ExpectedCommit: request.Commit,
		ExpectedTree: request.Tree, ExpectedRef: request.Ref, WorkflowSHA: request.WorkflowSHA,
		RunID: request.RunID, RunAttempt: request.RunAttempt, GHPath: "gh",
	}
	if err := verifySet(input); err != nil {
		t.Fatalf("complete cross-build set rejected: %v", err)
	}
	if calls != len(paths)*2 {
		t.Fatalf("GitHub verification calls = %d; want %d", calls, len(paths)*2)
	}
	wrongWorkflow := input
	wrongWorkflow.WorkflowSHA = strings.Repeat("e", 40)
	if err := verifySet(wrongWorkflow); err == nil || !strings.Contains(err.Error(), "workflow_sha") {
		t.Fatalf("wrong workflow revision error = %v; want workflow binding rejection", err)
	}
	wrongRun := input
	wrongRun.RunID = "987654321"
	if err := verifySet(wrongRun); err == nil || !strings.Contains(err.Error(), "run ID") {
		t.Fatalf("wrong run identity error = %v; want run binding rejection", err)
	}
	if err := verifySet(verifyRequest{
		Kind: "cross-build", SubjectPaths: paths[:len(paths)-1], ExpectedRepo: request.Repository,
		ExpectedWorkflow: ".github/workflows/ci.yml", ExpectedCommit: request.Commit,
		ExpectedTree: request.Tree, ExpectedRef: request.Ref, WorkflowSHA: request.WorkflowSHA,
		RunID: request.RunID, RunAttempt: request.RunAttempt, GHPath: "gh",
	}); err == nil || !strings.Contains(err.Error(), "exactly 9") {
		t.Fatalf("incomplete cross-build set error = %v; want exact-set rejection", err)
	}
}

func TestVerifyReleaseSetChecksExactArtifactsAndAttestsEverySubject(t *testing.T) {
	root := t.TempDir()
	version := "v1.2.3"
	names := releaseArchiveNames(version)
	digests := make(map[string]string, len(names))
	for _, name := range names {
		body := []byte("release fixture: " + name + "\n")
		if err := os.WriteFile(filepath.Join(root, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
		digests[name] = digestBytes(body)
	}
	checksumNames := append([]string(nil), names...)
	sort.Strings(checksumNames)
	checksumLines := make([]string, 0, len(checksumNames))
	for _, name := range checksumNames {
		checksumLines = append(checksumLines, digests[name]+" *./"+name)
	}
	if err := os.WriteFile(filepath.Join(root, "checksums.txt"), []byte(strings.Join(checksumLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldRunner := runGitHubAttestation
	defer func() { runGitHubAttestation = oldRunner }()
	var calls []string
	runGitHubAttestation = func(_ context.Context, _ string, artifact string, value source) ([]byte, error) {
		calls = append(calls, artifact)
		body, err := os.ReadFile(artifact)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal([]ghVerification{validGHVerification(value, digestBytes(body))})
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	input := verifyRequest{
		Kind: "release", ReleaseDir: root, ReleaseVersion: version,
		ExpectedRepo: "Yunushan/leaguebridge", ExpectedWorkflow: ".github/workflows/release.yml",
		ExpectedCommit: strings.Repeat("0", 40), ExpectedRef: "refs/tags/" + version,
		WorkflowSHA: strings.Repeat("f", 40), RunID: "123456789", RunAttempt: "1", GHPath: "gh",
	}
	if err := verifyReleaseSet(input); err != nil {
		t.Fatalf("valid release set rejected: %v", err)
	}
	if len(calls) != len(names)+1 {
		t.Fatalf("GitHub verification calls = %d; want %d", len(calls), len(names)+1)
	}
	badRef := input
	badRef.ExpectedRef = "refs/heads/main"
	if err := verifyReleaseSet(badRef); err == nil || !strings.Contains(err.Error(), "release ref") {
		t.Fatalf("non-tag release ref error = %v; want tag/version binding rejection", err)
	}

	if err := os.WriteFile(filepath.Join(root, "unexpected.txt"), []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseSet(input); err == nil || !strings.Contains(err.Error(), "unexpected release directory entry") {
		t.Fatalf("extra release file error = %v; want exact-set rejection", err)
	}
}

func TestVerifyReleaseSetRejectsChecksumDrift(t *testing.T) {
	root := t.TempDir()
	version := "v1.2.3"
	names := releaseArchiveNames(version)
	lines := make([]string, 0, len(names))
	for _, name := range names {
		body := []byte("release fixture: " + name + "\n")
		if err := os.WriteFile(filepath.Join(root, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, strings.Repeat("a", 64)+" *./"+name)
	}
	sort.Strings(lines)
	if err := os.WriteFile(filepath.Join(root, "checksums.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	input := verifyRequest{
		Kind: "release", ReleaseDir: root, ReleaseVersion: version,
		ExpectedRepo: "Yunushan/leaguebridge", ExpectedWorkflow: ".github/workflows/release.yml",
		ExpectedCommit: strings.Repeat("0", 40), ExpectedRef: "refs/tags/" + version,
		WorkflowSHA: strings.Repeat("f", 40), RunID: "123456789", RunAttempt: "1", GHPath: "gh",
	}
	if err := verifyReleaseSet(input); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("checksum drift error = %v; want checksum mismatch", err)
	}
}

func validGHVerification(value source, digest string) ghVerification {
	stringValue := func(value string) json.RawMessage {
		data, _ := json.Marshal(value)
		return data
	}
	repositoryURI := "https://github.com/" + value.Repository
	workflowURI := "https://github.com/" + value.WorkflowRef
	return ghVerification{VerificationResult: ghVerificationResult{
		Statement: ghStatement{
			PredicateType: slsaPredicateType,
			Subjects:      []ghSubject{{Name: "fixture", Digest: map[string]string{"sha256": digest}}},
		},
		Signature: ghSignature{Certificate: map[string]json.RawMessage{
			"issuer":                   stringValue(githubOIDCIssuer),
			"subjectAlternativeName":   stringValue(workflowURI),
			"githubWorkflowRepository": stringValue(value.Repository),
			"githubWorkflowRef":        stringValue(value.Ref),
			"githubWorkflowSHA":        stringValue(value.WorkflowSHA),
			"buildSignerURI":           stringValue(workflowURI),
			"buildSignerDigest":        stringValue(value.WorkflowSHA),
			"buildConfigURI":           stringValue(workflowURI),
			"buildConfigDigest":        stringValue(value.WorkflowSHA),
			"runnerEnvironment":        stringValue("github-hosted"),
			"sourceRepositoryURI":      stringValue(repositoryURI),
			"sourceRepositoryDigest":   stringValue(value.Commit),
			"sourceRepositoryRef":      stringValue(value.Ref),
			"runInvocationURI":         stringValue(repositoryURI + "/actions/runs/" + value.RunID + "/attempts/" + value.RunAttempt),
		}},
		VerifiedTimestamps: []json.RawMessage{json.RawMessage(`{"type":"Tlog"}`)},
	}}
}

func testRequest(kind string) request {
	return request{
		Kind: kind, GeneratedAt: "2026-08-28T12:00:00Z",
		Repository: "Yunushan/leaguebridge",
		Commit:     "0123456789abcdef0123456789abcdef01234567",
		Tree:       "89abcdef0123456789abcdef0123456789abcdef",
		Ref:        "refs/heads/main", Workflow: "CI",
		WorkflowRef: "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
		WorkflowSHA: "fedcba9876543210fedcba9876543210fedcba98",
		RunID:       "123456789", RunAttempt: "1", Job: "test",
		RunnerOS: "Linux", RunnerArchitecture: "X64", GoVersion: "go1.27.1",
		Command:    "go test -mod=vendor -race ./...; go vet -mod=vendor ./...",
		TargetGOOS: "linux", TargetGOARCH: "amd64",
	}
}
