package productionpackage

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type attestedSetFixture struct {
	facts     attestedCandidateFacts
	summaries []Summary
	input     AttestedCandidateRequest
	subjects  map[string]string
	run       stableCandidateRun
}

func makeAttestedSetFixture(t *testing.T) attestedSetFixture {
	t.Helper()
	facts := attestedCandidateFacts{
		version: "v0.1.0", commit: strings.Repeat("a", 40), tree: strings.Repeat("b", 40),
		releaseID: 384256185, scorecardSHA256: strings.Repeat("c", 64),
	}
	root := filepath.Join(t.TempDir(), "merged-packages")
	summaries := make([]Summary, 0, len(productionCells))
	inputs := make([]CandidatePaths, 0, len(productionCells))
	for _, cell := range productionCells {
		name, err := packageFilename(facts.version, cell.Family, cell.GOOS, cell.GOARCH)
		if err != nil {
			t.Fatal(err)
		}
		packagePath := filepath.Join(root, "native-package-output", string(cell.Family), cell.GOARCH, name)
		if err := os.MkdirAll(filepath.Dir(packagePath), 0o700); err != nil {
			t.Fatal(err)
		}
		body := []byte("fixture package for " + name)
		if err := os.WriteFile(packagePath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		summaries = append(summaries, Summary{
			Version: facts.version, Commit: facts.commit, Tree: facts.tree, ReleaseID: facts.releaseID,
			Family: cell.Family, GOOS: cell.GOOS, GOARCH: cell.GOARCH,
			PackageFilename: name, PackageSHA256: hex.EncodeToString(sum[:]),
			ArchiveSHA256: strings.Repeat("d", 64), ExecutableSHA256: strings.Repeat("e", 64),
			StagingManifestSHA256: strings.Repeat("f", 64),
		})
		inputs = append(inputs, CandidatePaths{PackagePath: packagePath})
	}
	record, subjects, err := expectedCandidateAttestation(facts, summaries)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(t.TempDir(), stableCandidateRecordName)
	if err := os.WriteFile(recordPath, record, 0o600); err != nil {
		t.Fatal(err)
	}
	return attestedSetFixture{
		facts: facts, summaries: summaries, subjects: subjects,
		input: AttestedCandidateRequest{Candidates: inputs, RecordPath: recordPath, GHPath: "gh", RunID: 123, RunAttempt: 2},
		run:   stableCandidateRun{id: 123, attempt: 2, workflowID: 44, commit: strings.Repeat("1", 40), workflowBlob: strings.Repeat("2", 40)},
	}
}

func candidateStatementFixture(run stableCandidateRun, subjects map[string]string) map[string]any {
	repositoryURI := "https://github.com/" + stableCandidateRepository
	workflowURI := repositoryURI + "/" + stableCandidateWorkflow + "@" + stableCandidateRef
	cert := map[string]any{
		"issuer": stableCandidateOIDCIssuer, "subjectAlternativeName": workflowURI,
		"githubWorkflowRepository": stableCandidateRepository, "githubWorkflowRef": stableCandidateRef,
		"githubWorkflowSHA": run.commit, "buildSignerURI": workflowURI,
		"buildSignerDigest": run.commit, "buildConfigURI": workflowURI,
		"buildConfigDigest": run.commit, "runnerEnvironment": "github-hosted",
		"sourceRepositoryURI": repositoryURI, "sourceRepositoryDigest": run.commit,
		"sourceRepositoryRef": stableCandidateRef,
		"runInvocationURI":    fmt.Sprintf("%s/actions/runs/%d/attempts/%d", repositoryURI, run.id, run.attempt),
	}
	names := make([]string, 0, len(subjects))
	for name := range subjects {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]any, 0, len(names))
	for _, name := range names {
		items = append(items, map[string]any{"name": name, "digest": map[string]any{"sha256": subjects[name]}})
	}
	return map[string]any{"verificationResult": map[string]any{
		"statement":          map[string]any{"predicateType": stableCandidatePredicate, "subject": items},
		"signature":          map[string]any{"certificate": cert},
		"verifiedTimestamps": []any{map[string]any{}},
	}}
}

func statementJSON(t *testing.T, values ...map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneStatement(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copied map[string]any
	if err := json.Unmarshal(data, &copied); err != nil {
		t.Fatal(err)
	}
	return copied
}

func statementParts(value map[string]any) (map[string]any, []any, map[string]any) {
	result := value["verificationResult"].(map[string]any)
	statement := result["statement"].(map[string]any)
	subjects := statement["subject"].([]any)
	certificate := result["signature"].(map[string]any)["certificate"].(map[string]any)
	return statement, subjects, certificate
}

func TestAttestedCandidateSetAuthenticatesExactScoreFreeStatement(t *testing.T) {
	fixture := makeAttestedSetFixture(t)
	output := statementJSON(t, candidateStatementFixture(fixture.run, fixture.subjects))
	reads := 0
	deps := attestationDependencies{
		readRun: func(_ context.Context, _ string, id int64, attempt int) (stableCandidateRun, error) {
			reads++
			if id != fixture.run.id || attempt != fixture.run.attempt {
				t.Fatal("wrong selected run")
			}
			return fixture.run, nil
		},
		verifyStatement: func(_ context.Context, _, snapshot string, _ stableCandidateRun) ([]byte, error) {
			if filepath.Base(snapshot) != stableCandidateRecordName {
				t.Fatal("attestation snapshot lost its subject name")
			}
			actual, err := os.ReadFile(snapshot)
			if err != nil || digest(actual) != fixture.subjects[stableCandidateRecordName] {
				t.Fatal("attestation snapshot differs from the canonical record")
			}
			return output, nil
		},
		recheckPayload: func(context.Context) ([]Summary, error) { return append([]Summary(nil), fixture.summaries...), nil },
		recheckRelease: func(context.Context) error { return nil },
	}
	verified, err := verifyAttestedCandidateSet(context.Background(), fixture.facts, fixture.summaries, fixture.input, deps)
	if err != nil || !verified.Valid() || reads != 2 {
		t.Fatalf("attested set = %+v, reads %d, error %v", verified, reads, err)
	}
	copyOfSummaries, err := verified.Summaries()
	if err != nil || len(copyOfSummaries) != 11 {
		t.Fatalf("verified summaries = %d, %v", len(copyOfSummaries), err)
	}
	copyOfSummaries[0].PackageSHA256 = "altered"
	if verified.summaries[0].PackageSHA256 == "altered" {
		t.Fatal("returned summary aliases the verified inventory")
	}
}

func TestCandidateStatementRejectsMissingExtraChangedAndAmbiguousSubjects(t *testing.T) {
	fixture := makeAttestedSetFixture(t)
	base := candidateStatementFixture(fixture.run, fixture.subjects)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing", func(value map[string]any) {
			statement, subjects, _ := statementParts(value)
			statement["subject"] = subjects[:len(subjects)-1]
		}},
		{"extra", func(value map[string]any) {
			statement, subjects, _ := statementParts(value)
			statement["subject"] = append(subjects, map[string]any{"name": "extra.pkg", "digest": map[string]any{"sha256": strings.Repeat("a", 64)}})
		}},
		{"changed digest", func(value map[string]any) {
			_, subjects, _ := statementParts(value)
			subjects[0].(map[string]any)["digest"] = map[string]any{"sha256": strings.Repeat("0", 64)}
		}},
		{"duplicate name", func(value map[string]any) {
			statement, subjects, _ := statementParts(value)
			subjects[1] = subjects[0]
			statement["subject"] = subjects
		}},
		{"other digest algorithm", func(value map[string]any) {
			_, subjects, _ := statementParts(value)
			subjects[0].(map[string]any)["digest"].(map[string]any)["sha512"] = "extra"
		}},
		{"wrong workflow", func(value map[string]any) {
			_, _, cert := statementParts(value)
			cert["subjectAlternativeName"] = "https://github.com/other/workflow"
		}},
		{"self hosted", func(value map[string]any) {
			_, _, cert := statementParts(value)
			cert["runnerEnvironment"] = "self-hosted"
		}},
		{"wrong source", func(value map[string]any) {
			_, _, cert := statementParts(value)
			cert["sourceRepositoryDigest"] = strings.Repeat("9", 40)
		}},
		{"wrong run", func(value map[string]any) {
			_, _, cert := statementParts(value)
			cert["runInvocationURI"] = "https://github.com/Yunushan/leaguebridge/actions/runs/1/attempts/1"
		}},
		{"wrong predicate", func(value map[string]any) {
			statement, _, _ := statementParts(value)
			statement["predicateType"] = "other"
		}},
		{"no timestamp", func(value map[string]any) {
			value["verificationResult"].(map[string]any)["verifiedTimestamps"] = []any{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := cloneStatement(t, base)
			test.mutate(value)
			if err := checkCandidateStatement(statementJSON(t, value), fixture.subjects, fixture.run); err == nil {
				t.Fatal("altered attestation was accepted")
			}
		})
	}
	unrelated := cloneStatement(t, base)
	_, _, cert := statementParts(unrelated)
	cert["runInvocationURI"] = "https://github.com/Yunushan/leaguebridge/actions/runs/1/attempts/1"
	if err := checkCandidateStatement(statementJSON(t, unrelated, base), fixture.subjects, fixture.run); err != nil {
		t.Fatalf("unrelated attestation should not hide selected run: %v", err)
	}
	if err := checkCandidateStatement(statementJSON(t, base, base), fixture.subjects, fixture.run); err == nil {
		t.Fatal("two attestations from selected run were accepted")
	}
}

func TestAttestedCandidateSetRejectsChangedLocalInputsAndRecheck(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *attestedSetFixture, *attestationDependencies)
	}{
		{"changed record", func(t *testing.T, fixture *attestedSetFixture, _ *attestationDependencies) {
			if err := os.WriteFile(fixture.input.RecordPath, []byte(`{"schema_version":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed package", func(t *testing.T, fixture *attestedSetFixture, _ *attestationDependencies) {
			if err := os.WriteFile(fixture.input.Candidates[0].PackagePath, []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra package", func(t *testing.T, fixture *attestedSetFixture, _ *attestationDependencies) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(fixture.input.Candidates[0].PackagePath), "extra.rpm"), []byte("extra"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, fixture *attestedSetFixture, _ *attestationDependencies) {
			if err := os.Symlink(fixture.input.Candidates[0].PackagePath, filepath.Join(filepath.Dir(fixture.input.Candidates[0].PackagePath), "alias.rpm")); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload recheck", func(_ *testing.T, _ *attestedSetFixture, deps *attestationDependencies) {
			deps.recheckPayload = func(context.Context) ([]Summary, error) { return nil, errors.New("changed staging") }
		}},
		{"release recheck", func(_ *testing.T, _ *attestedSetFixture, deps *attestationDependencies) {
			deps.recheckRelease = func(context.Context) error { return errors.New("release withdrawn") }
		}},
		{"run recheck", func(_ *testing.T, fixture *attestedSetFixture, deps *attestationDependencies) {
			reads := 0
			deps.readRun = func(context.Context, string, int64, int) (stableCandidateRun, error) {
				reads++
				if reads == 2 {
					return stableCandidateRun{}, errors.New("rerun")
				}
				return fixture.run, nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := makeAttestedSetFixture(t)
			output := statementJSON(t, candidateStatementFixture(fixture.run, fixture.subjects))
			deps := attestationDependencies{
				readRun:         func(context.Context, string, int64, int) (stableCandidateRun, error) { return fixture.run, nil },
				verifyStatement: func(context.Context, string, string, stableCandidateRun) ([]byte, error) { return output, nil },
				recheckPayload:  func(context.Context) ([]Summary, error) { return fixture.summaries, nil },
				recheckRelease:  func(context.Context) error { return nil },
			}
			test.mutate(t, &fixture, &deps)
			if _, err := verifyAttestedCandidateSet(context.Background(), fixture.facts, fixture.summaries, fixture.input, deps); err == nil {
				t.Fatal("changed or invalid input was accepted")
			}
		})
	}
}

func TestStableCandidateRunRequiresLatestSuccessfulReviewedWorkflow(t *testing.T) {
	workflowData, err := os.ReadFile("../../.github/workflows/stable-native-candidates.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflowSHA := sha256.Sum256(workflowData)
	if hex.EncodeToString(workflowSHA[:]) != stableCandidateWorkflowSHA256 {
		t.Fatal("reviewed candidate workflow pin is stale")
	}
	blobHash := sha1.New()
	fmt.Fprintf(blobHash, "blob %d\x00", len(workflowData))
	blobHash.Write(workflowData)
	blobID := hex.EncodeToString(blobHash.Sum(nil))
	commit := strings.Repeat("a", 40)
	treeA, treeB, treeC := strings.Repeat("b", 40), strings.Repeat("c", 40), strings.Repeat("d", 40)
	base := "repos/" + stableCandidateRepository
	runPath := base + "/actions/runs/123"
	validRun := stableRunResponse{ID: 123, Attempt: 2, WorkflowID: 44, Path: stableCandidateWorkflow,
		Event: "workflow_dispatch", Branch: "main", Commit: commit, Status: "completed", Conclusion: "success"}
	validRun.Repository.FullName = stableCandidateRepository
	validRun.HeadRepository.FullName = stableCandidateRepository
	entries := map[string]any{
		base + "/actions/workflows/stable-native-candidates.yml": stableWorkflowResponse{ID: 44, Path: stableCandidateWorkflow},
		runPath: validRun, runPath + "/attempts/2": validRun,
		base + "/git/commits/" + commit: candidateGitCommit{SHA: commit, Tree: candidateGitObject{SHA: treeA}},
		base + "/git/trees/" + treeA:    candidateGitTree{SHA: treeA, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: ".github", Type: "tree", Mode: "040000", SHA: treeB}}},
		base + "/git/trees/" + treeB:    candidateGitTree{SHA: treeB, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: "workflows", Type: "tree", Mode: "040000", SHA: treeC}}},
		base + "/git/trees/" + treeC:    candidateGitTree{SHA: treeC, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: "stable-native-candidates.yml", Type: "blob", Mode: "100644", SHA: blobID}}},
		base + "/git/blobs/" + blobID:   candidateGitBlob{SHA: blobID, Encoding: "base64", Size: int64(len(workflowData)), Content: base64.StdEncoding.EncodeToString(workflowData)},
	}
	api := func(_ context.Context, endpoint string, value any) error {
		item, ok := entries[endpoint]
		if !ok {
			return fmt.Errorf("unexpected endpoint %s", endpoint)
		}
		data, _ := json.Marshal(item)
		return json.Unmarshal(data, value)
	}
	run, err := readStableCandidateRunWithAPI(context.Background(), api, 123, 2)
	if err != nil || run.id != 123 || run.workflowBlob != blobID {
		t.Fatalf("reviewed run = %+v, %v", run, err)
	}
	failed := validRun
	failed.Conclusion = "failure"
	entries[runPath+"/attempts/2"] = failed
	if _, err := readStableCandidateRunWithAPI(context.Background(), api, 123, 2); err == nil {
		t.Fatal("failed run attempt accepted")
	}
	entries[runPath+"/attempts/2"] = validRun
	later := validRun
	later.Attempt = 3
	entries[runPath] = later
	if _, err := readStableCandidateRunWithAPI(context.Background(), api, 123, 2); err == nil {
		t.Fatal("superseded attempt accepted")
	}
	entries[runPath] = validRun
	altered := append([]byte(nil), workflowData...)
	altered = append(altered, '\n')
	entries[base+"/git/blobs/"+blobID] = candidateGitBlob{SHA: blobID, Encoding: "base64", Size: int64(len(altered)), Content: base64.StdEncoding.EncodeToString(altered)}
	if _, err := readStableCandidateRunWithAPI(context.Background(), api, 123, 2); err == nil {
		t.Fatal("changed workflow content accepted")
	}
}

func boolPointer(value bool) *bool { return &value }
