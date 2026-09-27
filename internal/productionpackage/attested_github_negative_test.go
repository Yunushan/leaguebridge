package productionpackage

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStableCandidateRunRejectsChangedLiveIdentityAndWorkflowTree(t *testing.T) {
	workflowData, err := os.ReadFile("../../.github/workflows/stable-native-candidates.yml")
	if err != nil {
		t.Fatal(err)
	}
	gitHash := sha1.New()
	fmt.Fprintf(gitHash, "blob %d\x00", len(workflowData))
	gitHash.Write(workflowData)
	blobID := hex.EncodeToString(gitHash.Sum(nil))
	commit := strings.Repeat("a", 40)
	treeA, treeB, treeC := strings.Repeat("b", 40), strings.Repeat("c", 40), strings.Repeat("d", 40)
	base := "repos/" + stableCandidateRepository
	runPath := base + "/actions/runs/123"
	workflowPath := base + "/actions/workflows/stable-native-candidates.yml"
	commitPath := base + "/git/commits/" + commit
	treePath := base + "/git/trees/" + treeA
	blobPath := base + "/git/blobs/" + blobID
	goodRun := stableRunResponse{ID: 123, Attempt: 2, WorkflowID: 44, Path: stableCandidateWorkflow,
		Event: "workflow_dispatch", Branch: "main", Commit: commit, Status: "completed", Conclusion: "success"}
	goodRun.Repository.FullName = stableCandidateRepository
	goodRun.HeadRepository.FullName = stableCandidateRepository
	makeEntries := func() map[string]any {
		return map[string]any{
			workflowPath: stableWorkflowResponse{ID: 44, Path: stableCandidateWorkflow},
			runPath:      goodRun, runPath + "/attempts/2": goodRun,
			commitPath:                   candidateGitCommit{SHA: commit, Tree: candidateGitObject{SHA: treeA}},
			treePath:                     candidateGitTree{SHA: treeA, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: ".github", Type: "tree", Mode: "040000", SHA: treeB}}},
			base + "/git/trees/" + treeB: candidateGitTree{SHA: treeB, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: "workflows", Type: "tree", Mode: "040000", SHA: treeC}}},
			base + "/git/trees/" + treeC: candidateGitTree{SHA: treeC, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: "stable-native-candidates.yml", Type: "blob", Mode: "100644", SHA: blobID}}},
			blobPath:                     candidateGitBlob{SHA: blobID, Encoding: "base64", Size: int64(len(workflowData)), Content: base64.StdEncoding.EncodeToString(workflowData)},
		}
	}
	tests := []struct {
		name   string
		change func(map[string]any)
	}{
		{"wrong workflow path", func(entries map[string]any) {
			entries[workflowPath] = stableWorkflowResponse{ID: 44, Path: "other.yml"}
		}},
		{"forked head repository", func(entries map[string]any) {
			run := goodRun
			run.HeadRepository.FullName = "another-owner/leaguebridge"
			entries[runPath+"/attempts/2"] = run
		}},
		{"scheduled event", func(entries map[string]any) {
			run := goodRun
			run.Event = "schedule"
			entries[runPath+"/attempts/2"] = run
		}},
		{"latest run differs from attempt", func(entries map[string]any) {
			run := goodRun
			run.Commit = strings.Repeat("9", 40)
			entries[runPath] = run
		}},
		{"commit points to other tree", func(entries map[string]any) {
			entries[commitPath] = candidateGitCommit{SHA: commit, Tree: candidateGitObject{SHA: strings.Repeat("9", 40)}}
		}},
		{"truncated tree", func(entries map[string]any) {
			entries[treePath] = candidateGitTree{SHA: treeA, Truncated: boolPointer(true), Entries: []candidateGitEntry{{Path: ".github", Type: "tree", Mode: "040000", SHA: treeB}}}
		}},
		{"ambiguous tree entry", func(entries map[string]any) {
			entry := candidateGitEntry{Path: ".github", Type: "tree", Mode: "040000", SHA: treeB}
			entries[treePath] = candidateGitTree{SHA: treeA, Truncated: boolPointer(false), Entries: []candidateGitEntry{entry, entry}}
		}},
		{"workflow directory replaced by blob", func(entries map[string]any) {
			entries[treePath] = candidateGitTree{SHA: treeA, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: ".github", Type: "blob", Mode: "100644", SHA: treeB}}}
		}},
		{"workflow file symlink", func(entries map[string]any) {
			entries[base+"/git/trees/"+treeC] = candidateGitTree{SHA: treeC, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: "stable-native-candidates.yml", Type: "blob", Mode: "120000", SHA: blobID}}}
		}},
		{"blob metadata size differs", func(entries map[string]any) {
			entries[blobPath] = candidateGitBlob{SHA: blobID, Encoding: "base64", Size: int64(len(workflowData) + 1), Content: base64.StdEncoding.EncodeToString(workflowData)}
		}},
		{"blob is malformed base64", func(entries map[string]any) {
			entries[blobPath] = candidateGitBlob{SHA: blobID, Encoding: "base64", Size: int64(len(workflowData)), Content: "@@@"}
		}},
		{"blob bytes do not match Git object", func(entries map[string]any) {
			changed := append(append([]byte(nil), workflowData...), '\n')
			entries[blobPath] = candidateGitBlob{SHA: blobID, Encoding: "base64", Size: int64(len(changed)), Content: base64.StdEncoding.EncodeToString(changed)}
		}},
		{"valid Git object has unreviewed workflow bytes", func(entries map[string]any) {
			changed := append(append([]byte(nil), workflowData...), '\n')
			hash := sha1.New()
			fmt.Fprintf(hash, "blob %d\x00", len(changed))
			hash.Write(changed)
			changedID := hex.EncodeToString(hash.Sum(nil))
			entries[base+"/git/trees/"+treeC] = candidateGitTree{SHA: treeC, Truncated: boolPointer(false), Entries: []candidateGitEntry{{Path: "stable-native-candidates.yml", Type: "blob", Mode: "100644", SHA: changedID}}}
			entries[base+"/git/blobs/"+changedID] = candidateGitBlob{SHA: changedID, Encoding: "base64", Size: int64(len(changed)), Content: base64.StdEncoding.EncodeToString(changed)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := makeEntries()
			test.change(entries)
			api := func(_ context.Context, endpoint string, value any) error {
				item, ok := entries[endpoint]
				if !ok {
					return fmt.Errorf("unexpected GitHub endpoint %q", endpoint)
				}
				data, err := json.Marshal(item)
				if err != nil {
					return err
				}
				return json.Unmarshal(data, value)
			}
			if _, err := readStableCandidateRunWithAPI(context.Background(), api, 123, 2); err == nil {
				t.Fatal("changed live run or workflow source was accepted")
			}
		})
	}
}

func TestStableCandidateRunRejectsInvalidLocatorsAndUnavailableAPI(t *testing.T) {
	failedAPI := func(context.Context, string, any) error { return errors.New("GitHub API unavailable") }
	for _, input := range []struct {
		name    string
		context context.Context
		api     candidateGitHubAPIClient
		id      int64
		attempt int
	}{
		{"zero run ID", context.Background(), failedAPI, 0, 1},
		{"zero attempt", context.Background(), failedAPI, 1, 0},
		{"nil context", nil, failedAPI, 1, 1},
		{"nil API", context.Background(), nil, 1, 1},
		{"API unavailable", context.Background(), failedAPI, 1, 1},
	} {
		t.Run(input.name, func(t *testing.T) {
			if _, err := readStableCandidateRunWithAPI(input.context, input.api, input.id, input.attempt); err == nil {
				t.Fatal("invalid run locator or unavailable GitHub API was accepted")
			}
		})
	}
}

func TestGitHubCLIRunnerBoundsOutputAndReportsFailures(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "fake-gh")
	writeScript := func(body string) {
		t.Helper()
		if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeScript("printf '%s\\n' \"$@\"")
	run := stableCandidateRun{commit: strings.Repeat("a", 40)}
	output, err := verifyStableCandidateStatement(context.Background(), scriptPath, "/tmp/CANDIDATE-SET.json", run)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, expected := range []string{
		"attestation", "verify", "/tmp/CANDIDATE-SET.json", "--hostname", "github.com", "--repo", stableCandidateRepository,
		"--signer-workflow", stableCandidateRepository + "/" + stableCandidateWorkflow,
		"--source-ref", stableCandidateRef, "--source-digest", run.commit,
		"--cert-oidc-issuer", stableCandidateOIDCIssuer, "--deny-self-hosted-runners",
		"--predicate-type", stableCandidatePredicate, "--format", "json",
	} {
		found := false
		for _, actual := range args {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("verified attestation command lacks %q: %q", expected, args)
		}
	}
	writeScript("exit 7")
	if _, err := runBoundedGitHub(context.Background(), scriptPath, time.Second, "api"); err == nil {
		t.Fatal("failed GitHub command was accepted")
	}
	writeScript("head -c 8388609 /dev/zero")
	if _, err := runBoundedGitHub(context.Background(), scriptPath, 5*time.Second, "api"); err == nil || !strings.Contains(err.Error(), "size bound") {
		t.Fatalf("oversized GitHub CLI response = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runBoundedGitHub(ctx, scriptPath, time.Second, "api"); err == nil {
		t.Fatal("cancelled GitHub command was accepted")
	}
	for _, invalid := range []struct {
		context context.Context
		path    string
		args    []string
	}{
		{nil, scriptPath, []string{"api"}},
		{context.Background(), "", []string{"api"}},
		{context.Background(), scriptPath, nil},
	} {
		if _, err := runBoundedGitHub(invalid.context, invalid.path, time.Second, invalid.args...); err == nil {
			t.Fatal("invalid GitHub command was accepted")
		}
	}
	bounded := &boundedGitHubOutput{}
	if count, err := bounded.Write([]byte("small")); err != nil || count != 5 {
		t.Fatalf("small GitHub output: count %d, error %v", count, err)
	}
	if _, err := bounded.Write(make([]byte, maximumGitHubResponse)); err == nil || !bounded.tooLarge {
		t.Fatal("oversized GitHub output was accepted")
	}
}

func TestCandidateGitHubAPIUsesBoundedCLIAndDecodesOneResponse(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "fake-gh")
	script := `#!/bin/sh
if [ "$1" != api ] || [ "$2" != --hostname ] || [ "$3" != github.com ]; then
  exit 7
fi
printf '%s' '{"id":44,"path":".github/workflows/stable-native-candidates.yml"}'
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var response stableWorkflowResponse
	if err := candidateGitHubAPI(scriptPath)(context.Background(), "repos/Yunushan/leaguebridge/actions/workflows/stable-native-candidates.yml", &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != 44 || response.Path != stableCandidateWorkflow {
		t.Fatalf("GitHub workflow response = %+v", response)
	}
}

func TestAttestedCandidateSetRejectsChangesDuringExternalChecks(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *attestedSetFixture, *attestationDependencies)
	}{
		{"run lookup unavailable", func(_ *testing.T, _ *attestedSetFixture, deps *attestationDependencies) {
			deps.readRun = func(context.Context, string, int64, int) (stableCandidateRun, error) {
				return stableCandidateRun{}, errors.New("GitHub API unavailable")
			}
		}},
		{"signature verification fails", func(_ *testing.T, _ *attestedSetFixture, deps *attestationDependencies) {
			deps.verifyStatement = func(context.Context, string, string, stableCandidateRun) ([]byte, error) {
				return nil, errors.New("unsigned candidate")
			}
		}},
		{"record swapped during attestation", func(t *testing.T, fixture *attestedSetFixture, deps *attestationDependencies) {
			original := deps.verifyStatement
			deps.verifyStatement = func(ctx context.Context, gh, path string, run stableCandidateRun) ([]byte, error) {
				if err := os.WriteFile(fixture.input.RecordPath, []byte("replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
				return original(ctx, gh, path, run)
			}
		}},
		{"package swapped during attestation", func(t *testing.T, fixture *attestedSetFixture, deps *attestationDependencies) {
			original := deps.verifyStatement
			deps.verifyStatement = func(ctx context.Context, gh, path string, run stableCandidateRun) ([]byte, error) {
				if err := os.WriteFile(fixture.input.Candidates[0].PackagePath, []byte("replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
				return original(ctx, gh, path, run)
			}
		}},
		{"summary differs at payload recheck", func(_ *testing.T, fixture *attestedSetFixture, deps *attestationDependencies) {
			deps.recheckPayload = func(context.Context) ([]Summary, error) {
				changed := append([]Summary(nil), fixture.summaries...)
				changed[0].ArchiveSHA256 = strings.Repeat("0", 64)
				return changed, nil
			}
		}},
		{"run changed at final recheck", func(_ *testing.T, fixture *attestedSetFixture, deps *attestationDependencies) {
			reads := 0
			deps.readRun = func(context.Context, string, int64, int) (stableCandidateRun, error) {
				reads++
				if reads == 2 {
					changed := fixture.run
					changed.workflowBlob = strings.Repeat("9", 40)
					return changed, nil
				}
				return fixture.run, nil
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := makeAttestedSetFixture(t)
			output := statementJSON(t, candidateStatementFixture(fixture.run, fixture.subjects))
			deps := attestationDependencies{
				readRun:         func(context.Context, string, int64, int) (stableCandidateRun, error) { return fixture.run, nil },
				verifyStatement: func(context.Context, string, string, stableCandidateRun) ([]byte, error) { return output, nil },
				recheckPayload:  func(context.Context) ([]Summary, error) { return fixture.summaries, nil },
				recheckRelease:  func(context.Context) error { return nil },
			}
			test.change(t, &fixture, &deps)
			if _, err := verifyAttestedCandidateSet(context.Background(), fixture.facts, fixture.summaries, fixture.input, deps); err == nil {
				t.Fatal("candidate inputs changed during external checks but verification succeeded")
			}
		})
	}
}

func TestCandidateJSONDecoderRejectsTrailingValuesAndMalformedInput(t *testing.T) {
	for _, value := range []string{"not JSON", `{"id":1} {"id":2}`, `{"id":1} invalid`} {
		var decoded struct {
			ID int `json:"id"`
		}
		if err := decodeOneJSON([]byte(value), &decoded); err == nil {
			t.Fatalf("malformed or trailing GitHub response %q was accepted", value)
		}
	}
	var decoded struct {
		ID int `json:"id"`
	}
	if err := decodeOneJSON([]byte(`{"id":1}`), &decoded); err != nil || decoded.ID != 1 {
		t.Fatalf("single GitHub response = %+v, %v", decoded, err)
	}
}

func TestCandidateStatementRejectsUnselectedOrMalformedVerification(t *testing.T) {
	fixture := makeAttestedSetFixture(t)
	base := candidateStatementFixture(fixture.run, fixture.subjects)
	unrelated := cloneStatement(t, base)
	_, _, otherCert := statementParts(unrelated)
	otherCert["runInvocationURI"] = "https://github.com/Yunushan/leaguebridge/actions/runs/999/attempts/1"
	missingIssuer := cloneStatement(t, base)
	_, _, issuerCert := statementParts(missingIssuer)
	delete(issuerCert, "issuer")
	wrongIssuerType := cloneStatement(t, base)
	_, _, typeCert := statementParts(wrongIssuerType)
	typeCert["issuer"] = 42
	for _, input := range []struct {
		name string
		data []byte
	}{
		{"malformed JSON", []byte("{")},
		{"no verified attestation", statementJSON(t)},
		{"oversized result set", statementJSON(t, make([]map[string]any, 33)...)},
		{"only another run", statementJSON(t, unrelated)},
		{"certificate missing issuer", statementJSON(t, missingIssuer)},
		{"certificate issuer not a string", statementJSON(t, wrongIssuerType)},
	} {
		t.Run(input.name, func(t *testing.T) {
			if err := checkCandidateStatement(input.data, fixture.subjects, fixture.run); err == nil {
				t.Fatal("malformed or unselected attestation was accepted")
			}
		})
	}
}

func TestAttestedCandidateSetRejectsInvalidTrustInputs(t *testing.T) {
	fixture := makeAttestedSetFixture(t)
	if _, _, err := expectedCandidateAttestation(attestedCandidateFacts{}, fixture.summaries); err == nil {
		t.Fatal("missing authenticated release identity was accepted")
	}
	changed := append([]Summary(nil), fixture.summaries...)
	changed[0].PackageSHA256 = "not a SHA-256 digest"
	if _, _, err := expectedCandidateAttestation(fixture.facts, changed); err == nil {
		t.Fatal("candidate with an invalid digest was accepted")
	}
	if err := checkAttestedPackageBytes(context.Background(), fixture.input.Candidates[:10], fixture.summaries); err == nil {
		t.Fatal("incomplete package set was accepted")
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(fixture.input.Candidates[0].PackagePath), "unexpected"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkAttestedPackageBytes(context.Background(), fixture.input.Candidates, fixture.summaries); err == nil {
		t.Fatal("extra directory in fixed candidate package tree was accepted")
	}
	var empty VerifiedAttestedCandidateSet
	if _, err := empty.Summaries(); err == nil {
		t.Fatal("unverified candidate set exposed summaries")
	}
}
