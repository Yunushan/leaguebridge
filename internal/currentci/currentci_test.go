package currentci

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
	"github.com/Yunushan/leaguebridge/internal/cireleasegate"
	"github.com/Yunushan/leaguebridge/internal/target"
)

const testCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testTree = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const githubTree = "cccccccccccccccccccccccccccccccccccccccc"
const workflowTree = "dddddddddddddddddddddddddddddddddddddddd"
const apiPrefix = "repos/" + repository

func workflowBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSupportedWorkflowPinMatchesRepository(t *testing.T) {
	digest := sha256.Sum256(workflowBytes(t))
	if hex.EncodeToString(digest[:]) != supportedWorkflowSHA256 {
		t.Fatal("CI workflow changed: review the supported non-reusable workflow contract")
	}
}

func sourceFixture(data []byte) map[string]any {
	hash := sha1.New()
	fmt.Fprintf(hash, "blob %d\x00", len(data))
	hash.Write(data)
	blob := hex.EncodeToString(hash.Sum(nil))
	truncated := false
	return map[string]any{
		apiPrefix + "/git/ref/heads/main":        gitReference{Ref: mainRef, Object: gitObject{SHA: testCommit, Type: "commit"}},
		apiPrefix + "/git/commits/" + testCommit: gitCommit{SHA: testCommit, Tree: gitObject{SHA: testTree}},
		apiPrefix + "/git/trees/" + testTree:     gitTree{SHA: testTree, Truncated: &truncated, Entries: []gitEntry{{Path: ".github", Mode: "040000", Type: "tree", SHA: githubTree}}},
		apiPrefix + "/git/trees/" + githubTree:   gitTree{SHA: githubTree, Truncated: &truncated, Entries: []gitEntry{{Path: "workflows", Mode: "040000", Type: "tree", SHA: workflowTree}}},
		apiPrefix + "/git/trees/" + workflowTree: gitTree{SHA: workflowTree, Truncated: &truncated, Entries: []gitEntry{{Path: "ci.yml", Mode: "100644", Type: "blob", SHA: blob}}},
		apiPrefix + "/git/blobs/" + blob:         gitBlob{SHA: blob, Encoding: "base64", Size: int64(len(data)), Content: base64.StdEncoding.EncodeToString(data)},
	}
}

func fixtureAPI(values map[string]any) apiClient {
	return func(ctx context.Context, endpoint string, out any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, ok := values[endpoint]
		if !ok {
			return errors.New("missing API fixture")
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, out)
	}
}

func testInput() VerifyRequest {
	input := VerifyRequest{GHPath: "trusted-gh", RaceVetSubject: "race.json"}
	for _, candidate := range target.Ordered() {
		input.CrossBuildSubjects = append(input.CrossBuildSubjects, candidate.GOOS+"-"+candidate.GOARCH+".json")
	}
	return input
}

func passingDependencies(data []byte) dependencies {
	return dependencies{
		api: fixtureAPI(sourceFixture(data)),
		gate: func(ctx context.Context, input cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
			return cireleasegate.RunIdentity{ID: 200, Attempt: 2, Commit: input.Commit}, ctx.Err()
		},
		signatures: func(ctx context.Context, input ciattestation.VerifyRequest) error { return ctx.Err() },
		now:        func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.FixedZone("offset", 3600)) },
	}
}

func TestVerifyDerivesSourceAndComposesBothEvidenceSets(t *testing.T) {
	input := testInput()
	deps := passingDependencies(workflowBytes(t))
	var gates []cireleasegate.VerifyRequest
	var signatures []ciattestation.VerifyRequest
	originalGate := deps.gate
	deps.gate = func(ctx context.Context, request cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
		if len(gates) == 0 && len(signatures) != 0 || len(gates) == 1 && len(signatures) != 2 {
			t.Fatal("gate/signature ordering changed")
		}
		gates = append(gates, request)
		return originalGate(ctx, request)
	}
	deps.signatures = func(ctx context.Context, request ciattestation.VerifyRequest) error {
		if len(gates) != 1 {
			t.Fatal("signature verification is not bracketed by complete gates")
		}
		signatures = append(signatures, request)
		return nil
	}
	got, err := verify(context.Background(), input, deps)
	if err != nil {
		t.Fatal(err)
	}
	want := Observation{Commit: testCommit, Tree: testTree, RunID: 200, RunAttempt: 2, ObservedAt: deps.now().UTC()}
	if got != want {
		t.Fatalf("observation = %#v; want %#v", got, want)
	}
	if len(gates) != 2 || len(signatures) != 2 {
		t.Fatalf("got %d gates and %d signed sets", len(gates), len(signatures))
	}
	expectedGate := cireleasegate.VerifyRequest{Commit: testCommit, GHPath: input.GHPath}
	if gates[0] != expectedGate || gates[1] != expectedGate {
		t.Fatalf("unexpected gates: %#v", gates)
	}
	for index, kind := range []string{"race-vet", "cross-build"} {
		paths := []string{input.RaceVetSubject}
		if index == 1 {
			paths = input.CrossBuildSubjects
		}
		expected := ciattestation.VerifyRequest{Kind: kind, SubjectPaths: paths, ExpectedRepo: repository, ExpectedWorkflow: workflowPath, ExpectedCommit: testCommit, ExpectedTree: testTree, ExpectedRef: mainRef, GHPath: input.GHPath, WorkflowSHA: testCommit, RunID: "200", RunAttempt: "2"}
		if !reflect.DeepEqual(signatures[index], expected) {
			t.Fatalf("request = %#v; want %#v", signatures[index], expected)
		}
	}
}

func TestVerifyRejectsInvalidInputBeforeReadingState(t *testing.T) {
	cases := map[string]func(*VerifyRequest){
		"no executable":           func(v *VerifyRequest) { v.GHPath = "" },
		"no race subject":         func(v *VerifyRequest) { v.RaceVetSubject = "" },
		"missing cross subject":   func(v *VerifyRequest) { v.CrossBuildSubjects = v.CrossBuildSubjects[:8] },
		"extra cross subject":     func(v *VerifyRequest) { v.CrossBuildSubjects = append(v.CrossBuildSubjects, "extra.json") },
		"empty cross subject":     func(v *VerifyRequest) { v.CrossBuildSubjects[0] = "" },
		"duplicate cross subject": func(v *VerifyRequest) { v.CrossBuildSubjects[1] = v.CrossBuildSubjects[0] },
		"race reused":             func(v *VerifyRequest) { v.CrossBuildSubjects[0] = v.RaceVetSubject },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := testInput()
			mutate(&input)
			got, err := verify(context.Background(), input, dependencies{})
			if err == nil || got != (Observation{}) {
				t.Fatalf("got %#v, %v", got, err)
			}
		})
	}
}

func TestResolveSourceRejectsMismatchedAndAmbiguousGitObjects(t *testing.T) {
	data := workflowBytes(t)
	cases := map[string]func(map[string]any){
		"wrong ref": func(f map[string]any) {
			v := f[apiPrefix+"/git/ref/heads/main"].(gitReference)
			v.Ref = "refs/heads/other"
			f[apiPrefix+"/git/ref/heads/main"] = v
		},
		"noncommit ref": func(f map[string]any) {
			v := f[apiPrefix+"/git/ref/heads/main"].(gitReference)
			v.Object.Type = "tag"
			f[apiPrefix+"/git/ref/heads/main"] = v
		},
		"abbreviated commit": func(f map[string]any) {
			v := f[apiPrefix+"/git/ref/heads/main"].(gitReference)
			v.Object.SHA = "abcdef"
			f[apiPrefix+"/git/ref/heads/main"] = v
		},
		"missing main": func(f map[string]any) { delete(f, apiPrefix+"/git/ref/heads/main") },
		"wrong commit": func(f map[string]any) {
			v := f[apiPrefix+"/git/commits/"+testCommit].(gitCommit)
			v.SHA = testTree
			f[apiPrefix+"/git/commits/"+testCommit] = v
		},
		"invalid source tree": func(f map[string]any) {
			v := f[apiPrefix+"/git/commits/"+testCommit].(gitCommit)
			v.Tree.SHA = "bad"
			f[apiPrefix+"/git/commits/"+testCommit] = v
		},
		"wrong tree object": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+testTree].(gitTree)
			v.SHA = githubTree
			f[apiPrefix+"/git/trees/"+testTree] = v
		},
		"truncated tree": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+testTree].(gitTree)
			yes := true
			v.Truncated = &yes
			f[apiPrefix+"/git/trees/"+testTree] = v
		},
		"missing truncation": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+testTree].(gitTree)
			v.Truncated = nil
			f[apiPrefix+"/git/trees/"+testTree] = v
		},
		"duplicate tree entry": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+testTree].(gitTree)
			v.Entries = append(v.Entries, v.Entries[0])
			f[apiPrefix+"/git/trees/"+testTree] = v
		},
		"empty tree": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+testTree].(gitTree)
			v.Entries = nil
			f[apiPrefix+"/git/trees/"+testTree] = v
		},
		"too many tree entries": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+testTree].(gitTree)
			v.Entries = make([]gitEntry, maximumTreeEntries+1)
			f[apiPrefix+"/git/trees/"+testTree] = v
		},
		"symlink parent": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+testTree].(gitTree)
			v.Entries[0].Mode = "120000"
			v.Entries[0].Type = "blob"
			f[apiPrefix+"/git/trees/"+testTree] = v
		},
		"symlink workflow": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+workflowTree].(gitTree)
			v.Entries[0].Mode = "120000"
			f[apiPrefix+"/git/trees/"+workflowTree] = v
		},
		"missing workflow": func(f map[string]any) {
			v := f[apiPrefix+"/git/trees/"+workflowTree].(gitTree)
			v.Entries[0].Path = "other.yml"
			f[apiPrefix+"/git/trees/"+workflowTree] = v
		},
	}
	blobCases := map[string]func(*gitBlob){
		"wrong blob ID":       func(v *gitBlob) { v.SHA = testCommit },
		"wrong blob encoding": func(v *gitBlob) { v.Encoding = "utf-8" },
		"empty blob":          func(v *gitBlob) { v.Size = 0 },
		"large blob":          func(v *gitBlob) { v.Size = maximumWorkflowSize + 1 },
		"large encoding":      func(v *gitBlob) { v.Content = strings.Repeat("A", 2*maximumWorkflowSize+1) },
		"invalid base64":      func(v *gitBlob) { v.Content = "%%%" },
		"mismatched size":     func(v *gitBlob) { v.Size++ },
		"mismatched blob bytes": func(v *gitBlob) {
			changed := append([]byte(nil), data...)
			changed[0] = 'N'
			v.Content = base64.StdEncoding.EncodeToString(changed)
		},
	}
	for name, mutate := range blobCases {
		cases[name] = func(f map[string]any) {
			for key, value := range f {
				if blob, ok := value.(gitBlob); ok {
					mutate(&blob)
					f[key] = blob
				}
			}
		}
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := sourceFixture(data)
			mutate(fixture)
			got, err := resolveSource(context.Background(), fixtureAPI(fixture))
			if err == nil || got != (sourceIdentity{}) {
				t.Fatalf("got %#v, %v", got, err)
			}
		})
	}
	t.Run("unapproved workflow with valid blob", func(t *testing.T) {
		changed := append(append([]byte(nil), data...), []byte("\n# changed\n")...)
		_, err := resolveSource(context.Background(), fixtureAPI(sourceFixture(changed)))
		if err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestVerifyRejectsRemoteStateChangesAndVerifierFailures(t *testing.T) {
	data := workflowBytes(t)
	cases := map[string]func(*dependencies){
		"initial missing or failed job": func(d *dependencies) {
			d.gate = func(context.Context, cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				return cireleasegate.RunIdentity{}, errors.New("missing/failed job sensitive-detail")
			}
		},
		"gate source mismatch": func(d *dependencies) {
			d.gate = func(context.Context, cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				return cireleasegate.RunIdentity{ID: 200, Attempt: 2, Commit: testTree}, nil
			}
		},
		"race signature failure": func(d *dependencies) {
			d.signatures = func(context.Context, ciattestation.VerifyRequest) error { return errors.New("sensitive-detail") }
		},
		"cross signature failure": func(d *dependencies) {
			d.signatures = func(_ context.Context, r ciattestation.VerifyRequest) error {
				if r.Kind == "cross-build" {
					return errors.New("sensitive-detail")
				}
				return nil
			}
		},
		"newer failed CI run": func(d *dependencies) {
			original := d.gate
			calls := 0
			d.gate = func(ctx context.Context, r cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				calls++
				if calls == 2 {
					return cireleasegate.RunIdentity{}, errors.New("sensitive-detail")
				}
				return original(ctx, r)
			}
		},
		"rerun during signatures": func(d *dependencies) {
			original := d.gate
			calls := 0
			d.gate = func(ctx context.Context, r cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				v, e := original(ctx, r)
				calls++
				if calls == 2 {
					v.Attempt++
				}
				return v, e
			}
		},
		"new successful run during signatures": func(d *dependencies) {
			original := d.gate
			calls := 0
			d.gate = func(ctx context.Context, r cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				v, e := original(ctx, r)
				calls++
				if calls == 2 {
					v.ID++
				}
				return v, e
			}
		},
		"main advances during signatures": func(d *dependencies) {
			original := d.api
			reads := 0
			d.api = func(ctx context.Context, e string, v any) error {
				if e == apiPrefix+"/git/commits/"+testTree {
					*v.(*gitCommit) = gitCommit{SHA: testTree, Tree: gitObject{SHA: testTree}}
					return nil
				}
				err := original(ctx, e, v)
				if ref, ok := v.(*gitReference); ok {
					reads++
					if reads == 2 {
						ref.Object.SHA = testTree
					}
				}
				return err
			}
		},
		"main advances during final gate": func(d *dependencies) {
			original := d.api
			reads := 0
			d.api = func(ctx context.Context, e string, v any) error {
				err := original(ctx, e, v)
				if ref, ok := v.(*gitReference); ok {
					reads++
					if reads == 3 {
						ref.Object.SHA = testTree
					}
				}
				return err
			}
		},
		"source tree changes during verification": func(d *dependencies) {
			original := d.api
			changedTree := strings.Repeat("e", 40)
			reads := 0
			d.api = func(ctx context.Context, e string, v any) error {
				if e == apiPrefix+"/git/trees/"+changedTree {
					truncated := false
					*v.(*gitTree) = gitTree{SHA: changedTree, Truncated: &truncated, Entries: []gitEntry{{Path: ".github", Mode: "040000", Type: "tree", SHA: githubTree}}}
					return nil
				}
				err := original(ctx, e, v)
				if commit, ok := v.(*gitCommit); ok {
					reads++
					if reads == 2 {
						commit.Tree.SHA = changedTree
					}
				}
				return err
			}
		},
		"workflow disappears during verification": func(d *dependencies) {
			original := d.api
			reads := 0
			d.api = func(ctx context.Context, e string, v any) error {
				if _, ok := v.(*gitBlob); ok {
					reads++
					if reads == 2 {
						return errors.New("missing blob sensitive-detail")
					}
				}
				return original(ctx, e, v)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			deps := passingDependencies(data)
			mutate(&deps)
			got, err := verify(context.Background(), testInput(), deps)
			if err == nil || got != (Observation{}) || strings.Contains(err.Error(), "sensitive-detail") {
				t.Fatalf("got %#v, %v", got, err)
			}
			if (name == "main advances during signatures" || name == "source tree changes during verification") && !strings.Contains(err.Error(), "source or workflow changed") {
				t.Fatalf("did not compare resolved identities: %v", err)
			}
		})
	}
}

func TestVerifyPropagatesCancellationAtEveryStage(t *testing.T) {
	data := workflowBytes(t)
	for _, stage := range []string{"before start", "source", "initial gate", "race-vet", "cross-build", "final gate"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deps := passingDependencies(data)
			if stage == "before start" {
				cancel()
			}
			if stage == "source" {
				deps.api = func(context.Context, string, any) error { cancel(); return ctx.Err() }
			}
			original := deps.gate
			calls := 0
			deps.gate = func(ctx context.Context, r cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				calls++
				if stage == "initial gate" && calls == 1 || stage == "final gate" && calls == 2 {
					cancel()
				}
				return original(ctx, r)
			}
			deps.signatures = func(ctx context.Context, r ciattestation.VerifyRequest) error {
				if r.Kind == stage {
					cancel()
				}
				return ctx.Err()
			}
			got, err := verify(ctx, testInput(), deps)
			if !errors.Is(err, context.Canceled) || got != (Observation{}) {
				t.Fatalf("got %#v, %v", got, err)
			}
		})
	}
}

// The public API integration uses the test binary as the trusted executable.
// Fixtures never contact GitHub and do not represent genuine signed evidence.
func TestMain(m *testing.M) {
	if path := os.Getenv("LEAGUEBRIDGE_CURRENTCI_FAKE_GH"); path != "" {
		os.Exit(fakeGitHubCommand(path))
	}
	os.Exit(m.Run())
}

func fakeGitHubCommand(path string) int {
	args := os.Args[1:]
	log, err := os.OpenFile(os.Getenv("LEAGUEBRIDGE_CURRENTCI_GH_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return 10
	}
	err = json.NewEncoder(log).Encode(args)
	log.Close()
	if err != nil {
		return 11
	}
	switch os.Getenv("LEAGUEBRIDGE_CURRENTCI_GH_MODE") {
	case "error":
		fmt.Fprintln(os.Stderr, "sensitive-detail")
		return 17
	case "trailing":
		fmt.Fprint(os.Stdout, "{} {}")
		return 0
	case "invalid":
		fmt.Fprint(os.Stdout, "{")
		return 0
	case "oversize":
		fmt.Fprint(os.Stdout, strings.Repeat(" ", maximumResponse+1))
		return 0
	case "block":
		time.Sleep(time.Minute)
		return 0
	}
	expectedPrefix := []string{"api", "--hostname", "github.com", "--method", "GET", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10"}
	if len(args) == 10 && reflect.DeepEqual(args[:9], expectedPrefix) {
		data, err := os.ReadFile(path)
		if err != nil {
			return 12
		}
		var fixtures map[string]json.RawMessage
		if json.Unmarshal(data, &fixtures) != nil {
			return 13
		}
		value, ok := fixtures[args[9]]
		if !ok {
			return 14
		}
		_, err = os.Stdout.Write(value)
		if err != nil {
			return 15
		}
		return 0
	}
	expectedAttestation := []string{"attestation", "verify", "", "--repo", repository, "--signer-workflow", repository + "/" + workflowPath, "--source-ref", mainRef, "--source-digest", testCommit, "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"}
	if len(args) != len(expectedAttestation) {
		return 16
	}
	expectedAttestation[2] = args[2]
	if !reflect.DeepEqual(args, expectedAttestation) {
		return 18
	}
	data, err := os.ReadFile(args[2])
	if err != nil {
		return 19
	}
	digest := sha256.Sum256(data)
	workflowURI := "https://github.com/" + repository + "/" + workflowPath + "@" + mainRef
	certificate := map[string]string{
		"issuer": "https://token.actions.githubusercontent.com", "subjectAlternativeName": workflowURI,
		"githubWorkflowRepository": repository, "githubWorkflowRef": mainRef, "githubWorkflowSHA": testCommit,
		"buildSignerURI": workflowURI, "buildSignerDigest": testCommit, "buildConfigURI": workflowURI, "buildConfigDigest": testCommit,
		"runnerEnvironment": "github-hosted", "sourceRepositoryURI": "https://github.com/" + repository,
		"sourceRepositoryDigest": testCommit, "sourceRepositoryRef": mainRef, "runInvocationURI": "https://github.com/" + repository + "/actions/runs/200/attempts/2",
	}
	result := []any{map[string]any{"verificationResult": map[string]any{
		"statement": map[string]any{"predicateType": "https://slsa.dev/provenance/v1", "subject": []any{map[string]any{"name": args[2], "digest": map[string]string{"sha256": hex.EncodeToString(digest[:])}}}},
		"signature": map[string]any{"certificate": certificate}, "verifiedTimestamps": []any{map[string]string{"time": "2026-09-07T12:00:00Z"}},
	}}}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 20
	}
	return 0
}

func fakeExecutable(t *testing.T, fixtures map[string]any) (string, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "api.json")
	log := filepath.Join(directory, "calls.jsonl")
	data, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEAGUEBRIDGE_CURRENTCI_FAKE_GH", path)
	t.Setenv("LEAGUEBRIDGE_CURRENTCI_GH_LOG", log)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable, log
}

func TestGitHubAPIRequiresBoundedSuccessfulJSONAndCancellation(t *testing.T) {
	for _, mode := range []string{"error", "trailing", "invalid", "oversize", "block"} {
		t.Run(mode, func(t *testing.T) {
			executable, _ := fakeExecutable(t, nil)
			t.Setenv("LEAGUEBRIDGE_CURRENTCI_GH_MODE", mode)
			ctx := context.Background()
			cancel := func() {}
			if mode == "block" {
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
			}
			defer cancel()
			var out gitReference
			err := githubAPI(executable)(ctx, apiPrefix+"/git/ref/heads/main", &out)
			if err == nil || strings.Contains(err.Error(), "sensitive-detail") {
				t.Fatalf("got %v", err)
			}
			if mode == "block" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline lost: %v", err)
			}
		})
	}
}

func addPassingGateFixtures(f map[string]any) {
	f[apiPrefix+"/actions/workflows/ci.yml"] = map[string]any{"id": 100, "name": "CI", "path": workflowPath, "state": "active"}
	run := map[string]any{"id": 200, "run_attempt": 2, "workflow_id": 100, "path": workflowPath, "event": "push", "head_branch": "main", "head_sha": testCommit, "status": "completed", "conclusion": "success", "repository": map[string]string{"full_name": repository}, "head_repository": map[string]string{"full_name": repository}}
	f[apiPrefix+"/actions/workflows/100/runs?head_sha="+testCommit+"&branch=main&per_page=100&page=1"] = map[string]any{"total_count": 1, "workflow_runs": []any{run}}
	names := []string{"Test (ubuntu-24.04)", "Minimum Go compatibility", "Coverage", "Reachable vulnerability scan", "Reproducible release smoke test", "Native packages (Linux)", "Attest Linux race/vet subject", "Verify signed CI attestations", "Verify signed native runtime attestations", "Verify signed native package attestations"}
	labels := map[string]string{"freebsd": "FreeBSD 15.1", "openbsd": "OpenBSD 7.9", "netbsd": "NetBSD 11.0", "dragonfly": "DragonFly BSD 6.4.2"}
	for _, candidate := range target.Ordered() {
		cell := candidate.GOOS + "/" + candidate.GOARCH
		names = append(names, "Build ("+cell+")", "Attest "+cell+" cross-build subject")
		if candidate.GOOS == "linux" {
			names = append(names, "Hosted Linux runtime ("+candidate.GOARCH+")", "Attest hosted Linux runtime ("+candidate.GOARCH+")")
			continue
		}
		label := labels[candidate.GOOS]
		names = append(names, "BSD kernel runtime ("+label+" "+candidate.GOARCH+")", "Attest BSD runtime ("+cell+")")
		if candidate.GOOS != "dragonfly" {
			label += " " + candidate.GOARCH
		}
		names = append(names, "Native package ("+label+")")
	}
	var jobs []any
	for index, name := range names {
		jobs = append(jobs, map[string]any{"id": 1000 + index, "run_id": 200, "head_sha": testCommit, "name": name, "status": "completed", "conclusion": "success"})
	}
	f[apiPrefix+"/actions/runs/200/attempts/2/jobs?per_page=100&page=1"] = map[string]any{"total_count": len(jobs), "jobs": jobs}
}

func TestVerifyPublicAPIWithRealLocalEvidenceAndOfflineGitHub(t *testing.T) {
	fixture := sourceFixture(workflowBytes(t))
	addPassingGateFixtures(fixture)
	executable, log := fakeExecutable(t, fixture)
	t.Chdir(t.TempDir())
	input := VerifyRequest{GHPath: executable, RaceVetSubject: "race.json"}
	request := ciattestation.GenerateRequest{Kind: "race-vet", GeneratedAt: "2026-09-07T12:00:00Z", Repository: repository, Commit: testCommit, Tree: testTree, Ref: mainRef, Workflow: "CI", WorkflowRef: repository + "/" + workflowPath + "@" + mainRef, WorkflowSHA: testCommit, RunID: "200", RunAttempt: "2", Job: "test", RunnerOS: "Linux", RunnerArchitecture: "X64", GoVersion: "go1.27.1", Command: "go test -mod=vendor -race ./...; go vet -mod=vendor ./...", TargetGOOS: "linux", TargetGOARCH: "amd64"}
	if err := ciattestation.GenerateFile(input.RaceVetSubject, request); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("ci-build", 0700); err != nil {
		t.Fatal(err)
	}
	request.Kind, request.Job, request.Command = "cross-build", "cross-build", "go build -mod=vendor ./..."
	for _, candidate := range target.Ordered() {
		binary := "ci-build/leaguebridge-" + candidate.GOOS + "-" + candidate.GOARCH
		if err := os.WriteFile(binary, []byte("offline integration binary fixture\n"), 0700); err != nil {
			t.Fatal(err)
		}
		request.TargetGOOS, request.TargetGOARCH = candidate.GOOS, candidate.GOARCH
		request.SubjectPaths = []string{binary}
		subject := candidate.GOOS + "-" + candidate.GOARCH + ".json"
		input.CrossBuildSubjects = append(input.CrossBuildSubjects, subject)
		if err := ciattestation.GenerateFile(subject, request); err != nil {
			t.Fatal(err)
		}
	}
	before := time.Now()
	got, err := Verify(context.Background(), input)
	after := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	if got.Commit != testCommit || got.Tree != testTree || got.RunID != 200 || got.RunAttempt != 2 || got.ObservedAt.Before(before) || got.ObservedAt.After(after) || got.ObservedAt.Location() != time.UTC {
		t.Fatalf("unexpected observation: %#v", got)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var args []string
		if err = json.Unmarshal([]byte(line), &args); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, args)
	}
	apiCalls, signatureCalls, runReads, mainReads := 0, 0, 0, 0
	for _, args := range calls {
		if args[0] == "api" {
			apiCalls++
			endpoint := args[len(args)-1]
			if strings.Contains(endpoint, "/runs?") {
				runReads++
			}
			if strings.HasSuffix(endpoint, "/git/ref/heads/main") {
				mainReads++
			}
		} else {
			signatureCalls++
		}
	}
	if apiCalls != 21 || signatureCalls != 19 || runReads != 4 || mainReads != 3 {
		t.Fatalf("API=%d signatures=%d run reads=%d main reads=%d", apiCalls, signatureCalls, runReads, mainReads)
	}
	// Subject identity is still untrusted input: changing it cannot select a new source.
	original, err := os.ReadFile(input.RaceVetSubject)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(original), testTree, githubTree, 1)
	if err = os.WriteFile(input.RaceVetSubject, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	rejected, err := Verify(context.Background(), input)
	if err == nil || rejected != (Observation{}) {
		t.Fatalf("mismatched evidence accepted: %#v, %v", rejected, err)
	}
}
