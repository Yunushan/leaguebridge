package releaseassessment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
	"github.com/Yunushan/leaguebridge/internal/cireleasegate"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/releasecheck"
	"github.com/Yunushan/leaguebridge/internal/target"
)

const fixturePrefix = "repos/" + repository
const fixtureCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fixtureVersion = "v0.1.0"

var fixtureNow = time.Date(2026, 9, 7, 19, 0, 0, 0, time.UTC)

type fixture struct {
	input    Request
	deps     dependencies
	values   map[string]any
	source   sourceIdentity
	card     []byte
	files    map[string][]byte
	apiMu    sync.Mutex
	apiCalls map[string]int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{values: make(map[string]any), files: make(map[string][]byte), apiCalls: make(map[string]int)}
	for _, name := range []string{ciWorkflow, releaseWorkflow} {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		f.files[name] = data
	}
	var card readiness.Scorecard
	if err := json.Unmarshal(readiness.EmbeddedJSON(), &card); err != nil {
		t.Fatal(err)
	}
	card.AssessedAt = fixtureNow.Add(-24 * time.Hour)
	card.ExpiresAt = fixtureNow.Add(24 * time.Hour)
	for categoryIndex := range card.Engineering {
		for criterionIndex := range card.Engineering[categoryIndex].Subcriteria {
			item := &card.Engineering[categoryIndex].Subcriteria[criterionIndex]
			for referenceIndex := range item.Evidence {
				ref := &item.Evidence[referenceIndex]
				if _, present := f.files[ref.Path]; !present {
					f.files[ref.Path] = []byte("synthetic source fixture: " + ref.Path + "\n")
				}
				ref.SHA256 = digestBytes(f.files[ref.Path])
			}
		}
	}
	var err error
	f.card, err = json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	f.files[scorecardPath] = f.card
	tree := f.addTree(f.files)
	f.source = sourceIdentity{fixtureCommit, tree, 1788801564}
	var commit gitCommit
	commit.SHA = fixtureCommit
	commit.Tree.SHA = tree
	commit.Committer.Date = time.Unix(f.source.Epoch, 0).UTC()
	f.values[fixturePrefix+"/git/commits/"+fixtureCommit] = commit
	f.values[fixturePrefix+"/git/ref/tags/"+fixtureVersion] = gitReference{Ref: "refs/tags/" + fixtureVersion, Object: gitObject{SHA: fixtureCommit, Type: "commit"}}
	var rule ruleset
	if err := json.Unmarshal([]byte(`{"id":91,"target":"tag","source_type":"Repository","source":"Yunushan/leaguebridge","enforcement":"active","bypass_actors":[],"conditions":{"ref_name":{"include":["refs/tags/v*"],"exclude":[]}},"rules":[{"type":"update"},{"type":"deletion"}]}`), &rule); err != nil {
		t.Fatal(err)
	}
	f.values[fixturePrefix+"/rulesets?includes_parents=true&per_page=100&page=1"] = []ruleset{rule}
	f.values[fixturePrefix+"/rulesets/91"] = rule
	f.values[fixturePrefix+"/actions/workflows/release.yml"] = workflow{44, "Release", releaseWorkflow, "active"}
	run := workflowRun{ID: 300, Attempt: 2, WorkflowID: 44, Path: releaseWorkflow, Event: "push", Branch: fixtureVersion, Commit: fixtureCommit, Status: "completed", Conclusion: "success", Repository: repositoryIdentity{repository}, HeadRepository: repositoryIdentity{repository}}
	f.values[f.runEndpoint()] = runPage{1, []workflowRun{run}}
	jobs := jobPage{Total: 3}
	for index, name := range []string{"Reject reachable known vulnerabilities", "Test and build unprivileged artifacts", "Attest and publish artifacts"} {
		attempt := 2
		jobs.Jobs = append(jobs.Jobs, job{ID: int64(index + 1), RunID: 300, Attempt: &attempt, Commit: fixtureCommit, Name: name, Status: "completed", Conclusion: "success"})
	}
	f.values[f.jobsEndpoint()] = jobs
	local := t.TempDir()
	f.input = Request{GHPath: "trusted-gh", Version: fixtureVersion, ReleaseDir: filepath.Join(local, "release"), RaceVetSubject: "ci-attestation/race-vet-linux.json"}
	for _, name := range []string{"release", "ci-attestation", "ci-build"} {
		if err := os.Mkdir(filepath.Join(local, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var assets []asset
	for index, name := range releaseNames(fixtureVersion) {
		data := []byte("synthetic release fixture: " + name + "\n")
		if err := os.WriteFile(filepath.Join(local, "release", name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		assets = append(assets, asset{ID: int64(index + 10), Name: name, State: "uploaded", Size: int64(len(data)), Digest: "sha256:" + digestBytes(data), URL: "https://github.com/" + repository + "/releases/download/" + fixtureVersion + "/" + name, UpdatedAt: fixtureNow.Add(-time.Hour)})
	}
	for _, item := range target.Ordered() {
		name := "ci-attestation/cross-build-" + item.GOOS + "-" + item.GOARCH + ".json"
		f.input.CrossBuildSubjects = append(f.input.CrossBuildSubjects, name)
		if err := os.WriteFile(filepath.Join(local, filepath.FromSlash(name)), []byte("synthetic signed subject"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(local, "ci-build", "leaguebridge-"+item.GOOS+"-"+item.GOARCH), []byte("synthetic signed binary"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(local, filepath.FromSlash(f.input.RaceVetSubject)), []byte("synthetic race/vet subject"), 0o600); err != nil {
		t.Fatal(err)
	}
	no := false
	f.values[fixturePrefix+"/releases/tags/"+fixtureVersion] = release{ID: 77, Tag: fixtureVersion, Draft: &no, Prerelease: &no, PublishedAt: fixtureNow.Add(-time.Hour), UpdatedAt: fixtureNow.Add(-time.Hour), URL: "https://github.com/" + repository + "/releases/tag/" + fixtureVersion, Assets: assets}
	f.values[fixturePrefix+"/releases/77/assets?per_page=100&page=1"] = assets
	f.deps = dependencies{
		api: f.api,
		gate: func(ctx context.Context, input cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
			return cireleasegate.RunIdentity{ID: 200, Attempt: 1, Commit: input.Commit}, ctx.Err()
		},
		signatures: func(ctx context.Context, input ciattestation.VerifyRequest) error { return ctx.Err() },
		archives:   func(input releasecheck.CheckRequest) error { return nil },
		now:        func() time.Time { return fixtureNow },
	}
	t.Chdir(local)
	return f
}

func (f *fixture) api(ctx context.Context, endpoint string, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.apiMu.Lock()
	defer f.apiMu.Unlock()
	f.apiCalls[endpoint]++
	value, exists := f.values[endpoint]
	if !exists {
		return fmt.Errorf("missing API fixture %s", endpoint)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, result)
}
func (f *fixture) runEndpoint() string {
	return fixturePrefix + "/actions/workflows/44/runs?head_sha=" + fixtureCommit + "&branch=" + fixtureVersion + "&per_page=100&page=1"
}
func (f *fixture) jobsEndpoint() string {
	return fixturePrefix + "/actions/runs/300/attempts/2/jobs?per_page=100&page=1"
}

func (f *fixture) addTree(files map[string][]byte) string {
	groups := make(map[string]map[string][]byte)
	var entries []gitEntry
	for name, data := range files {
		first, rest, nested := strings.Cut(name, "/")
		if nested {
			if groups[first] == nil {
				groups[first] = make(map[string][]byte)
			}
			groups[first][rest] = data
			continue
		}
		id := gitDigest("blob", data, 40)
		f.values[fixturePrefix+"/git/blobs/"+id] = gitBlob{SHA: id, Encoding: "base64", Size: int64(len(data)), Content: base64.StdEncoding.EncodeToString(data)}
		entries = append(entries, gitEntry{Path: first, Mode: "100644", Type: "blob", SHA: id})
	}
	for name, group := range groups {
		entries = append(entries, gitEntry{Path: name, Mode: "040000", Type: "tree", SHA: f.addTree(group)})
	}
	sort.Slice(entries, func(i, j int) bool {
		left, right := entries[i].Path, entries[j].Path
		if entries[i].Type == "tree" {
			left += "/"
		}
		if entries[j].Type == "tree" {
			right += "/"
		}
		return left < right
	})
	var raw bytes.Buffer
	for _, item := range entries {
		mode := strings.TrimLeft(item.Mode, "0")
		fmt.Fprintf(&raw, "%s %s\x00", mode, item.Path)
		id, _ := hex.DecodeString(item.SHA)
		raw.Write(id)
	}
	id := gitDigest("tree", raw.Bytes(), 40)
	no := false
	f.values[fixturePrefix+"/git/trees/"+id] = gitTree{SHA: id, Truncated: &no, Entries: entries}
	return id
}

func TestVerifyDerivesNamedReleaseAssessmentAndBindsEveryVerifier(t *testing.T) {
	f := newFixture(t)
	var signatures []ciattestation.VerifyRequest
	var gates []cireleasegate.VerifyRequest
	f.deps.gate = func(ctx context.Context, input cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
		gates = append(gates, input)
		return cireleasegate.RunIdentity{ID: 200, Attempt: 1, Commit: fixtureCommit}, nil
	}
	f.deps.signatures = func(ctx context.Context, input ciattestation.VerifyRequest) error {
		signatures = append(signatures, input)
		return nil
	}
	archiveCalls := 0
	privateDirectory := ""
	f.deps.archives = func(input releasecheck.CheckRequest) error {
		archiveCalls++
		privateDirectory = input.Dir
		if input.Dir == f.input.ReleaseDir || input.Dir == "" || input.Version != fixtureVersion || input.Commit != fixtureCommit || input.Tree != f.source.Tree || input.SourceDateEpoch != f.source.Epoch || input.BuilderGoVersion != packageinfo.ProductionBuilderGoVersion || !bytes.Equal(input.ExpectedScorecard, f.card) {
			t.Fatal("archive contents were not bound to the authenticated released source policy and private bytes")
		}
		return nil
	}
	got, err := verify(context.Background(), f.input, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.Version != fixtureVersion || got.Commit != fixtureCommit || got.Tree != f.source.Tree || got.ReleaseID != 77 || got.ReleaseRunID != 300 || got.ReleaseRunAttempt != 2 || got.CIRunID != 200 || got.CIRunAttempt != 1 || got.RepositoryScore != 74 || got.Score != 83 || !got.ObservedAt.Equal(fixtureNow) || !got.ScorecardExpiresAt.Equal(fixtureNow.Add(24*time.Hour)) {
		t.Fatalf("unexpected derived assessment: %+v", got)
	}
	if len(gates) != 2 || archiveCalls != 1 || len(signatures) != 3 || !reflect.DeepEqual(got.Criteria, additionalCriteria) {
		t.Fatal("incomplete verifier composition")
	}
	for _, gate := range gates {
		if gate.Commit != fixtureCommit || gate.GHPath != f.input.GHPath {
			t.Fatal("CI gate borrowed a different source")
		}
	}
	for index, request := range signatures {
		if request.ExpectedRepo != repository || request.ExpectedCommit != fixtureCommit || request.ExpectedTree != f.source.Tree || request.WorkflowSHA != fixtureCommit || request.GHPath != f.input.GHPath {
			t.Fatal("signature source binding missing")
		}
		if index < 2 {
			if request.ExpectedWorkflow != ciWorkflow || request.ExpectedRef != "refs/heads/main" || request.RunID != "200" || request.RunAttempt != "1" {
				t.Fatal("CI attestation run identity mismatch")
			}
		} else if request.Kind != "release" || request.ExpectedWorkflow != releaseWorkflow || request.ExpectedRef != "refs/tags/"+fixtureVersion || request.RunID != "300" || request.RunAttempt != "2" || request.ReleaseDir != privateDirectory || request.ReleaseVersion != fixtureVersion || len(request.SubjectPaths) != 0 {
			t.Fatal("release attestation identity mismatch")
		}
	}
	if _, err := os.Stat(privateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private release copy survived verification")
	}
	for endpoint, calls := range f.apiCalls {
		if strings.Contains(endpoint, "heads/main") {
			t.Fatal("named release assessment depends on current main")
		}
		if strings.Contains(endpoint, "/git/blobs/") && calls > 2 {
			t.Fatal("repository evidence was not deduplicated")
		}
	}
}

func TestVerifyRejectsPublicationAndIdentityFailures(t *testing.T) {
	cases := map[string]func(*fixture){
		"draft": func(f *fixture) {
			r := f.values[fixturePrefix+"/releases/tags/"+fixtureVersion].(release)
			yes := true
			r.Draft = &yes
			f.values[fixturePrefix+"/releases/tags/"+fixtureVersion] = r
		},
		"missing draft state": func(f *fixture) {
			r := f.values[fixturePrefix+"/releases/tags/"+fixtureVersion].(release)
			r.Draft = nil
			f.values[fixturePrefix+"/releases/tags/"+fixtureVersion] = r
		},
		"prerelease": func(f *fixture) {
			r := f.values[fixturePrefix+"/releases/tags/"+fixtureVersion].(release)
			yes := true
			r.Prerelease = &yes
			f.values[fixturePrefix+"/releases/tags/"+fixtureVersion] = r
		},
		"missing published assets": func(f *fixture) {
			a := f.values[fixturePrefix+"/releases/77/assets?per_page=100&page=1"].([]asset)
			f.values[fixturePrefix+"/releases/77/assets?per_page=100&page=1"] = a[:9]
		},
		"wrong tag source": func(f *fixture) {
			f.values[fixturePrefix+"/git/ref/tags/"+fixtureVersion] = gitReference{Ref: "refs/tags/" + fixtureVersion, Object: gitObject{SHA: strings.Repeat("b", 40), Type: "commit"}}
		},
		"unprotected tag": func(f *fixture) {
			f.values[fixturePrefix+"/rulesets?includes_parents=true&per_page=100&page=1"] = []ruleset{}
		},
		"ruleset bypass": func(f *fixture) {
			r := f.values[fixturePrefix+"/rulesets/91"].(ruleset)
			r.BypassActors = []json.RawMessage{json.RawMessage(`{"actor_id":1,"actor_type":"RepositoryRole","bypass_mode":"always"}`)}
			f.values[fixturePrefix+"/rulesets/91"] = r
		},
		"ruleset exclusion": func(f *fixture) {
			r := f.values[fixturePrefix+"/rulesets/91"].(ruleset)
			r.Conditions.RefName.Exclude = []string{"refs/tags/v0.1.0"}
			f.values[fixturePrefix+"/rulesets/91"] = r
		},
		"run wrong attempt job": func(f *fixture) {
			p := f.values[f.jobsEndpoint()].(jobPage)
			wrong := 1
			p.Jobs[1].Attempt = &wrong
			f.values[f.jobsEndpoint()] = p
		},
		"run wrong workflow": func(f *fixture) {
			p := f.values[f.runEndpoint()].(runPage)
			p.Runs[0].Path = ciWorkflow
			f.values[f.runEndpoint()] = p
		},
		"run wrong repository": func(f *fixture) {
			p := f.values[f.runEndpoint()].(runPage)
			p.Runs[0].HeadRepository.FullName = "attacker/fork"
			f.values[f.runEndpoint()] = p
		},
		"newer failed run": func(f *fixture) {
			p := f.values[f.runEndpoint()].(runPage)
			newer := p.Runs[0]
			newer.ID++
			newer.Conclusion = "failure"
			p.Runs = append(p.Runs, newer)
			p.Total++
			f.values[f.runEndpoint()] = p
		},
		"partial Release jobs": func(f *fixture) {
			p := f.values[f.jobsEndpoint()].(jobPage)
			p.Total = 2
			p.Jobs = p.Jobs[:2]
			f.values[f.jobsEndpoint()] = p
		},
		"skipped Release job": func(f *fixture) {
			p := f.values[f.jobsEndpoint()].(jobPage)
			p.Jobs[0].Conclusion = "skipped"
			f.values[f.jobsEndpoint()] = p
		},
		"wrong CI commit": func(f *fixture) {
			f.deps.gate = func(context.Context, cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				return cireleasegate.RunIdentity{ID: 200, Attempt: 1, Commit: strings.Repeat("b", 40)}, nil
			}
		},
		"signature failure": func(f *fixture) {
			f.deps.signatures = func(context.Context, ciattestation.VerifyRequest) error { return errors.New("secret signature stderr") }
		},
		"archive semantics failure": func(f *fixture) {
			f.deps.archives = func(releasecheck.CheckRequest) error { return errors.New("secret archive payload") }
		},
		"invalid local asset digest": func(f *fixture) {
			if err := os.WriteFile(filepath.Join(f.input.ReleaseDir, "checksums.txt"), []byte("changed"), 0o600); err != nil {
				panic(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(f)
			got, err := verify(context.Background(), f.input, f.deps)
			if err == nil || !reflect.DeepEqual(got, Result{}) {
				t.Fatalf("accepted %s: %+v %v", name, got, err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("untrusted diagnostic leaked")
			}
		})
	}
}

func TestVerifyRejectsChangesDuringVerification(t *testing.T) {
	cases := map[string]func(*testing.T, *fixture){
		"CI rerun": func(t *testing.T, f *fixture) {
			calls := 0
			f.deps.gate = func(context.Context, cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
				calls++
				return cireleasegate.RunIdentity{ID: 200, Attempt: calls, Commit: fixtureCommit}, nil
			}
		},
		"release asset replaced": func(t *testing.T, f *fixture) {
			f.deps.signatures = func(ctx context.Context, r ciattestation.VerifyRequest) error {
				if r.Kind == "release" {
					if err := os.WriteFile(filepath.Join(f.input.ReleaseDir, "checksums.txt"), []byte("replacement"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
		},
		"CI subject changed": func(t *testing.T, f *fixture) {
			f.deps.signatures = func(ctx context.Context, r ciattestation.VerifyRequest) error {
				if r.Kind == "release" {
					if err := os.WriteFile(f.input.RaceVetSubject, []byte("replacement"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
		},
		"CI binary changed": func(t *testing.T, f *fixture) {
			f.deps.signatures = func(ctx context.Context, r ciattestation.VerifyRequest) error {
				if r.Kind == "release" {
					if err := os.WriteFile("ci-build/leaguebridge-linux-amd64", []byte("replacement"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
		},
		"protection disabled": func(t *testing.T, f *fixture) {
			f.deps.signatures = func(ctx context.Context, r ciattestation.VerifyRequest) error {
				if r.Kind == "release" {
					rule := f.values[fixturePrefix+"/rulesets/91"].(ruleset)
					rule.Enforcement = "disabled"
					f.values[fixturePrefix+"/rulesets/91"] = rule
				}
				return nil
			}
		},
		"Release rerun": func(t *testing.T, f *fixture) {
			f.deps.signatures = func(ctx context.Context, r ciattestation.VerifyRequest) error {
				if r.Kind == "release" {
					p := f.values[f.runEndpoint()].(runPage)
					p.Runs[0].Attempt++
					f.values[f.runEndpoint()] = p
				}
				return nil
			}
		},
		"scorecard expires": func(t *testing.T, f *fixture) {
			calls := 0
			f.deps.now = func() time.Time {
				calls++
				if calls > 1 {
					return fixtureNow.Add(25 * time.Hour)
				}
				return fixtureNow
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(t, f)
			got, err := verify(context.Background(), f.input, f.deps)
			if err == nil || !reflect.DeepEqual(got, Result{}) {
				t.Fatalf("accepted mutation %s: %+v %v", name, got, err)
			}
		})
	}
}

func TestVerifyCancellationAndInputBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := Verify(ctx, Request{})
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, Result{}) {
		t.Fatalf("cancellation = %+v %v", got, err)
	}
	for _, version := range []string{"", "0.1.0", "v0.1.0-rc.1", "v0.1.0+build.1", "v0.1.0/../../main"} {
		got, err := verify(context.Background(), Request{GHPath: "gh", Version: version, ReleaseDir: "release", RaceVetSubject: "race", CrossBuildSubjects: make([]string, 9)}, dependencies{})
		if err == nil || !reflect.DeepEqual(got, Result{}) {
			t.Fatalf("accepted version %q", version)
		}
	}
	t.Run("cancel during signatures", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.deps.signatures = func(context.Context, ciattestation.VerifyRequest) error { cancel(); return context.Canceled }
		got, err := verify(ctx, f.input, f.deps)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, Result{}) {
			t.Fatalf("cancellation = %+v %v", got, err)
		}
	})
}

func TestGitSourceCannotSubstituteEvidenceOrPolicy(t *testing.T) {
	cases := map[string]func(*fixture){
		"tree bytes swapped": func(f *fixture) {
			p := fixturePrefix + "/git/trees/" + f.source.Tree
			tree := f.values[p].(gitTree)
			tree.Entries[0].SHA = strings.Repeat("f", 40)
			f.values[p] = tree
		},
		"truncated tree": func(f *fixture) {
			p := fixturePrefix + "/git/trees/" + f.source.Tree
			tree := f.values[p].(gitTree)
			yes := true
			tree.Truncated = &yes
			f.values[p] = tree
		},
		"workflow blob swapped": func(f *fixture) {
			id := gitDigest("blob", f.files[ciWorkflow], 40)
			p := fixturePrefix + "/git/blobs/" + id
			blob := f.values[p].(gitBlob)
			data := []byte(strings.Repeat("x", int(blob.Size)))
			blob.Content = base64.StdEncoding.EncodeToString(data)
			f.values[p] = blob
		},
		"repository blob swapped": func(f *fixture) {
			id := gitDigest("blob", f.files["README.md"], 40)
			p := fixturePrefix + "/git/blobs/" + id
			blob := f.values[p].(gitBlob)
			blob.Content = base64.StdEncoding.EncodeToString([]byte("replacement"))
			blob.Size = 11
			f.values[p] = blob
		},
		"missing evidence blob": func(f *fixture) {
			delete(f.values, fixturePrefix+"/git/blobs/"+gitDigest("blob", f.files["README.md"], 40))
		},
		"forged scorecard bytes": func(f *fixture) {
			id := gitDigest("blob", f.card, 40)
			p := fixturePrefix + "/git/blobs/" + id
			blob := f.values[p].(gitBlob)
			data := bytes.Replace(f.card, []byte(`"weight":4`), []byte(`"weight":9`), 1)
			blob.Content = base64.StdEncoding.EncodeToString(data)
			blob.Size = int64(len(data))
			f.values[p] = blob
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(f)
			_, _, _, err := resolveSource(context.Background(), f.api, fixtureCommit, fixtureNow)
			if err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestHistoricalPolicyPinPreservesContractAndExistingExpiry(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "reviewed-v0.1.0-scorecard.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(data) != reviewedHistoricalPolicy {
		t.Fatal("historical fixture differs from reviewed policy bytes")
	}
	card, err := parseReleasedPolicy(data, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if repositoryBaseline(card) != 74 || checkAdditionalContract(card) != nil {
		t.Fatal("historical policy criterion contract changed")
	}
	for _, now := range []time.Time{time.Time{}, card.AssessedAt.Add(-readiness.MaximumFutureSkew - time.Second), card.ExpiresAt.Add(time.Second)} {
		if _, err := parseReleasedPolicy(data, now); err == nil {
			t.Fatal("historical pin bypassed existing policy freshness")
		}
	}
	for _, mutation := range [][]byte{bytes.Replace(data, []byte(`"weight":4`), []byte(`"weight":9`), 1), append(append([]byte(nil), data...), []byte(` {}`)...), []byte(`{"schema_version":3,"engineering_score":100}`)} {
		if _, err := parseReleasedPolicy(mutation, fixtureNow); err == nil {
			t.Fatal("different or malformed historical policy inherited the pinned exception")
		}
	}
}

func TestSourceEvidenceDigestAndRegularFileRequirements(t *testing.T) {
	f := newFixture(t)
	var card readiness.Scorecard
	if err := json.Unmarshal(f.card, &card); err != nil {
		t.Fatal(err)
	}
	card.Engineering[0].Subcriteria[0].Evidence[0].SHA256 = strings.Repeat("0", 64)
	reader := sourceReader{api: f.api, tree: f.source.Tree, trees: make(map[string]map[string]gitEntry)}
	if err := reader.verifyEvidence(context.Background(), card); err == nil {
		t.Fatal("repository baseline accepted a digest not matching authenticated source")
	}
	entry := gitEntry{Path: "README.md", Mode: "120000", Type: "blob", SHA: gitDigest("blob", []byte("destination"), 40)}
	reader = sourceReader{tree: "synthetic-root", trees: map[string]map[string]gitEntry{"synthetic-root": {"README.md": entry}}}
	if _, err := reader.fileIdentity(context.Background(), "README.md"); err == nil {
		t.Fatal("source evidence symlink accepted")
	}
	for _, name := range []string{"../README.md", "/README.md", `dir\README.md`, "dir/../README.md"} {
		if _, err := reader.fileIdentity(context.Background(), name); err == nil {
			t.Fatalf("unsafe source path %q accepted", name)
		}
	}
}

func TestBoundedTransportAndCancellation(t *testing.T) {
	var buffer boundedOutput
	if _, err := buffer.Write(make([]byte, maximumResponse+1)); err == nil || buffer.Len() != 0 {
		t.Fatal("oversized API response accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := githubAPI("must-not-execute")(ctx, "anything", &struct{}{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transport = %v", err)
	}
}

func TestSubprocessOutputCannotBypassResponseBound(t *testing.T) {
	if os.Getenv("LEAGUEBRIDGE_ASSESSMENT_OUTPUT_CHILD") == "1" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), maximumResponse+1))
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSubprocessOutputCannotBypassResponseBound$")
	cmd.Env = append(os.Environ(), "LEAGUEBRIDGE_ASSESSMENT_OUTPUT_CHILD=1")
	var output boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		t.Fatal("os/exec stdout bypassed the bounded writer")
	}
	if output.Len() > maximumResponse {
		t.Fatalf("child output exceeded memory bound: %d", output.Len())
	}
	if ctx.Err() != nil {
		t.Fatal("oversized child output was not rejected promptly")
	}
}

func TestArchiveAndSignatureChecksSharePrivatePublishedBytes(t *testing.T) {
	f := newFixture(t)
	original, err := os.ReadFile(filepath.Join(f.input.ReleaseDir, "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	private := ""
	f.deps.archives = func(input releasecheck.CheckRequest) error {
		private = input.Dir
		// Simulate an adversary who owns the caller's source directory switching
		// A/B/A between the independent archive and signature verifiers.
		return os.WriteFile(filepath.Join(f.input.ReleaseDir, "checksums.txt"), []byte("unrelated signed bytes"), 0o600)
	}
	f.deps.signatures = func(ctx context.Context, input ciattestation.VerifyRequest) error {
		if input.Kind != "release" {
			return nil
		}
		if input.ReleaseDir != private || input.ReleaseDir == f.input.ReleaseDir {
			t.Fatal("signature verifier reopened caller-controlled archive inputs")
		}
		checked, err := os.ReadFile(filepath.Join(input.ReleaseDir, "checksums.txt"))
		if err != nil {
			return err
		}
		if !bytes.Equal(checked, original) {
			t.Fatal("signature verifier received different bytes from the semantic checker")
		}
		return os.WriteFile(filepath.Join(f.input.ReleaseDir, "checksums.txt"), original, 0o600)
	}
	if _, err := verify(context.Background(), f.input, f.deps); err != nil {
		t.Fatal(err)
	}
}

func TestMutationOfPrivateCopyCannotSurviveCheckerBoundary(t *testing.T) {
	f := newFixture(t)
	f.deps.archives = func(input releasecheck.CheckRequest) error {
		return os.WriteFile(filepath.Join(input.Dir, "checksums.txt"), []byte("tampered private copy"), 0o600)
	}
	releaseSignatures := 0
	f.deps.signatures = func(ctx context.Context, input ciattestation.VerifyRequest) error {
		if input.Kind == "release" {
			releaseSignatures++
		}
		return nil
	}
	got, err := verify(context.Background(), f.input, f.deps)
	if err == nil || !reflect.DeepEqual(got, Result{}) || releaseSignatures != 0 {
		t.Fatal("changed staged archive reached release signature verification")
	}
}
