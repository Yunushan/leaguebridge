package cireleasegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

type fakeGitHub struct {
	definition workflow
	runs       []workflowRun
	jobs       []job
	runReads   int
	changeRuns func(int)
	changePage func(string, any)
}

func passingGitHub() *fakeGitHub {
	run := workflowRun{ID: 200, Attempt: 1, WorkflowID: 100, Path: workflowPath, Event: "push", Branch: "main", Commit: testCommit, Status: "completed", Conclusion: "success", Repository: repoIdentity{repository}, HeadRepository: repoIdentity{repository}}
	fake := &fakeGitHub{definition: workflow{100, "CI", workflowPath, "active"}, runs: []workflowRun{run}}
	for index, name := range requiredJobs() {
		attempt := run.Attempt
		fake.jobs = append(fake.jobs, job{ID: int64(1000 + index), RunID: run.ID, Attempt: &attempt, Commit: testCommit, Name: name, Status: "completed", Conclusion: "success"})
	}
	return fake
}

func (f *fakeGitHub) api(ctx context.Context, endpoint string, destination any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if endpoint == "repos/"+repository+"/actions/workflows/ci.yml" {
		*destination.(*workflow) = f.definition
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	page, err := strconv.Atoi(u.Query().Get("page"))
	if err != nil || page <= 0 || u.Query().Get("per_page") != "100" {
		return errors.New("unexpected pagination request")
	}
	start := (page - 1) * pageSize
	if strings.HasSuffix(u.Path, "/runs") {
		if u.Query().Get("head_sha") != testCommit || u.Query().Get("branch") != "main" {
			return errors.New("request is not scoped to exact-commit main CI")
		}
		f.runReads++
		if f.changeRuns != nil {
			f.changeRuns(f.runReads)
		}
		end := min(start+pageSize, len(f.runs))
		if start > end {
			start = end
		}
		*destination.(*runPage) = runPage{Total: len(f.runs), Runs: append([]workflowRun(nil), f.runs[start:end]...)}
	} else if strings.HasSuffix(u.Path, "/jobs") {
		if !strings.Contains(u.Path, "/attempts/1/jobs") {
			return errors.New("job query is not bound to expected attempt")
		}
		end := min(start+pageSize, len(f.jobs))
		if start > end {
			start = end
		}
		*destination.(*jobPage) = jobPage{Total: len(f.jobs), Jobs: append([]job(nil), f.jobs[start:end]...)}
	} else {
		return fmt.Errorf("unexpected API endpoint %s", endpoint)
	}
	if f.changePage != nil {
		f.changePage(endpoint, destination)
	}
	return nil
}

func TestFullSuccessfulCommitAndAttemptPass(t *testing.T) {
	fake := passingGitHub()
	got, err := verify(context.Background(), fake.api, testCommit)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 200 || got.Attempt != 1 || fake.runReads != 2 {
		t.Fatalf("verification did not recheck selected run: %+v, reads=%d", got, fake.runReads)
	}
}

func TestEveryRequiredJobMustActuallySucceed(t *testing.T) {
	for _, name := range requiredJobs() {
		for _, state := range []string{"missing", "skipped", "failure", "cancelled", "neutral", "in_progress"} {
			t.Run(name+"/"+state, func(t *testing.T) {
				fake := passingGitHub()
				for i := range fake.jobs {
					if fake.jobs[i].Name != name {
						continue
					}
					if state == "missing" {
						fake.jobs = append(fake.jobs[:i], fake.jobs[i+1:]...)
					} else if state == "in_progress" {
						fake.jobs[i].Status = state
					} else {
						fake.jobs[i].Conclusion = state
					}
					break
				}
				if _, err := verify(context.Background(), fake.api, testCommit); err == nil {
					t.Fatal("incomplete required check authorized a release")
				}
			})
		}
	}
}

func TestRunSourceAndStateAreRequired(t *testing.T) {
	cases := map[string]func(*fakeGitHub){
		"wrong source repository": func(f *fakeGitHub) { f.runs[0].Repository.FullName = "other/project" },
		"fork":                    func(f *fakeGitHub) { f.runs[0].HeadRepository.FullName = "other/leaguebridge" },
		"wrong commit":            func(f *fakeGitHub) { f.runs[0].Commit = strings.Repeat("f", 40) },
		"non-main":                func(f *fakeGitHub) { f.runs[0].Branch = "feature" },
		"PR":                      func(f *fakeGitHub) { f.runs[0].Event = "pull_request" },
		"PR target":               func(f *fakeGitHub) { f.runs[0].Event = "pull_request_target" },
		"workflow mismatch":       func(f *fakeGitHub) { f.runs[0].WorkflowID = 999 },
		"workflow path":           func(f *fakeGitHub) { f.runs[0].Path = ".github/workflows/other.yml" },
		"inactive workflow":       func(f *fakeGitHub) { f.definition.State = "disabled_manually" },
		"renamed workflow":        func(f *fakeGitHub) { f.definition.Name = "Other" },
		"incomplete":              func(f *fakeGitHub) { f.runs[0].Status = "in_progress" },
		"failed":                  func(f *fakeGitHub) { f.runs[0].Conclusion = "failure" },
		"no attempt":              func(f *fakeGitHub) { f.runs[0].Attempt = 0 },
		"no run":                  func(f *fakeGitHub) { f.runs = nil },
		"duplicate run":           func(f *fakeGitHub) { f.runs = append(f.runs, f.runs[0]) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fake := passingGitHub()
			change(fake)
			if _, err := verify(context.Background(), fake.api, testCommit); err == nil {
				t.Fatal("invalid source or run authorized release")
			}
		})
	}
}

func TestNewestFailureOrPendingRunCannotBorrowOlderSuccess(t *testing.T) {
	for _, status := range []string{"queued", "in_progress", "completed"} {
		t.Run(status, func(t *testing.T) {
			fake := passingGitHub()
			newer := fake.runs[0]
			newer.ID++
			newer.Status = status
			newer.Conclusion = "failure"
			fake.runs = append(fake.runs, newer)
			if _, err := verify(context.Background(), fake.api, testCommit); err == nil {
				t.Fatal("selected old successful run despite newer unapproved run")
			}
		})
	}
}

func TestRunChangesDuringJobInspectionFailClosed(t *testing.T) {
	for _, state := range []string{"rerun", "new run", "status"} {
		t.Run(state, func(t *testing.T) {
			fake := passingGitHub()
			fake.changeRuns = func(read int) {
				if read != 2 {
					return
				}
				switch state {
				case "rerun":
					fake.runs[0].Attempt++
				case "new run":
					fake.runs[0].ID++
				case "status":
					fake.runs[0].Conclusion = "failure"
				}
			}
			if _, err := verify(context.Background(), fake.api, testCommit); err == nil {
				t.Fatal("changed run authorized a release")
			}
		})
	}
}

func TestJobsCannotBorrowAnotherRunCommitOrAttempt(t *testing.T) {
	cases := map[string]func(*fakeGitHub){
		"run":            func(f *fakeGitHub) { f.jobs[0].RunID++ },
		"attempt":        func(f *fakeGitHub) { *f.jobs[0].Attempt++ },
		"zero attempt":   func(f *fakeGitHub) { *f.jobs[0].Attempt = 0 },
		"commit":         func(f *fakeGitHub) { f.jobs[0].Commit = strings.Repeat("f", 40) },
		"duplicate id":   func(f *fakeGitHub) { f.jobs[1].ID = f.jobs[0].ID },
		"duplicate name": func(f *fakeGitHub) { f.jobs[1].Name = f.jobs[0].Name },
		"empty name":     func(f *fakeGitHub) { f.jobs[0].Name = "" },
		"extra failed job": func(f *fakeGitHub) {
			j := f.jobs[0]
			j.ID = 99999
			j.Name = "Additional failed check"
			j.Conclusion = "failure"
			f.jobs = append(f.jobs, j)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := passingGitHub()
			change(f)
			if _, err := verify(context.Background(), f.api, testCommit); err == nil {
				t.Fatal("unbound job authorized release")
			}
		})
	}
}

func TestCompletePaginationAndFinalPageFailures(t *testing.T) {
	fake := passingGitHub()
	for len(fake.jobs) < pageSize+3 {
		j := fake.jobs[0]
		j.ID = int64(10000 + len(fake.jobs))
		j.Name = fmt.Sprintf("Additional check %d", len(fake.jobs))
		fake.jobs = append(fake.jobs, j)
	}
	if _, err := verify(context.Background(), fake.api, testCommit); err != nil {
		t.Fatal(err)
	}
	fake.jobs[len(fake.jobs)-1].Conclusion = "failure"
	if _, err := verify(context.Background(), fake.api, testCommit); err == nil {
		t.Fatal("failure on second jobs page was ignored")
	}
}

func TestNewestRunOnLaterPageIsNotIgnored(t *testing.T) {
	fake := passingGitHub()
	for len(fake.runs) < pageSize+1 {
		r := fake.runs[0]
		r.ID += int64(len(fake.runs))
		fake.runs = append(fake.runs, r)
	}
	fake.runs[len(fake.runs)-1].Conclusion = "failure"
	if _, err := verify(context.Background(), fake.api, testCommit); err == nil {
		t.Fatal("newer failed run on second page was ignored")
	}
}

func TestTruncatedChangedAndOversizedInventoriesFail(t *testing.T) {
	for _, inventory := range []string{"runs", "jobs"} {
		for _, mode := range []string{"truncated", "oversized", "negative", "extra"} {
			t.Run(inventory+"/"+mode, func(t *testing.T) {
				fake := passingGitHub()
				fake.changePage = func(_ string, raw any) {
					var total *int
					switch page := raw.(type) {
					case *runPage:
						if inventory != "runs" {
							return
						}
						total = &page.Total
					case *jobPage:
						if inventory != "jobs" {
							return
						}
						total = &page.Total
					default:
						return
					}
					switch mode {
					case "truncated":
						*total += 100
					case "oversized":
						*total = maximumEntries + 1
					case "negative":
						*total = -1
					case "extra":
						*total = 0
					}
				}
				if _, err := verify(context.Background(), fake.api, testCommit); err == nil {
					t.Fatal("invalid pagination authorized release")
				}
			})
		}
	}
}

func TestInvalidCommitRejectedBeforeAPI(t *testing.T) {
	for _, commit := range []string{"", "main", "123", strings.Repeat("A", 40), testCommit + "&status=success"} {
		_, err := verify(context.Background(), func(context.Context, string, any) error { t.Fatal("API called for invalid commit"); return nil }, commit)
		if err == nil {
			t.Fatalf("accepted invalid commit %q", commit)
		}
	}
}

func TestAPIErrorsAndCancellationCannotPass(t *testing.T) {
	if _, err := verify(context.Background(), func(context.Context, string, any) error { return errors.New("denied") }, testCommit); err == nil {
		t.Fatal("API failure was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verify(ctx, passingGitHub().api, testCommit); err == nil {
		t.Fatal("cancellation was accepted")
	}
}

func TestBoundedOutputDoesNotRetainExcessResponse(t *testing.T) {
	b := &boundedOutput{limit: 8}
	if _, err := b.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("56789")); err == nil {
		t.Fatal("accepted oversized response")
	}
	if b.String() != "1234" {
		t.Fatal("retained excess data")
	}
}

func TestJobInventoryMatchesObservedWorkflowShape(t *testing.T) {
	// An API response can carry additional GitHub fields; forward-compatible
	// decoding must still preserve the identity fields needed for authorization.
	var value job
	if err := json.Unmarshal([]byte(`{"id":1,"run_id":2,"run_attempt":3,"head_sha":"abc","name":"check","status":"completed","conclusion":"success","runner_id":9}`), &value); err != nil {
		t.Fatal(err)
	}
	if value.RunID != 2 || value.Attempt == nil || *value.Attempt != 3 || value.Commit != "abc" {
		t.Fatal("lost source identity")
	}
}

func TestOptionalJobAttemptCanBeAbsentOnAttemptSpecificEndpoint(t *testing.T) {
	fake := passingGitHub()
	for index := range fake.jobs {
		encoded, err := json.Marshal(fake.jobs[index])
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, "run_attempt")
		encoded, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		fake.jobs[index] = job{}
		if err := json.Unmarshal(encoded, &fake.jobs[index]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verify(context.Background(), fake.api, testCommit); err != nil {
		t.Fatalf("documented optional job field prevented release: %v", err)
	}
}

// The public entry point must exercise the real executable boundary, not an
// exported callback that could return caller-authored GitHub responses.
func TestMain(m *testing.M) {
	if os.Getenv("LEAGUEBRIDGE_CI_GATE_TEST_GH") == "1" {
		os.Exit(runGitHubProcessFixture())
	}
	os.Exit(m.Run())
}

func runGitHubProcessFixture() int {
	prefix := []string{"api", "--hostname", "github.com", "--method", "GET", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10"}
	arguments := os.Args[1:]
	if len(arguments) != len(prefix)+1 || strings.Join(arguments[:len(prefix)], "\x00") != strings.Join(prefix, "\x00") {
		return 31
	}
	endpoint := arguments[len(prefix)]
	root := os.Getenv("LEAGUEBRIDGE_CI_GATE_TEST_FIXTURES")
	log, err := os.OpenFile(filepath.Join(root, "requests.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return 32
	}
	_, writeErr := fmt.Fprintln(log, endpoint)
	closeErr := log.Close()
	if writeErr != nil || closeErr != nil {
		return 33
	}
	if os.Getenv("LEAGUEBRIDGE_CI_GATE_TEST_DENY") == "1" {
		fmt.Fprintln(os.Stderr, "fixture sensitive authentication diagnostic")
		return 17
	}
	var file string
	switch endpoint {
	case "repos/" + repository + "/actions/workflows/ci.yml":
		file = "workflow.json"
	case "repos/" + repository + "/actions/workflows/100/runs?head_sha=" + testCommit + "&branch=main&per_page=100&page=1":
		file = "runs.json"
	case "repos/" + repository + "/actions/runs/200/attempts/1/jobs?per_page=100&page=1":
		file = "jobs.json"
	default:
		return 34
	}
	data, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		return 35
	}
	if _, err := os.Stdout.Write(data); err != nil {
		return 36
	}
	return 0
}

func TestVerifyUsesTrustedGitHubExecutable(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fake := passingGitHub()
	for name, value := range map[string]any{
		"workflow.json": fake.definition,
		"runs.json":     runPage{Total: len(fake.runs), Runs: fake.runs},
		"jobs.json":     jobPage{Total: len(fake.jobs), Jobs: fake.jobs},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LEAGUEBRIDGE_CI_GATE_TEST_GH", "1")
	t.Setenv("LEAGUEBRIDGE_CI_GATE_TEST_FIXTURES", root)
	t.Setenv("LEAGUEBRIDGE_CI_GATE_TEST_DENY", "0")
	input := VerifyRequest{Commit: testCommit, GHPath: executable}
	got, err := Verify(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	want := RunIdentity{ID: 200, Attempt: 1, Commit: testCommit}
	if got != want {
		t.Fatalf("run identity = %+v; want %+v", got, want)
	}
	data, err := os.ReadFile(filepath.Join(root, "requests.log"))
	if err != nil {
		t.Fatal(err)
	}
	requests := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(requests) != 4 || requests[1] != requests[3] {
		t.Fatalf("public verification did not reread the run after checking jobs: %q", requests)
	}

	t.Setenv("LEAGUEBRIDGE_CI_GATE_TEST_DENY", "1")
	got, err = Verify(context.Background(), input)
	if got != (RunIdentity{}) || err == nil || !strings.Contains(err.Error(), "GitHub API request failed") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("failed executable must return zero identity and redact diagnostics: %+v, %v", got, err)
	}
	got, err = Verify(context.Background(), VerifyRequest{Commit: testCommit})
	if got != (RunIdentity{}) || err == nil || err.Error() != "trusted GitHub CLI executable is required" {
		t.Fatalf("missing executable must fail closed: %+v, %v", got, err)
	}
}
