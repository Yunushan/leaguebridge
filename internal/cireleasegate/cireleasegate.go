// Package cireleasegate requires a complete successful CI attempt on main for
// the exact release commit. GitHub job state is read live; cached artifacts or
// pull-request checks cannot stand in for the privileged post-merge CI gates.
package cireleasegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"time"

	"github.com/Yunushan/leaguebridge/internal/target"
)

const (
	repository      = "Yunushan/leaguebridge"
	workflowPath    = ".github/workflows/ci.yml"
	pageSize        = 100
	maximumEntries  = 1000
	maximumResponse = 8 << 20
)

var commitPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

type workflow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

type repoIdentity struct {
	FullName string `json:"full_name"`
}

type workflowRun struct {
	ID             int64        `json:"id"`
	Attempt        int          `json:"run_attempt"`
	WorkflowID     int64        `json:"workflow_id"`
	Path           string       `json:"path"`
	Event          string       `json:"event"`
	Branch         string       `json:"head_branch"`
	Commit         string       `json:"head_sha"`
	Status         string       `json:"status"`
	Conclusion     string       `json:"conclusion"`
	Repository     repoIdentity `json:"repository"`
	HeadRepository repoIdentity `json:"head_repository"`
}

type runPage struct {
	Total int           `json:"total_count"`
	Runs  []workflowRun `json:"workflow_runs"`
}

type job struct {
	ID         int64  `json:"id"`
	RunID      int64  `json:"run_id"`
	Attempt    *int   `json:"run_attempt"`
	Commit     string `json:"head_sha"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

type jobPage struct {
	Total int   `json:"total_count"`
	Jobs  []job `json:"jobs"`
}

type apiClient func(context.Context, string, any) error

// VerifyRequest selects the exact source commit to check and the trusted GitHub
// CLI executable. Repository, branch, workflow, and required jobs are fixed by
// this package, not supplied by the caller.
type VerifyRequest struct {
	Commit string
	GHPath string
}

// RunIdentity identifies the complete successful CI attempt observed by Verify.
// It is not a readiness receipt, artifact signature, or proof of publication.
type RunIdentity struct {
	ID      int64
	Attempt int
	Commit  string
}

// Verify checks the latest eligible exact-commit main CI attempt through the
// trusted GitHub CLI. It requires every observed and required job to succeed and
// rereads run state before returning. It applies a two-minute timeout, bounded
// further by the caller's context. The result is a live-state
// observation; callers must verify again before a later publication decision.
func Verify(ctx context.Context, input VerifyRequest) (RunIdentity, error) {
	if input.GHPath == "" {
		return RunIdentity{}, errors.New("trusted GitHub CLI executable is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	run, err := verify(ctx, githubAPI(input.GHPath), input.Commit)
	if err != nil {
		return RunIdentity{}, err
	}
	return RunIdentity{ID: run.ID, Attempt: run.Attempt, Commit: run.Commit}, nil
}

func verify(ctx context.Context, api apiClient, commit string) (workflowRun, error) {
	if !commitPattern.MatchString(commit) {
		return workflowRun{}, errors.New("release commit must be a complete lowercase SHA")
	}
	var definition workflow
	if err := api(ctx, "repos/"+repository+"/actions/workflows/ci.yml", &definition); err != nil {
		return workflowRun{}, fmt.Errorf("read CI workflow identity: %w", err)
	}
	if definition.ID <= 0 || definition.Path != workflowPath || definition.Name != "CI" || definition.State != "active" {
		return workflowRun{}, errors.New("expected active CI workflow is unavailable")
	}
	run, err := latestRun(ctx, api, definition.ID, commit)
	if err != nil {
		return workflowRun{}, err
	}
	if run.Status != "completed" || run.Conclusion != "success" {
		return workflowRun{}, fmt.Errorf("latest exact-commit CI run %d attempt %d is %s/%s; complete a successful full CI attempt before release", run.ID, run.Attempt, run.Status, run.Conclusion)
	}
	jobs, err := loadJobs(ctx, api, run)
	if err != nil {
		return workflowRun{}, err
	}
	if err := verifyJobs(run, jobs); err != nil {
		return workflowRun{}, err
	}
	// A failed-job rerun or a newer workflow run must not replace the verified
	// attempt while its pages are being checked. Callers run this gate directly
	// before publication; the separate protected-tag gate binds the tag itself.
	current, err := latestRun(ctx, api, definition.ID, commit)
	if err != nil {
		return workflowRun{}, err
	}
	if current != run {
		return workflowRun{}, errors.New("CI run state changed during release verification; retry against the latest complete attempt")
	}
	return run, nil
}

func latestRun(ctx context.Context, api apiClient, workflowID int64, commit string) (workflowRun, error) {
	var latest workflowRun
	seen := make(map[int64]bool)
	total := -1
	count := 0
	for page := 1; page <= maximumEntries/pageSize; page++ {
		var response runPage
		endpoint := fmt.Sprintf("repos/%s/actions/workflows/%d/runs?head_sha=%s&branch=main&per_page=%d&page=%d", repository, workflowID, commit, pageSize, page)
		if err := api(ctx, endpoint, &response); err != nil {
			return workflowRun{}, fmt.Errorf("read CI runs: %w", err)
		}
		if response.Total < 0 || response.Total > maximumEntries || len(response.Runs) > pageSize || (total >= 0 && total != response.Total) {
			return workflowRun{}, errors.New("CI run pagination is incomplete, changed, or exceeds its bound")
		}
		total = response.Total
		count += len(response.Runs)
		if count > total || (len(response.Runs) == 0 && count != total) {
			return workflowRun{}, errors.New("CI run page does not match its declared total")
		}
		for _, candidate := range response.Runs {
			if candidate.ID <= 0 || candidate.Attempt <= 0 || seen[candidate.ID] {
				return workflowRun{}, errors.New("CI run identity is invalid or duplicated")
			}
			seen[candidate.ID] = true
			if candidate.WorkflowID != workflowID || candidate.Path != workflowPath || candidate.Commit != commit || candidate.Branch != "main" || candidate.Repository.FullName != repository || candidate.HeadRepository.FullName != repository {
				return workflowRun{}, errors.New("CI run source does not match the release repository, workflow, branch, and commit")
			}
			if candidate.Event != "push" && candidate.Event != "workflow_dispatch" {
				continue
			}
			if candidate.ID > latest.ID {
				latest = candidate
			}
		}
		if count == total {
			break
		}
	}
	if count != total || latest.ID == 0 {
		return workflowRun{}, errors.New("no complete post-merge CI run inventory for this commit on main")
	}
	return latest, nil
}

func loadJobs(ctx context.Context, api apiClient, run workflowRun) ([]job, error) {
	var result []job
	total := -1
	for page := 1; page <= maximumEntries/pageSize; page++ {
		var response jobPage
		endpoint := fmt.Sprintf("repos/%s/actions/runs/%d/attempts/%d/jobs?per_page=%d&page=%d", repository, run.ID, run.Attempt, pageSize, page)
		if err := api(ctx, endpoint, &response); err != nil {
			return nil, fmt.Errorf("read CI attempt jobs: %w", err)
		}
		if response.Total <= 0 || response.Total > maximumEntries || len(response.Jobs) > pageSize || (total >= 0 && total != response.Total) {
			return nil, errors.New("CI job pagination is empty, changed, or exceeds its bound")
		}
		total = response.Total
		result = append(result, response.Jobs...)
		if len(result) > total || (len(response.Jobs) == 0 && len(result) != total) {
			return nil, errors.New("CI job page does not match its declared total")
		}
		if len(result) == total {
			return result, nil
		}
	}
	return nil, errors.New("CI jobs exceed the complete-inventory limit")
}

func verifyJobs(run workflowRun, jobs []job) error {
	names := make(map[string]bool)
	ids := make(map[int64]bool)
	for _, item := range jobs {
		if item.ID <= 0 || ids[item.ID] || item.Name == "" || names[item.Name] {
			return errors.New("CI job identity or name is empty or duplicated")
		}
		// The authenticated attempt-specific endpoint supplies the attempt
		// binding. GitHub documents run_attempt as optional on individual jobs;
		// when supplied it must agree with the requested attempt.
		if item.RunID != run.ID || (item.Attempt != nil && *item.Attempt != run.Attempt) || item.Commit != run.Commit {
			return fmt.Errorf("CI job %q is not bound to the selected commit and run attempt", item.Name)
		}
		if item.Status != "completed" || item.Conclusion != "success" {
			return fmt.Errorf("CI job %q is %s/%s; skipped and failed checks cannot authorize release", item.Name, item.Status, item.Conclusion)
		}
		ids[item.ID], names[item.Name] = true, true
	}
	for _, required := range requiredJobs() {
		if !names[required] {
			return fmt.Errorf("required CI job %q is missing; run a complete CI attempt", required)
		}
	}
	return nil
}

// These job names are the release acceptance contract, not a caller-supplied
// allowlist. Updating the target or guest matrix also requires reviewing it.
func requiredJobs() []string {
	result := []string{
		"Test (ubuntu-24.04)", "Minimum Go compatibility", "Coverage",
		"Reachable vulnerability scan", "Reproducible release smoke test",
		"Native packages (Linux)", "Attest Linux race/vet subject",
		"Verify signed CI attestations", "Verify signed native runtime attestations",
		"Verify signed native package attestations",
	}
	labels := map[string]string{"freebsd": "FreeBSD 15.1", "openbsd": "OpenBSD 7.9", "netbsd": "NetBSD 11.0", "dragonfly": "DragonFly BSD 6.4.2"}
	for _, candidate := range target.Ordered() {
		cell := candidate.GOOS + "/" + candidate.GOARCH
		result = append(result, "Build ("+cell+")", "Attest "+cell+" cross-build subject")
		if candidate.GOOS == "linux" {
			result = append(result, "Hosted Linux runtime ("+candidate.GOARCH+")", "Attest hosted Linux runtime ("+candidate.GOARCH+")")
			continue
		}
		label := labels[candidate.GOOS]
		result = append(result, "BSD kernel runtime ("+label+" "+candidate.GOARCH+")", "Attest BSD runtime ("+cell+")")
		if candidate.GOOS != "dragonfly" {
			label += " " + candidate.GOARCH
		}
		result = append(result, "Native package ("+label+")")
	}
	return result
}

func githubAPI(gh string) apiClient {
	return func(ctx context.Context, endpoint string, result any) error {
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(requestCtx, gh, "api", "--hostname", "github.com", "--method", "GET", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10", endpoint)
		cmd.WaitDelay = 2 * time.Second
		output := &boundedOutput{limit: maximumResponse}
		cmd.Stdout = output
		// API diagnostics can contain authentication context. Report the command
		// error without echoing arbitrary stderr into release logs.
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("GitHub API request failed: %w", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
		if err := decoder.Decode(result); err != nil {
			return fmt.Errorf("decode GitHub response: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("GitHub response has trailing data")
		}
		return nil
	}
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

// Expose only the operations that preserve Write's subprocess-output bound.
// In particular, do not promote bytes.Buffer.ReadFrom through embedding.
func (b *boundedOutput) Len() int       { return b.buffer.Len() }
func (b *boundedOutput) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedOutput) String() string { return b.buffer.String() }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.Len() {
		return 0, errors.New("GitHub response exceeds its size limit")
	}
	return b.buffer.Write(data)
}
