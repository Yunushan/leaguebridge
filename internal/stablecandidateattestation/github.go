package stablecandidateattestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"time"
)

const (
	repository       = "Yunushan/leaguebridge"
	workflowPath     = ".github/workflows/stable-native-candidates.yml"
	workflowName     = "Stable native package candidates (score-free)"
	githubOIDCIssuer = "https://token.actions.githubusercontent.com"
	slsaPredicate    = "https://slsa.dev/provenance/v1"
	maximumResponse  = 8 << 20
)

var (
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	objectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

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

func verifySelectedRun(ctx context.Context, ghPath string, selectedID int64, selectedAttempt int) (workflowRun, map[string]job, error) {
	if ghPath == "" || selectedID <= 0 || selectedAttempt <= 0 {
		return workflowRun{}, nil, errors.New("trusted GitHub CLI and selected run attempt are required")
	}
	api := githubAPI(ghPath)
	var definition workflow
	if err := api(ctx, "repos/"+repository+"/actions/workflows/stable-native-candidates.yml", &definition); err != nil {
		return workflowRun{}, nil, fmt.Errorf("read stable candidate workflow identity: %w", err)
	}
	if definition.ID <= 0 || definition.Path != workflowPath || definition.Name != workflowName || definition.State != "active" {
		return workflowRun{}, nil, errors.New("expected active stable candidate workflow is unavailable")
	}
	var run workflowRun
	if err := api(ctx, fmt.Sprintf("repos/%s/actions/runs/%d", repository, selectedID), &run); err != nil {
		return workflowRun{}, nil, fmt.Errorf("read selected stable candidate run: %w", err)
	}
	if run.ID != selectedID || run.Attempt != selectedAttempt || run.WorkflowID != definition.ID ||
		run.Path != workflowPath || run.Event != "workflow_dispatch" || run.Branch != "main" ||
		!objectIDPattern.MatchString(run.Commit) ||
		run.Repository.FullName != repository || run.HeadRepository.FullName != repository ||
		run.Status != "completed" || run.Conclusion != "success" {
		return workflowRun{}, nil, errors.New("selected run is not a successful main workflow_dispatch attempt from the expected repository and workflow")
	}
	var response jobPage
	endpoint := fmt.Sprintf("repos/%s/actions/runs/%d/attempts/%d/jobs?per_page=100&page=1", repository, run.ID, run.Attempt)
	if err := api(ctx, endpoint, &response); err != nil {
		return workflowRun{}, nil, fmt.Errorf("read selected stable candidate jobs: %w", err)
	}
	required := requiredJobs()
	if response.Total != len(required) || len(response.Jobs) != len(required) {
		return workflowRun{}, nil, errors.New("selected run lacks the exact eleven expected jobs")
	}
	seenIDs := make(map[int64]bool, len(required))
	jobs := make(map[string]job, len(required))
	for _, current := range response.Jobs {
		if !required[current.Name] || current.ID <= 0 || seenIDs[current.ID] || jobs[current.Name].ID != 0 ||
			current.RunID != run.ID || (current.Attempt != nil && *current.Attempt != run.Attempt) ||
			current.Commit != run.Commit || current.Status != "completed" || current.Conclusion != "success" {
			return workflowRun{}, nil, fmt.Errorf("stable candidate job %q has an invalid identity or result", current.Name)
		}
		seenIDs[current.ID] = true
		jobs[current.Name] = current
	}
	if len(jobs) != len(required) || !reflect.DeepEqual(requiredJobs(), nameSet(jobs)) {
		return workflowRun{}, nil, errors.New("selected run is missing a required candidate build or aggregate job")
	}
	return run, jobs, nil
}

func requiredJobs() map[string]bool {
	result := map[string]bool{
		"Authenticate release and stage eleven native inputs":     true,
		"Native Linux candidates (amd64)":                         true,
		"Native Linux candidates (arm64)":                         true,
		"Native DragonFly BSD candidate (amd64)":                  true,
		"Verify all eleven release-bound native package payloads": true,
	}
	for _, goos := range []string{"freebsd", "openbsd", "netbsd"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			result["Native BSD candidate ("+goos+"/"+goarch+")"] = true
		}
	}
	return result
}

func nameSet(jobs map[string]job) map[string]bool {
	names := make(map[string]bool, len(jobs))
	for name := range jobs {
		names[name] = true
	}
	return names
}

func githubAPI(ghPath string) apiClient {
	return func(ctx context.Context, endpoint string, destination any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		command := exec.CommandContext(requestCtx, ghPath, "api", "--hostname", "github.com", "--method", "GET",
			"-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10", endpoint)
		command.WaitDelay = 2 * time.Second
		output := &boundedOutput{limit: maximumResponse}
		command.Stdout, command.Stderr = output, io.Discard
		if err := command.Run(); err != nil {
			if requestCtx.Err() != nil {
				return requestCtx.Err()
			}
			return fmt.Errorf("GitHub API request failed: %w", err)
		}
		if output.oversized {
			return errors.New("GitHub API response exceeds its bound")
		}
		decoder := json.NewDecoder(bytes.NewReader(output.bytes()))
		if err := decoder.Decode(destination); err != nil {
			return fmt.Errorf("decode GitHub API response: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return errors.New("GitHub API response has trailing data")
		}
		return nil
	}
}

type ghVerification struct {
	VerificationResult ghVerificationResult `json:"verificationResult"`
}

type ghVerificationResult struct {
	Statement          ghStatement       `json:"statement"`
	Signature          ghSignature       `json:"signature"`
	VerifiedTimestamps []json.RawMessage `json:"verifiedTimestamps"`
}

type ghStatement struct {
	PredicateType string      `json:"predicateType"`
	Subjects      []ghSubject `json:"subject"`
}

type ghSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type ghSignature struct {
	Certificate map[string]json.RawMessage `json:"certificate"`
}

func verifyGitHubAttestation(parent context.Context, ghPath, recordPath string, run workflowRun, subjects map[string]string) error {
	if len(subjects) != 12 {
		return errors.New("exactly twelve expected subjects are required")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, ghPath, "attestation", "verify", recordPath,
		"--repo", repository, "--signer-workflow", repository+"/"+workflowPath,
		"--source-ref", "refs/heads/main", "--source-digest", run.Commit,
		"--cert-oidc-issuer", githubOIDCIssuer, "--deny-self-hosted-runners",
		"--predicate-type", slsaPredicate, "--format", "json")
	command.WaitDelay = 2 * time.Second
	stdout := &boundedOutput{limit: maximumResponse}
	stderr := &boundedOutput{limit: maximumResponse}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if stdout.oversized || stderr.oversized {
			return errors.New("GitHub attestation verifier output exceeds its bound")
		}
		return fmt.Errorf("GitHub attestation verification failed: %w", err)
	}
	if stdout.oversized || stderr.oversized {
		return errors.New("GitHub attestation verifier output exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.bytes()))
	var results []ghVerification
	if err := decoder.Decode(&results); err != nil {
		return fmt.Errorf("decode GitHub attestation result: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("GitHub attestation result has trailing data")
	}
	if len(results) == 0 {
		return errors.New("GitHub returned no verified attestation")
	}
	for _, result := range results {
		if validateAttestation(result, run, subjects) == nil {
			return nil
		}
	}
	return errors.New("no GitHub attestation matches the selected run and exact twelve-subject inventory")
}

func validateAttestation(value ghVerification, run workflowRun, expected map[string]string) error {
	result := value.VerificationResult
	if result.Statement.PredicateType != slsaPredicate || len(result.VerifiedTimestamps) == 0 {
		return errors.New("SLSA provenance or verified timestamp is missing")
	}
	if err := validateCertificate(result.Signature.Certificate, run); err != nil {
		return err
	}
	if len(result.Statement.Subjects) != len(expected) {
		return errors.New("signed statement does not contain exactly twelve subjects")
	}
	seen := make(map[string]bool, len(expected))
	for _, subject := range result.Statement.Subjects {
		want, ok := expected[subject.Name]
		if !ok || seen[subject.Name] || len(subject.Digest) != 1 || subject.Digest["sha256"] != want {
			return fmt.Errorf("signed subject %q differs from the exact local inventory", subject.Name)
		}
		seen[subject.Name] = true
	}
	return nil
}

func validateCertificate(certificate map[string]json.RawMessage, run workflowRun) error {
	if len(certificate) == 0 {
		return errors.New("verified signing certificate is missing")
	}
	repositoryURI := "https://github.com/" + repository
	workflowRef := repository + "/" + workflowPath + "@refs/heads/main"
	workflowURI := "https://github.com/" + workflowRef
	runURI := repositoryURI + "/actions/runs/" + strconv.FormatInt(run.ID, 10) +
		"/attempts/" + strconv.Itoa(run.Attempt)
	want := map[string]string{
		"issuer": githubOIDCIssuer, "subjectAlternativeName": workflowURI,
		"githubWorkflowRepository": repository, "githubWorkflowRef": "refs/heads/main",
		"githubWorkflowSHA": run.Commit, "buildSignerURI": workflowURI,
		"buildSignerDigest": run.Commit, "buildConfigURI": workflowURI,
		"buildConfigDigest": run.Commit, "runnerEnvironment": "github-hosted",
		"sourceRepositoryURI": repositoryURI, "sourceRepositoryDigest": run.Commit,
		"sourceRepositoryRef": "refs/heads/main", "runInvocationURI": runURI,
	}
	for name, expected := range want {
		var actual string
		if err := json.Unmarshal(certificate[name], &actual); err != nil || actual != expected {
			return fmt.Errorf("verified certificate field %q differs from the selected run", name)
		}
	}
	return nil
}

// Do not expose ReaderFrom: subprocess copies must pass through Write.
type boundedOutput struct {
	buffer    bytes.Buffer
	limit     int
	oversized bool
}

func (output *boundedOutput) bytes() []byte { return output.buffer.Bytes() }

func (output *boundedOutput) Write(data []byte) (int, error) {
	if output.limit < 0 || len(data) > output.limit-output.buffer.Len() {
		output.oversized = true
		return 0, errors.New("bounded subprocess output exceeded")
	}
	return output.buffer.Write(data)
}
