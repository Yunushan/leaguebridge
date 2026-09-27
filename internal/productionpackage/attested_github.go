package productionpackage

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type stableCandidateRun struct {
	id, workflowID int64
	attempt        int
	commit         string
	workflowBlob   string
}

type stableWorkflowResponse struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
}

type stableRunResponse struct {
	ID         int64  `json:"id"`
	Attempt    int    `json:"run_attempt"`
	WorkflowID int64  `json:"workflow_id"`
	Path       string `json:"path"`
	Event      string `json:"event"`
	Branch     string `json:"head_branch"`
	Commit     string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	HeadRepository struct {
		FullName string `json:"full_name"`
	} `json:"head_repository"`
}

func readStableCandidateRun(ctx context.Context, ghPath string, runID int64, attempt int) (stableCandidateRun, error) {
	return readStableCandidateRunWithAPI(ctx, candidateGitHubAPI(ghPath), runID, attempt)
}

type candidateGitHubAPIClient func(context.Context, string, any) error

func candidateGitHubAPI(ghPath string) candidateGitHubAPIClient {
	return func(ctx context.Context, endpoint string, value any) error {
		data, err := runBoundedGitHub(ctx, ghPath, 2*time.Minute, "api",
			"--hostname", "github.com", "--method", "GET",
			"-H", "Accept: application/vnd.github+json",
			"-H", "X-GitHub-Api-Version: 2026-03-10", endpoint)
		if err != nil {
			return err
		}
		return decodeOneJSON(data, value)
	}
}

func readStableCandidateRunWithAPI(ctx context.Context, api candidateGitHubAPIClient, runID int64, attempt int) (stableCandidateRun, error) {
	if runID <= 0 || attempt <= 0 {
		return stableCandidateRun{}, errors.New("stable candidate run ID and attempt must be positive")
	}
	if ctx == nil || api == nil {
		return stableCandidateRun{}, errors.New("GitHub API and context are required")
	}
	var workflow stableWorkflowResponse
	if err := api(ctx, "repos/"+stableCandidateRepository+"/actions/workflows/stable-native-candidates.yml", &workflow); err != nil || workflow.ID <= 0 || workflow.Path != stableCandidateWorkflow {
		return stableCandidateRun{}, errors.New("GitHub stable candidate workflow identity is invalid")
	}
	base := "repos/" + stableCandidateRepository + "/actions/runs/" + strconv.FormatInt(runID, 10)
	var latest stableRunResponse
	if err := api(ctx, base, &latest); err != nil || latest.ID != runID || latest.Attempt != attempt {
		return stableCandidateRun{}, errors.New("selected stable candidate run is not the latest attempt")
	}
	var run stableRunResponse
	if err := api(ctx, base+"/attempts/"+strconv.Itoa(attempt), &run); err != nil {
		return stableCandidateRun{}, fmt.Errorf("read selected stable candidate run attempt: %w", err)
	}
	if run.ID != runID || run.Attempt != attempt || run.WorkflowID != workflow.ID || run.Path != stableCandidateWorkflow ||
		run.Event != "workflow_dispatch" || run.Branch != "main" || !objectIDPattern.MatchString(run.Commit) ||
		run.Status != "completed" || run.Conclusion != "success" ||
		run.Repository.FullName != stableCandidateRepository || run.HeadRepository.FullName != stableCandidateRepository {
		return stableCandidateRun{}, errors.New("GitHub stable candidate run does not match the successful main workflow contract")
	}
	if latest.WorkflowID != run.WorkflowID || latest.Path != run.Path || latest.Event != run.Event ||
		latest.Branch != run.Branch || latest.Commit != run.Commit || latest.Status != run.Status ||
		latest.Conclusion != run.Conclusion || latest.Repository.FullName != run.Repository.FullName ||
		latest.HeadRepository.FullName != run.HeadRepository.FullName {
		return stableCandidateRun{}, errors.New("latest stable candidate run and selected attempt disagree")
	}
	blob, err := verifyStableCandidateWorkflowSource(ctx, api, run.Commit)
	if err != nil {
		return stableCandidateRun{}, fmt.Errorf("authenticate stable candidate workflow source: %w", err)
	}
	return stableCandidateRun{id: run.ID, attempt: run.Attempt, workflowID: run.WorkflowID, commit: run.Commit, workflowBlob: blob}, nil
}

type candidateGitObject struct {
	SHA string `json:"sha"`
}

type candidateGitCommit struct {
	SHA  string             `json:"sha"`
	Tree candidateGitObject `json:"tree"`
}

type candidateGitEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type candidateGitTree struct {
	SHA       string              `json:"sha"`
	Truncated *bool               `json:"truncated"`
	Entries   []candidateGitEntry `json:"tree"`
}

type candidateGitBlob struct {
	SHA      string `json:"sha"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
	Content  string `json:"content"`
}

func verifyStableCandidateWorkflowSource(ctx context.Context, api candidateGitHubAPIClient, commit string) (string, error) {
	if !objectIDPattern.MatchString(commit) {
		return "", errors.New("candidate run source commit is invalid")
	}
	var object candidateGitCommit
	if err := api(ctx, "repos/"+stableCandidateRepository+"/git/commits/"+commit, &object); err != nil {
		return "", err
	}
	if object.SHA != commit || !objectIDPattern.MatchString(object.Tree.SHA) || len(object.Tree.SHA) != len(commit) {
		return "", errors.New("candidate run source tree is invalid")
	}
	current := object.Tree.SHA
	for index, component := range []string{".github", "workflows", "stable-native-candidates.yml"} {
		var tree candidateGitTree
		if err := api(ctx, "repos/"+stableCandidateRepository+"/git/trees/"+current, &tree); err != nil {
			return "", err
		}
		if tree.SHA != current || tree.Truncated == nil || *tree.Truncated || len(tree.Entries) == 0 || len(tree.Entries) > maximumGitTreeEntries {
			return "", errors.New("candidate workflow Git tree is invalid, truncated, or oversized")
		}
		seen := make(map[string]bool, len(tree.Entries))
		var selected candidateGitEntry
		for _, entry := range tree.Entries {
			if entry.Path == "" || seen[entry.Path] {
				return "", errors.New("candidate workflow Git tree contains ambiguous entries")
			}
			seen[entry.Path] = true
			if entry.Path == component {
				selected = entry
			}
		}
		if !objectIDPattern.MatchString(selected.SHA) || len(selected.SHA) != len(commit) {
			return "", errors.New("candidate workflow path has no valid Git object")
		}
		if index < 2 {
			if selected.Type != "tree" || selected.Mode != "040000" {
				return "", errors.New("candidate workflow parent is not a Git directory")
			}
		} else if selected.Type != "blob" || (selected.Mode != "100644" && selected.Mode != "100755") {
			return "", errors.New("candidate workflow is not a regular Git file")
		}
		current = selected.SHA
	}
	var blob candidateGitBlob
	if err := api(ctx, "repos/"+stableCandidateRepository+"/git/blobs/"+current, &blob); err != nil {
		return "", err
	}
	if blob.SHA != current || blob.Encoding != "base64" || blob.Size <= 0 || blob.Size > maximumWorkflowBlob || len(blob.Content) > int(2*maximumWorkflowBlob) {
		return "", errors.New("candidate workflow Git blob is invalid or oversized")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(blob.Content)
	if err != nil || int64(len(data)) != blob.Size {
		return "", errors.New("candidate workflow Git blob content does not match its metadata")
	}
	var objectHash hash.Hash = sha1.New() // Git object identity; reviewed policy uses SHA-256 below.
	if len(current) == 64 {
		objectHash = sha256.New()
	}
	fmt.Fprintf(objectHash, "blob %d\x00", len(data))
	objectHash.Write(data)
	if hex.EncodeToString(objectHash.Sum(nil)) != current {
		return "", errors.New("candidate workflow bytes do not match the Git blob object")
	}
	approved := sha256.Sum256(data)
	if hex.EncodeToString(approved[:]) != stableCandidateWorkflowSHA256 {
		return "", errors.New("candidate workflow content is not the reviewed stable candidate contract")
	}
	return current, nil
}

func verifyStableCandidateStatement(ctx context.Context, ghPath, recordPath string, run stableCandidateRun) ([]byte, error) {
	return runBoundedGitHub(ctx, ghPath, 5*time.Minute,
		"attestation", "verify", recordPath,
		"--hostname", "github.com",
		"--repo", stableCandidateRepository,
		"--signer-workflow", stableCandidateRepository+"/"+stableCandidateWorkflow,
		"--source-ref", stableCandidateRef,
		"--source-digest", run.commit,
		"--cert-oidc-issuer", stableCandidateOIDCIssuer,
		"--deny-self-hosted-runners",
		"--predicate-type", stableCandidatePredicate,
		"--format", "json")
}

type candidateGitHubVerification struct {
	VerificationResult struct {
		Statement struct {
			PredicateType string `json:"predicateType"`
			Subjects      []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
		} `json:"statement"`
		Signature struct {
			Certificate map[string]json.RawMessage `json:"certificate"`
		} `json:"signature"`
		VerifiedTimestamps []json.RawMessage `json:"verifiedTimestamps"`
	} `json:"verificationResult"`
}

func checkCandidateStatement(data []byte, want map[string]string, run stableCandidateRun) error {
	var values []candidateGitHubVerification
	if err := decodeOneJSON(data, &values); err != nil {
		return fmt.Errorf("decode GitHub candidate attestation: %w", err)
	}
	if len(values) == 0 || len(values) > 32 {
		return errors.New("GitHub returned an empty or oversized candidate attestation set")
	}
	runURI := fmt.Sprintf("https://github.com/%s/actions/runs/%d/attempts/%d", stableCandidateRepository, run.id, run.attempt)
	selected := -1
	for index, value := range values {
		var signedRunURI string
		if err := json.Unmarshal(value.VerificationResult.Signature.Certificate["runInvocationURI"], &signedRunURI); err != nil || signedRunURI != runURI {
			continue
		}
		if selected >= 0 {
			return errors.New("GitHub returned multiple attestations for the selected candidate run")
		}
		selected = index
	}
	if selected < 0 {
		return errors.New("GitHub returned no attestation from the selected candidate run")
	}
	result := values[selected].VerificationResult
	if result.Statement.PredicateType != stableCandidatePredicate || len(result.VerifiedTimestamps) == 0 {
		return errors.New("candidate attestation predicate or verified timestamp is missing")
	}
	if err := checkCandidateCertificate(result.Signature.Certificate, run); err != nil {
		return err
	}
	if len(result.Statement.Subjects) != len(want) || len(want) != len(productionCells)+1 {
		return errors.New("candidate attestation does not contain exactly twelve subjects")
	}
	seen := make(map[string]bool, len(want))
	for _, subject := range result.Statement.Subjects {
		expectedSHA, known := want[subject.Name]
		if !known || seen[subject.Name] || len(subject.Digest) != 1 || subject.Digest["sha256"] != expectedSHA {
			return fmt.Errorf("candidate attestation has an extra, duplicate, or changed subject %q", subject.Name)
		}
		seen[subject.Name] = true
	}
	if len(seen) != len(want) {
		return errors.New("candidate attestation is missing a required subject")
	}
	return nil
}

func checkCandidateCertificate(cert map[string]json.RawMessage, run stableCandidateRun) error {
	if len(cert) == 0 || run.id <= 0 || run.attempt <= 0 || !objectIDPattern.MatchString(run.commit) {
		return errors.New("candidate attestation certificate or run identity is invalid")
	}
	repositoryURI := "https://github.com/" + stableCandidateRepository
	workflowRef := stableCandidateRepository + "/" + stableCandidateWorkflow + "@" + stableCandidateRef
	workflowURI := "https://github.com/" + workflowRef
	expected := map[string]string{
		"issuer":                   stableCandidateOIDCIssuer,
		"subjectAlternativeName":   workflowURI,
		"githubWorkflowRepository": stableCandidateRepository,
		"githubWorkflowRef":        stableCandidateRef,
		"githubWorkflowSHA":        run.commit,
		"buildSignerURI":           workflowURI,
		"buildSignerDigest":        run.commit,
		"buildConfigURI":           workflowURI,
		"buildConfigDigest":        run.commit,
		"runnerEnvironment":        "github-hosted",
		"sourceRepositoryURI":      repositoryURI,
		"sourceRepositoryDigest":   run.commit,
		"sourceRepositoryRef":      stableCandidateRef,
		"runInvocationURI":         fmt.Sprintf("%s/actions/runs/%d/attempts/%d", repositoryURI, run.id, run.attempt),
	}
	for name, value := range expected {
		raw, ok := cert[name]
		if !ok {
			return fmt.Errorf("candidate attestation certificate is missing %q", name)
		}
		var actual string
		if err := json.Unmarshal(raw, &actual); err != nil || actual != value {
			return fmt.Errorf("candidate attestation certificate %q differs from the selected run", name)
		}
	}
	return nil
}

func decodeOneJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

type boundedGitHubOutput struct {
	data     bytes.Buffer
	tooLarge bool
}

func (buffer *boundedGitHubOutput) Write(data []byte) (int, error) {
	if buffer.data.Len() > maximumGitHubResponse || len(data) > maximumGitHubResponse-buffer.data.Len() {
		buffer.tooLarge = true
		return 0, errors.New("GitHub output exceeds its size bound")
	}
	return buffer.data.Write(data)
}

func runBoundedGitHub(parent context.Context, ghPath string, timeout time.Duration, arguments ...string) ([]byte, error) {
	if parent == nil || strings.TrimSpace(ghPath) == "" || len(arguments) == 0 {
		return nil, errors.New("trusted GitHub CLI and context are required")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, ghPath, arguments...)
	command.WaitDelay = 2 * time.Second
	output := &boundedGitHubOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if output.tooLarge {
			return nil, errors.New("GitHub output exceeds its size bound")
		}
		return nil, fmt.Errorf("GitHub CLI %s failed: %w", arguments[0], err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output.data.Bytes(), nil
}
