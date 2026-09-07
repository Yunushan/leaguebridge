// Package currentci observes whether the current main source has a complete
// successful CI attempt and authentic matching race/vet and cross-build bytes.
// An observation is not a score receipt, age policy, or publication approval.
package currentci

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
	"regexp"
	"strconv"
	"time"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
	"github.com/Yunushan/leaguebridge/internal/cireleasegate"
)

const (
	repository   = "Yunushan/leaguebridge"
	mainRef      = "refs/heads/main"
	workflowPath = ".github/workflows/ci.yml"
	// This reviewed non-reusable workflow uses the event source revision for
	// push/workflow_dispatch on main. Changes require explicit contract review.
	supportedWorkflowSHA256 = "deb4351ce333350397d1bc0a08732dcab869325e6c94c53d87d321a76b1ed0e9"
	maximumResponse         = 8 << 20
	maximumTreeEntries      = 1000
	maximumWorkflowSize     = 256 << 10
)

var objectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// VerifyRequest supplies only a trusted GitHub CLI executable and local evidence
// paths. Paths retain ciattestation's process-working-directory semantics. No
// source, run, workflow, repository or acceptance policy comes from the caller.
type VerifyRequest struct {
	GHPath             string
	RaceVetSubject     string
	CrossBuildSubjects []string
}

// Observation records live checks completed at ObservedAt. GitHub provides no
// atomic snapshot across branch and Actions APIs: this is not a durable claim
// about later state, a maximum evidence age, or permission to publish.
type Observation struct {
	Commit     string
	Tree       string
	RunID      int64
	RunAttempt int
	ObservedAt time.Time
}

type apiClient func(context.Context, string, any) error

type dependencies struct {
	api        apiClient
	gate       func(context.Context, cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error)
	signatures func(context.Context, ciattestation.VerifyRequest) error
	now        func() time.Time
}

// Verify independently resolves current main and its supported workflow, checks
// the full CI gate before and after verifying both signed evidence sets, and
// rejects changes observed during verification. It applies a fifteen-minute
// timeout bounded further by ctx; every failure returns a zero Observation.
func Verify(ctx context.Context, input VerifyRequest) (Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	return verify(ctx, input, dependencies{
		api: githubAPI(input.GHPath), gate: cireleasegate.Verify,
		signatures: ciattestation.VerifySetContext, now: time.Now,
	})
}

func verify(ctx context.Context, input VerifyRequest, deps dependencies) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if input.GHPath == "" || input.RaceVetSubject == "" || len(input.CrossBuildSubjects) != 9 {
		return Observation{}, errors.New("trusted GitHub CLI, one race/vet subject, and nine cross-build subjects are required")
	}
	seen := map[string]bool{input.RaceVetSubject: true}
	for _, path := range input.CrossBuildSubjects {
		if path == "" || seen[path] {
			return Observation{}, errors.New("CI subject paths must be nonempty and distinct")
		}
		seen[path] = true
	}
	source, err := resolveSource(ctx, deps.api)
	if err != nil {
		return Observation{}, err
	}
	gateRequest := cireleasegate.VerifyRequest{Commit: source.Commit, GHPath: input.GHPath}
	run, err := deps.gate(ctx, gateRequest)
	if err != nil {
		return Observation{}, stageFailure(ctx, "initial complete CI gate", err)
	}
	if run.ID <= 0 || run.Attempt <= 0 || run.Commit != source.Commit {
		return Observation{}, errors.New("CI gate returned an inconsistent source or run identity")
	}
	request := ciattestation.VerifyRequest{
		ExpectedRepo: repository, ExpectedWorkflow: workflowPath,
		ExpectedCommit: source.Commit, ExpectedTree: source.Tree, ExpectedRef: mainRef,
		WorkflowSHA: source.Commit, RunID: strconv.FormatInt(run.ID, 10),
		RunAttempt: strconv.Itoa(run.Attempt), GHPath: input.GHPath,
		Kind: "race-vet", SubjectPaths: []string{input.RaceVetSubject},
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if err := deps.signatures(ctx, request); err != nil {
		return Observation{}, stageFailure(ctx, "signed race/vet evidence", err)
	}
	request.Kind = "cross-build"
	request.SubjectPaths = append([]string(nil), input.CrossBuildSubjects...)
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if err := deps.signatures(ctx, request); err != nil {
		return Observation{}, stageFailure(ctx, "signed cross-build evidence", err)
	}
	currentSource, err := resolveSource(ctx, deps.api)
	if err != nil {
		return Observation{}, err
	}
	if currentSource != source {
		return Observation{}, errors.New("main source or workflow changed during CI verification")
	}
	currentRun, err := deps.gate(ctx, gateRequest)
	if err != nil {
		return Observation{}, stageFailure(ctx, "final complete CI gate", err)
	}
	if currentRun != run {
		return Observation{}, errors.New("latest CI run or attempt changed during verification")
	}
	// Check main again after the final gate, which may itself require pagination.
	finalCommit, err := resolveMain(ctx, deps.api)
	if err != nil {
		return Observation{}, err
	}
	if finalCommit != source.Commit {
		return Observation{}, errors.New("main advanced during the final CI gate")
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	return Observation{Commit: source.Commit, Tree: source.Tree, RunID: run.ID, RunAttempt: run.Attempt, ObservedAt: deps.now().UTC()}, nil
}

// Do not forward arbitrary subprocess stderr or subject-provided diagnostics.
func stageFailure(ctx context.Context, stage string, err error) error {
	if contextError := ctx.Err(); contextError != nil {
		return fmt.Errorf("%s: %w", stage, contextError)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", stage, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", stage, context.DeadlineExceeded)
	}
	return fmt.Errorf("%s failed", stage)
}

type sourceIdentity struct{ Commit, Tree, WorkflowBlob string }
type gitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}
type gitReference struct {
	Ref    string    `json:"ref"`
	Object gitObject `json:"object"`
}
type gitCommit struct {
	SHA  string    `json:"sha"`
	Tree gitObject `json:"tree"`
}
type gitEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}
type gitTree struct {
	SHA       string     `json:"sha"`
	Truncated *bool      `json:"truncated"`
	Entries   []gitEntry `json:"tree"`
}
type gitBlob struct {
	SHA      string `json:"sha"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
	Content  string `json:"content"`
}

func resolveMain(ctx context.Context, api apiClient) (string, error) {
	var ref gitReference
	if err := api(ctx, "repos/"+repository+"/git/ref/heads/main", &ref); err != nil {
		return "", stageFailure(ctx, "read current main ref", err)
	}
	if ref.Ref != mainRef || ref.Object.Type != "commit" || !objectIDPattern.MatchString(ref.Object.SHA) {
		return "", errors.New("current main ref does not identify one exact commit")
	}
	return ref.Object.SHA, nil
}

func resolveSource(ctx context.Context, api apiClient) (sourceIdentity, error) {
	commit, err := resolveMain(ctx, api)
	if err != nil {
		return sourceIdentity{}, err
	}
	var object gitCommit
	if err := api(ctx, "repos/"+repository+"/git/commits/"+commit, &object); err != nil {
		return sourceIdentity{}, stageFailure(ctx, "read main commit", err)
	}
	if object.SHA != commit || !objectIDPattern.MatchString(object.Tree.SHA) || len(object.Tree.SHA) != len(commit) {
		return sourceIdentity{}, errors.New("main commit does not identify its exact source tree")
	}
	current := object.Tree.SHA
	for index, component := range []string{".github", "workflows", "ci.yml"} {
		var tree gitTree
		if err := api(ctx, "repos/"+repository+"/git/trees/"+current, &tree); err != nil {
			return sourceIdentity{}, stageFailure(ctx, "read CI workflow tree", err)
		}
		if tree.SHA != current || tree.Truncated == nil || *tree.Truncated || len(tree.Entries) == 0 || len(tree.Entries) > maximumTreeEntries {
			return sourceIdentity{}, errors.New("CI workflow tree is missing, inconsistent, truncated or exceeds its bound")
		}
		seen := make(map[string]bool, len(tree.Entries))
		var selected gitEntry
		for _, entry := range tree.Entries {
			if entry.Path == "" || seen[entry.Path] {
				return sourceIdentity{}, errors.New("CI workflow tree has an ambiguous entry inventory")
			}
			seen[entry.Path] = true
			if entry.Path == component {
				selected = entry
			}
		}
		if !objectIDPattern.MatchString(selected.SHA) || len(selected.SHA) != len(commit) {
			return sourceIdentity{}, errors.New("CI workflow path is missing or has an invalid object identity")
		}
		if index < 2 {
			if selected.Type != "tree" || selected.Mode != "040000" {
				return sourceIdentity{}, errors.New("CI workflow parent is not a Git directory")
			}
		} else if selected.Type != "blob" || (selected.Mode != "100644" && selected.Mode != "100755") {
			return sourceIdentity{}, errors.New("CI workflow is not a regular Git file")
		}
		current = selected.SHA
	}
	var blob gitBlob
	if err := api(ctx, "repos/"+repository+"/git/blobs/"+current, &blob); err != nil {
		return sourceIdentity{}, stageFailure(ctx, "read CI workflow blob", err)
	}
	if blob.SHA != current || blob.Encoding != "base64" || blob.Size <= 0 || blob.Size > maximumWorkflowSize || len(blob.Content) > 2*maximumWorkflowSize {
		return sourceIdentity{}, errors.New("CI workflow blob metadata is invalid or exceeds its bound")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(blob.Content)
	if err != nil || int64(len(data)) != blob.Size {
		return sourceIdentity{}, errors.New("CI workflow blob content does not match its metadata")
	}
	var digest hash.Hash = sha1.New() // Git object identity; approval uses SHA-256 below.
	if len(current) == 64 {
		digest = sha256.New()
	}
	fmt.Fprintf(digest, "blob %d\x00", len(data))
	digest.Write(data)
	if hex.EncodeToString(digest.Sum(nil)) != current {
		return sourceIdentity{}, errors.New("CI workflow bytes do not match the selected Git blob")
	}
	approved := sha256.Sum256(data)
	if hex.EncodeToString(approved[:]) != supportedWorkflowSHA256 {
		return sourceIdentity{}, errors.New("CI workflow revision is unsupported; review the workflow contract before verification")
	}
	return sourceIdentity{Commit: commit, Tree: object.Tree.SHA, WorkflowBlob: current}, nil
}

func githubAPI(gh string) apiClient {
	return func(ctx context.Context, endpoint string, result any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(requestCtx, gh, "api", "--hostname", "github.com", "--method", "GET", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10", endpoint)
		cmd.WaitDelay = 2 * time.Second
		output := &boundedOutput{}
		cmd.Stdout, cmd.Stderr = output, io.Discard
		if err := cmd.Run(); err != nil {
			if contextError := requestCtx.Err(); contextError != nil {
				return contextError
			}
			return errors.New("GitHub API request failed")
		}
		decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
		if err := decoder.Decode(result); err != nil {
			return errors.New("GitHub API response is invalid")
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("GitHub API response contains trailing data")
		}
		return nil
	}
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > maximumResponse-b.Len() {
		return 0, errors.New("GitHub API response exceeds its size bound")
	}
	return b.Buffer.Write(data)
}
