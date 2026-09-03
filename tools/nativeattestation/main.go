// Command nativeattestation creates and verifies score-free native runtime
// evidence. The JSON document is a subject for GitHub's artifact-attestation
// service; it is not an attestation and it never contains a readiness score or
// a gameplay-support claim.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
)

const (
	schemaID          = "https://github.com/Yunushan/leaguebridge/schemas/native-runtime-attestation.schema.json"
	schemaVersion     = 2
	attestationType   = "leaguebridge.native-runtime-attestation.v2"
	maxDocumentSize   = 64 << 10
	maxSubjectSize    = int64(128 << 20)
	maxEvidenceFiles  = 128
	maxGitHubOutput   = 8 << 20
	githubOIDCIssuer  = "https://token.actions.githubusercontent.com"
	slsaPredicateType = "https://slsa.dev/provenance/v1"
	defaultRepository = "Yunushan/leaguebridge"
	defaultWorkflow   = ".github/workflows/ci.yml"
	githubTimeout     = 5 * time.Minute
)

var (
	objectIDPattern   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	jobPattern        = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	runIDPattern      = regexp.MustCompile(`^[1-9][0-9]{0,31}$`)
	attemptPattern    = regexp.MustCompile(`^[1-9][0-9]{0,7}$`)
	goVersionPattern  = regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	refPattern        = regexp.MustCompile(`^refs/[A-Za-z0-9._/@-]{1,250}$`)
	sha256Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type document struct {
	Schema          string    `json:"$schema"`
	SchemaVersion   int       `json:"schema_version"`
	AttestationType string    `json:"attestation_type"`
	Kind            string    `json:"kind"`
	GeneratedAt     string    `json:"generated_at"`
	Source          source    `json:"source"`
	Execution       execution `json:"execution"`
	Subjects        []subject `json:"subjects"`
}

type source struct {
	Repository  string `json:"repository"`
	Commit      string `json:"commit"`
	Tree        string `json:"tree"`
	Ref         string `json:"ref"`
	Workflow    string `json:"workflow"`
	WorkflowRef string `json:"workflow_ref"`
	WorkflowSHA string `json:"workflow_sha"`
	RunID       string `json:"run_id"`
	RunAttempt  string `json:"run_attempt"`
}

type execution struct {
	Job                string `json:"job"`
	RunnerOS           string `json:"runner_os"`
	RunnerArchitecture string `json:"runner_architecture"`
	HostClass          string `json:"host_class"`
	GoVersion          string `json:"go_version"`
	Command            string `json:"command"`
	Target             target `json:"target"`
}

type target struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

type subject struct {
	Path      string `json:"path"`
	Role      string `json:"role"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type request struct {
	Kind               string
	GeneratedAt        string
	Repository         string
	Commit             string
	Tree               string
	Ref                string
	Workflow           string
	WorkflowRef        string
	WorkflowSHA        string
	RunID              string
	RunAttempt         string
	Job                string
	RunnerOS           string
	RunnerArchitecture string
	HostClass          string
	GoVersion          string
	Command            string
	TargetGOOS         string
	TargetGOARCH       string
	EvidenceDir        string
	OutputPath         string
	SubjectPaths       []string
}

type verifyRequest struct {
	Kind              string
	SubjectPaths      []string
	ExpectedRepo      string
	ExpectedWorkflow  string
	ExpectedCommit    string
	ExpectedTree      string
	ExpectedRef       string
	WorkflowSHA       string
	RunID             string
	RunAttempt        string
	ExpectedHostClass string
	GHPath            string
}

type loadedDocument struct {
	Path  string
	Data  []byte
	Value document
}

type verifiedArtifact struct {
	Path   string
	Digest string
	Size   int64
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

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("subject path must not be empty")
	}
	*values = append(*values, value)
	return nil
}

type ghAttestationRunner func(context.Context, string, string, source) ([]byte, error)

var runGitHubAttestation ghAttestationRunner = runGitHubAttestationCommand

func main() {
	set := flag.NewFlagSet("nativeattestation", flag.ExitOnError)
	verify := set.Bool("verify", false, "verify signed native runtime attestations")
	kind := set.String("kind", "", "attestation kind: linux-runtime or bsd-runtime")
	output := set.String("output", "", "new JSON subject path")
	evidenceDir := set.String("evidence-dir", "", "runtime evidence directory to inventory")
	generatedAt := set.String("generated-at", "", "canonical UTC RFC3339 generation timestamp; defaults to current UTC time")
	targetGOOS := set.String("target-goos", "", "target GOOS")
	targetGOARCH := set.String("target-goarch", "", "target GOARCH")
	hostClass := set.String("host-class", "", "runtime host class: hosted, virtualized, or physical")
	command := set.String("command", "", "bounded description of the runtime test command")
	var subjects stringList
	set.Var(&subjects, "subject", "regular file executed or consumed by the runtime test; may be repeated")
	var verifySubjects stringList
	set.Var(&verifySubjects, "verify-subject", "native runtime attestation subject JSON to verify; may be repeated")
	expectedRepository := set.String("expected-repository", defaultRepository, "expected GitHub owner/repository")
	expectedWorkflow := set.String("expected-workflow", defaultWorkflow, "expected workflow path relative to the repository")
	expectedCommit := set.String("expected-commit", "", "expected source commit object ID (required when verifying)")
	expectedTree := set.String("expected-tree", "", "expected source tree object ID (required when verifying)")
	expectedRef := set.String("expected-ref", "", "expected source ref (required when verifying)")
	expectedWorkflowSHA := set.String("expected-workflow-sha", "", "expected workflow revision object ID (required when verifying)")
	runID := set.String("run-id", "", "GitHub Actions run ID (required when verifying)")
	runAttempt := set.String("run-attempt", "", "GitHub Actions run attempt (required when verifying)")
	expectedHostClass := set.String("expected-host-class", "", "expected host class (required when verifying)")
	ghPath := set.String("gh", "gh", "GitHub CLI executable used for verification")
	if err := set.Parse(os.Args[1:]); err != nil {
		return
	}
	if *verify {
		if *output != "" || *evidenceDir != "" || len(subjects) != 0 || *generatedAt != "" || *targetGOOS != "" || *targetGOARCH != "" || *hostClass != "" || *command != "" {
			fail("generation flags cannot be used with -verify")
		}
		if err := verifySet(verifyRequest{
			Kind: *kind, SubjectPaths: verifySubjects, ExpectedRepo: *expectedRepository,
			ExpectedWorkflow: *expectedWorkflow, ExpectedCommit: *expectedCommit,
			ExpectedTree: *expectedTree, ExpectedRef: *expectedRef,
			WorkflowSHA: *expectedWorkflowSHA, RunID: *runID, RunAttempt: *runAttempt,
			ExpectedHostClass: *expectedHostClass, GHPath: *ghPath,
		}); err != nil {
			fail("verify native runtime attestations: %v", err)
		}
		fmt.Printf("verified GitHub native runtime attestation set kind=%s subjects=%d commit=%s\n", *kind, len(verifySubjects), *expectedCommit)
		return
	}
	if len(verifySubjects) != 0 || *expectedCommit != "" || *expectedTree != "" || *expectedRef != "" || *expectedRepository != defaultRepository || *expectedWorkflow != defaultWorkflow || *expectedWorkflowSHA != "" || *runID != "" || *runAttempt != "" || *expectedHostClass != "" || *ghPath != "gh" {
		fail("verification flags require -verify")
	}
	if *output == "" || *evidenceDir == "" || *kind == "" || *targetGOOS == "" || *targetGOARCH == "" || *hostClass == "" || *command == "" {
		fail("kind, output, evidence-dir, target, host-class, and command are required")
	}
	if *generatedAt == "" {
		*generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	outputPath, err := normalizedRelativePath(*output)
	if err != nil {
		fail("output path: %v", err)
	}
	document, err := build(request{
		Kind: *kind, GeneratedAt: *generatedAt,
		Repository: os.Getenv("GITHUB_REPOSITORY"), Commit: os.Getenv("GITHUB_SHA"),
		Tree: os.Getenv("CI_ATTESTATION_TREE"), Ref: os.Getenv("GITHUB_REF"),
		Workflow: os.Getenv("GITHUB_WORKFLOW"), WorkflowRef: os.Getenv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA: os.Getenv("GITHUB_WORKFLOW_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"),
		RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Job: os.Getenv("GITHUB_JOB"),
		RunnerOS: os.Getenv("RUNNER_OS"), RunnerArchitecture: os.Getenv("RUNNER_ARCH"),
		HostClass: *hostClass, GoVersion: runtime.Version(), Command: *command,
		TargetGOOS: *targetGOOS, TargetGOARCH: *targetGOARCH,
		EvidenceDir: *evidenceDir, OutputPath: outputPath, SubjectPaths: subjects,
	})
	if err != nil {
		fail("build native runtime attestation subject: %v", err)
	}
	data, err := marshal(document)
	if err != nil {
		fail("marshal native runtime attestation subject: %v", err)
	}
	if err := writeNew(*output, data); err != nil {
		fail("write native runtime attestation subject: %v", err)
	}
	fmt.Printf("created native runtime attestation subject %s\n", *output)
}

func build(input request) (document, error) {
	if err := validateKind(input.Kind); err != nil {
		return document{}, err
	}
	value := document{
		Schema: schemaID, SchemaVersion: schemaVersion, AttestationType: attestationType,
		Kind: input.Kind, GeneratedAt: input.GeneratedAt,
		Source: source{Repository: input.Repository, Commit: input.Commit, Tree: input.Tree,
			Ref: input.Ref, Workflow: input.Workflow, WorkflowRef: input.WorkflowRef,
			WorkflowSHA: input.WorkflowSHA, RunID: input.RunID, RunAttempt: input.RunAttempt},
		Execution: execution{Job: input.Job, RunnerOS: input.RunnerOS,
			RunnerArchitecture: input.RunnerArchitecture, HostClass: input.HostClass,
			GoVersion: input.GoVersion, Command: input.Command,
			Target: target{GOOS: input.TargetGOOS, GOARCH: input.TargetGOARCH}},
	}
	if _, err := canonicalTimestamp(input.GeneratedAt); err != nil {
		return document{}, err
	}
	if err := validateSource(value.Source); err != nil {
		return document{}, err
	}
	if err := validateExecution(value.Execution, input.Kind); err != nil {
		return document{}, err
	}
	if strings.TrimSpace(input.EvidenceDir) == "" {
		return document{}, errors.New("evidence directory is required")
	}
	seen := make(map[string]struct{})
	for _, path := range input.SubjectPaths {
		item, err := hashPath(path, "runtime-binary")
		if err != nil {
			return document{}, err
		}
		if _, duplicate := seen[item.Path]; duplicate {
			return document{}, fmt.Errorf("subject path %q is duplicated", item.Path)
		}
		seen[item.Path] = struct{}{}
		value.Subjects = append(value.Subjects, item)
	}
	evidence, err := hashEvidenceDirectory(input.EvidenceDir, input.OutputPath, seen)
	if err != nil {
		return document{}, err
	}
	value.Subjects = append(value.Subjects, evidence...)
	sort.Slice(value.Subjects, func(i, j int) bool { return value.Subjects[i].Path < value.Subjects[j].Path })
	if err := validateDocument(value); err != nil {
		return document{}, err
	}
	return value, nil
}

func hashEvidenceDirectory(directory, outputPath string, seen map[string]struct{}) ([]subject, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence directory: %w", err)
	}
	if err := fileinput.RejectSymlinkedParents(absolute); err != nil {
		return nil, fmt.Errorf("evidence directory path: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect evidence directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("evidence directory must be a regular non-symlink directory")
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	var result []subject
	err = filepath.WalkDir(absolute, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence tree contains symlink %q", path)
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("evidence entry %q is not a regular file", path)
		}
		relative, err := filepath.Rel(workingDirectory, path)
		if err != nil {
			return fmt.Errorf("relativize evidence file %q: %w", path, err)
		}
		relative = filepath.ToSlash(relative)
		normalized, err := normalizedRelativePath(relative)
		if err != nil {
			return fmt.Errorf("evidence file %q: %w", path, err)
		}
		if normalized == outputPath {
			return nil
		}
		if _, duplicate := seen[normalized]; duplicate {
			return fmt.Errorf("evidence file %q is also an explicit subject", normalized)
		}
		item, err := hashPath(normalized, "runtime-evidence")
		if err != nil {
			return err
		}
		seen[normalized] = struct{}{}
		result = append(result, item)
		if len(result) > maxEvidenceFiles {
			return fmt.Errorf("evidence directory contains more than %d files", maxEvidenceFiles)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory evidence directory: %w", err)
	}
	if len(result) == 0 {
		return nil, errors.New("evidence directory contains no regular files")
	}
	return result, nil
}

func verifySet(input verifyRequest) error {
	if err := validateKind(input.Kind); err != nil {
		return err
	}
	if input.GHPath == "" {
		return errors.New("GitHub CLI path is required")
	}
	if len(input.SubjectPaths) == 0 {
		return errors.New("at least one -verify-subject is required")
	}
	if input.ExpectedRepo == "" || !repositoryPattern.MatchString(input.ExpectedRepo) || len(input.ExpectedRepo) > 255 {
		return errors.New("expected repository is invalid")
	}
	workflowPath, err := normalizedRelativePath(input.ExpectedWorkflow)
	if err != nil || workflowPath != filepath.ToSlash(input.ExpectedWorkflow) || workflowPath != defaultWorkflow {
		return errors.New("expected workflow path is invalid or not the CI workflow")
	}
	if !objectIDPattern.MatchString(input.ExpectedCommit) || !objectIDPattern.MatchString(input.ExpectedTree) || !objectIDPattern.MatchString(input.WorkflowSHA) {
		return errors.New("expected commit, tree, and workflow SHA must be lowercase 40- or 64-character object IDs")
	}
	if !refPattern.MatchString(input.ExpectedRef) || !runIDPattern.MatchString(input.RunID) || !attemptPattern.MatchString(input.RunAttempt) {
		return errors.New("expected ref, run ID, or run attempt is invalid")
	}
	if input.ExpectedHostClass != "hosted" && input.ExpectedHostClass != "virtualized" && input.ExpectedHostClass != "physical" {
		return errors.New("expected host class is invalid")
	}
	if input.ExpectedHostClass == "physical" {
		return errors.New("physical host claims require an independent physical attestation; GitHub-hosted verification only accepts hosted or virtualized claims")
	}
	seen := make(map[string]struct{}, len(input.SubjectPaths))
	loaded := make([]loadedDocument, 0, len(input.SubjectPaths))
	for _, path := range input.SubjectPaths {
		if _, duplicate := seen[path]; duplicate {
			return fmt.Errorf("verification subject %q is duplicated", path)
		}
		seen[path] = struct{}{}
		item, err := loadDocument(path)
		if err != nil {
			return err
		}
		if item.Value.Kind != input.Kind {
			return fmt.Errorf("subject %q has kind %q; want %q", path, item.Value.Kind, input.Kind)
		}
		if item.Value.Execution.HostClass != input.ExpectedHostClass {
			return fmt.Errorf("subject %q has host class %q; want %q", path, item.Value.Execution.HostClass, input.ExpectedHostClass)
		}
		if err := validateExpectedSource(item.Value, input, workflowPath); err != nil {
			return fmt.Errorf("subject %q: %w", path, err)
		}
		loaded = append(loaded, item)
	}
	if err := validateSetShape(input.Kind, loaded); err != nil {
		return err
	}
	commonSource := loaded[0].Value.Source
	seenArtifacts := make(map[string]struct{})
	for _, item := range loaded {
		artifacts := []verifiedArtifact{{Path: item.Path, Digest: digestBytes(item.Data), Size: int64(len(item.Data))}}
		for _, declared := range item.Value.Subjects {
			if _, duplicate := seenArtifacts[declared.Path]; duplicate {
				return fmt.Errorf("runtime artifact %q is listed more than once", declared.Path)
			}
			seenArtifacts[declared.Path] = struct{}{}
			actual, err := hashPath(declared.Path, declared.Role)
			if err != nil {
				return fmt.Errorf("subject %q artifact %q: %w", item.Path, declared.Path, err)
			}
			if actual.SizeBytes != declared.SizeBytes || actual.SHA256 != declared.SHA256 {
				return fmt.Errorf("subject %q artifact %q does not match its declared size or SHA-256", item.Path, declared.Path)
			}
			artifacts = append(artifacts, verifiedArtifact{Path: declared.Path, Digest: declared.SHA256, Size: declared.SizeBytes})
		}
		for _, artifact := range artifacts {
			if err := verifyGitHubArtifact(artifact, commonSource, input.GHPath); err != nil {
				return fmt.Errorf("subject %q artifact %q: %w", item.Path, artifact.Path, err)
			}
		}
	}
	return nil
}

func validateSetShape(kind string, values []loadedDocument) error {
	want := map[string]struct{}{}
	switch kind {
	case "linux-runtime":
		want["linux/amd64"] = struct{}{}
		want["linux/arm64"] = struct{}{}
	case "bsd-runtime":
		for _, goos := range []string{"freebsd", "openbsd", "netbsd"} {
			want[goos+"/amd64"] = struct{}{}
			want[goos+"/arm64"] = struct{}{}
		}
		want["dragonfly/amd64"] = struct{}{}
	default:
		return fmt.Errorf("unsupported native runtime kind %q", kind)
	}
	if len(values) != len(want) {
		return fmt.Errorf("%s verification requires exactly %d subjects, got %d", kind, len(want), len(values))
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := value.Value.Execution.Target.GOOS + "/" + value.Value.Execution.Target.GOARCH
		if _, ok := want[key]; !ok {
			return fmt.Errorf("subject %q has unexpected target %q", value.Path, key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("target %q is duplicated", key)
		}
		seen[key] = struct{}{}
		expectedJob, expectedRunner, expectedArch := expectedExecution(kind, value.Value.Execution.Target)
		if value.Value.Execution.Job != expectedJob || value.Value.Execution.RunnerOS != expectedRunner || value.Value.Execution.RunnerArchitecture != expectedArch || value.Value.Execution.GoVersion != "go1.27.0" {
			return fmt.Errorf("subject %q is not from the pinned native runtime job contract", value.Path)
		}
	}
	if len(seen) != len(want) {
		return fmt.Errorf("%s verification set is incomplete", kind)
	}
	return nil
}

func expectedExecution(kind string, target target) (job, runner, architecture string) {
	switch kind {
	case "linux-runtime":
		if target.GOARCH == "arm64" {
			return "linux-runtime", "Linux", "ARM64"
		}
		return "linux-runtime", "Linux", "X64"
	case "bsd-runtime":
		if target.GOOS == "dragonfly" {
			return "dragonfly-runtime", "Linux", "X64"
		}
		return "bsd-runtime", "Linux", "X64"
	default:
		return "", "", ""
	}
}

func loadDocument(path string) (loadedDocument, error) {
	normalized, err := normalizedRelativePath(path)
	if err != nil || normalized != filepath.ToSlash(path) {
		return loadedDocument{}, fmt.Errorf("verification subject path %q is invalid", path)
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return loadedDocument{}, fmt.Errorf("open verification subject %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return loadedDocument{}, fmt.Errorf("stat verification subject %q: %w", path, err)
	}
	if info.Size() <= 0 || info.Size() > maxDocumentSize {
		return loadedDocument{}, fmt.Errorf("verification subject %q size is outside 1..%d bytes", path, maxDocumentSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDocumentSize+1))
	if err != nil {
		return loadedDocument{}, fmt.Errorf("read verification subject %q: %w", path, err)
	}
	after, err := file.Stat()
	if err != nil {
		return loadedDocument{}, fmt.Errorf("inspect verification subject %q: %w", path, err)
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() || !os.SameFile(info, after) || !os.SameFile(info, pathAfter) || int64(len(data)) != after.Size() || int64(len(data)) != pathAfter.Size() {
		return loadedDocument{}, fmt.Errorf("verification subject %q changed while reading", path)
	}
	if len(data) == 0 || len(data) > maxDocumentSize {
		return loadedDocument{}, fmt.Errorf("verification subject %q exceeds %d bytes", path, maxDocumentSize)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return loadedDocument{}, fmt.Errorf("decode verification subject %q: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value document
	if err := decoder.Decode(&value); err != nil {
		return loadedDocument{}, fmt.Errorf("decode verification subject %q: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return loadedDocument{}, fmt.Errorf("verification subject %q contains multiple JSON values", path)
		}
		return loadedDocument{}, fmt.Errorf("decode trailing verification subject data: %w", err)
	}
	if err := exactjson.ValidateKeys(data, document{}); err != nil {
		return loadedDocument{}, fmt.Errorf("validate verification subject %q fields: %w", path, err)
	}
	if err := validateDocument(value); err != nil {
		return loadedDocument{}, fmt.Errorf("validate verification subject %q: %w", path, err)
	}
	return loadedDocument{Path: normalized, Data: data, Value: value}, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func(string, int) error
	walk = func(location string, depth int) error {
		if depth > 128 {
			return errors.New("JSON exceeds 128 levels")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("%s contains a non-string object key", location)
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate key %q at %s", key, location)
				}
				seen[key] = struct{}{}
				if err := walk(location+"."+key, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			index := 0
			for decoder.More() {
				if err := walk(fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
					return err
				}
				index++
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk("$", 0); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func validateExpectedSource(value document, input verifyRequest, workflowPath string) error {
	expectedWorkflowRef := input.ExpectedRepo + "/" + workflowPath + "@" + input.ExpectedRef
	if value.Source.Repository != input.ExpectedRepo {
		return fmt.Errorf("repository %q is not the expected %q", value.Source.Repository, input.ExpectedRepo)
	}
	if value.Source.Commit != input.ExpectedCommit || value.Source.Tree != input.ExpectedTree || value.Source.Ref != input.ExpectedRef {
		return errors.New("source commit, tree, or ref does not match the expected checkout")
	}
	if value.Source.WorkflowRef != expectedWorkflowRef {
		return fmt.Errorf("workflow_ref %q is not %q", value.Source.WorkflowRef, expectedWorkflowRef)
	}
	if value.Source.WorkflowSHA != input.WorkflowSHA {
		return fmt.Errorf("workflow_sha %q is not the expected %q", value.Source.WorkflowSHA, input.WorkflowSHA)
	}
	if value.Source.RunID != input.RunID || value.Source.RunAttempt != input.RunAttempt {
		return errors.New("source run ID or attempt does not match the expected workflow run")
	}
	return nil
}

func verifyGitHubArtifact(artifact verifiedArtifact, value source, ghPath string) error {
	if artifact.Size <= 0 || !sha256Pattern.MatchString(artifact.Digest) {
		return fmt.Errorf("artifact %q has an invalid expected digest", artifact.Path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), githubTimeout)
	defer cancel()
	output, err := runGitHubAttestation(ctx, ghPath, artifact.Path, value)
	if err != nil {
		return err
	}
	if err := verifyGitHubOutput(output, artifact.Digest, value); err != nil {
		return err
	}
	actual, err := hashPath(artifact.Path, "verified-artifact")
	if err != nil {
		return fmt.Errorf("recheck artifact %q after GitHub verification: %w", artifact.Path, err)
	}
	if actual.SizeBytes != artifact.Size || actual.SHA256 != artifact.Digest {
		return fmt.Errorf("artifact %q changed during GitHub verification", artifact.Path)
	}
	return nil
}

func runGitHubAttestationCommand(ctx context.Context, ghPath, artifactPath string, value source) ([]byte, error) {
	signerWorkflow, err := githubSignerWorkflow(value)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, ghPath, "attestation", "verify", artifactPath,
		"--repo", value.Repository, "--signer-workflow", signerWorkflow,
		"--source-ref", value.Ref, "--source-digest", value.Commit,
		"--cert-oidc-issuer", githubOIDCIssuer, "--deny-self-hosted-runners",
		"--predicate-type", slsaPredicateType, "--format", "json")
	stdout := &boundedBuffer{Maximum: maxGitHubOutput}
	stderr := &boundedBuffer{Maximum: maxGitHubOutput}
	command.Stdout, command.Stderr = stdout, stderr
	err = command.Run()
	if stdout.Oversized || stderr.Oversized {
		return nil, errors.New("GitHub CLI output exceeds the bounded limit")
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("GitHub CLI verification failed: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("GitHub CLI verification failed: %w", err)
	}
	return stdout.Bytes(), nil
}

func githubSignerWorkflow(value source) (string, error) {
	prefix := value.Repository + "/"
	if !strings.HasPrefix(value.WorkflowRef, prefix) {
		return "", errors.New("workflow_ref is not rooted in the expected repository")
	}
	pathAndRef := strings.TrimPrefix(value.WorkflowRef, prefix)
	separator := strings.LastIndexByte(pathAndRef, '@')
	if separator <= 0 || separator == len(pathAndRef)-1 {
		return "", errors.New("workflow_ref must contain a workflow path and ref")
	}
	workflowPath := pathAndRef[:separator]
	if _, err := normalizedRelativePath(workflowPath); err != nil {
		return "", fmt.Errorf("workflow_ref contains an invalid workflow path: %w", err)
	}
	return prefix + workflowPath, nil
}

type boundedBuffer struct {
	bytes.Buffer
	Maximum   int
	Oversized bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if b.Maximum < 0 || b.Len() > b.Maximum || len(value) > b.Maximum-b.Len() {
		b.Oversized = true
		return 0, errors.New("bounded output limit exceeded")
	}
	return b.Buffer.Write(value)
}

func verifyGitHubOutput(data []byte, expectedDigest string, value source) error {
	if !sha256Pattern.MatchString(expectedDigest) {
		return errors.New("expected GitHub subject digest is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var results []ghVerification
	if err := decoder.Decode(&results); err != nil {
		return fmt.Errorf("decode GitHub verification result: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("GitHub verification result contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing GitHub verification result: %w", err)
	}
	if len(results) == 0 {
		return errors.New("GitHub verification returned no attestations")
	}
	var reasons []string
	for index, result := range results {
		if err := validateGitHubVerification(result, expectedDigest, value); err != nil {
			reasons = append(reasons, fmt.Sprintf("%d: %v", index, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("no GitHub attestation matched the required policy (%s)", strings.Join(reasons, "; "))
}

func validateGitHubVerification(value ghVerification, expectedDigest string, sourceValue source) error {
	result := value.VerificationResult
	if result.Statement.PredicateType != slsaPredicateType {
		return fmt.Errorf("predicate type is %q", result.Statement.PredicateType)
	}
	if len(result.VerifiedTimestamps) == 0 {
		return errors.New("verified timestamp is missing")
	}
	if err := validateGitHubCertificate(result.Signature.Certificate, sourceValue); err != nil {
		return err
	}
	for _, item := range result.Statement.Subjects {
		if item.Name != "" && item.Digest["sha256"] == expectedDigest {
			return nil
		}
	}
	return fmt.Errorf("signed subject does not contain SHA-256 %s", expectedDigest)
}

func validateGitHubCertificate(certificate map[string]json.RawMessage, value source) error {
	if len(certificate) == 0 {
		return errors.New("verified certificate is missing")
	}
	repositoryURI := "https://github.com/" + value.Repository
	workflowURI := "https://github.com/" + value.WorkflowRef
	runURI := fmt.Sprintf("%s/actions/runs/%s/attempts/%s", repositoryURI, value.RunID, value.RunAttempt)
	expected := map[string]string{
		"issuer": githubOIDCIssuer, "subjectAlternativeName": workflowURI,
		"githubWorkflowRepository": value.Repository, "githubWorkflowRef": value.Ref,
		"githubWorkflowSHA": value.WorkflowSHA, "buildSignerURI": workflowURI,
		"buildSignerDigest": value.WorkflowSHA, "buildConfigURI": workflowURI,
		"buildConfigDigest": value.WorkflowSHA, "runnerEnvironment": "github-hosted",
		"sourceRepositoryURI": repositoryURI, "sourceRepositoryDigest": value.Commit,
		"sourceRepositoryRef": value.Ref, "runInvocationURI": runURI,
	}
	for name, want := range expected {
		raw, ok := certificate[name]
		if !ok {
			return fmt.Errorf("verified certificate is missing %q", name)
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil || got != want {
			return fmt.Errorf("verified certificate %q is not %q", name, want)
		}
	}
	return nil
}

func hashPath(path, role string) (subject, error) {
	normalized, err := normalizedRelativePath(path)
	if err != nil {
		return subject{}, err
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return subject{}, fmt.Errorf("open subject %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return subject{}, fmt.Errorf("stat subject %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSubjectSize {
		return subject{}, fmt.Errorf("subject %q size is outside 1..%d bytes", path, maxSubjectSize)
	}
	if role == "runtime-binary" && info.Mode().Perm()&0o111 == 0 && strings.ToLower(filepath.Ext(path)) != ".exe" {
		return subject{}, fmt.Errorf("runtime binary subject %q is not executable", path)
	}
	digest := sha256.New()
	if _, err := io.CopyN(digest, file, info.Size()); err != nil {
		return subject{}, fmt.Errorf("hash subject %q: %w", path, err)
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); err != io.EOF || count != 0 {
		return subject{}, fmt.Errorf("subject %q changed while hashing", path)
	}
	after, err := file.Stat()
	if err != nil {
		return subject{}, fmt.Errorf("inspect subject %q after hashing: %w", path, err)
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() || !os.SameFile(info, after) || !os.SameFile(info, pathAfter) || after.Size() != info.Size() || pathAfter.Size() != info.Size() {
		return subject{}, fmt.Errorf("subject %q changed while hashing", path)
	}
	return subject{Path: normalized, Role: role, SizeBytes: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
}

func validateKind(kind string) error {
	switch kind {
	case "linux-runtime", "bsd-runtime":
		return nil
	default:
		return fmt.Errorf("kind must be linux-runtime or bsd-runtime")
	}
}

func validateSource(value source) error {
	if !repositoryPattern.MatchString(value.Repository) || len(value.Repository) > 255 {
		return errors.New("repository must be a bounded owner/repository identifier")
	}
	for name, candidate := range map[string]string{"commit": value.Commit, "tree": value.Tree, "workflow_sha": value.WorkflowSHA} {
		if !objectIDPattern.MatchString(candidate) {
			return fmt.Errorf("%s must be a lowercase 40- or 64-character object ID", name)
		}
	}
	if !refPattern.MatchString(value.Ref) {
		return errors.New("ref must be a bounded refs/ name")
	}
	if !boundedText(value.Workflow, 512) || !boundedText(value.WorkflowRef, 512) {
		return errors.New("workflow identity is required and bounded")
	}
	if !runIDPattern.MatchString(value.RunID) || !attemptPattern.MatchString(value.RunAttempt) {
		return errors.New("run_id and run_attempt must be positive decimal identifiers")
	}
	return nil
}

func validateExecution(value execution, kind string) error {
	if !jobPattern.MatchString(value.Job) || len(value.Job) > 128 {
		return errors.New("job must be a bounded lowercase identifier")
	}
	if value.RunnerOS != "Linux" {
		return fmt.Errorf("unsupported runner OS %q", value.RunnerOS)
	}
	if value.RunnerArchitecture != "X64" && value.RunnerArchitecture != "ARM64" {
		return fmt.Errorf("unsupported runner architecture %q", value.RunnerArchitecture)
	}
	if value.HostClass != "hosted" && value.HostClass != "virtualized" && value.HostClass != "physical" {
		return fmt.Errorf("unsupported host class %q", value.HostClass)
	}
	if !goVersionPattern.MatchString(value.GoVersion) {
		return errors.New("go version must use canonical go1.x.y form")
	}
	if !boundedText(value.Command, 512) {
		return errors.New("command is required, bounded, and must not contain control characters")
	}
	if err := validateTarget(kind, value.Target); err != nil {
		return err
	}
	expectedJob, expectedRunner, expectedArchitecture := expectedExecution(kind, value.Target)
	if value.Job != expectedJob || value.RunnerOS != expectedRunner || value.RunnerArchitecture != expectedArchitecture {
		return fmt.Errorf("execution identity %q/%q/%q is not %q/%q/%q for %s/%s", value.Job, value.RunnerOS, value.RunnerArchitecture, expectedJob, expectedRunner, expectedArchitecture, value.Target.GOOS, value.Target.GOARCH)
	}
	return nil
}

func validateTarget(kind string, value target) error {
	switch kind {
	case "linux-runtime":
		if value.GOOS != "linux" || (value.GOARCH != "amd64" && value.GOARCH != "arm64") {
			return errors.New("linux runtime target must be linux/amd64 or linux/arm64")
		}
	case "bsd-runtime":
		if (value.GOARCH != "amd64" && value.GOARCH != "arm64") || (value.GOOS != "freebsd" && value.GOOS != "openbsd" && value.GOOS != "netbsd" && value.GOOS != "dragonfly") || (value.GOOS == "dragonfly" && value.GOARCH != "amd64") {
			return errors.New("BSD runtime target must be FreeBSD, OpenBSD, or NetBSD amd64/arm64, or DragonFly amd64")
		}
	default:
		return fmt.Errorf("unsupported native runtime kind %q", kind)
	}
	return nil
}

func validateDocument(value document) error {
	if value.Schema != schemaID || value.SchemaVersion != schemaVersion || value.AttestationType != attestationType {
		return errors.New("native runtime attestation subject identity is invalid")
	}
	if err := validateKind(value.Kind); err != nil {
		return err
	}
	if _, err := canonicalTimestamp(value.GeneratedAt); err != nil {
		return err
	}
	if err := validateSource(value.Source); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if err := validateExecution(value.Execution, value.Kind); err != nil {
		return fmt.Errorf("execution: %w", err)
	}
	if len(value.Subjects) < 2 || len(value.Subjects) > maxEvidenceFiles+1 {
		return errors.New("native runtime attestation must contain a binary and at least one evidence file")
	}
	previous := ""
	binaryCount, evidenceCount := 0, 0
	for _, item := range value.Subjects {
		normalized, err := normalizedRelativePath(item.Path)
		if err != nil || normalized != item.Path || item.Path <= previous {
			return fmt.Errorf("native runtime subjects must be strictly sorted, unique, and safe: %q", item.Path)
		}
		previous = item.Path
		if item.Role != "runtime-binary" && item.Role != "runtime-evidence" {
			return fmt.Errorf("subject %q has an unsupported role", item.Path)
		}
		if item.SizeBytes <= 0 || item.SizeBytes > maxSubjectSize || !sha256Pattern.MatchString(item.SHA256) {
			return fmt.Errorf("subject %q has invalid size or SHA-256", item.Path)
		}
		if item.Role == "runtime-binary" {
			binaryCount++
		} else {
			evidenceCount++
		}
	}
	if binaryCount == 0 || evidenceCount == 0 {
		return errors.New("native runtime attestation must contain both runtime-binary and runtime-evidence subjects")
	}
	return nil
}

func marshal(value document) ([]byte, error) {
	if err := validateDocument(value); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > maxDocumentSize {
		return nil, fmt.Errorf("native runtime attestation subject exceeds %d bytes", maxDocumentSize)
	}
	return data, nil
}

func writeNew(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("output path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(filepath.Clean(absolute)))
	if err != nil {
		return fmt.Errorf("open output parent: %w", err)
	}
	defer parent.Close()
	name := filepath.Base(absolute)
	if name == "" || name == "." || name == string(filepath.Separator) || filepath.VolumeName(name) != "" {
		return errors.New("output path is invalid")
	}
	if info, err := parent.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("output path is a symlink")
		}
		return errors.New("output path already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output path: %w", err)
	}
	file, err := parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	removePartial := true
	defer func() {
		_ = file.Close()
		if removePartial {
			_ = parent.Remove(name)
		}
	}()
	written, err := file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	removePartial = false
	return nil
}

func normalizedRelativePath(value string) (string, error) {
	if strings.TrimSpace(value) == "" || filepath.IsAbs(value) || strings.ContainsRune(value, '\\') {
		return "", fmt.Errorf("path %q must be a non-empty relative path", value)
	}
	normalized := filepath.ToSlash(filepath.Clean(value))
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") || strings.Contains(normalized, "//") || strings.Contains(normalized, ":") || strings.ContainsAny(normalized, "\x00\r\n") {
		return "", fmt.Errorf("path %q is unsafe", value)
	}
	for _, component := range strings.Split(normalized, "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("path %q is unsafe", value)
		}
	}
	if len(normalized) > 256 {
		return "", fmt.Errorf("path %q is too long", value)
	}
	return normalized, nil
}

func canonicalTimestamp(value string) (string, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return "", errors.New("generated_at must be a canonical whole-second UTC RFC3339 timestamp")
	}
	return value, nil
}

func boundedText(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (b *boundedBuffer) Bytes() []byte { return append([]byte(nil), b.Buffer.Bytes()...) }

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "nativeattestation: "+format+"\n", arguments...)
	os.Exit(2)
}
