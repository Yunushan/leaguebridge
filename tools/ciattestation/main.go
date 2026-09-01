// Command ciattestation generates strict, score-free subjects for CI artifact
// attestations and verifies complete sets of externally signed GitHub artifact
// attestations. Generated JSON is not itself an attestation: GitHub's
// artifact-attestation service must sign the exact bytes before an external
// verifier can consider the execution evidence.
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
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
	targetcontract "github.com/Yunushan/leaguebridge/internal/target"
)

const (
	schemaID               = "https://github.com/Yunushan/leaguebridge/schemas/ci-attestation.schema.json"
	schemaVersion          = 1
	attestationType        = "leaguebridge.ci-attestation.v1"
	maxDocumentSize        = 64 << 10
	maxSubjectSize         = 1 << 30
	maxRepositoryLength    = 255
	maxJobLength           = 128
	maxGitHubOutputSize    = 8 << 20
	maxReleaseArchiveSize  = int64(256 << 20)
	maxReleaseChecksumSize = int64(64 << 10)
	githubOIDCIssuer       = "https://token.actions.githubusercontent.com"
	slsaPredicateType      = "https://slsa.dev/provenance/v1"
	defaultRepository      = "Yunushan/leaguebridge"
	defaultWorkflowPath    = ".github/workflows/ci.yml"
	githubVerifyTimeout    = 5 * time.Minute
)

var (
	objectIDPattern   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	jobPattern        = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	runIDPattern      = regexp.MustCompile(`^[1-9][0-9]{0,31}$`)
	attemptPattern    = regexp.MustCompile(`^[1-9][0-9]{0,7}$`)
	goVersionPattern  = regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	refPattern        = regexp.MustCompile(`^refs/[A-Za-z0-9._/@-]{1,250}$`)
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
	GoVersion          string
	Command            string
	TargetGOOS         string
	TargetGOARCH       string
	SubjectPaths       []string
}

type verifyRequest struct {
	Kind             string
	SubjectPaths     []string
	ExpectedRepo     string
	ExpectedWorkflow string
	ExpectedCommit   string
	ExpectedTree     string
	ExpectedRef      string
	GHPath           string
	ReleaseDir       string
	ReleaseVersion   string
	WorkflowSHA      string
	RunID            string
	RunAttempt       string
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

type ghAttestationRunner func(context.Context, string, string, source) ([]byte, error)

var runGitHubAttestation ghAttestationRunner = runGitHubAttestationCommand

func main() {
	set := flag.NewFlagSet("ciattestation", flag.ExitOnError)
	verify := set.Bool("verify", false, "verify signed GitHub artifact attestations for a complete CI set")
	kind := set.String("kind", "", "attestation kind: race-vet, cross-build, or release")
	output := set.String("output", "", "new JSON subject path")
	generatedAt := set.String("generated-at", "", "canonical UTC RFC3339 generation timestamp; defaults to current UTC time")
	targetGOOS := set.String("target-goos", "", "target GOOS")
	targetGOARCH := set.String("target-goarch", "", "target GOARCH")
	command := set.String("command", "", "exact command description")
	var subjects stringList
	set.Var(&subjects, "subject", "regular file to hash; may be repeated for cross-build")
	var verifySubjects stringList
	set.Var(&verifySubjects, "verify-subject", "CI attestation subject JSON to verify; may be repeated")
	expectedRepository := set.String("expected-repository", defaultRepository, "expected GitHub owner/repository")
	expectedWorkflow := set.String("expected-workflow", defaultWorkflowPath, "expected workflow path relative to the repository")
	expectedCommit := set.String("expected-commit", "", "expected source commit object ID (required when verifying)")
	expectedTree := set.String("expected-tree", "", "expected source tree object ID (required when verifying)")
	expectedRef := set.String("expected-ref", "", "expected source ref (required when verifying)")
	expectedWorkflowSHA := set.String("expected-workflow-sha", "", "expected workflow revision object ID (required when verifying)")
	runID := set.String("run-id", "", "GitHub Actions run ID (required when verifying)")
	runAttempt := set.String("run-attempt", "", "GitHub Actions run attempt (required when verifying)")
	releaseDir := set.String("release-dir", "", "release artifact directory (required for release verification)")
	releaseVersion := set.String("release-version", "", "v-prefixed release version (required for release verification)")
	ghPath := set.String("gh", "gh", "GitHub CLI executable used for verification")
	if err := set.Parse(os.Args[1:]); err != nil {
		return
	}
	if *verify {
		if *output != "" || len(subjects) != 0 || *generatedAt != "" || *targetGOOS != "" || *targetGOARCH != "" || *command != "" {
			fail("generation flags cannot be used with -verify")
		}
		if err := verifySet(verifyRequest{
			Kind: *kind, SubjectPaths: verifySubjects, ExpectedRepo: *expectedRepository,
			ExpectedWorkflow: *expectedWorkflow, ExpectedCommit: *expectedCommit,
			ExpectedTree: *expectedTree, ExpectedRef: *expectedRef, GHPath: *ghPath,
			ReleaseDir: *releaseDir, ReleaseVersion: *releaseVersion,
			WorkflowSHA: *expectedWorkflowSHA, RunID: *runID, RunAttempt: *runAttempt,
		}); err != nil {
			fail("verify attestation set: %v", err)
		}
		if *kind == "release" {
			fmt.Printf("verified GitHub release attestation set version=%s subjects=9 commit=%s\n", *releaseVersion, *expectedCommit)
		} else {
			fmt.Printf("verified GitHub CI attestation set kind=%s subjects=%d commit=%s\n", *kind, len(verifySubjects), *expectedCommit)
		}
		return
	}
	if len(verifySubjects) != 0 || *expectedCommit != "" || *expectedTree != "" || *expectedRef != "" || *expectedRepository != defaultRepository || *expectedWorkflow != defaultWorkflowPath || *expectedWorkflowSHA != "" || *runID != "" || *runAttempt != "" || *releaseDir != "" || *releaseVersion != "" || *ghPath != "gh" {
		fail("verification flags require -verify")
	}
	if *output == "" {
		fail("-output is required")
	}
	if *generatedAt == "" {
		*generatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	document, err := build(request{
		Kind:               *kind,
		GeneratedAt:        *generatedAt,
		Repository:         os.Getenv("GITHUB_REPOSITORY"),
		Commit:             os.Getenv("GITHUB_SHA"),
		Tree:               os.Getenv("CI_ATTESTATION_TREE"),
		Ref:                os.Getenv("GITHUB_REF"),
		Workflow:           os.Getenv("GITHUB_WORKFLOW"),
		WorkflowRef:        os.Getenv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA:        os.Getenv("GITHUB_WORKFLOW_SHA"),
		RunID:              os.Getenv("GITHUB_RUN_ID"),
		RunAttempt:         os.Getenv("GITHUB_RUN_ATTEMPT"),
		Job:                os.Getenv("GITHUB_JOB"),
		RunnerOS:           os.Getenv("RUNNER_OS"),
		RunnerArchitecture: os.Getenv("RUNNER_ARCH"),
		GoVersion:          runtime.Version(),
		Command:            *command,
		TargetGOOS:         *targetGOOS,
		TargetGOARCH:       *targetGOARCH,
		SubjectPaths:       subjects,
	})
	if err != nil {
		fail("build CI attestation subject: %v", err)
	}
	data, err := marshal(document)
	if err != nil {
		fail("marshal CI attestation subject: %v", err)
	}
	if err := writeNew(*output, data); err != nil {
		fail("write CI attestation subject: %v", err)
	}
	fmt.Printf("created CI attestation subject %s\n", *output)
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

func build(input request) (document, error) {
	if input.Kind != "race-vet" && input.Kind != "cross-build" {
		return document{}, fmt.Errorf("kind must be race-vet or cross-build")
	}
	if err := validateSource(source{
		Repository: input.Repository, Commit: input.Commit, Tree: input.Tree,
		Ref: input.Ref, Workflow: input.Workflow, WorkflowRef: input.WorkflowRef,
		WorkflowSHA: input.WorkflowSHA, RunID: input.RunID, RunAttempt: input.RunAttempt,
	}); err != nil {
		return document{}, err
	}
	if err := validateExecution(execution{
		Job: input.Job, RunnerOS: input.RunnerOS, RunnerArchitecture: input.RunnerArchitecture,
		GoVersion: input.GoVersion, Command: input.Command,
		Target: target{GOOS: input.TargetGOOS, GOARCH: input.TargetGOARCH},
	}, input.Kind); err != nil {
		return document{}, err
	}
	generatedAt, err := canonicalTimestamp(input.GeneratedAt)
	if err != nil {
		return document{}, err
	}
	if input.Kind == "race-vet" && len(input.SubjectPaths) != 0 {
		return document{}, errors.New("race-vet subjects must be empty")
	}
	if input.Kind == "cross-build" && len(input.SubjectPaths) != 1 {
		return document{}, errors.New("cross-build requires exactly one binary subject")
	}

	result := document{
		Schema:          schemaID,
		SchemaVersion:   schemaVersion,
		AttestationType: attestationType,
		Kind:            input.Kind,
		GeneratedAt:     generatedAt,
		Source: source{
			Repository: input.Repository, Commit: input.Commit, Tree: input.Tree,
			Ref: input.Ref, Workflow: input.Workflow, WorkflowRef: input.WorkflowRef,
			WorkflowSHA: input.WorkflowSHA, RunID: input.RunID, RunAttempt: input.RunAttempt,
		},
		Execution: execution{
			Job: input.Job, RunnerOS: input.RunnerOS, RunnerArchitecture: input.RunnerArchitecture,
			GoVersion: input.GoVersion, Command: input.Command,
			Target: target{GOOS: input.TargetGOOS, GOARCH: input.TargetGOARCH},
		},
		Subjects: make([]subject, 0, len(input.SubjectPaths)),
	}
	for _, path := range input.SubjectPaths {
		item, err := hashSubject(path)
		if err != nil {
			return document{}, err
		}
		result.Subjects = append(result.Subjects, item)
	}
	sort.Slice(result.Subjects, func(i, j int) bool { return result.Subjects[i].Path < result.Subjects[j].Path })
	if err := validateDocument(result); err != nil {
		return document{}, err
	}
	return result, nil
}

type loadedDocument struct {
	Path  string
	Data  []byte
	Value document
}

// verifySet is the external-evidence boundary for CI readiness. It invokes
// GitHub CLI for every subject and never treats a copied subject JSON file as
// authentication. The expected commit, tree, ref, repository, and workflow
// are supplied by the caller so stale or forked evidence cannot silently be
// accepted for this repository.
func verifySet(input verifyRequest) error {
	if input.Kind == "release" {
		return verifyReleaseSet(input)
	}
	if input.Kind != "race-vet" && input.Kind != "cross-build" {
		return errors.New("kind must be race-vet or cross-build")
	}
	if input.ReleaseDir != "" || input.ReleaseVersion != "" {
		return errors.New("release verification flags require kind release")
	}
	if input.GHPath == "" {
		return errors.New("GitHub CLI path is required")
	}
	if len(input.SubjectPaths) == 0 {
		return errors.New("at least one -verify-subject is required")
	}
	if input.ExpectedRepo == "" || !repositoryPattern.MatchString(input.ExpectedRepo) || len(input.ExpectedRepo) > maxRepositoryLength {
		return errors.New("expected repository is invalid")
	}
	workflowPath, err := safeRelativePath(input.ExpectedWorkflow)
	if err != nil || workflowPath != filepath.ToSlash(input.ExpectedWorkflow) {
		return errors.New("expected workflow path is invalid")
	}
	if !objectIDPattern.MatchString(input.ExpectedCommit) || !objectIDPattern.MatchString(input.ExpectedTree) {
		return errors.New("expected commit and tree must be lowercase 40- or 64-character object IDs")
	}
	if !refPattern.MatchString(input.ExpectedRef) {
		return errors.New("expected ref is invalid")
	}
	if !objectIDPattern.MatchString(input.WorkflowSHA) {
		return errors.New("expected workflow SHA must be a lowercase 40- or 64-character object ID")
	}
	if !runIDPattern.MatchString(input.RunID) || !attemptPattern.MatchString(input.RunAttempt) {
		return errors.New("run ID and run attempt are invalid")
	}
	seenPaths := make(map[string]struct{}, len(input.SubjectPaths))
	loaded := make([]loadedDocument, 0, len(input.SubjectPaths))
	for _, path := range input.SubjectPaths {
		if _, duplicate := seenPaths[path]; duplicate {
			return fmt.Errorf("verification subject %q is duplicated", path)
		}
		seenPaths[path] = struct{}{}
		item, err := loadDocument(path)
		if err != nil {
			return err
		}
		if err := validateExpectedSource(item.Value, input, workflowPath); err != nil {
			return fmt.Errorf("subject %q: %w", path, err)
		}
		if item.Value.Kind != input.Kind {
			return fmt.Errorf("subject %q has kind %q; want %q", path, item.Value.Kind, input.Kind)
		}
		loaded = append(loaded, item)
	}
	if len(loaded) > 1 {
		commonSource := loaded[0].Value.Source
		for _, item := range loaded[1:] {
			if item.Value.Source != commonSource {
				return fmt.Errorf("verification subjects are not from one workflow run")
			}
		}
	}
	if err := validateSetShape(input.Kind, loaded); err != nil {
		return err
	}
	for _, item := range loaded {
		artifacts := []verifiedArtifact{{Path: item.Path, Digest: digestBytes(item.Data), Size: int64(len(item.Data))}}
		if item.Value.Kind == "cross-build" {
			declared := item.Value.Subjects[0]
			actual, err := hashSubject(declared.Path)
			if err != nil {
				return fmt.Errorf("subject %q binary %q: %w", item.Path, declared.Path, err)
			}
			if actual.SizeBytes != declared.SizeBytes || actual.SHA256 != declared.SHA256 {
				return fmt.Errorf("subject %q binary %q does not match its declared size or SHA-256", item.Path, declared.Path)
			}
			artifacts = append(artifacts, verifiedArtifact{Path: declared.Path, Digest: declared.SHA256, Size: declared.SizeBytes})
		}
		for _, artifact := range artifacts {
			if err := verifyGitHubArtifact(artifact, item.Value.Source, input.GHPath); err != nil {
				return fmt.Errorf("subject %q artifact %q: %w", item.Path, artifact.Path, err)
			}
		}
	}
	return nil
}

// verifyReleaseSet is the publication-evidence boundary. Release archives do
// not have a generated CI subject document, so the verifier derives the exact
// nine attested files from the v-prefixed release version, checks the canonical
// checksum manifest and then invokes the same certificate policy used by CI.
// The preceding releasecheck step binds each archive's embedded package
// manifest to the expected source tree; this mode binds the outer attestations
// to the expected commit, tag ref, workflow revision, run, and hosted runner.
func verifyReleaseSet(input verifyRequest) error {
	if input.GHPath == "" {
		return errors.New("GitHub CLI path is required")
	}
	if input.ReleaseDir == "" {
		return errors.New("release directory is required")
	}
	if !releaseversion.Valid(input.ReleaseVersion) {
		return errors.New("release version must be a valid v-prefixed Semantic Version")
	}
	if input.ExpectedRepo == "" || !repositoryPattern.MatchString(input.ExpectedRepo) || len(input.ExpectedRepo) > maxRepositoryLength {
		return errors.New("expected repository is invalid")
	}
	workflowPath, err := safeRelativePath(input.ExpectedWorkflow)
	if err != nil || workflowPath != filepath.ToSlash(input.ExpectedWorkflow) {
		return errors.New("expected workflow path is invalid")
	}
	if workflowPath != ".github/workflows/release.yml" {
		return errors.New("release verification requires .github/workflows/release.yml")
	}
	if !objectIDPattern.MatchString(input.ExpectedCommit) {
		return errors.New("expected commit must be a lowercase 40- or 64-character object ID")
	}
	if !refPattern.MatchString(input.ExpectedRef) {
		return errors.New("expected ref is invalid")
	}
	if input.ExpectedRef != "refs/tags/"+input.ReleaseVersion {
		return errors.New("release ref must exactly match the release version tag")
	}
	if !objectIDPattern.MatchString(input.WorkflowSHA) {
		return errors.New("expected workflow SHA must be a lowercase 40- or 64-character object ID")
	}
	if !runIDPattern.MatchString(input.RunID) || !attemptPattern.MatchString(input.RunAttempt) {
		return errors.New("run ID and run attempt are invalid")
	}
	if len(input.SubjectPaths) != 0 {
		return errors.New("release verification does not accept CI subject JSON paths")
	}

	releaseDirectory, err := filepath.Abs(input.ReleaseDir)
	if err != nil {
		return fmt.Errorf("resolve release directory: %w", err)
	}
	releaseRoot, err := fileinput.OpenDirectoryRoot(releaseDirectory)
	if err != nil {
		return fmt.Errorf("open release directory: %w", err)
	}
	defer releaseRoot.Close()

	names := releaseArchiveNames(input.ReleaseVersion)
	expected := make(map[string]struct{}, len(names)+1)
	expected["checksums.txt"] = struct{}{}
	for _, name := range names {
		expected[name] = struct{}{}
	}
	if err := verifyReleaseDirectory(releaseRoot, expected); err != nil {
		return err
	}

	archiveDigests := make(map[string]string, len(names))
	archiveSizes := make(map[string]int64, len(names))
	for _, name := range names {
		data, err := fileinput.ReadRegularBoundedFromRoot(releaseRoot, name, maxReleaseArchiveSize)
		if err != nil {
			return fmt.Errorf("read release archive %q: %w", name, err)
		}
		if len(data) == 0 {
			return fmt.Errorf("release archive %q is empty", name)
		}
		archiveDigests[name] = digestBytes(data)
		archiveSizes[name] = int64(len(data))
	}
	checksums, err := fileinput.ReadRegularBoundedFromRoot(releaseRoot, "checksums.txt", maxReleaseChecksumSize)
	if err != nil {
		return fmt.Errorf("read checksums.txt: %w", err)
	}
	if err := verifyReleaseChecksums(checksums, archiveDigests); err != nil {
		return err
	}
	checksumDigest := digestBytes(checksums)
	checksumSize := int64(len(checksums))

	value := source{
		Repository:  input.ExpectedRepo,
		Commit:      input.ExpectedCommit,
		Ref:         input.ExpectedRef,
		WorkflowRef: input.ExpectedRepo + "/" + workflowPath + "@" + input.ExpectedRef,
		WorkflowSHA: input.WorkflowSHA,
		RunID:       input.RunID,
		RunAttempt:  input.RunAttempt,
	}
	artifactNames := append([]string{"checksums.txt"}, names...)
	for _, name := range artifactNames {
		data, err := fileinput.ReadRegularBoundedFromRoot(releaseRoot, name, maxReleaseSizeFor(name))
		if err != nil {
			return fmt.Errorf("re-read release subject %q: %w", name, err)
		}
		artifact := verifiedArtifact{
			Path:   filepath.Join(releaseDirectory, name),
			Digest: digestBytes(data),
			Size:   int64(len(data)),
		}
		if name == "checksums.txt" {
			if artifact.Digest != checksumDigest || artifact.Size != checksumSize {
				return fmt.Errorf("checksums.txt changed before attestation verification")
			}
		} else {
			if artifact.Digest != archiveDigests[name] || artifact.Size != archiveSizes[name] {
				return fmt.Errorf("release archive %q changed before attestation verification", name)
			}
		}
		if err := verifyGitHubArtifactFromRoot(releaseRoot, name, artifact, value, input.GHPath); err != nil {
			return fmt.Errorf("release subject %q: %w", name, err)
		}
	}
	return nil
}

func releaseArchiveNames(version string) []string {
	base := "leaguebridge_" + strings.TrimPrefix(version, "v")
	names := make([]string, 0, len(targetcontract.Ordered()))
	for _, candidate := range targetcontract.Ordered() {
		names = append(names, base+"_"+candidate.GOOS+"_"+candidate.GOARCH+".tar.gz")
	}
	return names
}

func maxReleaseSizeFor(name string) int64 {
	if name == "checksums.txt" {
		return maxReleaseChecksumSize
	}
	return maxReleaseArchiveSize
}

func verifyReleaseDirectory(root *os.Root, expected map[string]struct{}) error {
	if root == nil {
		return errors.New("release directory root is nil")
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open release directory: %w", err)
	}
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close release directory: %w", closeErr)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected release directory entry %q", name)
		}
		info, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("inspect release subject %q: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("release subject %q is not a regular non-symlink file", name)
		}
		seen[name] = struct{}{}
	}
	for name := range expected {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("missing release subject %q", name)
		}
	}
	return nil
}

func verifyReleaseChecksums(data []byte, digests map[string]string) error {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return errors.New("checksums.txt must be non-empty and end with a newline")
	}
	if bytes.ContainsRune(data, '\r') {
		return errors.New("checksums.txt must use LF line endings")
	}
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != len(names) {
		return fmt.Errorf("checksums.txt has %d entries; want %d", len(lines), len(names))
	}
	for index, line := range lines {
		if len(line) < 69 || line[64:68] != " *./" || !sha256Pattern(line[:64]) {
			return fmt.Errorf("checksums.txt line %d is not canonical binary-mode sha256sum output", index+1)
		}
		name := line[68:]
		if name != names[index] {
			return fmt.Errorf("checksums.txt line %d names %q; want canonical entry %q", index+1, name, names[index])
		}
		if line[:64] != digests[name] {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
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
	if value.Source.WorkflowSHA == "" {
		return errors.New("workflow_sha is empty")
	}
	if value.Source.WorkflowSHA != input.WorkflowSHA {
		return fmt.Errorf("workflow_sha %q is not the expected %q", value.Source.WorkflowSHA, input.WorkflowSHA)
	}
	if value.Source.RunID != input.RunID || value.Source.RunAttempt != input.RunAttempt {
		return errors.New("source run ID or attempt does not match the expected workflow run")
	}
	return nil
}

func validateSetShape(kind string, values []loadedDocument) error {
	if kind == "race-vet" {
		if len(values) != 1 {
			return fmt.Errorf("race-vet verification requires exactly one subject, got %d", len(values))
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if value.Value.Execution.Job != "test" || value.Value.Execution.RunnerArchitecture != "X64" || value.Value.Execution.GoVersion != "go1.27.0" {
				return fmt.Errorf("race-vet subject %q is not from the pinned test job contract", value.Path)
			}
			goos := value.Value.Execution.Target.GOOS
			if goos != "linux" || value.Value.Execution.Target.GOARCH != "amd64" {
				return fmt.Errorf("race-vet subject %q has unexpected target %s/%s", value.Path, goos, value.Value.Execution.Target.GOARCH)
			}
			if _, duplicate := seen[goos]; duplicate {
				return fmt.Errorf("race-vet target %q is duplicated", goos)
			}
			seen[goos] = struct{}{}
			if value.Value.Execution.RunnerOS != "Linux" {
				return fmt.Errorf("race-vet target %q ran on %q; want Linux", goos, value.Value.Execution.RunnerOS)
			}
		}
		if len(seen) != 1 {
			return errors.New("race-vet set is missing the Linux subject")
		}
		return nil
	}

	expected := make(map[string]struct{}, len(targetcontract.Ordered()))
	for _, candidate := range targetcontract.Ordered() {
		expected[candidate.GOOS+"/"+candidate.GOARCH] = struct{}{}
	}
	if len(values) != len(expected) {
		return fmt.Errorf("cross-build verification requires exactly %d subjects, got %d", len(expected), len(values))
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value.Value.Execution.Job != "cross-build" || value.Value.Execution.RunnerOS != "Linux" || value.Value.Execution.RunnerArchitecture != "X64" || value.Value.Execution.GoVersion != "go1.27.0" {
			return fmt.Errorf("cross-build subject %q is not from the pinned cross-build job contract", value.Path)
		}
		key := value.Value.Execution.Target.GOOS + "/" + value.Value.Execution.Target.GOARCH
		if _, ok := expected[key]; !ok {
			return fmt.Errorf("cross-build subject %q has unexpected target %q", value.Path, key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("cross-build target %q is duplicated", key)
		}
		seen[key] = struct{}{}
	}
	for key := range expected {
		if _, ok := seen[key]; !ok {
			return fmt.Errorf("cross-build set is missing target %q", key)
		}
	}
	return nil
}

func loadDocument(path string) (loadedDocument, error) {
	normalized, err := safeRelativePath(path)
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
	if len(data) == 0 || len(data) > maxDocumentSize {
		return loadedDocument{}, fmt.Errorf("verification subject %q exceeds %d bytes", path, maxDocumentSize)
	}
	after, err := file.Stat()
	if err != nil {
		return loadedDocument{}, fmt.Errorf("inspect verification subject %q: %w", path, err)
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() || !os.SameFile(info, after) || !os.SameFile(info, pathAfter) || after.Size() != int64(len(data)) || pathAfter.Size() != int64(len(data)) {
		return loadedDocument{}, fmt.Errorf("verification subject %q changed while reading", path)
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
			return loadedDocument{}, fmt.Errorf("decode verification subject %q: multiple JSON values", path)
		}
		return loadedDocument{}, fmt.Errorf("decode verification subject %q: trailing data: %w", path, err)
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
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
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

type verifiedArtifact struct {
	Path   string
	Digest string
	Size   int64
}

func verifyGitHubArtifact(artifact verifiedArtifact, value source, ghPath string) error {
	if artifact.Size <= 0 || !sha256Pattern(artifact.Digest) {
		return fmt.Errorf("artifact %q has an invalid expected digest", artifact.Path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), githubVerifyTimeout)
	defer cancel()
	output, err := runGitHubAttestation(ctx, ghPath, artifact.Path, value)
	if err != nil {
		return err
	}
	if err := verifyGitHubOutput(output, artifact.Digest, value); err != nil {
		return err
	}
	actual, err := hashSubject(artifact.Path)
	if err != nil {
		return fmt.Errorf("recheck artifact %q after GitHub verification: %w", artifact.Path, err)
	}
	if actual.SizeBytes != artifact.Size || actual.SHA256 != artifact.Digest {
		return fmt.Errorf("artifact %q changed during GitHub verification", artifact.Path)
	}
	return nil
}

func verifyGitHubArtifactFromRoot(root *os.Root, name string, artifact verifiedArtifact, value source, ghPath string) error {
	if root == nil {
		return errors.New("release directory root is nil")
	}
	if artifact.Size <= 0 || !sha256Pattern(artifact.Digest) {
		return fmt.Errorf("artifact %q has an invalid expected digest", artifact.Path)
	}
	before, err := fileinput.ReadRegularBoundedFromRoot(root, name, maxReleaseSizeFor(name))
	if err != nil {
		return fmt.Errorf("read artifact before GitHub verification: %w", err)
	}
	if int64(len(before)) != artifact.Size || digestBytes(before) != artifact.Digest {
		return fmt.Errorf("artifact %q changed before GitHub verification", artifact.Path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), githubVerifyTimeout)
	defer cancel()
	output, err := runGitHubAttestation(ctx, ghPath, artifact.Path, value)
	if err != nil {
		return err
	}
	if err := verifyGitHubOutput(output, artifact.Digest, value); err != nil {
		return err
	}
	after, err := fileinput.ReadRegularBoundedFromRoot(root, name, maxReleaseSizeFor(name))
	if err != nil {
		return fmt.Errorf("recheck artifact %q after GitHub verification: %w", artifact.Path, err)
	}
	if int64(len(after)) != artifact.Size || digestBytes(after) != artifact.Digest {
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
		"--repo", value.Repository,
		"--signer-workflow", signerWorkflow,
		"--source-ref", value.Ref,
		"--source-digest", value.Commit,
		"--cert-oidc-issuer", githubOIDCIssuer,
		"--deny-self-hosted-runners",
		"--predicate-type", slsaPredicateType,
		"--format", "json")
	stdout := &boundedBuffer{Maximum: maxGitHubOutputSize}
	stderr := &boundedBuffer{Maximum: maxGitHubOutputSize}
	command.Stdout = stdout
	command.Stderr = stderr
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
	if _, err := safeRelativePath(workflowPath); err != nil {
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
	if !sha256Pattern(expectedDigest) {
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
	for _, subject := range result.Statement.Subjects {
		if subject.Name == "" {
			continue
		}
		if subject.Digest["sha256"] == expectedDigest {
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
		"issuer":                   githubOIDCIssuer,
		"subjectAlternativeName":   workflowURI,
		"githubWorkflowRepository": value.Repository,
		"githubWorkflowRef":        value.Ref,
		"githubWorkflowSHA":        value.WorkflowSHA,
		"buildSignerURI":           workflowURI,
		"buildSignerDigest":        value.WorkflowSHA,
		"buildConfigURI":           workflowURI,
		"buildConfigDigest":        value.WorkflowSHA,
		"runnerEnvironment":        "github-hosted",
		"sourceRepositoryURI":      repositoryURI,
		"sourceRepositoryDigest":   value.Commit,
		"sourceRepositoryRef":      value.Ref,
		"runInvocationURI":         runURI,
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

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validateTarget(kind, goos, goarch string) error {
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
	default:
		return fmt.Errorf("unsupported target operating system %q", goos)
	}
	if !targetcontract.IsSupported(goos, goarch) {
		return fmt.Errorf("unsupported target %s/%s", goos, goarch)
	}
	if kind == "race-vet" && (goos != "linux" || goarch != "amd64") {
		return errors.New("race-vet target must be linux/amd64")
	}
	return nil
}

func validateSource(value source) error {
	if !repositoryPattern.MatchString(value.Repository) {
		return errors.New("repository must be a bounded owner/repository identifier")
	}
	if len(value.Repository) > maxRepositoryLength {
		return errors.New("repository is too long")
	}
	for name, candidate := range map[string]string{
		"commit": value.Commit, "tree": value.Tree, "workflow_sha": value.WorkflowSHA,
	} {
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
	if !jobPattern.MatchString(value.Job) || len(value.Job) > maxJobLength {
		return errors.New("job must be a bounded lowercase identifier")
	}
	if value.RunnerOS != "Linux" {
		return fmt.Errorf("unsupported runner OS %q", value.RunnerOS)
	}
	if value.RunnerArchitecture != "X64" {
		return fmt.Errorf("unsupported runner architecture %q", value.RunnerArchitecture)
	}
	if !goVersionPattern.MatchString(value.GoVersion) {
		return fmt.Errorf("go version must use canonical go1.x.y form")
	}
	if !boundedText(value.Command, 512) {
		return errors.New("command is required, bounded, and must not contain control characters")
	}
	return validateTarget(kind, value.Target.GOOS, value.Target.GOARCH)
}

func hashSubject(path string) (subject, error) {
	normalized, err := safeRelativePath(path)
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
	if info.Size() <= 0 || info.Size() > maxSubjectSize {
		return subject{}, fmt.Errorf("subject %q size %d is outside 1..%d bytes", path, info.Size(), maxSubjectSize)
	}
	digest := sha256.New()
	if _, err := io.CopyN(digest, file, info.Size()); err != nil {
		return subject{}, fmt.Errorf("hash subject %q: %w", path, err)
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); err != io.EOF || count != 0 {
		return subject{}, fmt.Errorf("subject %q changed while hashing", path)
	}
	if err := validateSubjectAfterHash(path, info, file); err != nil {
		return subject{}, err
	}
	return subject{Path: normalized, Role: "cross-build-binary", SizeBytes: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
}

func validateSubjectAfterHash(path string, expected os.FileInfo, file *os.File) error {
	if expected == nil || file == nil {
		return fmt.Errorf("subject %q changed while hashing", path)
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect subject %q after hashing: %w", path, err)
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect subject %q after hashing: %w", path, err)
	}
	if !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(expected, after) || !os.SameFile(expected, pathAfter) ||
		after.Size() != expected.Size() || pathAfter.Size() != expected.Size() {
		return fmt.Errorf("subject %q changed while hashing", path)
	}
	return nil
}

func safeRelativePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" || filepath.IsAbs(path) || strings.ContainsRune(path, '\\') {
		return "", fmt.Errorf("subject path %q must be a non-empty relative path", path)
	}
	raw := filepath.ToSlash(path)
	for _, component := range strings.Split(raw, "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("subject path %q is unsafe", path)
		}
	}
	normalized := filepath.ToSlash(filepath.Clean(path))
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") || strings.Contains(normalized, "//") || strings.Contains(normalized, ":") {
		return "", fmt.Errorf("subject path %q is unsafe", path)
	}
	for _, component := range strings.Split(normalized, "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("subject path %q is unsafe", path)
		}
	}
	if len(normalized) > 256 || strings.ContainsAny(normalized, "\x00\r\n") {
		return "", fmt.Errorf("subject path %q is invalid", path)
	}
	return normalized, nil
}

func validateDocument(value document) error {
	if value.Schema != schemaID || value.SchemaVersion != schemaVersion || value.AttestationType != attestationType {
		return errors.New("CI attestation subject identity is invalid")
	}
	if value.Kind != "race-vet" && value.Kind != "cross-build" {
		return fmt.Errorf("kind must be race-vet or cross-build")
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
	if value.Kind == "cross-build" && len(value.Subjects) != 1 {
		return errors.New("cross-build attestation subject must contain one binary subject")
	}
	if value.Kind == "race-vet" && len(value.Subjects) != 0 {
		return errors.New("race-vet attestation subject cannot contain binary subjects")
	}
	expectedPath := ""
	if value.Kind == "cross-build" {
		expectedPath = crossBuildSubjectPath(value.Execution.Target)
	}
	previous := ""
	for _, item := range value.Subjects {
		normalized, err := safeRelativePath(item.Path)
		if err != nil || normalized != item.Path {
			return fmt.Errorf("invalid CI attestation subject path %q", item.Path)
		}
		if expectedPath != "" && item.Path != expectedPath {
			return fmt.Errorf("CI attestation subject path %q is not bound to target %s/%s", item.Path, value.Execution.Target.GOOS, value.Execution.Target.GOARCH)
		}
		if item.Path <= previous {
			return errors.New("CI attestation subjects must be strictly sorted and unique")
		}
		previous = item.Path
		if item.Role != "cross-build-binary" || item.SizeBytes <= 0 || item.SizeBytes > maxSubjectSize || !sha256Pattern(item.SHA256) {
			return fmt.Errorf("invalid CI attestation subject %q", item.Path)
		}
	}
	return nil
}

func crossBuildSubjectPath(value target) string {
	return fmt.Sprintf("ci-build/leaguebridge-%s-%s", value.GOOS, value.GOARCH)
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
		return nil, fmt.Errorf("CI attestation subject exceeds %d bytes", maxDocumentSize)
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
	clean := filepath.Clean(absolute)
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(clean))
	if err != nil {
		return fmt.Errorf("open output parent: %w", err)
	}
	defer parent.Close()
	name := filepath.Base(clean)
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

func sha256Pattern(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "ciattestation: "+format+"\n", arguments...)
	os.Exit(2)
}
