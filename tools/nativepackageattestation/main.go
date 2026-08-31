// Command nativepackageattestation generates and verifies score-free evidence
// for native package builders. Package bytes and their staging inputs must be
// signed by GitHub's artifact-attestation service before they can be used for
// a readiness assessment.
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
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

const (
	schemaID               = "https://github.com/Yunushan/leaguebridge/schemas/native-package-attestation.schema.json"
	schemaVersion          = 1
	attestationType        = "leaguebridge.native-package-attestation.v1"
	defaultRepository      = "Yunushan/leaguebridge"
	defaultWorkflow        = ".github/workflows/ci.yml"
	maxDocumentSize        = 128 << 10
	maxSubjectSize         = int64(256 << 20)
	maxInstallEvidenceSize = int64(1 << 20)
	maxEvidenceFiles       = 8
	maxGitHubOutput        = 8 << 20
	githubTimeout          = 5 * time.Minute
	githubOIDCIssuer       = "https://token.actions.githubusercontent.com"
	slsaPredicateType      = "https://slsa.dev/provenance/v1"
)

var (
	objectIDPattern   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	jobPattern        = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	runIDPattern      = regexp.MustCompile(`^[1-9][0-9]{0,31}$`)
	attemptPattern    = regexp.MustCompile(`^[1-9][0-9]{0,7}$`)
	goVersionPattern  = regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	refPattern        = regexp.MustCompile(`^refs/[A-Za-z0-9._/@-]{1,250}$`)
	filenamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,240}$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
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
	Job                string          `json:"job"`
	RunnerOS           string          `json:"runner_os"`
	RunnerArchitecture string          `json:"runner_architecture"`
	HostClass          string          `json:"host_class"`
	GoVersion          string          `json:"go_version"`
	Command            string          `json:"command"`
	Target             target          `json:"target"`
	Package            packageArtifact `json:"package"`
}

type target struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

type packageArtifact struct {
	Family              string `json:"family"`
	Format              string `json:"format"`
	Version             string `json:"version"`
	Filename            string `json:"filename"`
	StagingManifestPath string `json:"staging_manifest_path"`
	InstallEvidencePath string `json:"install_evidence_path"`
}

type subject struct {
	Path      string `json:"path"`
	Role      string `json:"role"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type request struct {
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
	Family             string
	Format             string
	PackagePath        string
	StagingDir         string
	InstallEvidence    string
	OutputPath         string
}

type verifyRequest struct {
	SubjectPaths     []string
	ExpectedRepo     string
	ExpectedWorkflow string
	ExpectedCommit   string
	ExpectedTree     string
	ExpectedRef      string
	WorkflowSHA      string
	RunID            string
	RunAttempt       string
	GHPath           string
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

type ghAttestationRunner func(context.Context, string, string, source) ([]byte, error)

var runGitHubAttestation ghAttestationRunner = runGitHubAttestationCommand

func main() {
	set := flag.NewFlagSet("nativepackageattestation", flag.ExitOnError)
	verify := set.Bool("verify", false, "verify signed native package attestations")
	output := set.String("output", "", "new JSON subject path")
	generatedAt := set.String("generated-at", "", "canonical UTC RFC3339 generation timestamp; defaults to current UTC time")
	targetGOOS := set.String("target-goos", "", "target GOOS")
	targetGOARCH := set.String("target-goarch", "", "target GOARCH")
	family := set.String("family", "", "native package family")
	format := set.String("format", "", "native package byte format")
	packagePath := set.String("package", "", "new native package path")
	stagingDir := set.String("staging-dir", "", "verified native package staging directory")
	installEvidence := set.String("install-evidence", "", "native package install-test evidence path")
	command := set.String("command", "", "bounded description of the package build and install test")
	var verifySubjects stringList
	set.Var(&verifySubjects, "verify-subject", "native package attestation subject JSON to verify; may be repeated")
	expectedRepository := set.String("expected-repository", defaultRepository, "expected GitHub owner/repository")
	expectedWorkflow := set.String("expected-workflow", defaultWorkflow, "expected workflow path relative to the repository")
	expectedCommit := set.String("expected-commit", "", "expected source commit object ID (required when verifying)")
	expectedTree := set.String("expected-tree", "", "expected source tree object ID (required when verifying)")
	expectedRef := set.String("expected-ref", "", "expected source ref (required when verifying)")
	expectedWorkflowSHA := set.String("expected-workflow-sha", "", "expected workflow revision object ID (required when verifying)")
	runID := set.String("run-id", "", "GitHub Actions run ID (required when verifying)")
	runAttempt := set.String("run-attempt", "", "GitHub Actions run attempt (required when verifying)")
	ghPath := set.String("gh", "gh", "GitHub CLI executable used for verification")
	if err := set.Parse(os.Args[1:]); err != nil {
		return
	}
	if *verify {
		if *output != "" || *generatedAt != "" || *targetGOOS != "" || *targetGOARCH != "" || *family != "" || *format != "" || *packagePath != "" || *stagingDir != "" || *installEvidence != "" || *command != "" {
			fail("generation flags cannot be used with -verify")
		}
		if err := verifySet(verifyRequest{
			SubjectPaths: verifySubjects, ExpectedRepo: *expectedRepository,
			ExpectedWorkflow: *expectedWorkflow, ExpectedCommit: *expectedCommit,
			ExpectedTree: *expectedTree, ExpectedRef: *expectedRef,
			WorkflowSHA: *expectedWorkflowSHA, RunID: *runID, RunAttempt: *runAttempt,
			GHPath: *ghPath,
		}); err != nil {
			fail("verify native package attestations: %v", err)
		}
		fmt.Printf("verified GitHub native package attestation set subjects=%d commit=%s\n", len(verifySubjects), *expectedCommit)
		return
	}
	if len(verifySubjects) != 0 || *expectedCommit != "" || *expectedTree != "" || *expectedRef != "" || *expectedRepository != defaultRepository || *expectedWorkflow != defaultWorkflow || *expectedWorkflowSHA != "" || *runID != "" || *runAttempt != "" || *ghPath != "gh" {
		fail("verification flags require -verify")
	}
	if *output == "" || *targetGOOS == "" || *targetGOARCH == "" || *family == "" || *format == "" || *packagePath == "" || *stagingDir == "" || *installEvidence == "" || *command == "" {
		fail("output, target, family, format, package, staging-dir, install-evidence, and command are required")
	}
	if *generatedAt == "" {
		*generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	outputPath, err := normalizedRelativePath(*output)
	if err != nil {
		fail("output path: %v", err)
	}
	document, err := build(request{
		GeneratedAt: *generatedAt,
		Repository:  os.Getenv("GITHUB_REPOSITORY"), Commit: os.Getenv("GITHUB_SHA"),
		Tree: os.Getenv("CI_ATTESTATION_TREE"), Ref: os.Getenv("GITHUB_REF"),
		Workflow: os.Getenv("GITHUB_WORKFLOW"), WorkflowRef: os.Getenv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA: os.Getenv("GITHUB_WORKFLOW_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"),
		RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Job: os.Getenv("GITHUB_JOB"),
		RunnerOS: os.Getenv("RUNNER_OS"), RunnerArchitecture: os.Getenv("RUNNER_ARCH"),
		HostClass: expectedHostClass(*family), GoVersion: runtime.Version(), Command: *command,
		TargetGOOS: *targetGOOS, TargetGOARCH: *targetGOARCH, Family: *family, Format: *format,
		PackagePath: *packagePath, StagingDir: *stagingDir, InstallEvidence: *installEvidence,
		OutputPath: outputPath,
	})
	if err != nil {
		fail("build native package attestation subject: %v", err)
	}
	data, err := marshal(document)
	if err != nil {
		fail("marshal native package attestation subject: %v", err)
	}
	if err := writeNew(*output, data); err != nil {
		fail("write native package attestation subject: %v", err)
	}
	fmt.Printf("created native package attestation subject %s\n", *output)
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("verification subject path must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func build(input request) (document, error) {
	if _, err := canonicalTimestamp(input.GeneratedAt); err != nil {
		return document{}, err
	}
	value := document{
		Schema: schemaID, SchemaVersion: schemaVersion, AttestationType: attestationType,
		Kind: "native-package", GeneratedAt: input.GeneratedAt,
		Source: source{Repository: input.Repository, Commit: input.Commit, Tree: input.Tree,
			Ref: input.Ref, Workflow: input.Workflow, WorkflowRef: input.WorkflowRef,
			WorkflowSHA: input.WorkflowSHA, RunID: input.RunID, RunAttempt: input.RunAttempt},
		Execution: execution{Job: input.Job, RunnerOS: input.RunnerOS,
			RunnerArchitecture: input.RunnerArchitecture, HostClass: input.HostClass,
			GoVersion: input.GoVersion, Command: input.Command,
			Target:  target{GOOS: input.TargetGOOS, GOARCH: input.TargetGOARCH},
			Package: packageArtifact{Family: input.Family, Format: input.Format}},
	}
	if err := validateSource(value.Source); err != nil {
		return document{}, err
	}
	packagePath, err := normalizedRelativePath(input.PackagePath)
	if err != nil {
		return document{}, fmt.Errorf("package path: %w", err)
	}
	stagingDir, err := normalizedRelativePath(input.StagingDir)
	if err != nil {
		return document{}, fmt.Errorf("staging directory: %w", err)
	}
	installEvidence, err := normalizedRelativePath(input.InstallEvidence)
	if err != nil {
		return document{}, fmt.Errorf("install evidence path: %w", err)
	}
	outputPath, err := normalizedRelativePath(input.OutputPath)
	if err != nil {
		return document{}, fmt.Errorf("output path: %w", err)
	}
	stagingRoot, err := fileinput.OpenDirectoryRoot(stagingDir)
	if err != nil {
		return document{}, fmt.Errorf("open staging directory: %w", err)
	}
	manifest, err := nativepackage.VerifyStagingRoot(stagingRoot)
	closeErr := stagingRoot.Close()
	if err != nil {
		return document{}, fmt.Errorf("verify staging directory: %w", err)
	}
	if closeErr != nil {
		return document{}, fmt.Errorf("close staging directory: %w", closeErr)
	}
	if string(manifest.Package.Family) != input.Family || manifest.Target.GOOS != input.TargetGOOS || manifest.Target.GOARCH != input.TargetGOARCH {
		return document{}, errors.New("package family or target does not match the verified staging manifest")
	}
	value.Execution.Package.Version = manifest.Version
	value.Execution.Package.Filename = path.Base(packagePath)
	value.Execution.Package.StagingManifestPath = filepath.ToSlash(filepath.Join(stagingDir, nativepackage.StagingManifestName))
	value.Execution.Package.InstallEvidencePath = installEvidence
	if err := validateExecution(value.Execution); err != nil {
		return document{}, err
	}
	if err := validateInstallEvidence(input.InstallEvidence, input.Family, manifest.Version, value.Execution.Package.Filename, value.Execution.Target); err != nil {
		return document{}, err
	}
	seen := make(map[string]struct{})
	packageSubject, err := hashPath(packagePath, "package")
	if err != nil {
		return document{}, err
	}
	seen[packageSubject.Path] = struct{}{}
	value.Subjects = append(value.Subjects, packageSubject)
	stagingSubjects, err := hashStagingTree(stagingDir, outputPath, seen)
	if err != nil {
		return document{}, err
	}
	value.Subjects = append(value.Subjects, stagingSubjects...)
	installSubject, err := hashPath(installEvidence, "package-install-evidence")
	if err != nil {
		return document{}, err
	}
	if _, duplicate := seen[installSubject.Path]; duplicate {
		return document{}, fmt.Errorf("install evidence path %q is duplicated", installSubject.Path)
	}
	value.Subjects = append(value.Subjects, installSubject)
	sort.Slice(value.Subjects, func(i, j int) bool { return value.Subjects[i].Path < value.Subjects[j].Path })
	if err := validateDocument(value); err != nil {
		return document{}, err
	}
	return value, nil
}

func hashStagingTree(directory, outputPath string, seen map[string]struct{}) ([]subject, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve staging directory: %w", err)
	}
	if err := fileinput.RejectSymlinkedParents(absolute); err != nil {
		return nil, fmt.Errorf("staging directory path: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect staging directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("staging directory must be a regular non-symlink directory")
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
			return fmt.Errorf("staging tree contains symlink %q", path)
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("staging entry %q is not a regular file", path)
		}
		relative, err := filepath.Rel(workingDirectory, path)
		if err != nil {
			return fmt.Errorf("relativize staging file %q: %w", path, err)
		}
		relative = filepath.ToSlash(relative)
		normalized, err := normalizedRelativePath(relative)
		if err != nil {
			return fmt.Errorf("staging file %q: %w", path, err)
		}
		if normalized == outputPath {
			return nil
		}
		if _, duplicate := seen[normalized]; duplicate {
			return fmt.Errorf("staging file %q is also another subject", normalized)
		}
		role := "staging-payload"
		if normalized == filepath.ToSlash(filepath.Join(directory, nativepackage.StagingManifestName)) {
			role = "staging-manifest"
		}
		item, err := hashPath(normalized, role)
		if err != nil {
			return err
		}
		seen[normalized] = struct{}{}
		result = append(result, item)
		if len(result) > maxEvidenceFiles-2 {
			return fmt.Errorf("staging directory contains more than %d files", maxEvidenceFiles-2)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory staging directory: %w", err)
	}
	if len(result) != 6 {
		return nil, fmt.Errorf("staging directory contains %d regular files; want exactly 6", len(result))
	}
	return result, nil
}

func verifySet(input verifyRequest) error {
	if input.GHPath == "" {
		return errors.New("GitHub CLI path is required")
	}
	if len(input.SubjectPaths) == 0 {
		return errors.New("at least one -verify-subject is required")
	}
	if input.ExpectedRepo == "" || !repositoryPattern.MatchString(input.ExpectedRepo) {
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
		loaded = append(loaded, item)
	}
	if err := validateSetShape(loaded); err != nil {
		return err
	}
	commonSource := loaded[0].Value.Source
	seenArtifacts := make(map[string]struct{})
	for _, item := range loaded {
		if err := verifyStagingDocument(item.Value); err != nil {
			return fmt.Errorf("subject %q staging: %w", item.Path, err)
		}
		artifact := item.Value.Execution.Package
		if err := validateInstallEvidence(artifact.InstallEvidencePath, artifact.Family, artifact.Version, artifact.Filename, item.Value.Execution.Target); err != nil {
			return fmt.Errorf("subject %q install evidence: %w", item.Path, err)
		}
		artifacts := []verifiedArtifact{{Path: item.Path, Digest: digestBytes(item.Data), Size: int64(len(item.Data))}}
		for _, declared := range item.Value.Subjects {
			if _, duplicate := seenArtifacts[declared.Path]; duplicate {
				return fmt.Errorf("package artifact %q is listed more than once", declared.Path)
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

func verifyStagingDocument(value document) error {
	manifestPath := value.Execution.Package.StagingManifestPath
	stagingDirectory := filepath.ToSlash(filepath.Dir(manifestPath))
	root, err := fileinput.OpenDirectoryRoot(stagingDirectory)
	if err != nil {
		return fmt.Errorf("open staging directory: %w", err)
	}
	manifest, verifyErr := nativepackage.VerifyStagingRoot(root)
	closeErr := root.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return fmt.Errorf("close staging directory: %w", closeErr)
	}
	artifact := value.Execution.Package
	if string(manifest.Package.Family) != artifact.Family || manifest.Version != artifact.Version || manifest.Target.GOOS != value.Execution.Target.GOOS || manifest.Target.GOARCH != value.Execution.Target.GOARCH {
		return errors.New("staging manifest identity does not match the attestation package")
	}
	stagingDirectory = filepath.ToSlash(stagingDirectory)
	expectedManifestPath := path.Join(stagingDirectory, nativepackage.StagingManifestName)
	if artifact.StagingManifestPath != expectedManifestPath {
		return errors.New("staging manifest path is not rooted in its staging directory")
	}
	expectedPayloads := make(map[string]struct{}, len(manifest.Payload))
	for _, entry := range manifest.Payload {
		relative := strings.TrimPrefix(entry.InstallPath, "/")
		expectedPayloads[path.Join(stagingDirectory, "root", relative)] = struct{}{}
	}
	actualPayloads := make(map[string]struct{}, len(manifest.Payload))
	for _, entry := range value.Subjects {
		if entry.Role == "staging-payload" {
			actualPayloads[entry.Path] = struct{}{}
		}
	}
	if len(actualPayloads) != len(expectedPayloads) {
		return errors.New("staging payload subject set is not bound to the verified staging manifest")
	}
	for expected := range expectedPayloads {
		if _, ok := actualPayloads[expected]; !ok {
			return fmt.Errorf("staging payload subject %q is missing", expected)
		}
	}
	return nil
}

// validateInstallEvidence keeps the package-install subject meaningful at the
// verifier boundary. The log remains an observation, not a signature or a
// substitute for package-manager metadata, but it must at least be the bounded
// output of the declared package/version smoke test rather than an arbitrary
// opaque file.
func validateInstallEvidence(path, family, version, filename string, targetValue target) error {
	normalized, err := normalizedRelativePath(path)
	if err != nil || normalized != filepath.ToSlash(path) {
		return fmt.Errorf("install evidence path %q is invalid", path)
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return fmt.Errorf("open install evidence: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat install evidence: %w", err)
	}
	if info.Size() <= 0 || info.Size() > maxInstallEvidenceSize {
		return fmt.Errorf("install evidence size is outside 1..%d bytes", maxInstallEvidenceSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxInstallEvidenceSize+1))
	if err != nil {
		return fmt.Errorf("read install evidence: %w", err)
	}
	if len(data) == 0 || int64(len(data)) > maxInstallEvidenceSize || bytes.IndexByte(data, 0) >= 0 {
		return fmt.Errorf("install evidence is empty, oversized, or contains NUL bytes")
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect install evidence after reading: %w", err)
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() || !os.SameFile(info, after) || !os.SameFile(info, pathAfter) || after.Size() != int64(len(data)) || pathAfter.Size() != int64(len(data)) {
		return errors.New("install evidence changed while reading")
	}
	expected := map[string]string{
		"package":   "package=" + family,
		"version":   "version=" + version,
		"filename":  "filename=" + filename,
		"target":    "target=" + targetValue.GOOS + "/" + targetValue.GOARCH,
		"install":   "install=pass",
		"uninstall": "uninstall=pass",
	}
	seen := make(map[string]int, len(expected))
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		for key, want := range expected {
			prefix := key + "="
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			seen[key]++
			if line != want {
				return fmt.Errorf("install evidence has invalid %s marker %q", key, line)
			}
		}
	}
	for key, want := range expected {
		switch seen[key] {
		case 0:
			return fmt.Errorf("install evidence is missing required line %q", want)
		case 1:
		default:
			return fmt.Errorf("install evidence contains duplicate %s markers", key)
		}
	}
	return nil
}

func validateSetShape(values []loadedDocument) error {
	expected := map[string]string{
		"debian": "linux/amd64", "rpm": "linux/amd64",
		"freebsd-pkg": "freebsd/amd64", "openbsd-pkg": "openbsd/amd64",
		"pkgsrc": "netbsd/amd64", "dports": "dragonfly/amd64",
	}
	if len(values) != len(expected) {
		return fmt.Errorf("native package verification requires exactly %d subjects, got %d", len(expected), len(values))
	}
	seen := make(map[string]struct{}, len(values))
	version := ""
	for _, value := range values {
		artifact := value.Value.Execution.Package
		key := string(artifact.Family)
		want, ok := expected[key]
		if !ok {
			return fmt.Errorf("subject %q has unexpected package family %q", value.Path, artifact.Family)
		}
		got := value.Value.Execution.Target.GOOS + "/" + value.Value.Execution.Target.GOARCH
		if got != want {
			return fmt.Errorf("subject %q has target %q; want %q", value.Path, got, want)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("package family %q is duplicated", key)
		}
		seen[key] = struct{}{}
		job, runner, arch, host := expectedExecution(value.Value.Execution.Target, artifact.Family)
		if value.Value.Execution.Job != job || value.Value.Execution.RunnerOS != runner || value.Value.Execution.RunnerArchitecture != arch || value.Value.Execution.HostClass != host || value.Value.Execution.GoVersion != "go1.27.0" {
			return fmt.Errorf("subject %q is not from the pinned native package job contract", value.Path)
		}
		if version == "" {
			version = artifact.Version
		} else if artifact.Version != version {
			return errors.New("native package set contains mixed package versions")
		}
	}
	for key := range expected {
		if _, ok := seen[key]; !ok {
			return fmt.Errorf("native package set is missing family %q", key)
		}
	}
	return nil
}

func expectedExecution(targetValue target, family string) (job, runner, architecture, hostClass string) {
	switch targetValue.GOOS {
	case "linux":
		return "native-package-linux", "Linux", "X64", "hosted"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		return "native-package-bsd", "Linux", "X64", "virtualized"
	default:
		return "", "", "", ""
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
	if err := exactjson.ValidateKeys(data, document{}); err != nil {
		return loadedDocument{}, fmt.Errorf("verification subject %q fields are invalid: %w", path, err)
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
			return loadedDocument{}, errors.New("verification subject contains multiple JSON values")
		}
		return loadedDocument{}, fmt.Errorf("verification subject has trailing JSON data: %w", err)
	}
	if err := validateDocument(value); err != nil {
		return loadedDocument{}, fmt.Errorf("verification subject %q: %w", path, err)
	}
	canonical, err := marshal(value)
	if err != nil {
		return loadedDocument{}, fmt.Errorf("canonicalize verification subject %q: %w", path, err)
	}
	if !bytes.Equal(data, canonical) {
		return loadedDocument{}, fmt.Errorf("verification subject %q is not canonical", path)
	}
	return loadedDocument{Path: normalized, Data: data, Value: value}, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch delimiter := token.(type) {
		case json.Delim:
			switch delimiter {
			case '{':
				seen := map[string]struct{}{}
				for decoder.More() {
					key, err := decoder.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok {
						return errors.New("object key is not a string")
					}
					if _, duplicate := seen[name]; duplicate {
						return fmt.Errorf("duplicate JSON key %q", name)
					}
					seen[name] = struct{}{}
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			case '[':
				for decoder.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			}
		}
		return nil
	}
	if err := walk(); err != nil {
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

func validateExpectedSource(value document, input verifyRequest, workflowPath string) error {
	expectedWorkflowRef := input.ExpectedRepo + "/" + workflowPath + "@" + input.ExpectedRef
	if value.Source.Repository != input.ExpectedRepo {
		return fmt.Errorf("repository %q is not the expected %q", value.Source.Repository, input.ExpectedRepo)
	}
	if value.Source.Commit != input.ExpectedCommit || value.Source.Tree != input.ExpectedTree || value.Source.Ref != input.ExpectedRef {
		return errors.New("source commit, tree, or ref does not match the expected checkout")
	}
	if value.Source.WorkflowRef != expectedWorkflowRef || value.Source.WorkflowSHA != input.WorkflowSHA {
		return errors.New("workflow identity does not match the expected workflow revision")
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

func validateDocument(value document) error {
	if value.Schema != schemaID || value.SchemaVersion != schemaVersion || value.AttestationType != attestationType || value.Kind != "native-package" {
		return errors.New("native package attestation subject identity is invalid")
	}
	if _, err := canonicalTimestamp(value.GeneratedAt); err != nil {
		return err
	}
	if err := validateSource(value.Source); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if err := validateExecution(value.Execution); err != nil {
		return fmt.Errorf("execution: %w", err)
	}
	if len(value.Subjects) != maxEvidenceFiles {
		return fmt.Errorf("native package attestation must contain exactly %d subjects", maxEvidenceFiles)
	}
	previous := ""
	roles := map[string]int{}
	for _, item := range value.Subjects {
		normalized, err := normalizedRelativePath(item.Path)
		if err != nil || normalized != item.Path || item.Path <= previous {
			return fmt.Errorf("native package subjects must be strictly sorted, unique, and safe: %q", item.Path)
		}
		previous = item.Path
		switch item.Role {
		case "package", "staging-manifest", "staging-payload", "package-install-evidence":
		default:
			return fmt.Errorf("subject %q has an unsupported role", item.Path)
		}
		if item.SizeBytes <= 0 || item.SizeBytes > maxSubjectSize || !sha256Pattern.MatchString(item.SHA256) {
			return fmt.Errorf("subject %q has invalid size or SHA-256", item.Path)
		}
		roles[item.Role]++
	}
	if roles["package"] != 1 || roles["staging-manifest"] != 1 || roles["staging-payload"] != 5 || roles["package-install-evidence"] != 1 {
		return fmt.Errorf("native package subject roles are invalid: %+v", roles)
	}
	artifact := value.Execution.Package
	if artifact.Filename != "" && path.Base(artifact.Filename) != artifact.Filename {
		return errors.New("package filename must be a basename")
	}
	if !filenamePattern.MatchString(artifact.Filename) || path.Base(findRolePath(value.Subjects, "package")) != artifact.Filename || !validPackageSuffix(artifact.Family, artifact.Filename) {
		return errors.New("package filename is not bound to the package subject")
	}
	if artifact.StagingManifestPath != findRolePath(value.Subjects, "staging-manifest") || artifact.InstallEvidencePath != findRolePath(value.Subjects, "package-install-evidence") {
		return errors.New("package evidence paths are not bound to their subject roles")
	}
	return nil
}

func validPackageSuffix(family, filename string) bool {
	switch family {
	case string(nativepackage.FamilyDebian):
		return strings.HasSuffix(filename, ".deb")
	case string(nativepackage.FamilyRPM):
		return strings.HasSuffix(filename, ".rpm")
	case string(nativepackage.FamilyFreeBSD), string(nativepackage.FamilyOpenBSD), string(nativepackage.FamilyPkgsrc), string(nativepackage.FamilyDPorts):
		return strings.HasSuffix(filename, ".pkg") || strings.HasSuffix(filename, ".txz") || strings.HasSuffix(filename, ".tgz")
	default:
		return false
	}
}

func findRolePath(subjects []subject, role string) string {
	for _, item := range subjects {
		if item.Role == role {
			return item.Path
		}
	}
	return ""
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

func validateExecution(value execution) error {
	if !jobPattern.MatchString(value.Job) || len(value.Job) > 128 {
		return errors.New("job must be a bounded lowercase identifier")
	}
	if value.RunnerOS != "Linux" {
		return fmt.Errorf("unsupported runner OS %q", value.RunnerOS)
	}
	if value.RunnerArchitecture != "X64" {
		return fmt.Errorf("unsupported runner architecture %q", value.RunnerArchitecture)
	}
	if value.HostClass != expectedHostClass(value.Package.Family) {
		return fmt.Errorf("host class %q is not valid for package family %q", value.HostClass, value.Package.Family)
	}
	if !goVersionPattern.MatchString(value.GoVersion) {
		return errors.New("go version must use canonical go1.x.y form")
	}
	if !boundedText(value.Command, 512) {
		return errors.New("command is required, bounded, and must not contain control characters")
	}
	if !releaseversion.Valid(value.Package.Version) {
		return errors.New("package version must be a valid v-prefixed Semantic Version")
	}
	if !validFamilyTarget(value.Package.Family, value.Target) {
		return fmt.Errorf("package family %q is not valid for target %s/%s", value.Package.Family, value.Target.GOOS, value.Target.GOARCH)
	}
	if value.Package.Format != packageFormat(value.Package.Family) {
		return fmt.Errorf("package format %q is not valid for family %q", value.Package.Format, value.Package.Family)
	}
	if _, err := normalizedRelativePath(value.Package.StagingManifestPath); err != nil {
		return fmt.Errorf("staging manifest path: %w", err)
	}
	if _, err := normalizedRelativePath(value.Package.InstallEvidencePath); err != nil {
		return fmt.Errorf("install evidence path: %w", err)
	}
	job, runner, architecture, host := expectedExecution(value.Target, value.Package.Family)
	if value.Job != job || value.RunnerOS != runner || value.RunnerArchitecture != architecture || value.HostClass != host {
		return errors.New("execution does not match the native package job contract")
	}
	return nil
}

func validFamilyTarget(family string, value target) bool {
	for _, candidate := range nativepackage.SupportedFamilies() {
		if string(candidate) == family {
			for _, targetFamily := range nativepackage.PackageFamiliesForTarget(value.GOOS, value.GOARCH) {
				if targetFamily == candidate {
					return true
				}
			}
		}
	}
	return false
}

func expectedHostClass(family string) string {
	switch family {
	case string(nativepackage.FamilyFreeBSD), string(nativepackage.FamilyOpenBSD), string(nativepackage.FamilyPkgsrc), string(nativepackage.FamilyDPorts):
		return "virtualized"
	default:
		return "hosted"
	}
}

func packageFormat(family string) string {
	if family == string(nativepackage.FamilyDebian) {
		return "deb"
	}
	if family == string(nativepackage.FamilyRPM) {
		return "rpm"
	}
	return "pkg"
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
		return nil, fmt.Errorf("native package attestation subject exceeds %d bytes", maxDocumentSize)
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
	fmt.Fprintf(os.Stderr, "nativepackageattestation: "+format+"\n", arguments...)
	os.Exit(2)
}
