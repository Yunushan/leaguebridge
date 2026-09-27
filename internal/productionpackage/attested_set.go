package productionpackage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

const (
	stableCandidateRepository = "Yunushan/leaguebridge"
	stableCandidateWorkflow   = ".github/workflows/stable-native-candidates.yml"
	stableCandidateRef        = "refs/heads/main"
	stableCandidateRecordName = "CANDIDATE-SET.json"
	stableCandidateOIDCIssuer = "https://token.actions.githubusercontent.com"
	stableCandidatePredicate  = "https://slsa.dev/provenance/v1"
	// Any change to the candidate workflow requires review of this contract.
	stableCandidateWorkflowSHA256 = "d76e6d97041fcf83ecd45bd6788b393a42c36d8bd3541082b5a6d4ad284672cd"
	maximumCandidateSetRecord     = int64(64 << 10)
	maximumGitHubResponse         = 8 << 20
	maximumWorkflowBlob           = int64(256 << 10)
	maximumGitTreeEntries         = 1000
)

// AttestedCandidateRequest names a GitHub workflow run and locates untrusted
// local files. The repository, workflow, source branch, OIDC issuer, and
// predicate policy are fixed by this verifier; the run locator is checked
// against live GitHub metadata before its attestation is accepted.
type AttestedCandidateRequest struct {
	Release    releaseassessment.VerifiedRelease
	Candidates []CandidatePaths
	RecordPath string
	GHPath     string
	RunID      int64
	RunAttempt int
}

// VerifiedAttestedCandidateSet is a score-free prerequisite for a future
// publisher. It does not prove package-manager signing, live publication,
// withdrawal state, or independent native installation.
type VerifiedAttestedCandidateSet struct {
	valid     bool
	summaries []Summary
	runID     int64
	attempt   int
}

func (set VerifiedAttestedCandidateSet) Valid() bool { return set.valid }

func (set VerifiedAttestedCandidateSet) Summaries() ([]Summary, error) {
	if !set.valid {
		return nil, errors.New("stable candidate attestation has not been verified")
	}
	return append([]Summary(nil), set.summaries...), nil
}

// VerifyAttestedCandidateSet binds the one twelve-subject GitHub attestation
// to a live authenticated release and inspected package payloads. It never
// awards readiness points or accepts a caller-selected trust root.
func VerifyAttestedCandidateSet(ctx context.Context, input AttestedCandidateRequest) (VerifiedAttestedCandidateSet, error) {
	if ctx == nil {
		return VerifiedAttestedCandidateSet{}, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	if input.RunID <= 0 || input.RunAttempt <= 0 || strings.TrimSpace(input.GHPath) == "" {
		return VerifiedAttestedCandidateSet{}, errors.New("GitHub CLI and positive run ID and attempt are required")
	}
	if filepath.Base(input.RecordPath) != stableCandidateRecordName {
		return VerifiedAttestedCandidateSet{}, errors.New("candidate record must be named CANDIDATE-SET.json")
	}
	input.Candidates = append([]CandidatePaths(nil), input.Candidates...)
	assessment, err := input.Release.Assessment()
	if err != nil {
		return VerifiedAttestedCandidateSet{}, fmt.Errorf("authenticated release is required: %w", err)
	}
	scorecardSHA, err := input.Release.ScorecardSHA256()
	if err != nil || !digestPattern.MatchString(scorecardSHA) {
		return VerifiedAttestedCandidateSet{}, errors.New("authenticated release scorecard digest is unavailable")
	}
	set, err := VerifyPayloadSet(ctx, input.Release, input.Candidates)
	if err != nil {
		return VerifiedAttestedCandidateSet{}, fmt.Errorf("verify release-bound package payloads: %w", err)
	}
	summaries, err := set.Summaries()
	if err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	return verifyAttestedCandidateSet(ctx, attestedCandidateFacts{
		version: assessment.Version, commit: assessment.Commit, tree: assessment.Tree,
		releaseID: assessment.ReleaseID, scorecardSHA256: scorecardSHA,
	}, summaries, input, attestationDependencies{
		readRun:         readStableCandidateRun,
		verifyStatement: verifyStableCandidateStatement,
		recheckPayload: func(ctx context.Context) ([]Summary, error) {
			current, err := VerifyPayloadSet(ctx, input.Release, input.Candidates)
			if err != nil {
				return nil, err
			}
			return current.Summaries()
		},
		recheckRelease: input.Release.Recheck,
	})
}

type attestedCandidateFacts struct {
	version, commit, tree, scorecardSHA256 string
	releaseID                              int64
}

type attestationDependencies struct {
	readRun         func(context.Context, string, int64, int) (stableCandidateRun, error)
	verifyStatement func(context.Context, string, string, stableCandidateRun) ([]byte, error)
	recheckPayload  func(context.Context) ([]Summary, error)
	recheckRelease  func(context.Context) error
}

func verifyAttestedCandidateSet(ctx context.Context, facts attestedCandidateFacts, summaries []Summary, input AttestedCandidateRequest, deps attestationDependencies) (VerifiedAttestedCandidateSet, error) {
	if ctx == nil {
		return VerifiedAttestedCandidateSet{}, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	if deps.readRun == nil || deps.verifyStatement == nil || deps.recheckPayload == nil || deps.recheckRelease == nil {
		return VerifiedAttestedCandidateSet{}, errors.New("candidate attestation verifier is unavailable")
	}
	expectedRecord, expectedSubjects, err := expectedCandidateAttestation(facts, summaries)
	if err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	data, err := readRegularBounded(ctx, input.RecordPath, maximumCandidateSetRecord)
	if err != nil {
		return VerifiedAttestedCandidateSet{}, fmt.Errorf("read candidate-set record: %w", err)
	}
	// Raw equality with freshly derived canonical bytes rejects duplicate keys,
	// unknown fields, noncanonical formatting, and self-declared identities.
	if !bytes.Equal(data, expectedRecord) {
		return VerifiedAttestedCandidateSet{}, errors.New("candidate-set record differs from the authenticated release and eleven payloads")
	}
	if err := checkAttestedPackageBytes(ctx, input.Candidates, summaries); err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	run, err := deps.readRun(ctx, input.GHPath, input.RunID, input.RunAttempt)
	if err != nil {
		return VerifiedAttestedCandidateSet{}, fmt.Errorf("authenticate stable candidate workflow run: %w", err)
	}
	privatePath, cleanup, err := privateCandidateRecord(data)
	if err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	defer cleanup()
	verifiedJSON, err := deps.verifyStatement(ctx, input.GHPath, privatePath, run)
	if err != nil {
		return VerifiedAttestedCandidateSet{}, fmt.Errorf("verify GitHub candidate attestation: %w", err)
	}
	if err := checkCandidateStatement(verifiedJSON, expectedSubjects, run); err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	if err := deps.recheckRelease(ctx); err != nil {
		return VerifiedAttestedCandidateSet{}, fmt.Errorf("recheck authenticated release: %w", err)
	}
	// The release check may take minutes. Recheck staging and installed
	// payload equivalence afterwards, immediately before local file and run
	// state checks.
	currentPayload, err := deps.recheckPayload(ctx)
	if err != nil || len(currentPayload) != len(summaries) {
		return VerifiedAttestedCandidateSet{}, errors.New("candidate package payloads changed during attestation verification")
	}
	for i := range summaries {
		if currentPayload[i] != summaries[i] {
			return VerifiedAttestedCandidateSet{}, errors.New("candidate package payload set changed during attestation verification")
		}
	}
	currentRecord, err := readRegularBounded(ctx, input.RecordPath, maximumCandidateSetRecord)
	if err != nil || !bytes.Equal(currentRecord, data) {
		return VerifiedAttestedCandidateSet{}, errors.New("candidate-set record changed during attestation verification")
	}
	if err := checkAttestedPackageBytes(ctx, input.Candidates, summaries); err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	current, err := deps.readRun(ctx, input.GHPath, input.RunID, input.RunAttempt)
	if err != nil || current != run {
		return VerifiedAttestedCandidateSet{}, errors.New("stable candidate workflow run changed during verification")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedAttestedCandidateSet{}, err
	}
	return VerifiedAttestedCandidateSet{valid: true, summaries: append([]Summary(nil), summaries...), runID: run.id, attempt: run.attempt}, nil
}

type candidateAttestationRecord struct {
	SchemaVersion   int                              `json:"schema_version"`
	RecordType      string                           `json:"record_type"`
	ValidationScope string                           `json:"validation_scope"`
	Release         candidateAttestationRelease      `json:"release"`
	Cells           []candidateAttestationRecordCell `json:"cells"`
}

type candidateAttestationRelease struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	Tree            string `json:"tree"`
	ReleaseID       int64  `json:"release_id"`
	ScorecardSHA256 string `json:"scorecard_sha256"`
}

type candidateAttestationRecordCell struct {
	Family                string `json:"family"`
	GOOS                  string `json:"goos"`
	GOARCH                string `json:"goarch"`
	PackageFilename       string `json:"package_filename"`
	PackageSHA256         string `json:"package_sha256"`
	ArchiveSHA256         string `json:"archive_sha256"`
	ExecutableSHA256      string `json:"executable_sha256"`
	StagingManifestSHA256 string `json:"staging_manifest_sha256"`
}

func expectedCandidateAttestation(facts attestedCandidateFacts, summaries []Summary) ([]byte, map[string]string, error) {
	if !stableVersion(facts.version) || !objectIDPattern.MatchString(facts.commit) ||
		!objectIDPattern.MatchString(facts.tree) || facts.releaseID <= 0 ||
		!digestPattern.MatchString(facts.scorecardSHA256) || len(summaries) != len(productionCells) {
		return nil, nil, errors.New("authenticated stable release or complete candidate set is invalid")
	}
	record := candidateAttestationRecord{
		SchemaVersion: 1, RecordType: "leaguebridge.native-package-candidate-set.v1",
		ValidationScope: "candidate-payload-integrity-only",
		Release:         candidateAttestationRelease{facts.version, facts.commit, facts.tree, facts.releaseID, facts.scorecardSHA256},
		Cells:           make([]candidateAttestationRecordCell, 0, len(productionCells)),
	}
	subjects := make(map[string]string, len(productionCells)+1)
	for i, cell := range productionCells {
		summary := summaries[i]
		expectedFilename, err := packageFilename(facts.version, cell.Family, cell.GOOS, cell.GOARCH)
		if err != nil || summary.Version != facts.version || summary.Commit != facts.commit ||
			summary.Tree != facts.tree || summary.ReleaseID != facts.releaseID ||
			summary.Family != cell.Family || summary.GOOS != cell.GOOS || summary.GOARCH != cell.GOARCH ||
			summary.PackageFilename != expectedFilename || !digestPattern.MatchString(summary.PackageSHA256) ||
			!digestPattern.MatchString(summary.ArchiveSHA256) || !digestPattern.MatchString(summary.ExecutableSHA256) ||
			!digestPattern.MatchString(summary.StagingManifestSHA256) {
			return nil, nil, fmt.Errorf("candidate cell %d differs from the fixed authenticated inventory", i)
		}
		record.Cells = append(record.Cells, candidateAttestationRecordCell{
			Family: string(cell.Family), GOOS: cell.GOOS, GOARCH: cell.GOARCH,
			PackageFilename: summary.PackageFilename, PackageSHA256: summary.PackageSHA256,
			ArchiveSHA256: summary.ArchiveSHA256, ExecutableSHA256: summary.ExecutableSHA256,
			StagingManifestSHA256: summary.StagingManifestSHA256,
		})
		// actions/attest@1e69f48 signs the basename of each subject-path
		// file. Local directory layout is checked separately below.
		name := expectedFilename
		if _, duplicate := subjects[name]; duplicate {
			return nil, nil, errors.New("candidate attestation subject name is duplicated")
		}
		subjects[name] = summary.PackageSHA256
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("encode candidate-set record: %w", err)
	}
	data = append(data, '\n')
	if int64(len(data)) > maximumCandidateSetRecord {
		return nil, nil, errors.New("candidate-set record exceeds its size bound")
	}
	subjects[stableCandidateRecordName] = digest(data)
	return data, subjects, nil
}

func checkAttestedPackageBytes(ctx context.Context, inputs []CandidatePaths, summaries []Summary) error {
	if len(inputs) != len(productionCells) || len(summaries) != len(productionCells) {
		return errors.New("exactly eleven candidate package files are required")
	}
	want := make(map[string]string, len(summaries))
	expectedCell := make(map[string]Cell, len(summaries))
	for index, summary := range summaries {
		if _, duplicate := want[summary.PackageFilename]; duplicate {
			return errors.New("candidate package filename is duplicated")
		}
		want[summary.PackageFilename] = summary.PackageSHA256
		expectedCell[summary.PackageFilename] = productionCells[index]
	}
	seen := make(map[string]bool, len(inputs))
	packageRoot := ""
	expectedPaths := make(map[string]bool, len(inputs))
	expectedDirectories := make(map[string]bool, len(inputs)*3)
	for _, input := range inputs {
		name := filepath.Base(input.PackagePath)
		expectedSHA, known := want[name]
		if !known || seen[name] {
			return fmt.Errorf("package file %q is extra or duplicated", name)
		}
		seen[name] = true
		cell := expectedCell[name]
		absolute, err := filepath.Abs(input.PackagePath)
		if err != nil {
			return fmt.Errorf("resolve candidate package path %q: %w", name, err)
		}
		root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(absolute))))
		expectedPath := filepath.Join(root, "native-package-output", string(cell.Family), cell.GOARCH, name)
		if absolute != expectedPath || (packageRoot != "" && root != packageRoot) {
			return fmt.Errorf("package file %q is outside the fixed merged candidate tree", name)
		}
		packageRoot = root
		expectedPaths[absolute] = true
		for directory := filepath.Dir(absolute); directory != root; directory = filepath.Dir(directory) {
			expectedDirectories[directory] = true
		}
		actualSHA, _, err := hashRegular(ctx, input.PackagePath, maximumPackage)
		if err != nil || actualSHA != expectedSHA {
			return fmt.Errorf("package file %q changed after payload verification", name)
		}
	}
	if len(seen) != len(want) {
		return errors.New("candidate package file inventory is incomplete")
	}
	if err := fileinput.RejectSymlinkedParents(packageRoot); err != nil {
		return fmt.Errorf("candidate package root: %w", err)
	}
	err := filepath.WalkDir(packageRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == packageRoot {
			if !entry.IsDir() {
				return errors.New("candidate package root is not a directory")
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("candidate package tree contains symlink %q", path)
		}
		if entry.IsDir() {
			if !expectedDirectories[path] {
				return fmt.Errorf("candidate package tree has an extra directory %q", path)
			}
			return nil
		}
		if !entry.Type().IsRegular() || !expectedPaths[path] {
			return fmt.Errorf("candidate package tree has an extra or nonregular file %q", path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func privateCandidateRecord(data []byte) (string, func(), error) {
	directory, err := os.MkdirTemp("", "leaguebridge-attested-candidates-")
	if err != nil {
		return "", nil, fmt.Errorf("create private attestation snapshot: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	path := filepath.Join(directory, stableCandidateRecordName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("write private attestation snapshot: %w", err)
	}
	return path, cleanup, nil
}
