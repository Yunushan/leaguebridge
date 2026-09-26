package stablecandidateattestation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/Yunushan/leaguebridge/internal/productionpackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

// PackageInput locates one archive, complete staging tree, and native package
// already extracted from the retained candidate artifact and release inputs.
// It cannot supply candidate metadata, a trust root, or a readiness score.
type PackageInput struct {
	ArchivePath string
	StagingDir  string
	PackagePath string
}

// VerifyRequest selects one existing main workflow_dispatch attempt and local
// bytes. The release identity comes only from an opaque live release verifier.
// GHPath must name a trusted GitHub CLI executable.
type VerifyRequest struct {
	Release    releaseassessment.VerifiedRelease
	RunID      int64
	RunAttempt int
	GHPath     string
	RecordPath string
	Packages   []PackageInput
}

// VerifiedCandidates is a score-free observation. Its zero value is invalid.
// It does not establish publisher signatures, package repository publication,
// independent physical-host observations, or native package lifecycle results.
type VerifiedCandidates struct {
	valid          bool
	releaseVersion string
	releaseCommit  string
	dispatchCommit string
	runID          int64
	runAttempt     int
	recordSHA256   string
	summaries      []productionpackage.Summary
}

func (value VerifiedCandidates) Valid() bool { return value.valid }

// Summaries returns a detached copy of the exact eleven verified candidates.
func (value VerifiedCandidates) Summaries() ([]productionpackage.Summary, error) {
	if !value.valid {
		return nil, errors.New("stable native candidate attestation has not been verified")
	}
	return append([]productionpackage.Summary(nil), value.summaries...), nil
}

// Identity distinguishes the stable release commit from the later main
// workflow_dispatch commit that signed these candidate bytes.
func (value VerifiedCandidates) Identity() (releaseVersion, releaseCommit, dispatchCommit, recordSHA256 string, runID int64, runAttempt int, err error) {
	if !value.valid {
		return "", "", "", "", 0, 0, errors.New("stable native candidate attestation has not been verified")
	}
	return value.releaseVersion, value.releaseCommit, value.dispatchCommit, value.recordSHA256, value.runID, value.runAttempt, nil
}

// Verify authenticates the selected successful run and its one exact
// twelve-subject GitHub provenance statement, then independently rechecks
// every release-bound native package payload. It establishes that the selected
// run attested these exact bytes, not that later main source still matches a
// reviewed build implementation. It awards no production readiness row.
func Verify(ctx context.Context, request VerifyRequest) (VerifiedCandidates, error) {
	if ctx == nil {
		return VerifiedCandidates{}, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedCandidates{}, err
	}
	if request.GHPath == "" || request.RunID <= 0 || request.RunAttempt <= 0 || request.RecordPath == "" {
		return VerifiedCandidates{}, errors.New("trusted GitHub CLI, selected run attempt, and candidate-set record are required")
	}
	packages := append([]PackageInput(nil), request.Packages...)
	if len(packages) != len(productionpackage.ExpectedCells()) {
		return VerifiedCandidates{}, errors.New("exactly eleven native package paths are required")
	}
	run, jobs, err := verifySelectedRun(ctx, request.GHPath, request.RunID, request.RunAttempt)
	if err != nil {
		return VerifiedCandidates{}, fmt.Errorf("authenticate stable candidate run: %w", err)
	}
	inputs, cleanup, err := reconstructCandidates(ctx, request.Release, packages)
	if err != nil {
		return VerifiedCandidates{}, fmt.Errorf("reconstruct private candidate metadata: %w", err)
	}
	defer cleanup()
	verifiedPayloads, err := productionpackage.VerifyPayloadSet(ctx, request.Release, inputs)
	if err != nil {
		return VerifiedCandidates{}, fmt.Errorf("verify release-bound candidate payloads: %w", err)
	}
	summaries, err := verifiedPayloads.Summaries()
	if err != nil {
		return VerifiedCandidates{}, err
	}
	canonical, err := canonicalRecord(request.Release, summaries)
	if err != nil {
		return VerifiedCandidates{}, fmt.Errorf("derive canonical candidate-set record: %w", err)
	}
	recordDigest, err := checkRecord(ctx, request.RecordPath, canonical)
	if err != nil {
		return VerifiedCandidates{}, err
	}
	subjects, paths, err := subjectInventory(ctx, recordDigest, summaries, inputs)
	if err != nil {
		return VerifiedCandidates{}, err
	}
	if err := verifyGitHubAttestation(ctx, request.GHPath, request.RecordPath, run, subjects); err != nil {
		return VerifiedCandidates{}, fmt.Errorf("authenticate exact twelve-subject GitHub attestation: %w", err)
	}

	// A signed record cannot substitute for the complete live release and native
	// archive checks. Repeat them after network verification to catch mutable
	// local inputs, a changed release, or a changed selected run attempt.
	currentPayloads, err := productionpackage.VerifyPayloadSet(ctx, request.Release, inputs)
	if err != nil {
		return VerifiedCandidates{}, fmt.Errorf("recheck native candidate payloads: %w", err)
	}
	currentSummaries, err := currentPayloads.Summaries()
	if err != nil {
		return VerifiedCandidates{}, err
	}
	if err := compareSummaries(summaries, currentSummaries); err != nil {
		return VerifiedCandidates{}, err
	}
	if err := request.Release.Recheck(ctx); err != nil {
		return VerifiedCandidates{}, fmt.Errorf("final authenticated release recheck: %w", err)
	}
	currentRun, currentJobs, err := verifySelectedRun(ctx, request.GHPath, request.RunID, request.RunAttempt)
	if err != nil || !reflect.DeepEqual(run, currentRun) || !reflect.DeepEqual(jobs, currentJobs) {
		return VerifiedCandidates{}, errors.New("selected stable candidate run changed during verification")
	}
	if currentRecord, err := checkRecord(ctx, request.RecordPath, canonical); err != nil || currentRecord != recordDigest {
		return VerifiedCandidates{}, errors.New("candidate-set record changed during attestation verification")
	}
	for name, path := range paths {
		actual, err := hashRegular(ctx, path, 256<<20)
		if err != nil || actual != subjects[name] {
			return VerifiedCandidates{}, fmt.Errorf("native package %q changed during attestation verification", name)
		}
	}
	if err := ctx.Err(); err != nil {
		return VerifiedCandidates{}, err
	}
	return VerifiedCandidates{
		valid: true, releaseVersion: summaries[0].Version,
		releaseCommit:  summaries[0].Commit,
		dispatchCommit: run.Commit, runID: run.ID, runAttempt: run.Attempt,
		recordSHA256: recordDigest, summaries: append([]productionpackage.Summary(nil), summaries...),
	}, nil
}

func subjectInventory(ctx context.Context, recordDigest string, summaries []productionpackage.Summary, inputs []productionpackage.CandidatePaths) (map[string]string, map[string]string, error) {
	if !sha256Pattern.MatchString(recordDigest) || len(summaries) != 11 || len(inputs) != 11 {
		return nil, nil, errors.New("complete candidate subject inventory is required")
	}
	subjects := map[string]string{"CANDIDATE-SET.json": recordDigest}
	paths := make(map[string]string, len(inputs))
	for _, input := range inputs {
		name := filepath.Base(input.PackagePath)
		if name == "." || name == string(filepath.Separator) || paths[name] != "" {
			return nil, nil, fmt.Errorf("duplicate or invalid candidate package filename %q", name)
		}
		paths[name] = input.PackagePath
	}
	for _, summary := range summaries {
		name := summary.PackageFilename
		path := paths[name]
		if path == "" || !sha256Pattern.MatchString(summary.PackageSHA256) {
			return nil, nil, fmt.Errorf("required attestation package %q is missing or has an invalid digest", name)
		}
		if _, duplicate := subjects[name]; duplicate {
			return nil, nil, fmt.Errorf("duplicate candidate subject %q", name)
		}
		digest, err := hashRegular(ctx, path, 256<<20)
		if err != nil || digest != summary.PackageSHA256 {
			return nil, nil, fmt.Errorf("candidate package %q changed before attestation verification", name)
		}
		subjects[name] = digest
	}
	if len(subjects) != 12 {
		return nil, nil, errors.New("attestation must have one record and exactly eleven package subjects")
	}
	return subjects, paths, nil
}
