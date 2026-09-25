package productionpackage

import (
	"context"
	"errors"
	"fmt"

	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

// CandidatePaths locates one untrusted production package candidate and the
// local bytes needed to verify it. Paths cannot select the required inventory
// or supply a release identity, signing key, publication state, or score.
type CandidatePaths struct {
	CandidatePath string
	ArchivePath   string
	StagingDir    string
	PackagePath   string
}

// VerifiedSet is a complete, score-free candidate inventory. Its zero value
// is invalid. It does not establish native package signatures, publication,
// package-manager payload identity, or installation.
type VerifiedSet struct {
	valid     bool
	summaries []Summary
}

func (set VerifiedSet) Valid() bool { return set.valid }

// Summaries returns the complete inventory in ExpectedCells order, detached
// from the set's retained values.
func (set VerifiedSet) Summaries() ([]Summary, error) {
	if !set.valid {
		return nil, errors.New("production package candidate set has not been verified")
	}
	return append([]Summary(nil), set.summaries...), nil
}

// VerifySet checks exactly one candidate for every fixed production package
// cell against the opaque, authenticated release. Each input is checked by the
// existing single-candidate verifier before it can count toward the set.
func VerifySet(ctx context.Context, release releaseassessment.VerifiedRelease, inputs []CandidatePaths) (VerifiedSet, error) {
	if ctx == nil {
		return VerifiedSet{}, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedSet{}, err
	}
	facts, err := factsFromRelease(release)
	if err != nil {
		return VerifiedSet{}, fmt.Errorf("verify candidate set release: %w", err)
	}
	return verifyCandidateSet(ctx, facts, inputs, func(ctx context.Context, input CandidatePaths) (VerifiedCandidate, error) {
		return Verify(ctx, release, input.CandidatePath, input.ArchivePath, input.StagingDir, input.PackagePath)
	})
}

// Recheck rederives all eleven candidate summaries and compares them with the
// retained set after rechecking the live release. A production publisher must
// additionally authenticate the exact bytes it signs and publishes; local
// files can change again after this score-free observation.
func (set VerifiedSet) Recheck(ctx context.Context, release releaseassessment.VerifiedRelease, inputs []CandidatePaths) error {
	if !set.valid || len(set.summaries) != len(productionCells) {
		return errors.New("production package candidate set has not been verified")
	}
	if ctx == nil {
		return errors.New("verification context is required")
	}
	if err := release.Recheck(ctx); err != nil {
		return fmt.Errorf("recheck authenticated release: %w", err)
	}
	current, err := VerifySet(ctx, release, inputs)
	if err != nil {
		return err
	}
	return compareVerifiedSets(set, current)
}

func compareVerifiedSets(previous, current VerifiedSet) error {
	if !previous.valid || !current.valid || len(previous.summaries) != len(productionCells) || len(current.summaries) != len(productionCells) {
		return errors.New("production package candidate set has not been verified")
	}
	for index, expected := range previous.summaries {
		if current.summaries[index] != expected {
			return fmt.Errorf("production package candidate cell %+v changed after verification", productionCells[index])
		}
	}
	return nil
}

// verifySetWithFacts exercises the same per-candidate bytes check for package
// tests, which cannot construct a live VerifiedRelease. It is not a public
// trust path and cannot award readiness credit.
func verifySetWithFacts(ctx context.Context, facts releaseFacts, inputs []CandidatePaths) (VerifiedSet, error) {
	return verifyCandidateSet(ctx, facts, inputs, func(ctx context.Context, input CandidatePaths) (VerifiedCandidate, error) {
		data, err := readRegularBounded(ctx, input.CandidatePath, maximumCandidate)
		if err != nil {
			return VerifiedCandidate{}, fmt.Errorf("read candidate metadata: %w", err)
		}
		return verifyBytes(ctx, facts, data, input.ArchivePath, input.StagingDir, input.PackagePath)
	})
}

func verifyCandidateSet(ctx context.Context, facts releaseFacts, inputs []CandidatePaths, verifyOne func(context.Context, CandidatePaths) (VerifiedCandidate, error)) (VerifiedSet, error) {
	if ctx == nil {
		return VerifiedSet{}, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedSet{}, err
	}
	if verifyOne == nil {
		return VerifiedSet{}, errors.New("candidate verifier is unavailable")
	}
	if len(inputs) != len(productionCells) {
		return VerifiedSet{}, fmt.Errorf("production package candidate set has %d entries, want exactly %d", len(inputs), len(productionCells))
	}
	// Take a stable copy of the caller's path list before opening any input.
	inputs = append([]CandidatePaths(nil), inputs...)
	ordered := make([]Summary, len(productionCells))
	seen := make(map[Cell]struct{}, len(productionCells))
	for inputIndex, input := range inputs {
		if err := ctx.Err(); err != nil {
			return VerifiedSet{}, err
		}
		verified, err := verifyOne(ctx, input)
		if err != nil {
			return VerifiedSet{}, fmt.Errorf("verify production package candidate %d: %w", inputIndex, err)
		}
		if !verified.Valid() {
			return VerifiedSet{}, fmt.Errorf("production package candidate %d returned an invalid verification", inputIndex)
		}
		summary, err := verified.Summary()
		if err != nil {
			return VerifiedSet{}, fmt.Errorf("read production package candidate %d summary: %w", inputIndex, err)
		}
		if summary.Version != facts.Version || summary.Commit != facts.Commit ||
			summary.Tree != facts.Tree || summary.ReleaseID != facts.ReleaseID {
			return VerifiedSet{}, fmt.Errorf("production package candidate %d belongs to a different release", inputIndex)
		}
		cell := Cell{Family: summary.Family, GOOS: summary.GOOS, GOARCH: summary.GOARCH}
		cellIndex := -1
		for index, expected := range productionCells {
			if cell == expected {
				cellIndex = index
				break
			}
		}
		if cellIndex < 0 {
			return VerifiedSet{}, fmt.Errorf("production package candidate %d has an extra unsupported cell %+v", inputIndex, cell)
		}
		if _, duplicate := seen[cell]; duplicate {
			return VerifiedSet{}, fmt.Errorf("production package candidate set repeats cell %+v", cell)
		}
		seen[cell] = struct{}{}
		ordered[cellIndex] = summary
	}
	if err := ctx.Err(); err != nil {
		return VerifiedSet{}, err
	}
	if len(seen) != len(productionCells) {
		return VerifiedSet{}, errors.New("production package candidate set is missing a required cell")
	}
	return VerifiedSet{valid: true, summaries: ordered}, nil
}
