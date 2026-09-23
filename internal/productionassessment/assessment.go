// Package productionassessment composes a live, named release assessment with
// the fixed external engineering criteria. No production trust roots for those
// criteria are provisioned yet, so this package cannot award their 17 points.
package productionassessment

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

const (
	repositoryScore = 74
	releaseScore    = 83
)

var (
	stableVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	objectID      = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	sha256Digest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Asset describes an exact file in the authenticated ten-file GitHub release.
type Asset struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// Release is the identity authenticated by releaseassessment in this call.
type Release struct {
	Version            string    `json:"version"`
	Commit             string    `json:"commit"`
	Tree               string    `json:"tree"`
	ReleaseID          int64     `json:"release_id"`
	ReleaseRunID       int64     `json:"release_run_id"`
	ReleaseRunAttempt  int       `json:"release_run_attempt"`
	CIRunID            int64     `json:"ci_run_id"`
	CIRunAttempt       int       `json:"ci_run_attempt"`
	ScorecardSHA256    string    `json:"scorecard_sha256"`
	ScorecardExpiresAt time.Time `json:"scorecard_expires_at"`
	Assets             []Asset   `json:"assets"`
}

// Criterion is an all-or-nothing row in the fixed production contract.
// MissingEvidence is populated only when no production verifier can award it.
type Criterion struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Weight          int      `json:"weight"`
	EvidenceType    string   `json:"evidence_type"`
	VerifierID      string   `json:"verifier_id"`
	Points          int      `json:"points"`
	Status          string   `json:"status"`
	MissingEvidence []string `json:"missing_evidence,omitempty"`
}

// Result is an observation, not a durable certificate or gameplay permission.
// Its score is derived only after live release verification and final recheck.
type Result struct {
	SchemaVersion     int         `json:"schema_version"`
	Release           Release     `json:"release"`
	ObservedAt        time.Time   `json:"observed_at"`
	EvidenceExpiresAt time.Time   `json:"evidence_expires_at"`
	RepositoryScore   int         `json:"repository_score"`
	ReleaseScore      int         `json:"release_score"`
	Score             int         `json:"score"`
	Criteria          []Criterion `json:"criteria"`
}

// Verify accepts only the release selector and local bytes required by the
// live release verifier. It cannot ingest a saved assessment, acceptance
// policy, score, signing key, or caller-declared verification result.
func Verify(ctx context.Context, input releaseassessment.Request) (Result, error) {
	return verify(ctx, input, dependencies{
		verifyRelease: func(ctx context.Context, request releaseassessment.Request) (verifiedRelease, error) {
			return releaseassessment.VerifyForProduction(ctx, request)
		},
		now: time.Now,
	})
}

// The interface and dependency seam are private to this package. Production
// calls always use the opaque VerifiedRelease returned by the live verifier.
type verifiedRelease interface {
	Assessment() (releaseassessment.Result, error)
	ScorecardSHA256() (string, error)
	PublishedAssets() ([]releaseassessment.PublishedAsset, error)
	Recheck(context.Context) error
}

type dependencies struct {
	verifyRelease func(context.Context, releaseassessment.Request) (verifiedRelease, error)
	now           func() time.Time
}

func verify(ctx context.Context, input releaseassessment.Request, deps dependencies) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if deps.verifyRelease == nil || deps.now == nil {
		return Result{}, errors.New("production assessment dependencies are unavailable")
	}
	verified, err := deps.verifyRelease(ctx, input)
	if err != nil {
		return Result{}, fmt.Errorf("live release verification failed: %w", err)
	}
	if verified == nil {
		return Result{}, errors.New("live release verification returned no identity")
	}
	baseline, err := verified.Assessment()
	if err != nil {
		return Result{}, fmt.Errorf("live release identity is invalid: %w", err)
	}
	if err := checkReleaseAssessment(input, baseline); err != nil {
		return Result{}, err
	}
	scorecardSHA256, err := verified.ScorecardSHA256()
	if err != nil || !sha256Digest.MatchString(scorecardSHA256) {
		return Result{}, errors.New("authenticated released scorecard digest is unavailable")
	}
	published, err := verified.PublishedAssets()
	if err != nil || !validAssets(baseline.Version, published) {
		return Result{}, errors.New("authenticated ten-file release inventory is invalid")
	}
	assets := make([]Asset, len(published))
	for i, item := range published {
		assets[i] = Asset{item.Name, item.SHA256, item.SizeBytes}
	}

	// The six production trust policies and their independent verifiers are not
	// provisioned. Existing CI/native attestations cannot be promoted to these
	// rows, even when their bytes are present in the release assessment.
	criteria := missingCriteria()
	if err := verified.Recheck(ctx); err != nil {
		return Result{}, fmt.Errorf("final live release recheck failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	observedAt := deps.now().UTC()
	if observedAt.IsZero() || observedAt.Before(baseline.ObservedAt) || !observedAt.Before(baseline.ScorecardExpiresAt) {
		return Result{}, errors.New("release observation is expired or its clock moved backward")
	}
	return Result{
		SchemaVersion: 1,
		Release: Release{
			Version: baseline.Version, Commit: baseline.Commit, Tree: baseline.Tree,
			ReleaseID: baseline.ReleaseID, ReleaseRunID: baseline.ReleaseRunID,
			ReleaseRunAttempt: baseline.ReleaseRunAttempt, CIRunID: baseline.CIRunID,
			CIRunAttempt: baseline.CIRunAttempt, ScorecardSHA256: scorecardSHA256,
			ScorecardExpiresAt: baseline.ScorecardExpiresAt.UTC(), Assets: assets,
		},
		ObservedAt: observedAt, EvidenceExpiresAt: baseline.ScorecardExpiresAt.UTC(),
		RepositoryScore: repositoryScore, ReleaseScore: releaseScore, Score: releaseScore,
		Criteria: criteria,
	}, nil
}

func checkReleaseAssessment(input releaseassessment.Request, result releaseassessment.Result) error {
	if result.SchemaVersion != 1 || !stableVersion.MatchString(result.Version) || result.Version != input.Version ||
		!objectID.MatchString(result.Commit) || !objectID.MatchString(result.Tree) || len(result.Commit) != len(result.Tree) ||
		result.ReleaseID <= 0 || result.ReleaseRunID <= 0 || result.ReleaseRunAttempt <= 0 ||
		result.CIRunID <= 0 || result.CIRunAttempt <= 0 || result.ObservedAt.IsZero() ||
		result.ScorecardExpiresAt.IsZero() || !result.ObservedAt.Before(result.ScorecardExpiresAt) ||
		result.RepositoryScore != repositoryScore || result.Score != releaseScore {
		return errors.New("live release assessment does not match the fixed production baseline")
	}
	expected := [...]releaseassessment.Criterion{
		{ID: "tests-race-vet-linux", Name: "Linux race and vet", EvidenceType: "ci-attestation-v1", VerifierID: "ci-race-vet-v1", Points: 3},
		{ID: "tests-nine-target-cross-build", Name: "Nine-target Linux/BSD cross-build", EvidenceType: "ci-attestation-v1", VerifierID: "ci-nine-target-cross-build-v1", Points: 3},
		{ID: "packaging-nine-release-archives", Name: "Nine published Linux/BSD release archives", EvidenceType: "release-attestation-v1", VerifierID: "release-nine-archives-v1", Points: 2},
		{ID: "packaging-publication-attestation", Name: "Release publication and attestation", EvidenceType: "release-attestation-v1", VerifierID: "release-publication-attestation-v1", Points: 1},
	}
	if len(result.Criteria) != len(expected) {
		return errors.New("live release assessment has an incomplete criterion inventory")
	}
	for i, item := range expected {
		if result.Criteria[i] != item {
			return errors.New("live release assessment changed a fixed release criterion")
		}
	}
	return nil
}

func validAssets(version string, assets []releaseassessment.PublishedAsset) bool {
	if len(assets) != 10 || !stableVersion.MatchString(version) {
		return false
	}
	base := "leaguebridge_" + strings.TrimPrefix(version, "v") + "_"
	names := [...]string{
		"checksums.txt",
		base + "dragonfly_amd64.tar.gz",
		base + "freebsd_amd64.tar.gz",
		base + "freebsd_arm64.tar.gz",
		base + "linux_amd64.tar.gz",
		base + "linux_arm64.tar.gz",
		base + "netbsd_amd64.tar.gz",
		base + "netbsd_arm64.tar.gz",
		base + "openbsd_amd64.tar.gz",
		base + "openbsd_arm64.tar.gz",
	}
	for i, item := range assets {
		if item.Name != names[i] || !sha256Digest.MatchString(item.SHA256) || item.SizeBytes <= 0 {
			return false
		}
	}
	return true
}

func missingCriteria() []Criterion {
	return []Criterion{
		{ID: "architecture-upstream-authorization", Name: "Authorized upstream extension contract", Weight: 2,
			EvidenceType: "vendor-authorization-v1", VerifierID: "riot-linux-bsd-authorization-v1", Status: "missing_evidence",
			MissingEvidence: []string{"Authenticated Riot authorization and current validity are not provisioned"}},
		{ID: "implementation-native-validated-integration", Name: "Native validated platform integration", Weight: 3,
			EvidenceType: "native-runtime-attestation-v2", VerifierID: "native-integration-v2", Status: "missing_evidence",
			MissingEvidence: []string{"Independently governed physical native integration proof is not provisioned"}},
		{ID: "tests-native-bsd-physical-smoke", Name: "Native BSD and physical-hardware smoke tests", Weight: 5,
			EvidenceType: "native-runtime-attestation-v2", VerifierID: "native-bsd-physical-smoke-v2", Status: "missing_evidence",
			MissingEvidence: []string{"Independently witnessed physical BSD smoke proof is not provisioned"}},
		{ID: "security-independent-audit-closed", Name: "Closed independent audit findings", Weight: 2,
			EvidenceType: "independent-audit-v1", VerifierID: "independent-audit-v1", Status: "missing_evidence",
			MissingEvidence: []string{"Independent auditor identity, findings, and closure proof are not provisioned"}},
		{ID: "packaging-native-os-packages", Name: "Native OS packages", Weight: 3,
			EvidenceType: "package-attestation-v1", VerifierID: "native-packages-v1", Status: "missing_evidence",
			MissingEvidence: []string{"Native package signing, publication, and withdrawal proof are not provisioned"}},
		{ID: "packaging-install-uninstall-native-smoke", Name: "Install/uninstall and native smoke evidence", Weight: 2,
			EvidenceType: "native-runtime-attestation-v2", VerifierID: "install-native-smoke-v2", Status: "missing_evidence",
			MissingEvidence: []string{"Independent production-package lifecycle proof is not provisioned"}},
	}
}
