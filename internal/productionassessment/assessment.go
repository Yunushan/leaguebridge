// Package productionassessment composes a live, named release assessment with
// the fixed external engineering criteria. The current application verifier is
// unprovisioned and awards no external points; the composer accepts only opaque,
// release-bound results from future application-owned verifiers.
package productionassessment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	maximumScore    = 100
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
		verifyExternal: unprovisionedExternalEvidence,
		now:            time.Now,
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
	// External verifiers receive the authenticated release capability and a
	// separate binding copy for release-specific candidate checks.
	verifyExternal func(context.Context, verifiedRelease, releaseBinding) (externalVerification, error)
	now            func() time.Time
}

type externalCriterionSpec struct {
	id              string
	name            string
	weight          int
	evidenceType    string
	verifierID      string
	missingEvidence string
}

var externalCriterionSpecs = [...]externalCriterionSpec{
	{"architecture-upstream-authorization", "Authorized upstream extension contract", 2, "vendor-authorization-v1", "riot-linux-bsd-authorization-v1", "Authenticated Riot authorization and current validity are not provisioned"},
	{"implementation-native-validated-integration", "Native validated platform integration", 3, "native-runtime-attestation-v2", "native-integration-v2", "Independently governed physical native integration proof is not provisioned"},
	{"tests-native-bsd-physical-smoke", "Native BSD and physical-hardware smoke tests", 5, "native-runtime-attestation-v2", "native-bsd-physical-smoke-v2", "Independently witnessed physical BSD smoke proof is not provisioned"},
	{"security-independent-audit-closed", "Closed independent audit findings", 2, "independent-audit-v1", "independent-audit-v1", "Independent auditor identity, findings, and closure proof are not provisioned"},
	{"packaging-native-os-packages", "Native OS packages", 3, "package-attestation-v1", "native-packages-v1", "Native package signing, publication, and withdrawal proof are not provisioned"},
	{"packaging-install-uninstall-native-smoke", "Install/uninstall and native smoke evidence", 2, "native-runtime-attestation-v2", "install-native-smoke-v2", "Independent production-package lifecycle proof is not provisioned"},
}

// releaseBinding is the immutable release identity against which every
// independently verified production criterion is scoped.
type releaseBinding struct {
	version            string
	commit             string
	tree               string
	releaseID          int64
	releaseRunID       int64
	releaseRunAttempt  int
	ciRunID            int64
	ciRunAttempt       int
	scorecardSHA256    string
	scorecardExpiresAt time.Time
	assets             []Asset
}

// criterionProof is an opaque in-process result. Only a criterion verifier in
// this package may construct one after authenticating its evidence. It is not
// a wire type and cannot be supplied by the CLI or a saved assessment.
type criterionProof struct {
	valid                bool
	criterionID          string
	releaseBindingSHA256 string
	evidenceSHA256       string
	verifiedAt           time.Time
	expiresAt            time.Time
}

// externalVerification carries opaque criterion proofs and the live-state
// recheck that must run immediately before the release's final recheck.
type externalVerification struct {
	proofs  []criterionProof
	missing map[string][]string
	recheck func(context.Context) error
}

func verify(ctx context.Context, input releaseassessment.Request, deps dependencies) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if deps.verifyRelease == nil || deps.verifyExternal == nil || deps.now == nil {
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
	binding := releaseBinding{
		version: baseline.Version, commit: baseline.Commit, tree: baseline.Tree,
		releaseID: baseline.ReleaseID, releaseRunID: baseline.ReleaseRunID,
		releaseRunAttempt: baseline.ReleaseRunAttempt, ciRunID: baseline.CIRunID,
		ciRunAttempt: baseline.CIRunAttempt, scorecardSHA256: scorecardSHA256,
		scorecardExpiresAt: baseline.ScorecardExpiresAt.UTC(), assets: assets,
	}
	external, err := deps.verifyExternal(ctx, verified, cloneReleaseBinding(binding))
	if err != nil {
		return Result{}, fmt.Errorf("external production evidence verification failed: %w", err)
	}
	if external.recheck == nil {
		return Result{}, errors.New("external production verifier did not provide a final state recheck")
	}
	// Validate once before rechecking remote state so malformed or mismatched
	// proof tokens fail before a costly live release recheck.
	if _, _, _, err := deriveExternalCriteria(binding, external, deps.now().UTC()); err != nil {
		return Result{}, err
	}
	if err := external.recheck(ctx); err != nil {
		return Result{}, fmt.Errorf("initial external evidence recheck failed: %w", err)
	}
	if err := verified.Recheck(ctx); err != nil {
		return Result{}, fmt.Errorf("final live release recheck failed: %w", err)
	}
	// A release recheck may take long enough for mutable external authorization,
	// audit, or package-index state to change. Check it again before taking the
	// final observation time.
	if err := external.recheck(ctx); err != nil {
		return Result{}, fmt.Errorf("final external evidence recheck failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	observedAt := deps.now().UTC()
	if observedAt.IsZero() || observedAt.Before(baseline.ObservedAt) || !observedAt.Before(baseline.ScorecardExpiresAt) {
		return Result{}, errors.New("release observation is expired or its clock moved backward")
	}
	criteria, earnedPoints, evidenceExpiresAt, err := deriveExternalCriteria(binding, external, observedAt)
	if err != nil {
		return Result{}, err
	}
	score := releaseScore + earnedPoints
	if score > maximumScore {
		return Result{}, errors.New("derived production score exceeds the fixed 100-point contract")
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
		ObservedAt: observedAt, EvidenceExpiresAt: evidenceExpiresAt,
		RepositoryScore: repositoryScore, ReleaseScore: releaseScore, Score: score,
		Criteria: criteria,
	}, nil
}

func releaseBindingDigest(binding releaseBinding) (string, error) {
	if !stableVersion.MatchString(binding.version) || !objectID.MatchString(binding.commit) ||
		!objectID.MatchString(binding.tree) || len(binding.commit) != len(binding.tree) ||
		binding.releaseID <= 0 || binding.releaseRunID <= 0 || binding.releaseRunAttempt <= 0 ||
		binding.ciRunID <= 0 || binding.ciRunAttempt <= 0 || !sha256Digest.MatchString(binding.scorecardSHA256) ||
		binding.scorecardExpiresAt.IsZero() || !validAssets(binding.version, publishedAssets(binding.assets)) {
		return "", errors.New("release binding is invalid")
	}
	type canonicalReleaseBinding struct {
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
	data, err := json.Marshal(canonicalReleaseBinding{
		Version: binding.version, Commit: binding.commit, Tree: binding.tree,
		ReleaseID: binding.releaseID, ReleaseRunID: binding.releaseRunID,
		ReleaseRunAttempt: binding.releaseRunAttempt, CIRunID: binding.ciRunID,
		CIRunAttempt: binding.ciRunAttempt, ScorecardSHA256: binding.scorecardSHA256,
		ScorecardExpiresAt: binding.scorecardExpiresAt.UTC(), Assets: binding.assets,
	})
	if err != nil {
		return "", fmt.Errorf("encode release binding: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func cloneReleaseBinding(binding releaseBinding) releaseBinding {
	binding.assets = append([]Asset(nil), binding.assets...)
	return binding
}

func publishedAssets(assets []Asset) []releaseassessment.PublishedAsset {
	result := make([]releaseassessment.PublishedAsset, len(assets))
	for i, asset := range assets {
		result[i] = releaseassessment.PublishedAsset{Name: asset.Name, SHA256: asset.SHA256, SizeBytes: asset.SizeBytes}
	}
	return result
}

func newCriterionProof(id string, binding releaseBinding, evidenceSHA256 string, verifiedAt, expiresAt time.Time) (criterionProof, error) {
	if !knownExternalCriterion(id) {
		return criterionProof{}, fmt.Errorf("unknown external production criterion %q", id)
	}
	if !sha256Digest.MatchString(evidenceSHA256) {
		return criterionProof{}, errors.New("external criterion evidence digest is invalid")
	}
	if verifiedAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(verifiedAt) ||
		expiresAt.After(binding.scorecardExpiresAt) {
		return criterionProof{}, errors.New("external criterion validity must be nonempty and end no later than the released scorecard")
	}
	bindingSHA256, err := releaseBindingDigest(binding)
	if err != nil {
		return criterionProof{}, err
	}
	return criterionProof{
		valid: true, criterionID: id, releaseBindingSHA256: bindingSHA256,
		evidenceSHA256: evidenceSHA256, verifiedAt: verifiedAt.UTC(), expiresAt: expiresAt.UTC(),
	}, nil
}

func deriveExternalCriteria(binding releaseBinding, verification externalVerification, observedAt time.Time) ([]Criterion, int, time.Time, error) {
	if observedAt.IsZero() {
		return nil, 0, time.Time{}, errors.New("external evidence assessment time is required")
	}
	observedAt = observedAt.UTC()
	if !observedAt.Before(binding.scorecardExpiresAt) {
		return nil, 0, time.Time{}, errors.New("released scorecard expired during production assessment")
	}
	bindingSHA256, err := releaseBindingDigest(binding)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	specs := make(map[string]externalCriterionSpec, len(externalCriterionSpecs))
	for _, spec := range externalCriterionSpecs {
		specs[spec.id] = spec
	}
	proofs := make(map[string]criterionProof, len(verification.proofs))
	for _, proof := range verification.proofs {
		if _, ok := specs[proof.criterionID]; !ok || !proof.valid {
			return nil, 0, time.Time{}, errors.New("external verifier returned an invalid or unknown criterion proof")
		}
		if _, duplicate := proofs[proof.criterionID]; duplicate {
			return nil, 0, time.Time{}, fmt.Errorf("external verifier repeated criterion %q", proof.criterionID)
		}
		if proof.releaseBindingSHA256 != bindingSHA256 || !sha256Digest.MatchString(proof.evidenceSHA256) {
			return nil, 0, time.Time{}, fmt.Errorf("criterion %q is not bound to the authenticated release and evidence digest", proof.criterionID)
		}
		if proof.verifiedAt.IsZero() || proof.expiresAt.IsZero() || proof.verifiedAt.After(observedAt) ||
			!proof.expiresAt.After(observedAt) || !proof.expiresAt.After(proof.verifiedAt) ||
			proof.expiresAt.After(binding.scorecardExpiresAt) {
			return nil, 0, time.Time{}, fmt.Errorf("criterion %q is future-dated, expired, or exceeds scorecard validity", proof.criterionID)
		}
		proofs[proof.criterionID] = proof
	}
	for id, reasons := range verification.missing {
		if _, ok := specs[id]; !ok {
			return nil, 0, time.Time{}, fmt.Errorf("external verifier reported unknown missing criterion %q", id)
		}
		if len(reasons) == 0 || len(reasons) > 16 {
			return nil, 0, time.Time{}, fmt.Errorf("criterion %q has an invalid missing-evidence reason list", id)
		}
		if _, hasProof := proofs[id]; hasProof {
			return nil, 0, time.Time{}, fmt.Errorf("criterion %q is simultaneously verified and missing", id)
		}
		seen := make(map[string]struct{}, len(reasons))
		for _, reason := range reasons {
			if strings.TrimSpace(reason) == "" || len(reason) > 512 {
				return nil, 0, time.Time{}, fmt.Errorf("criterion %q has an empty or oversized missing-evidence reason", id)
			}
			if _, duplicate := seen[reason]; duplicate {
				return nil, 0, time.Time{}, fmt.Errorf("criterion %q repeats a missing-evidence reason", id)
			}
			seen[reason] = struct{}{}
		}
	}
	criteria := make([]Criterion, 0, len(externalCriterionSpecs))
	earned := 0
	evidenceExpiresAt := binding.scorecardExpiresAt
	for _, spec := range externalCriterionSpecs {
		if proof, ok := proofs[spec.id]; ok {
			criteria = append(criteria, Criterion{ID: spec.id, Name: spec.name, Weight: spec.weight,
				EvidenceType: spec.evidenceType, VerifierID: spec.verifierID, Points: spec.weight, Status: "verified"})
			earned += spec.weight
			if proof.expiresAt.Before(evidenceExpiresAt) {
				evidenceExpiresAt = proof.expiresAt
			}
			continue
		}
		reasons, ok := verification.missing[spec.id]
		if !ok {
			reasons = []string{spec.missingEvidence}
		}
		criteria = append(criteria, Criterion{ID: spec.id, Name: spec.name, Weight: spec.weight,
			EvidenceType: spec.evidenceType, VerifierID: spec.verifierID, Status: "missing_evidence",
			MissingEvidence: append([]string(nil), reasons...)})
	}
	if earned > maximumScore-releaseScore {
		return nil, 0, time.Time{}, errors.New("external criteria exceed the fixed production score contract")
	}
	return criteria, earned, evidenceExpiresAt.UTC(), nil
}

func knownExternalCriterion(id string) bool {
	for _, spec := range externalCriterionSpecs {
		if spec.id == id {
			return true
		}
	}
	return false
}

func unprovisionedExternalEvidence(ctx context.Context, _ verifiedRelease, _ releaseBinding) (externalVerification, error) {
	if err := ctx.Err(); err != nil {
		return externalVerification{}, err
	}
	missing := make(map[string][]string, len(externalCriterionSpecs))
	for _, spec := range externalCriterionSpecs {
		missing[spec.id] = []string{spec.missingEvidence}
	}
	return externalVerification{
		missing: missing,
		recheck: func(ctx context.Context) error { return ctx.Err() },
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
