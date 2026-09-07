// Package releaseassessment derives a live engineering assessment for a named
// published release. It authenticates evidence itself; public observations and
// caller-supplied scores, source identities, policies, or receipts are not inputs.
package releaseassessment

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
	"github.com/Yunushan/leaguebridge/internal/cireleasegate"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/releasecheck"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

const repository = "Yunushan/leaguebridge"
const ciWorkflow = ".github/workflows/ci.yml"
const releaseWorkflow = ".github/workflows/release.yml"

// Request selects a release and local bytes, never an acceptance policy. The
// CI binary subjects retain ciattestation's process-working-directory semantics.
type Request struct {
	GHPath             string
	Version            string
	ReleaseDir         string
	RaceVetSubject     string
	CrossBuildSubjects []string
}

// Criterion is one fixed additional criterion whose complete evidence was
// authenticated during this call. It is not accepted as an input anywhere.
type Criterion struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	EvidenceType string `json:"evidence_type"`
	VerifierID   string `json:"verifier_id"`
	Points       int    `json:"points"`
}

// Result describes checks observed during a single live invocation. It is not
// a durable readiness receipt or authorization for a later publication. The
// released v3 scorecard and native/remote gameplay gates are unchanged.
type Result struct {
	SchemaVersion      int         `json:"schema_version"`
	Version            string      `json:"version"`
	Commit             string      `json:"commit"`
	Tree               string      `json:"tree"`
	ReleaseID          int64       `json:"release_id"`
	ReleaseRunID       int64       `json:"release_run_id"`
	ReleaseRunAttempt  int         `json:"release_run_attempt"`
	CIRunID            int64       `json:"ci_run_id"`
	CIRunAttempt       int         `json:"ci_run_attempt"`
	ObservedAt         time.Time   `json:"observed_at"`
	ScorecardExpiresAt time.Time   `json:"scorecard_expires_at"`
	RepositoryScore    int         `json:"repository_score"`
	Score              int         `json:"score"`
	Criteria           []Criterion `json:"criteria"`
}

var additionalCriteria = []Criterion{
	{"tests-race-vet-linux", "Linux race and vet", readiness.CIAttestationV1, "ci-race-vet-v1", 3},
	{"tests-nine-target-cross-build", "Nine-target Linux/BSD cross-build", readiness.CIAttestationV1, "ci-nine-target-cross-build-v1", 3},
	{"packaging-nine-release-archives", "Nine published Linux/BSD release archives", readiness.ReleaseAttestation, "release-nine-archives-v1", 2},
	{"packaging-publication-attestation", "Release publication and attestation", readiness.ReleaseAttestation, "release-publication-attestation-v1", 1},
}

type dependencies struct {
	api        apiClient
	gate       func(context.Context, cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error)
	signatures func(context.Context, ciattestation.VerifyRequest) error
	archives   func(releasecheck.CheckRequest) error
	now        func() time.Time
}

// Verify resolves the published tag and its exact source, authenticates the
// released repository baseline and complete CI/publication evidence, and
// rereads mutable GitHub state and local bytes before returning. A 30-minute
// operation deadline is not an evidence-age policy. Every failure returns zero.
func Verify(ctx context.Context, input Request) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return verify(ctx, input, dependencies{githubAPI(input.GHPath), cireleasegate.Verify,
		ciattestation.VerifySetContext, releasecheck.Check, time.Now})
}

func verify(ctx context.Context, input Request, deps dependencies) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(input.GHPath) == "" || input.ReleaseDir == "" || input.RaceVetSubject == "" || len(input.CrossBuildSubjects) != 9 || !stableVersion(input.Version) {
		return Result{}, errors.New("trusted GitHub CLI, stable v-prefixed release version, release directory, race/vet subject, and nine cross-build subjects are required")
	}
	seen := map[string]bool{input.RaceVetSubject: true}
	for _, name := range input.CrossBuildSubjects {
		if name == "" || seen[name] {
			return Result{}, errors.New("CI subject paths must be nonempty and distinct")
		}
		seen[name] = true
	}
	initial, err := resolvePublication(ctx, deps.api, input.Version)
	if err != nil {
		return Result{}, err
	}
	source, cardBytes, card, err := resolveSource(ctx, deps.api, initial.Commit, deps.now().UTC())
	if err != nil {
		return Result{}, err
	}
	if err := checkAdditionalContract(card); err != nil {
		return Result{}, err
	}
	releaseRun, err := verifyReleaseRun(ctx, deps.api, input.Version, source.Commit)
	if err != nil {
		return Result{}, err
	}
	gateRequest := cireleasegate.VerifyRequest{Commit: source.Commit, GHPath: input.GHPath}
	ciRun, err := deps.gate(ctx, gateRequest)
	if err != nil {
		return Result{}, stageFailure(ctx, "initial complete CI gate", err)
	}
	if ciRun.ID <= 0 || ciRun.Attempt <= 0 || ciRun.Commit != source.Commit {
		return Result{}, errors.New("CI gate returned an inconsistent exact-release source identity")
	}
	local, err := snapshotEvidence(ctx, input, initial.Assets)
	if err != nil {
		return Result{}, err
	}
	privateRelease, cleanup, err := stageRelease(ctx, input.ReleaseDir, initial.Assets)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	request := ciattestation.VerifyRequest{Kind: "race-vet", SubjectPaths: []string{input.RaceVetSubject}, ExpectedRepo: repository,
		ExpectedWorkflow: ciWorkflow, ExpectedCommit: source.Commit, ExpectedTree: source.Tree, ExpectedRef: "refs/heads/main",
		GHPath: input.GHPath, WorkflowSHA: source.Commit, RunID: strconv.FormatInt(ciRun.ID, 10), RunAttempt: strconv.Itoa(ciRun.Attempt)}
	if err := deps.signatures(ctx, request); err != nil {
		return Result{}, stageFailure(ctx, "signed race/vet evidence", err)
	}
	request.Kind, request.SubjectPaths = "cross-build", append([]string(nil), input.CrossBuildSubjects...)
	if err := deps.signatures(ctx, request); err != nil {
		return Result{}, stageFailure(ctx, "signed cross-build evidence", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := deps.archives(releasecheck.CheckRequest{Dir: privateRelease, Version: input.Version, SourceDateEpoch: source.Epoch,
		Commit: source.Commit, Tree: source.Tree, BuilderGoVersion: packageinfo.ProductionBuilderGoVersion, ExpectedScorecard: append([]byte(nil), cardBytes...)}); err != nil {
		return Result{}, stageFailure(ctx, "released archive contents", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if _, err := snapshotRelease(ctx, privateRelease, initial.Assets); err != nil {
		return Result{}, err
	}
	request = ciattestation.VerifyRequest{Kind: "release", ExpectedRepo: repository, ExpectedWorkflow: releaseWorkflow,
		ExpectedCommit: source.Commit, ExpectedTree: source.Tree, ExpectedRef: "refs/tags/" + input.Version, GHPath: input.GHPath,
		ReleaseDir: privateRelease, ReleaseVersion: input.Version, WorkflowSHA: source.Commit,
		RunID: strconv.FormatInt(releaseRun.ID, 10), RunAttempt: strconv.Itoa(releaseRun.Attempt)}
	if err := deps.signatures(ctx, request); err != nil {
		return Result{}, stageFailure(ctx, "signed published release evidence", err)
	}
	if _, err := snapshotRelease(ctx, privateRelease, initial.Assets); err != nil {
		return Result{}, err
	}
	finalCI, err := deps.gate(ctx, gateRequest)
	if err != nil {
		return Result{}, stageFailure(ctx, "final complete CI gate", err)
	}
	if finalCI != ciRun {
		return Result{}, errors.New("latest exact-release CI run or attempt changed during verification")
	}
	finalRun, err := verifyReleaseRun(ctx, deps.api, input.Version, source.Commit)
	if err != nil {
		return Result{}, err
	}
	if finalRun != releaseRun {
		return Result{}, errors.New("latest Release run or attempt changed during verification")
	}
	final, err := resolvePublication(ctx, deps.api, input.Version)
	if err != nil {
		return Result{}, err
	}
	if !reflect.DeepEqual(final, initial) {
		return Result{}, errors.New("published release, assets, tag, or protection changed during verification")
	}
	finalSource, err := resolveCommit(ctx, deps.api, final.Commit)
	if err != nil {
		return Result{}, err
	}
	if finalSource != source {
		return Result{}, errors.New("release source identity changed during verification")
	}
	finalLocal, err := snapshotEvidence(ctx, input, final.Assets)
	if err != nil {
		return Result{}, err
	}
	if !reflect.DeepEqual(local, finalLocal) {
		return Result{}, errors.New("local authenticated evidence bytes changed during verification")
	}
	observedAt := deps.now().UTC()
	if err := validatePolicyTime(card, observedAt); err != nil {
		return Result{}, stageFailure(ctx, "released scorecard final validity", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	baseline := repositoryBaseline(card)
	total := baseline
	for _, item := range additionalCriteria {
		total += item.Points
	}
	if baseline <= 0 || total > 100 {
		return Result{}, errors.New("derived assessment is outside the fixed score contract")
	}
	return Result{1, input.Version, source.Commit, source.Tree, initial.Release.ID, releaseRun.ID, releaseRun.Attempt,
		ciRun.ID, ciRun.Attempt, observedAt, card.ExpiresAt, baseline, total, append([]Criterion(nil), additionalCriteria...)}, nil
}

func stableVersion(version string) bool {
	return len(version) <= 128 && releaseversion.Valid(version) && !strings.ContainsAny(version, "+-")
}

func checkAdditionalContract(card readiness.Scorecard) error {
	for _, expected := range additionalCriteria {
		count := 0
		for _, category := range card.Engineering {
			for _, item := range category.Subcriteria {
				if item.ID != expected.ID {
					continue
				}
				count++
				if item.Name != expected.Name || item.Weight != expected.Points || item.EvidenceType != expected.EvidenceType || item.VerifierID != expected.VerifierID || len(item.Evidence) != 0 {
					return errors.New("released scorecard does not match the reviewed live-evidence criterion contract")
				}
			}
		}
		if count != 1 {
			return errors.New("released scorecard lacks a unique reviewed live-evidence criterion")
		}
	}
	return nil
}

func stageFailure(ctx context.Context, stage string, err error) error {
	if e := ctx.Err(); e != nil {
		return fmt.Errorf("%s: %w", stage, e)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", stage, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", stage, context.DeadlineExceeded)
	}
	return fmt.Errorf("%s failed", stage)
}
