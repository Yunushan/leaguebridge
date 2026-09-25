package productionassessment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

var fixtureTime = time.Date(2030, time.September, 1, 12, 0, 0, 0, time.UTC)

type fixtureIdentity struct {
	result     releaseassessment.Result
	digest     string
	assets     []releaseassessment.PublishedAsset
	recheckErr error
	rechecks   int
}

type recheckHookIdentity struct {
	verifiedRelease
	after func()
}

func (value recheckHookIdentity) Recheck(ctx context.Context) error {
	err := value.verifiedRelease.Recheck(ctx)
	if value.after != nil {
		value.after()
	}
	return err
}

func (f *fixtureIdentity) Assessment() (releaseassessment.Result, error) { return f.result, nil }
func (f *fixtureIdentity) ScorecardSHA256() (string, error)              { return f.digest, nil }
func (f *fixtureIdentity) PublishedAssets() ([]releaseassessment.PublishedAsset, error) {
	return f.assets, nil
}
func (f *fixtureIdentity) Recheck(context.Context) error {
	f.rechecks++
	return f.recheckErr
}

func fixtureRelease() *fixtureIdentity {
	version := "v1.2.3"
	base := "leaguebridge_1.2.3_"
	names := []string{
		"checksums.txt", base + "dragonfly_amd64.tar.gz", base + "freebsd_amd64.tar.gz",
		base + "freebsd_arm64.tar.gz", base + "linux_amd64.tar.gz", base + "linux_arm64.tar.gz",
		base + "netbsd_amd64.tar.gz", base + "netbsd_arm64.tar.gz", base + "openbsd_amd64.tar.gz",
		base + "openbsd_arm64.tar.gz",
	}
	assets := make([]releaseassessment.PublishedAsset, len(names))
	for i, name := range names {
		assets[i] = releaseassessment.PublishedAsset{Name: name, SHA256: strings.Repeat("a", 64), SizeBytes: 1024}
	}
	return &fixtureIdentity{
		result: releaseassessment.Result{
			SchemaVersion: 1, Version: version, Commit: strings.Repeat("b", 40), Tree: strings.Repeat("c", 40),
			ReleaseID: 1, ReleaseRunID: 2, ReleaseRunAttempt: 1, CIRunID: 3, CIRunAttempt: 1,
			ObservedAt: fixtureTime, ScorecardExpiresAt: fixtureTime.Add(24 * time.Hour),
			RepositoryScore: 74, Score: 83,
			Criteria: []releaseassessment.Criterion{
				{ID: "tests-race-vet-linux", Name: "Linux race and vet", EvidenceType: "ci-attestation-v1", VerifierID: "ci-race-vet-v1", Points: 3},
				{ID: "tests-nine-target-cross-build", Name: "Nine-target Linux/BSD cross-build", EvidenceType: "ci-attestation-v1", VerifierID: "ci-nine-target-cross-build-v1", Points: 3},
				{ID: "packaging-nine-release-archives", Name: "Nine published Linux/BSD release archives", EvidenceType: "release-attestation-v1", VerifierID: "release-nine-archives-v1", Points: 2},
				{ID: "packaging-publication-attestation", Name: "Release publication and attestation", EvidenceType: "release-attestation-v1", VerifierID: "release-publication-attestation-v1", Points: 1},
			},
		},
		digest: strings.Repeat("d", 64), assets: assets,
	}
}

func fixtureDependencies(identity verifiedRelease, verifyErr error) dependencies {
	return dependencies{
		verifyRelease: func(context.Context, releaseassessment.Request) (verifiedRelease, error) {
			return identity, verifyErr
		},
		verifyExternal: unprovisionedExternalEvidence,
		now:            func() time.Time { return fixtureTime.Add(time.Minute) },
	}
}

func fixtureBinding(identity *fixtureIdentity) releaseBinding {
	assets := make([]Asset, len(identity.assets))
	for i, item := range identity.assets {
		assets[i] = Asset{Name: item.Name, SHA256: item.SHA256, SizeBytes: item.SizeBytes}
	}
	return releaseBinding{
		version: identity.result.Version, commit: identity.result.Commit, tree: identity.result.Tree,
		releaseID: identity.result.ReleaseID, releaseRunID: identity.result.ReleaseRunID,
		releaseRunAttempt: identity.result.ReleaseRunAttempt, ciRunID: identity.result.CIRunID,
		ciRunAttempt: identity.result.CIRunAttempt, scorecardSHA256: identity.digest,
		scorecardExpiresAt: identity.result.ScorecardExpiresAt, assets: assets,
	}
}

func fixtureProof(t *testing.T, identity *fixtureIdentity, criterionID string, expiresAt time.Time) criterionProof {
	t.Helper()
	proof, err := newCriterionProof(criterionID, fixtureBinding(identity), strings.Repeat("e", 64), fixtureTime, expiresAt)
	if err != nil {
		t.Fatalf("construct opaque fixture proof: %v", err)
	}
	return proof
}

func TestVerifyProducesSchemaConformingMissingEvidenceWithoutCredit(t *testing.T) {
	identity := fixtureRelease()
	input := releaseassessment.Request{Version: "v1.2.3"}
	result, err := verify(context.Background(), input, fixtureDependencies(identity, nil))
	if err != nil {
		t.Fatal(err)
	}
	if identity.rechecks != 1 || result.Score != 83 || result.ReleaseScore != 83 || result.RepositoryScore != 74 ||
		!result.ObservedAt.Equal(fixtureTime.Add(time.Minute)) || !result.EvidenceExpiresAt.Equal(identity.result.ScorecardExpiresAt) ||
		result.Release.ScorecardSHA256 != identity.digest || len(result.Release.Assets) != 10 || len(result.Criteria) != 6 {
		t.Fatalf("unexpected fixed release composition: %+v; rechecks=%d", result, identity.rechecks)
	}
	weight := 0
	for _, criterion := range result.Criteria {
		weight += criterion.Weight
		if criterion.Points != 0 || criterion.Status != "missing_evidence" || len(criterion.MissingEvidence) == 0 {
			t.Fatalf("unprovisioned evidence was promoted: %+v", criterion)
		}
	}
	if weight != 17 {
		t.Fatalf("external criterion weights total %d, want 17", weight)
	}
	assertProductionAssessmentSchema(t, result)
}

func assertProductionAssessmentSchema(t *testing.T, result Result) {
	t.Helper()
	// The fixtures are deliberately synthetic and cannot authenticate a
	// release; schema validation checks only the emitted shape and order.
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schemas", "production-assessment.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaValue any
	schemaDecoder := json.NewDecoder(bytes.NewReader(schemaData))
	schemaDecoder.UseNumber()
	if err := schemaDecoder.Decode(&schemaValue); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	const schemaID = "https://github.com/Yunushan/leaguebridge/schemas/production-assessment.schema.json"
	if err := compiler.AddResource(schemaID, schemaValue); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("composition output violates production schema: %v", err)
	}
}

func TestVerifyPassesAuthenticatedReleaseToExternalVerifier(t *testing.T) {
	identity := fixtureRelease()
	called := false
	deps := fixtureDependencies(identity, nil)
	deps.verifyExternal = func(ctx context.Context, authenticated verifiedRelease, binding releaseBinding) (externalVerification, error) {
		called = true
		if authenticated != identity {
			t.Fatal("external verifier did not receive the authenticated release capability")
		}
		assessment, err := authenticated.Assessment()
		if err != nil || binding.version != assessment.Version || binding.commit != assessment.Commit || binding.tree != assessment.Tree {
			t.Fatalf("external verifier received inconsistent release identity: %+v, %v", binding, err)
		}
		binding.assets[0].Name = "mutated"
		return unprovisionedExternalEvidence(ctx, authenticated, binding)
	}
	result, err := verify(context.Background(), releaseassessment.Request{Version: "v1.2.3"}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if !called || result.Release.Assets[0].Name != "checksums.txt" || identity.assets[0].Name != "checksums.txt" {
		t.Fatalf("external verifier changed authenticated release output: %+v", result.Release.Assets)
	}
}

func TestVerifyDerivesScoreFromReleaseBoundCriteria(t *testing.T) {
	identity := fixtureRelease()
	var proofs []criterionProof
	for _, spec := range externalCriterionSpecs {
		proofs = append(proofs, fixtureProof(t, identity, spec.id, fixtureTime.Add(2*time.Hour)))
	}
	rechecks := 0
	deps := fixtureDependencies(identity, nil)
	deps.verifyExternal = func(context.Context, verifiedRelease, releaseBinding) (externalVerification, error) {
		return externalVerification{proofs: proofs, recheck: func(context.Context) error { rechecks++; return nil }}, nil
	}
	result, err := verify(context.Background(), releaseassessment.Request{Version: "v1.2.3"}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 100 || result.ReleaseScore != 83 || result.RepositoryScore != 74 ||
		!result.EvidenceExpiresAt.Equal(fixtureTime.Add(2*time.Hour)) || rechecks != 2 || identity.rechecks != 1 {
		t.Fatalf("complete release-bound evidence did not derive 100 with final rechecks: %+v; external=%d release=%d", result, rechecks, identity.rechecks)
	}
	assertProductionAssessmentSchema(t, result)
	for _, criterion := range result.Criteria {
		if criterion.Status != "verified" || criterion.Points != criterion.Weight || len(criterion.MissingEvidence) != 0 {
			t.Fatalf("criterion was not derived as complete: %+v", criterion)
		}
	}
}

func TestVerifyRejectsExternalRevocationDuringReleaseRecheck(t *testing.T) {
	identity := fixtureRelease()
	var proofs []criterionProof
	for _, spec := range externalCriterionSpecs {
		proofs = append(proofs, fixtureProof(t, identity, spec.id, fixtureTime.Add(2*time.Hour)))
	}
	active := true
	externalRechecks := 0
	deps := fixtureDependencies(recheckHookIdentity{verifiedRelease: identity, after: func() { active = false }}, nil)
	deps.verifyExternal = func(context.Context, verifiedRelease, releaseBinding) (externalVerification, error) {
		return externalVerification{proofs: proofs, recheck: func(context.Context) error {
			externalRechecks++
			if !active {
				return errors.New("external authorization was revoked")
			}
			return nil
		}}, nil
	}
	result, err := verify(context.Background(), releaseassessment.Request{Version: "v1.2.3"}, deps)
	if err == nil || !strings.Contains(err.Error(), "external authorization was revoked") || result.Score != 0 ||
		identity.rechecks != 1 || externalRechecks != 2 {
		t.Fatalf("revocation during release recheck earned points: %+v, %v; release=%d external=%d", result, err, identity.rechecks, externalRechecks)
	}
}

func TestVerifyDerivesPartialScoreAndRejectsInvalidExternalProofs(t *testing.T) {
	identity := fixtureRelease()
	proof := fixtureProof(t, identity, externalCriterionSpecs[0].id, fixtureTime.Add(2*time.Hour))
	deps := fixtureDependencies(identity, nil)
	deps.verifyExternal = func(context.Context, verifiedRelease, releaseBinding) (externalVerification, error) {
		return externalVerification{proofs: []criterionProof{proof}, recheck: func(context.Context) error { return nil }}, nil
	}
	result, err := verify(context.Background(), releaseassessment.Request{Version: "v1.2.3"}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 85 || result.Criteria[0].Status != "verified" || result.Criteria[0].Points != 2 ||
		result.Criteria[1].Status != "missing_evidence" {
		t.Fatalf("partial external evidence was not scored all-or-nothing: %+v", result)
	}

	for _, tc := range []struct {
		name   string
		change func(*criterionProof)
	}{
		{"wrong release binding", func(value *criterionProof) { value.releaseBindingSHA256 = strings.Repeat("0", 64) }},
		{"expired proof", func(value *criterionProof) { value.expiresAt = fixtureTime.Add(30 * time.Second) }},
		{"invalid evidence digest", func(value *criterionProof) { value.evidenceSHA256 = "caller" }},
		{"zero proof", func(value *criterionProof) { *value = criterionProof{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := fixtureRelease()
			candidate := fixtureProof(t, identity, externalCriterionSpecs[0].id, fixtureTime.Add(2*time.Hour))
			tc.change(&candidate)
			deps := fixtureDependencies(identity, nil)
			deps.verifyExternal = func(context.Context, verifiedRelease, releaseBinding) (externalVerification, error) {
				return externalVerification{proofs: []criterionProof{candidate}, recheck: func(context.Context) error { return nil }}, nil
			}
			result, err := verify(context.Background(), releaseassessment.Request{Version: "v1.2.3"}, deps)
			if err == nil || result.Score != 0 || identity.rechecks != 0 {
				t.Fatalf("invalid external proof earned points or reached final release recheck: %+v, %v; rechecks=%d", result, err, identity.rechecks)
			}
		})
	}
}

func TestVerifyRejectsZeroIdentityAndReleaseFailure(t *testing.T) {
	input := releaseassessment.Request{Version: "v1.2.3"}
	var zero releaseassessment.VerifiedRelease
	for _, tc := range []struct {
		name string
		deps dependencies
	}{
		{"zero opaque identity", fixtureDependencies(zero, nil)},
		{"failed live verification", fixtureDependencies(nil, errors.New("release unavailable"))},
		{"missing identity", fixtureDependencies(nil, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := verify(context.Background(), input, tc.deps)
			if err == nil || result.SchemaVersion != 0 || result.Score != 0 {
				t.Fatalf("invalid release earned an assessment: %+v, %v", result, err)
			}
		})
	}
}

func TestVerifyRejectsMismatchedReleaseAndAssetIdentity(t *testing.T) {
	input := releaseassessment.Request{Version: "v1.2.3"}
	for _, tc := range []struct {
		name   string
		change func(*fixtureIdentity)
	}{
		{"wrong version", func(f *fixtureIdentity) { f.result.Version = "v1.2.4" }},
		{"incomplete release score", func(f *fixtureIdentity) { f.result.Score = 82 }},
		{"swapped release criterion", func(f *fixtureIdentity) {
			f.result.Criteria[0], f.result.Criteria[1] = f.result.Criteria[1], f.result.Criteria[0]
		}},
		{"missing published asset", func(f *fixtureIdentity) { f.assets = f.assets[:9] }},
		{"duplicate published asset", func(f *fixtureIdentity) { f.assets[1].Name = f.assets[0].Name }},
		{"invalid scorecard digest", func(f *fixtureIdentity) { f.digest = "caller" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := fixtureRelease()
			tc.change(identity)
			result, err := verify(context.Background(), input, fixtureDependencies(identity, nil))
			if err == nil || result.SchemaVersion != 0 || result.Score != 0 || identity.rechecks != 0 {
				t.Fatalf("mismatched identity reached final recheck or earned credit: %+v, %v; rechecks=%d", result, err, identity.rechecks)
			}
		})
	}
}

func TestVerifyRejectsRecheckDriftAndExpiry(t *testing.T) {
	input := releaseassessment.Request{Version: "v1.2.3"}
	identity := fixtureRelease()
	identity.recheckErr = errors.New("publication changed")
	result, err := verify(context.Background(), input, fixtureDependencies(identity, nil))
	if err == nil || result.Score != 0 || identity.rechecks != 1 {
		t.Fatalf("changed publication was accepted: %+v, %v; rechecks=%d", result, err, identity.rechecks)
	}

	identity = fixtureRelease()
	deps := fixtureDependencies(identity, nil)
	clockReads := 0
	deps.now = func() time.Time {
		clockReads++
		if clockReads == 1 {
			return fixtureTime.Add(time.Minute)
		}
		return identity.result.ScorecardExpiresAt
	}
	result, err = verify(context.Background(), input, deps)
	if err == nil || result.Score != 0 || identity.rechecks != 1 {
		t.Fatalf("expired final observation was accepted: %+v, %v; rechecks=%d", result, err, identity.rechecks)
	}
}
