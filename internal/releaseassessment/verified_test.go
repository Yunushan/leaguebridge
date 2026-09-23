package releaseassessment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
	"github.com/Yunushan/leaguebridge/internal/cireleasegate"
)

func TestVerifiedReleaseCapturesAndRechecksLiveIdentity(t *testing.T) {
	fixture := newFixture(t)
	verified, err := verifyForProduction(context.Background(), fixture.input, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verified.Assessment()
	if err != nil || result.Score != 83 || result.RepositoryScore != 74 {
		t.Fatalf("unexpected verified assessment: %+v, %v", result, err)
	}
	digest, err := verified.ScorecardSHA256()
	if err != nil || digest != digestBytes(fixture.card) {
		t.Fatalf("released scorecard digest mismatch: %q, %v", digest, err)
	}
	assets, err := verified.PublishedAssets()
	if err != nil || len(assets) != 10 {
		t.Fatalf("expected ten captured assets, got %d: %v", len(assets), err)
	}
	assets[0].Name = "changed"
	result.Criteria[0].Points = 100
	again, err := verified.PublishedAssets()
	if err != nil || again[0].Name == "changed" {
		t.Fatal("caller changed retained asset identity")
	}
	result, err = verified.Assessment()
	if err != nil || result.Criteria[0].Points == 100 {
		t.Fatal("caller changed retained release assessment")
	}
	if err := verified.recheck(context.Background(), fixture.deps); err != nil {
		t.Fatalf("unchanged live release should recheck: %v", err)
	}
	fixture.deps.gate = func(ctx context.Context, request cireleasegate.VerifyRequest) (cireleasegate.RunIdentity, error) {
		return cireleasegate.RunIdentity{ID: 201, Attempt: 1, Commit: request.Commit}, ctx.Err()
	}
	if err := verified.recheck(context.Background(), fixture.deps); err == nil {
		t.Fatal("changed CI run was accepted by final recheck")
	}
}

func TestVerifiedReleaseZeroAndFailureStayUntrusted(t *testing.T) {
	var zero VerifiedRelease
	if _, err := zero.Assessment(); err == nil {
		t.Fatal("zero release returned an assessment")
	}
	if _, err := zero.ScorecardSHA256(); err == nil {
		t.Fatal("zero release returned a scorecard digest")
	}
	if _, err := zero.PublishedAssets(); err == nil {
		t.Fatal("zero release returned published assets")
	}
	if err := zero.Recheck(context.Background()); err == nil {
		t.Fatal("zero release passed a final recheck")
	}
	fixture := newFixture(t)
	fixture.deps.signatures = func(context.Context, ciattestation.VerifyRequest) error {
		return errors.New("unsigned")
	}
	verified, err := verifyForProduction(context.Background(), fixture.input, fixture.deps)
	if err == nil || verified.valid {
		t.Fatal("failed live signature check returned a trusted identity")
	}
}

func TestVerifiedReleaseRecheckRejectsChangedPublishedAsset(t *testing.T) {
	fixture := newFixture(t)
	verified, err := verifyForProduction(context.Background(), fixture.input, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	key := fixturePrefix + "/releases/tags/" + fixtureVersion
	published := fixture.values[key].(release)
	published.Assets = append([]asset(nil), published.Assets...)
	changed := []byte("changed published file\n")
	item := &published.Assets[0]
	item.Size = int64(len(changed))
	item.Digest = "sha256:" + digestBytes(changed)
	if err := os.WriteFile(filepath.Join(fixture.input.ReleaseDir, item.Name), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.values[key] = published
	fixture.values[fixturePrefix+"/releases/77/assets?per_page=100&page=1"] = published.Assets
	if err := verified.recheck(context.Background(), fixture.deps); err == nil {
		t.Fatal("changed published asset was accepted by final recheck")
	}
}

func TestVerifiedReleaseRecheckRejectsPublicationContinuityChanges(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*fixture)
	}{
		{"asset reuploaded with identical bytes", func(f *fixture) {
			key := fixturePrefix + "/releases/tags/" + fixtureVersion
			published := f.values[key].(release)
			published.Assets = append([]asset(nil), published.Assets...)
			published.Assets[0].ID = 999
			f.values[key] = published
			f.values[fixturePrefix+"/releases/77/assets?per_page=100&page=1"] = published.Assets
		}},
		{"qualifying protection ruleset replaced", func(f *fixture) {
			rule := f.values[fixturePrefix+"/rulesets/91"].(ruleset)
			rule.ID = 92
			f.values[fixturePrefix+"/rulesets?includes_parents=true&per_page=100&page=1"] = []ruleset{rule}
			f.values[fixturePrefix+"/rulesets/92"] = rule
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			fixture := newFixture(t)
			verified, err := verifyForProduction(context.Background(), fixture.input, fixture.deps)
			if err != nil {
				t.Fatal(err)
			}
			item.change(fixture)
			if err := verified.recheck(context.Background(), fixture.deps); err == nil {
				t.Fatal("changed publication state was accepted by final recheck")
			}
		})
	}
}

func TestVerifiedReleaseRecheckRejectsChangedLocalCIEvidence(t *testing.T) {
	fixture := newFixture(t)
	verified, err := verifyForProduction(context.Background(), fixture.input, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.FromSlash(fixture.input.RaceVetSubject), []byte("different signed CI fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verified.recheck(context.Background(), fixture.deps); err == nil {
		t.Fatal("changed local CI subject was accepted by final recheck")
	}
}
