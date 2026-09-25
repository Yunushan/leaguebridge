package productionpackage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

type candidateSetFixture struct {
	facts  releaseFacts
	inputs []CandidatePaths
}

// The two Linux package families share each published archive. This fixture
// normalizes their staging trees to that one authenticated archive per target.
func makeCandidateSetFixture(t *testing.T) candidateSetFixture {
	t.Helper()
	ctx := context.Background()
	inputs := make([]CandidatePaths, 0, len(productionCells))
	assets := make([]releaseassessment.PublishedAsset, 0, 9)
	archives := make(map[string]fixture, 9)
	var facts releaseFacts
	for _, cell := range ExpectedCells() {
		value := makeFixture(t, cell)
		if facts.Version == "" {
			facts = value.facts
		}
		name := filepath.Base(value.archivePath)
		if original, duplicateTarget := archives[name]; duplicateTarget {
			asset := original.facts.Assets[0]
			archiveData, err := os.ReadFile(original.archivePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(value.archivePath, archiveData, 0o644); err != nil {
				t.Fatal(err)
			}
			sourceData, err := sourceManifestFromPublishedArchive(ctx, original.archivePath, asset)
			if err != nil {
				t.Fatal(err)
			}
			var source packageinfo.Manifest
			if err := json.Unmarshal(sourceData, &source); err != nil {
				t.Fatal(err)
			}
			staging, err := nativepackage.Build(source, sourceData, asset.SHA256, cell.Family)
			if err != nil {
				t.Fatal(err)
			}
			stagingData, err := nativepackage.Marshal(staging)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(value.stagingDir, nativepackage.StagingManifestName), stagingData, 0o644); err != nil {
				t.Fatal(err)
			}
			for _, payload := range staging.Payload {
				if payload.SourcePath != packageinfo.ManifestName {
					continue
				}
				path := filepath.Join(value.stagingDir, "root", filepath.FromSlash(strings.TrimPrefix(payload.InstallPath, "/")))
				if err := os.WriteFile(path, sourceData, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		} else {
			archives[name] = value
			assets = append(assets, value.facts.Assets[0])
		}
		candidatePath := filepath.Join(t.TempDir(), "candidate.json")
		inputs = append(inputs, CandidatePaths{
			CandidatePath: candidatePath, ArchivePath: value.archivePath,
			StagingDir: value.stagingDir, PackagePath: value.packagePath,
		})
	}
	facts.Assets = assets
	for _, input := range inputs {
		value, err := derive(ctx, facts, input.ArchivePath, input.StagingDir, input.PackagePath)
		if err != nil {
			t.Fatal(err)
		}
		data, err := marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(input.CandidatePath, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return candidateSetFixture{facts: facts, inputs: inputs}
}

func TestCandidateSetRequiresEveryVerifiedCellAndReturnsDetachedCanonicalSummaries(t *testing.T) {
	fixture := makeCandidateSetFixture(t)
	// Neither input order nor later mutation of a returned summary can change
	// the fixed candidate inventory retained by the result.
	for left, right := 0, len(fixture.inputs)-1; left < right; left, right = left+1, right-1 {
		fixture.inputs[left], fixture.inputs[right] = fixture.inputs[right], fixture.inputs[left]
	}
	set, err := verifySetWithFacts(context.Background(), fixture.facts, fixture.inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Valid() {
		t.Fatal("complete candidate set returned an invalid result")
	}
	summaries, err := set.Summaries()
	if err != nil || len(summaries) != len(ExpectedCells()) {
		t.Fatalf("complete candidate summaries = %d, %v", len(summaries), err)
	}
	for index, cell := range ExpectedCells() {
		got := summaries[index]
		if (Cell{got.Family, got.GOOS, got.GOARCH}) != cell ||
			got.Version != fixture.facts.Version || got.Commit != fixture.facts.Commit ||
			got.Tree != fixture.facts.Tree || got.ReleaseID != fixture.facts.ReleaseID ||
			got.ArchiveSHA256 == "" || got.ExecutableSHA256 == "" || got.PackageSHA256 == "" || got.CandidateSHA256 == "" {
			t.Fatalf("candidate summary %d is not bound to the expected release and cell: %+v", index, got)
		}
	}
	summaries[0].PackageSHA256 = "caller mutation"
	again, err := set.Summaries()
	if err != nil || again[0].PackageSHA256 == "caller mutation" {
		t.Fatalf("caller changed a verified set summary: %+v, %v", again[0], err)
	}
}

func TestCandidateSetRejectsMissingDuplicateExtraAndWrongRelease(t *testing.T) {
	fixture := makeCandidateSetFixture(t)
	ctx := context.Background()
	if set, err := verifySetWithFacts(ctx, fixture.facts, fixture.inputs[:len(fixture.inputs)-1]); err == nil || set.Valid() {
		t.Fatalf("missing candidate cell was accepted: %+v, %v", set, err)
	}
	duplicate := append([]CandidatePaths(nil), fixture.inputs...)
	duplicate[len(duplicate)-1] = duplicate[0]
	if set, err := verifySetWithFacts(ctx, fixture.facts, duplicate); err == nil || set.Valid() || !strings.Contains(err.Error(), "repeats cell") {
		t.Fatalf("duplicate candidate cell was accepted: %+v, %v", set, err)
	}
	extra := append(append([]CandidatePaths(nil), fixture.inputs...), fixture.inputs[0])
	if set, err := verifySetWithFacts(ctx, fixture.facts, extra); err == nil || set.Valid() {
		t.Fatalf("extra candidate cell was accepted: %+v, %v", set, err)
	}
	data, err := os.ReadFile(fixture.inputs[0].CandidatePath)
	if err != nil {
		t.Fatal(err)
	}
	wrongRelease, err := unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	wrongRelease.Release.Commit = strings.Repeat("f", 40)
	data, err = marshal(wrongRelease)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.inputs[0].CandidatePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if set, err := verifySetWithFacts(ctx, fixture.facts, fixture.inputs); err == nil || set.Valid() {
		t.Fatalf("wrong-release candidate cell was accepted: %+v, %v", set, err)
	}
}

func TestCandidateSetRejectsInvalidReleaseContextAndResult(t *testing.T) {
	fixture := makeCandidateSetFixture(t)
	if set, err := VerifySet(context.Background(), releaseassessment.VerifiedRelease{}, fixture.inputs); err == nil || set.Valid() {
		t.Fatalf("zero live release identity was accepted: %+v, %v", set, err)
	}
	if set, err := verifySetWithFacts(nil, fixture.facts, fixture.inputs); err == nil || set.Valid() {
		t.Fatalf("nil context was accepted: %+v, %v", set, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if set, err := verifySetWithFacts(ctx, fixture.facts, fixture.inputs); !errors.Is(err, context.Canceled) || set.Valid() {
		t.Fatalf("canceled context was accepted: %+v, %v", set, err)
	}
	var zero VerifiedSet
	if zero.Valid() {
		t.Fatal("zero candidate set was valid")
	}
	if summaries, err := zero.Summaries(); err == nil || len(summaries) != 0 {
		t.Fatalf("zero candidate set disclosed summaries: %+v, %v", summaries, err)
	}
	if err := zero.Recheck(context.Background(), releaseassessment.VerifiedRelease{}, fixture.inputs); err == nil {
		t.Fatal("zero candidate set was rechecked")
	}
}

func TestCandidateSetRecheckDetectsChangedPackageBytes(t *testing.T) {
	fixture := makeCandidateSetFixture(t)
	previous, err := verifySetWithFacts(context.Background(), fixture.facts, fixture.inputs)
	if err != nil {
		t.Fatal(err)
	}
	current, err := verifySetWithFacts(context.Background(), fixture.facts, fixture.inputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareVerifiedSets(previous, current); err != nil {
		t.Fatalf("unchanged complete set failed recheck: %v", err)
	}

	input := fixture.inputs[0]
	packageData, err := os.ReadFile(input.PackagePath)
	if err != nil {
		t.Fatal(err)
	}
	packageData[0] ^= 0xff
	if err := os.WriteFile(input.PackagePath, packageData, 0o644); err != nil {
		t.Fatal(err)
	}
	// Even if the candidate metadata is regenerated for the modified package,
	// it cannot silently replace a package in an earlier verified set.
	updated, err := derive(context.Background(), fixture.facts, input.ArchivePath, input.StagingDir, input.PackagePath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input.CandidatePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	current, err = verifySetWithFacts(context.Background(), fixture.facts, fixture.inputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareVerifiedSets(previous, current); err == nil || !strings.Contains(err.Error(), "changed after verification") {
		t.Fatalf("changed package candidate replaced an earlier verified cell: %v", err)
	}
}
