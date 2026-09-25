package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/productionpackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/target"
)

func TestReleaseSetStagesEveryAuthenticatedCellWithoutBuildingPackages(t *testing.T) {
	facts, releaseDir := releaseSetFixture(t)
	output := filepath.Join(t.TempDir(), "release-inputs")
	rechecks := 0
	if err := stageReleaseSet(context.Background(), facts, releaseDir, output, func(context.Context) error {
		rechecks++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rechecks != 2 {
		t.Fatalf("live release rechecks = %d; want 2", rechecks)
	}
	data, err := os.ReadFile(filepath.Join(output, releaseSetManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var plan releaseSetManifest
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.SchemaVersion != 1 || plan.PlanType != "leaguebridge-release-bound-native-package-inputs" ||
		plan.ValidationScope != "release-bound-staging-only" || plan.Release.Version != facts.version ||
		plan.Release.Commit != facts.commit || plan.Release.Tree != facts.tree || plan.Release.ReleaseID != facts.releaseID ||
		plan.Release.ScorecardSHA256 != facts.scorecardSHA256 {
		t.Fatalf("input plan release identity = %+v", plan)
	}
	expected := productionpackage.ExpectedCells()
	if len(plan.Cells) != 11 || len(plan.Cells) != len(expected) {
		t.Fatalf("input plan contains %d cells; want eleven", len(plan.Cells))
	}
	for index, cell := range plan.Cells {
		want := expected[index]
		if cell.Family != want.Family || cell.GOOS != want.GOOS || cell.GOARCH != want.GOARCH ||
			cell.StagingPath != string(want.Family)+"/"+want.GOARCH ||
			cell.PackageState != "unbuilt" || cell.SigningState != "not_performed" ||
			cell.PublicationState != "not_performed" || cell.LifecycleState != "not_verified" ||
			!releaseSetDigestPattern.MatchString(cell.ArchiveSHA256) ||
			!releaseSetDigestPattern.MatchString(cell.StagingManifestSHA256) {
			t.Errorf("cell %d = %+v; want score-free staged %s %s/%s", index, cell, want.Family, want.GOOS, want.GOARCH)
		}
		if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(cell.StagingPath), "root")); err != nil {
			t.Errorf("cell %d has no staged root: %v", index, err)
		}
	}
	if err := filepath.WalkDir(output, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".deb") || strings.HasSuffix(path, ".rpm") || strings.HasSuffix(path, ".pkg") || strings.HasSuffix(path, ".tgz") {
			t.Errorf("release-set created a native package instead of staging inputs: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseSetRejectsChangedArchiveAndLeavesNoOutput(t *testing.T) {
	facts, releaseDir := releaseSetFixture(t)
	facts.assets[0].SHA256 = strings.Repeat("f", 64)
	output := filepath.Join(t.TempDir(), "release-inputs")
	if err := stageReleaseSet(context.Background(), facts, releaseDir, output, func(context.Context) error { return nil }); err == nil || !strings.Contains(err.Error(), "source archive bytes differ") {
		t.Fatalf("changed published digest error = %v", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed release-set left output: %v", err)
	}
}

func TestReleaseSetRejectsChangedStagingDuringLiveRecheck(t *testing.T) {
	facts, releaseDir := releaseSetFixture(t)
	output := filepath.Join(t.TempDir(), "release-inputs")
	calls := 0
	err := stageReleaseSet(context.Background(), facts, releaseDir, output, func(context.Context) error {
		calls++
		if calls == 1 {
			binary := filepath.Join(output, "debian", "amd64", "root", "usr", "bin", "leaguebridge")
			return os.WriteFile(binary, []byte("changed while release recheck ran"), 0o755)
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "final recheck") || calls != 1 {
		t.Fatalf("changed staging error = %v; rechecks = %d", err, calls)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed staging recheck left output: %v", err)
	}
}

func TestReleaseSetRejectsFailedLiveRecheckAndLeavesNoOutput(t *testing.T) {
	facts, releaseDir := releaseSetFixture(t)
	output := filepath.Join(t.TempDir(), "release-inputs")
	err := stageReleaseSet(context.Background(), facts, releaseDir, output, func(context.Context) error {
		return errors.New("published release changed")
	})
	if err == nil || !strings.Contains(err.Error(), "published release changed") {
		t.Fatalf("live release recheck error = %v", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed release recheck left output: %v", err)
	}
}

func TestReleaseSetRequiresExclusiveOutputOutsideReleaseDirectory(t *testing.T) {
	facts, releaseDir := releaseSetFixture(t)
	output := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := stageReleaseSet(context.Background(), facts, releaseDir, output, func(context.Context) error { return nil }); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output error = %v", err)
	}
	if err := stageReleaseSet(context.Background(), facts, releaseDir, filepath.Join(releaseDir, "inputs"), func(context.Context) error { return nil }); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("inside release directory error = %v", err)
	}
	if err := stageReleaseSet(context.Background(), facts, releaseDir, filepath.Join(t.TempDir(), "zero"), nil); err == nil || !strings.Contains(err.Error(), "recheck") {
		t.Fatalf("nil release recheck error = %v", err)
	}
	if err := stageReleaseSet(nil, facts, releaseDir, filepath.Join(t.TempDir(), "nil-context"), func(context.Context) error { return nil }); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("nil staging context error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stageReleaseSet(ctx, facts, releaseDir, filepath.Join(t.TempDir(), "canceled"), func(context.Context) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled staging context error = %v", err)
	}
}

func TestReleaseSetRejectsCallerSuppliedReleaseJSONAndInvalidCapability(t *testing.T) {
	if _, err := parseReleaseSetOptions([]string{"--version", "v1.2.3", "--release-dir", "release", "--output", "out", "--release-json", "claim.json"}); err == nil {
		t.Fatal("release-set accepted caller-supplied release JSON")
	}
	if _, err := parseReleaseSetOptions([]string{"--version", "v1.2.3-rc.1", "--release-dir", "release", "--output", "out"}); err == nil {
		t.Fatal("release-set accepted a prerelease version")
	}
	if _, err := parseReleaseSetOptions([]string{"--version", "v1.2." + strings.Repeat("3", 130), "--release-dir", "release", "--output", "out"}); err == nil {
		t.Fatal("release-set accepted an oversized version")
	}
	if _, err := factsFromVerifiedRelease(releaseassessment.VerifiedRelease{}); err == nil {
		t.Fatal("release-set accepted the zero verified-release capability")
	}
	request := releaseSetRequest(releaseSetOptions{version: "v1.2.3", releaseDir: "release", gh: "trusted-gh"})
	if request.Version != "v1.2.3" || request.ReleaseDir != "release" || request.GHPath != "trusted-gh" ||
		request.RaceVetSubject != "ci-attestation/race-vet-linux.json" || len(request.CrossBuildSubjects) != 9 {
		t.Fatalf("release-set live request = %+v", request)
	}
}

func TestReleaseSetRejectsMismatchedCommitAndTreeIdentity(t *testing.T) {
	facts, releaseDir := releaseSetFixture(t)
	facts.tree = strings.Repeat("f", 64)
	output := filepath.Join(t.TempDir(), "release-inputs")
	if err := stageReleaseSet(context.Background(), facts, releaseDir, output, func(context.Context) error { return nil }); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("mismatched commit/tree identity was accepted: %v", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid release identity created output: %v", err)
	}
}

func releaseSetFixture(t *testing.T) (releaseSetFacts, string) {
	t.Helper()
	releaseDir := t.TempDir()
	facts := releaseSetFacts{
		version: "v1.2.3", commit: "0123456789abcdef0123456789abcdef01234567",
		tree: "89abcdef0123456789abcdef0123456789abcdef", scorecardSHA256: strings.Repeat("a", 64), releaseID: 77,
	}
	var checksums strings.Builder
	for _, candidate := range target.Ordered() {
		fixture := makeArchiveFixture(t, candidate.GOOS, candidate.GOARCH)
		data := mustRead(t, fixture.archive)
		name := filepath.Base(fixture.archive)
		if err := os.WriteFile(filepath.Join(releaseDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		digest := hex.EncodeToString(hash[:])
		facts.assets = append(facts.assets, releaseassessment.PublishedAsset{Name: name, SHA256: digest, SizeBytes: int64(len(data))})
		fmt.Fprintf(&checksums, "%s *./%s\n", digest, name)
	}
	checksumData := []byte(checksums.String())
	if err := os.WriteFile(filepath.Join(releaseDir, "checksums.txt"), checksumData, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(checksumData)
	facts.assets = append(facts.assets, releaseassessment.PublishedAsset{Name: "checksums.txt", SHA256: hex.EncodeToString(hash[:]), SizeBytes: int64(len(checksumData))})
	return facts, releaseDir
}
