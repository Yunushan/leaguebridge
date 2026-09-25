package productionpackage

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
)

func payloadSetFixture(t *testing.T) (candidateSetFixture, VerifiedSet, func(context.Context, CandidatePaths) (VerifiedCandidate, error), packageInspector) {
	t.Helper()
	fixture := makeCandidateSetFixture(t)
	verified, err := verifySetWithFacts(context.Background(), fixture.facts, fixture.inputs)
	if err != nil {
		t.Fatal(err)
	}
	verifyOne := func(ctx context.Context, input CandidatePaths) (VerifiedCandidate, error) {
		data, err := readRegularBounded(ctx, input.CandidatePath, maximumCandidate)
		if err != nil {
			return VerifiedCandidate{}, err
		}
		return verifyBytes(ctx, fixture.facts, data, input.ArchivePath, input.StagingDir, input.PackagePath)
	}
	packages := make(map[Cell]inspectedPackage, len(productionCells))
	for index, cell := range ExpectedCells() {
		root, err := fileinput.OpenDirectoryRoot(fixture.inputs[index].StagingDir)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := nativepackage.VerifyStagingRootContext(context.Background(), root)
		_ = root.Close()
		if err != nil {
			t.Fatal(err)
		}
		files := make([]inspectedFile, len(manifest.Payload))
		for index, entry := range manifest.Payload {
			files[index] = inspectedFile{Path: entry.InstallPath, Mode: entry.Mode, Size: entry.Size, SHA256: entry.SHA256}
		}
		packages[cell] = inspectedPackage{Name: nativepackage.PackageName, Version: manifest.Version, Architecture: manifest.Package.Architecture, Files: files}
	}
	inspect := func(_ context.Context, _ []byte, cell Cell) (inspectedPackage, error) { return packages[cell], nil }
	return fixture, verified, verifyOne, inspect
}

func TestPayloadSetRequiresEveryPackageByteAndStagedFile(t *testing.T) {
	fixture, candidates, verifyOne, inspect := payloadSetFixture(t)
	rechecks := 0
	verified, err := verifyPayloadSet(context.Background(), candidates, fixture.inputs, verifyOne,
		func(ctx context.Context) error {
			rechecks++
			current, err := verifySetWithFacts(ctx, fixture.facts, fixture.inputs)
			if err != nil {
				return err
			}
			return compareVerifiedSets(candidates, current)
		}, inspect)
	if err != nil || !verified.Valid() || rechecks != 1 {
		t.Fatalf("complete payload set = %+v, %v; rechecks=%d", verified, err, rechecks)
	}
	summaries, err := verified.Summaries()
	if err != nil || len(summaries) != len(productionCells) {
		t.Fatalf("verified payload summaries = %d, %v", len(summaries), err)
	}
	summaries[0].PackageSHA256 = "changed by caller"
	again, err := verified.Summaries()
	if err != nil || again[0].PackageSHA256 == "changed by caller" {
		t.Fatalf("caller changed retained payload summary: %+v, %v", again[0], err)
	}
}

func TestPayloadSetRejectsChangedPackageAfterCandidateVerification(t *testing.T) {
	fixture, candidates, verifyOne, inspect := payloadSetFixture(t)
	base := verifyOne
	changed := false
	verifyOne = func(ctx context.Context, input CandidatePaths) (VerifiedCandidate, error) {
		verified, err := base(ctx, input)
		if err != nil || changed {
			return verified, err
		}
		changed = true
		data, readErr := os.ReadFile(input.PackagePath)
		if readErr != nil {
			return VerifiedCandidate{}, readErr
		}
		data[0] ^= 0xff
		if writeErr := os.WriteFile(input.PackagePath, data, 0o644); writeErr != nil {
			return VerifiedCandidate{}, writeErr
		}
		return verified, nil
	}
	verified, err := verifyPayloadSet(context.Background(), candidates, fixture.inputs, verifyOne,
		func(context.Context) error { return nil }, inspect)
	if err == nil || verified.Valid() || !strings.Contains(err.Error(), "changed after candidate verification") {
		t.Fatalf("same-inode package overwrite was accepted: %+v, %v", verified, err)
	}
}

func TestPayloadSetRejectsIncompleteOrSubstitutedInspection(t *testing.T) {
	fixture, candidates, verifyOne, inspect := payloadSetFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*inspectedPackage)
	}{
		{"wrong package name", func(value *inspectedPackage) { value.Name = "other" }},
		{"wrong architecture", func(value *inspectedPackage) { value.Architecture = "other" }},
		{"missing file", func(value *inspectedPackage) { value.Files = value.Files[:len(value.Files)-1] }},
		{"extra file", func(value *inspectedPackage) { value.Files = append(value.Files, inspectedFile{Path: "/etc/extra"}) }},
		{"changed file digest", func(value *inspectedPackage) { value.Files[0].SHA256 = strings.Repeat("f", 64) }},
		{"duplicate path", func(value *inspectedPackage) { value.Files[0] = value.Files[1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspectChanged := func(ctx context.Context, data []byte, cell Cell) (inspectedPackage, error) {
				value, err := inspect(ctx, data, cell)
				if cell == productionCells[0] {
					value.Files = append([]inspectedFile(nil), value.Files...)
					tc.change(&value)
				}
				return value, err
			}
			verified, err := verifyPayloadSet(context.Background(), candidates, fixture.inputs, verifyOne,
				func(context.Context) error { return nil }, inspectChanged)
			if err == nil || verified.Valid() {
				t.Fatalf("substituted package inspection was accepted: %+v, %v", verified, err)
			}
		})
	}
}

func TestPayloadSetRejectsUnavailableVerifierAndFinalRecheckFailure(t *testing.T) {
	fixture, candidates, verifyOne, inspect := payloadSetFixture(t)
	var zero VerifiedPayloadSet
	if zero.Valid() {
		t.Fatal("zero payload set is valid")
	}
	if summaries, err := zero.Summaries(); err == nil || len(summaries) != 0 {
		t.Fatalf("zero payload set disclosed summaries: %+v, %v", summaries, err)
	}
	if value, err := verifyPayloadSet(context.Background(), candidates, fixture.inputs, verifyOne, nil, inspect); err == nil || value.Valid() {
		t.Fatalf("missing final recheck was accepted: %+v, %v", value, err)
	}
	if value, err := verifyPayloadSet(context.Background(), candidates, fixture.inputs, verifyOne,
		func(context.Context) error { return errors.New("withdrawn release") }, inspect); err == nil || value.Valid() {
		t.Fatalf("failed final recheck was accepted: %+v, %v", value, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if value, err := verifyPayloadSet(ctx, candidates, fixture.inputs, verifyOne,
		func(context.Context) error { return nil }, inspect); !errors.Is(err, context.Canceled) || value.Valid() {
		t.Fatalf("canceled payload verification was accepted: %+v, %v", value, err)
	}
}
