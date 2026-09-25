package productionpackage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

// VerifiedPayloadSet means every package's metadata and declared install
// payload matched the authenticated release's staging tree at verification
// time. Its zero value is invalid. It is score-free: publisher signatures,
// repository publication, revocation, and native installation are separate.
type VerifiedPayloadSet struct {
	valid     bool
	summaries []Summary
}

func (set VerifiedPayloadSet) Valid() bool { return set.valid }

func (set VerifiedPayloadSet) Summaries() ([]Summary, error) {
	if !set.valid {
		return nil, errors.New("native package payload set has not been verified")
	}
	return append([]Summary(nil), set.summaries...), nil
}

type packageInspector func(context.Context, []byte, Cell) (inspectedPackage, error)

// VerifyStagedPayload checks one native package against its verified staging
// tree using the built-in package format inspector. It is a local, score-free
// check for package build pipelines; it does not authenticate a release,
// publisher, repository, or installed system.
func VerifyStagedPayload(ctx context.Context, packagePath, stagingDir string) error {
	if ctx == nil {
		return errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := fileinput.OpenDirectoryRoot(stagingDir)
	if err != nil {
		return fmt.Errorf("open package staging: %w", err)
	}
	manifest, err := nativepackage.VerifyStagingRootContext(ctx, root)
	_ = root.Close()
	if err != nil {
		return fmt.Errorf("verify package staging: %w", err)
	}
	cell := Cell{Family: manifest.Package.Family, GOOS: manifest.Target.GOOS, GOARCH: manifest.Target.GOARCH}
	if !supportedCell(cell) {
		return fmt.Errorf("unsupported native package cell %+v", cell)
	}
	snapshot, err := readRegularBounded(ctx, packagePath, maximumPackage)
	if err != nil {
		return fmt.Errorf("snapshot native package: %w", err)
	}
	if len(snapshot) == 0 {
		return errors.New("native package is empty")
	}
	observed, err := inspectNativePackage(ctx, snapshot, cell)
	if err != nil {
		return fmt.Errorf("inspect native package: %w", err)
	}
	if err := matchInspectedPayload(manifest, observed); err != nil {
		return fmt.Errorf("native package payload: %w", err)
	}
	current, err := readRegularBounded(ctx, packagePath, maximumPackage)
	if err != nil {
		return fmt.Errorf("recheck native package: %w", err)
	}
	if !bytes.Equal(snapshot, current) {
		return errors.New("native package changed during payload verification")
	}
	root, err = fileinput.OpenDirectoryRoot(stagingDir)
	if err != nil {
		return fmt.Errorf("reopen package staging: %w", err)
	}
	currentManifest, err := nativepackage.VerifyStagingRootContext(ctx, root)
	_ = root.Close()
	if err != nil {
		return fmt.Errorf("recheck package staging: %w", err)
	}
	if !reflect.DeepEqual(manifest, currentManifest) {
		return errors.New("package staging changed during payload verification")
	}
	return nil
}

// VerifyPayloadSet inspects exactly one native package for every fixed cell.
// It uses private package-byte snapshots and built-in format inspectors; no
// caller-supplied report, parser result, or signing key can select acceptance.
func VerifyPayloadSet(ctx context.Context, release releaseassessment.VerifiedRelease, inputs []CandidatePaths) (VerifiedPayloadSet, error) {
	if ctx == nil {
		return VerifiedPayloadSet{}, errors.New("verification context is required")
	}
	inputs = append([]CandidatePaths(nil), inputs...)
	set, err := VerifySet(ctx, release, inputs)
	if err != nil {
		return VerifiedPayloadSet{}, fmt.Errorf("verify package candidate inventory: %w", err)
	}
	return verifyPayloadSet(ctx, set, inputs,
		func(ctx context.Context, input CandidatePaths) (VerifiedCandidate, error) {
			return Verify(ctx, release, input.CandidatePath, input.ArchivePath, input.StagingDir, input.PackagePath)
		},
		func(ctx context.Context) error { return set.Recheck(ctx, release, inputs) },
		inspectNativePackage)
}

func inspectNativePackage(ctx context.Context, snapshot []byte, cell Cell) (inspectedPackage, error) {
	switch cell.Family {
	case nativepackage.FamilyDebian:
		return inspectDeb(ctx, snapshot)
	case nativepackage.FamilyRPM:
		return inspectRPM(ctx, snapshot)
	case nativepackage.FamilyFreeBSD, nativepackage.FamilyDPorts:
		return inspectFreeBSDPkg(ctx, snapshot, cell.GOOS)
	case nativepackage.FamilyOpenBSD:
		return inspectOpenBSDPkg(ctx, snapshot)
	case nativepackage.FamilyPkgsrc:
		return inspectNetBSDPkg(ctx, snapshot)
	default:
		return inspectedPackage{}, fmt.Errorf("unsupported native package cell %+v", cell)
	}
}

func verifyPayloadSet(ctx context.Context, set VerifiedSet, inputs []CandidatePaths,
	verifyOne func(context.Context, CandidatePaths) (VerifiedCandidate, error),
	recheck func(context.Context) error, inspect packageInspector) (VerifiedPayloadSet, error) {
	if ctx == nil {
		return VerifiedPayloadSet{}, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedPayloadSet{}, err
	}
	if !set.valid || len(set.summaries) != len(productionCells) || len(inputs) != len(productionCells) {
		return VerifiedPayloadSet{}, errors.New("complete verified eleven-cell candidate set is required")
	}
	if verifyOne == nil || recheck == nil || inspect == nil {
		return VerifiedPayloadSet{}, errors.New("native package payload verifier is unavailable")
	}
	inputs = append([]CandidatePaths(nil), inputs...)
	indices := make(map[Cell]int, len(productionCells))
	for index, cell := range productionCells {
		indices[cell] = index
	}
	seen := make(map[Cell]bool, len(productionCells))
	for inputIndex, input := range inputs {
		if err := ctx.Err(); err != nil {
			return VerifiedPayloadSet{}, err
		}
		verified, err := verifyOne(ctx, input)
		if err != nil {
			return VerifiedPayloadSet{}, fmt.Errorf("reverify candidate %d: %w", inputIndex, err)
		}
		summary, err := verified.Summary()
		if err != nil {
			return VerifiedPayloadSet{}, fmt.Errorf("candidate %d is not verified: %w", inputIndex, err)
		}
		cell := Cell{Family: summary.Family, GOOS: summary.GOOS, GOARCH: summary.GOARCH}
		index, supported := indices[cell]
		if !supported || seen[cell] || summary != set.summaries[index] {
			return VerifiedPayloadSet{}, fmt.Errorf("candidate %d changed the fixed verified inventory", inputIndex)
		}
		seen[cell] = true
		snapshot, err := readRegularBounded(ctx, input.PackagePath, maximumPackage)
		if err != nil {
			return VerifiedPayloadSet{}, fmt.Errorf("snapshot native package %s/%s %s: %w", cell.GOOS, cell.GOARCH, cell.Family, err)
		}
		if len(snapshot) == 0 || digest(snapshot) != summary.PackageSHA256 {
			return VerifiedPayloadSet{}, fmt.Errorf("native package %s/%s %s changed after candidate verification", cell.GOOS, cell.GOARCH, cell.Family)
		}
		manifest, err := payloadStagingManifest(ctx, input.StagingDir, summary)
		if err != nil {
			return VerifiedPayloadSet{}, fmt.Errorf("verify staging for %s/%s %s: %w", cell.GOOS, cell.GOARCH, cell.Family, err)
		}
		observed, err := inspect(ctx, snapshot, cell)
		if err != nil {
			return VerifiedPayloadSet{}, fmt.Errorf("inspect native package %s/%s %s: %w", cell.GOOS, cell.GOARCH, cell.Family, err)
		}
		if err := matchInspectedPayload(manifest, observed); err != nil {
			return VerifiedPayloadSet{}, fmt.Errorf("native package %s/%s %s payload: %w", cell.GOOS, cell.GOARCH, cell.Family, err)
		}
	}
	if len(seen) != len(productionCells) {
		return VerifiedPayloadSet{}, errors.New("native package payload set is missing a required cell")
	}
	if err := recheck(ctx); err != nil {
		return VerifiedPayloadSet{}, fmt.Errorf("final candidate and live release recheck: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedPayloadSet{}, err
	}
	return VerifiedPayloadSet{valid: true, summaries: append([]Summary(nil), set.summaries...)}, nil
}

func payloadStagingManifest(ctx context.Context, stagingDir string, summary Summary) (nativepackage.Manifest, error) {
	root, err := fileinput.OpenDirectoryRoot(stagingDir)
	if err != nil {
		return nativepackage.Manifest{}, err
	}
	defer root.Close()
	manifest, err := nativepackage.VerifyStagingRootContext(ctx, root)
	if err != nil {
		return nativepackage.Manifest{}, err
	}
	data, err := fileinput.ReadRegularBoundedFromRoot(root, nativepackage.StagingManifestName, nativepackage.MaximumManifestSize)
	if err != nil || digest(data) != summary.StagingManifestSHA256 {
		return nativepackage.Manifest{}, errors.New("staging manifest changed after candidate verification")
	}
	if manifest.Version != summary.Version || manifest.Package.Family != summary.Family ||
		manifest.Target.GOOS != summary.GOOS || manifest.Target.GOARCH != summary.GOARCH ||
		manifest.Package.Architecture != summary.Architecture ||
		manifest.SourceArtifact.Filename != summary.ArchiveFilename ||
		manifest.SourceArtifact.SHA256 != summary.ArchiveSHA256 {
		return nativepackage.Manifest{}, errors.New("staging identity differs from the verified release candidate")
	}
	return manifest, nil
}

func matchInspectedPayload(manifest nativepackage.Manifest, observed inspectedPackage) error {
	if observed.Name != nativepackage.PackageName || observed.Version != manifest.Version ||
		observed.Architecture != manifest.Package.Architecture {
		return errors.New("native package name, version, or architecture differs from staging")
	}
	if len(observed.Files) != len(manifest.Payload) {
		return fmt.Errorf("native package has %d installed files, want %d", len(observed.Files), len(manifest.Payload))
	}
	want := make(map[string]nativepackage.PayloadFile, len(manifest.Payload))
	for _, item := range manifest.Payload {
		want[item.InstallPath] = item
	}
	seen := make(map[string]bool, len(observed.Files))
	for _, item := range observed.Files {
		if item.Path == "" || item.Path[0] != '/' || path.Clean(item.Path) != item.Path || seen[item.Path] {
			return fmt.Errorf("duplicate or unsafe installed path %q", item.Path)
		}
		seen[item.Path] = true
		expected, ok := want[item.Path]
		if !ok {
			return fmt.Errorf("unexpected installed file %q", item.Path)
		}
		if item.Mode != expected.Mode || item.Size != expected.Size || item.SHA256 != expected.SHA256 {
			return fmt.Errorf("installed file %q differs from verified staging bytes or mode", item.Path)
		}
	}
	return nil
}
