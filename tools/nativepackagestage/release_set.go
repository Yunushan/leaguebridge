package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/productionpackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
	"github.com/Yunushan/leaguebridge/internal/target"
)

const releaseSetManifestName = "RELEASE-BOUND-NATIVE-PACKAGE-INPUTS.json"

var (
	releaseSetDigestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	releaseSetObjectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

type releaseSetOptions struct {
	version, releaseDir, output, gh string
}

// releaseSetFacts is populated only from the opaque live release in the
// production command. Keeping the stage operation separate allows hermetic
// tests of filesystem behavior without inventing a verified release token.
type releaseSetFacts struct {
	version, commit, tree, scorecardSHA256 string
	releaseID                              int64
	assets                                 []releaseassessment.PublishedAsset
}

type releaseSetManifest struct {
	SchemaVersion   int                `json:"schema_version"`
	PlanType        string             `json:"plan_type"`
	ValidationScope string             `json:"validation_scope"`
	Release         releaseSetIdentity `json:"release"`
	Cells           []releaseSetCell   `json:"cells"`
}

type releaseSetIdentity struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	Tree            string `json:"tree"`
	ReleaseID       int64  `json:"release_id"`
	ScorecardSHA256 string `json:"scorecard_sha256"`
}

type releaseSetCell struct {
	Family                nativepackage.Family `json:"family"`
	GOOS                  string               `json:"goos"`
	GOARCH                string               `json:"goarch"`
	ArchiveFilename       string               `json:"archive_filename"`
	ArchiveSHA256         string               `json:"archive_sha256"`
	ArchiveSizeBytes      int64                `json:"archive_size_bytes"`
	StagingPath           string               `json:"staging_path"`
	StagingManifestSHA256 string               `json:"staging_manifest_sha256"`
	PackageState          string               `json:"package_state"`
	SigningState          string               `json:"signing_state"`
	PublicationState      string               `json:"publication_state"`
	LifecycleState        string               `json:"lifecycle_state"`
}

func runReleaseSet(ctx context.Context, args []string, stdout io.Writer) error {
	opts, err := parseReleaseSetOptions(args)
	if err != nil {
		return err
	}
	verified, err := releaseassessment.VerifyForProduction(ctx, releaseSetRequest(opts))
	if err != nil {
		return fmt.Errorf("authenticate live stable release: %w", err)
	}
	facts, err := factsFromVerifiedRelease(verified)
	if err != nil {
		return err
	}
	if err := stageReleaseSet(ctx, facts, opts.releaseDir, opts.output, verified.Recheck); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "created score-free release-bound staging inputs for eleven cells in %s\npackage bytes, signatures, publication, and lifecycle evidence remain unbuilt or unverified\n", opts.output)
	return err
}

func parseReleaseSetOptions(args []string) (releaseSetOptions, error) {
	var opts releaseSetOptions
	set := flag.NewFlagSet("nativepackagestage release-set", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&opts.version, "version", "", "published stable release tag")
	set.StringVar(&opts.releaseDir, "release-dir", "", "directory containing ten downloaded release files")
	set.StringVar(&opts.output, "output", "", "new eleven-cell staging directory")
	set.StringVar(&opts.gh, "gh", "gh", "trusted GitHub CLI executable")
	if err := set.Parse(args); err != nil {
		return releaseSetOptions{}, err
	}
	if set.NArg() != 0 || !stableReleaseSetVersion(opts.version) || blankReleaseSet(opts.releaseDir) || blankReleaseSet(opts.output) || blankReleaseSet(opts.gh) {
		return releaseSetOptions{}, errors.New("usage: nativepackagestage release-set --version STABLE_TAG --release-dir DIR --output NEW_DIR [--gh TRUSTED_GH]; run from the downloaded CI evidence directory")
	}
	return opts, nil
}

func blankReleaseSet(value string) bool { return strings.TrimSpace(value) == "" }

func stableReleaseSetVersion(version string) bool {
	return len(version) <= 128 && releaseversion.Valid(version) && !strings.ContainsAny(version, "+-")
}

// CI subject paths intentionally retain releaseassessment's process-working-
// directory semantics, matching the production package candidate command.
func releaseSetRequest(opts releaseSetOptions) releaseassessment.Request {
	request := releaseassessment.Request{
		GHPath: opts.gh, Version: opts.version, ReleaseDir: opts.releaseDir,
		RaceVetSubject: "ci-attestation/race-vet-linux.json",
	}
	for _, candidate := range target.Ordered() {
		request.CrossBuildSubjects = append(request.CrossBuildSubjects,
			"ci-attestation/cross-build-"+candidate.GOOS+"-"+candidate.GOARCH+".json")
	}
	return request
}

func factsFromVerifiedRelease(verified releaseassessment.VerifiedRelease) (releaseSetFacts, error) {
	assessment, err := verified.Assessment()
	if err != nil {
		return releaseSetFacts{}, fmt.Errorf("verified release assessment: %w", err)
	}
	assets, err := verified.PublishedAssets()
	if err != nil {
		return releaseSetFacts{}, fmt.Errorf("verified release assets: %w", err)
	}
	scorecardSHA256, err := verified.ScorecardSHA256()
	if err != nil {
		return releaseSetFacts{}, fmt.Errorf("verified release scorecard: %w", err)
	}
	return releaseSetFacts{assessment.Version, assessment.Commit, assessment.Tree, scorecardSHA256, assessment.ReleaseID, assets}, nil
}

func validateReleaseSetFacts(facts releaseSetFacts) (map[string]releaseassessment.PublishedAsset, error) {
	if !stableReleaseSetVersion(facts.version) || !releaseSetObjectIDPattern.MatchString(facts.commit) ||
		!releaseSetObjectIDPattern.MatchString(facts.tree) || len(facts.commit) != len(facts.tree) || facts.releaseID <= 0 ||
		!releaseSetDigestPattern.MatchString(facts.scorecardSHA256) || len(facts.assets) != 10 {
		return nil, errors.New("complete authenticated stable release identity is required")
	}
	allowed := make(map[string]bool, 10)
	allowed["checksums.txt"] = true
	for _, candidate := range target.Ordered() {
		allowed[fmt.Sprintf("leaguebridge_%s_%s_%s.tar.gz", strings.TrimPrefix(facts.version, "v"), candidate.GOOS, candidate.GOARCH)] = true
	}
	assets := make(map[string]releaseassessment.PublishedAsset, len(facts.assets))
	for _, asset := range facts.assets {
		if !allowed[asset.Name] || !releaseSetDigestPattern.MatchString(asset.SHA256) || asset.SizeBytes <= 0 {
			return nil, fmt.Errorf("invalid published release asset %q", asset.Name)
		}
		if _, exists := assets[asset.Name]; exists {
			return nil, fmt.Errorf("duplicate published release asset %q", asset.Name)
		}
		assets[asset.Name] = asset
	}
	if len(assets) != len(allowed) {
		return nil, errors.New("published release asset inventory is incomplete")
	}
	return assets, nil
}

// stageReleaseSet creates input trees only. The package state in every cell
// remains unbuilt; callers must separately build, sign, publish, and verify
// native packages from independently governed infrastructure.
func stageReleaseSet(ctx context.Context, facts releaseSetFacts, releaseDir, output string, recheck func(context.Context) error) error {
	if ctx == nil {
		return errors.New("staging context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if recheck == nil {
		return errors.New("live release recheck is required")
	}
	assets, err := validateReleaseSetFacts(facts)
	if err != nil {
		return err
	}
	releaseAbsolute, err := filepath.Abs(releaseDir)
	if err != nil {
		return fmt.Errorf("resolve release directory: %w", err)
	}
	releaseRoot, err := fileinput.OpenDirectoryRoot(releaseAbsolute)
	if err != nil {
		return fmt.Errorf("open release directory: %w", err)
	}
	defer releaseRoot.Close()
	outputAbsolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}
	if pathWithin(releaseAbsolute, outputAbsolute) {
		return errors.New("output must be outside the authenticated release directory")
	}
	if err := fileinput.RejectSymlinkedParents(outputAbsolute); err != nil {
		return fmt.Errorf("output path: %w", err)
	}
	outputName := filepath.Base(outputAbsolute)
	if outputName == "." || outputName == ".." || outputName == string(filepath.Separator) || outputName == "" {
		return errors.New("output must name a new child directory")
	}
	parentAbsolute := filepath.Dir(outputAbsolute)
	parent, err := fileinput.OpenDirectoryRoot(parentAbsolute)
	if err != nil {
		return fmt.Errorf("open output parent: %w", err)
	}
	defer parent.Close()
	if _, err := parent.Lstat(outputName); err == nil {
		return errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output: %w", err)
	}

	temporary, temporaryName, err := fileinput.CreateTempDirectory(parent, ".leaguebridge-release-package-inputs-", 0o700)
	if err != nil {
		return fmt.Errorf("create private staging root: %w", err)
	}
	defer func() {
		_ = temporary.Close()
		_ = fileinput.RemoveAllInRoot(parent, temporaryName)
	}()
	temporaryPath := filepath.Join(parentAbsolute, temporaryName)
	cells := productionpackage.ExpectedCells()
	if len(cells) != 11 {
		return errors.New("production package inventory no longer has exactly eleven cells")
	}
	plan := releaseSetManifest{
		SchemaVersion: 1, PlanType: "leaguebridge-release-bound-native-package-inputs",
		ValidationScope: "release-bound-staging-only",
		Release:         releaseSetIdentity{facts.version, facts.commit, facts.tree, facts.releaseID, facts.scorecardSHA256},
		Cells:           make([]releaseSetCell, 0, len(cells)),
	}
	families := make([]string, 0, 6)
	seenFamilies := make(map[string]bool)
	for _, cell := range cells {
		if err := ctx.Err(); err != nil {
			return err
		}
		family := string(cell.Family)
		if !seenFamilies[family] {
			if err := temporary.Mkdir(family, 0o700); err != nil {
				return fmt.Errorf("create %s staging family: %w", family, err)
			}
			seenFamilies[family] = true
			families = append(families, family)
		}
		archiveName := fmt.Sprintf("leaguebridge_%s_%s_%s.tar.gz", strings.TrimPrefix(facts.version, "v"), cell.GOOS, cell.GOARCH)
		asset := assets[archiveName]
		if err := checkReleaseSetArchive(releaseRoot, asset); err != nil {
			return fmt.Errorf("authenticate source archive for %s %s/%s: %w", family, cell.GOOS, cell.GOARCH, err)
		}
		relative := path.Join(family, cell.GOARCH)
		if err := stage(filepath.Join(releaseAbsolute, archiveName), filepath.Join(temporaryPath, filepath.FromSlash(relative)), cell.Family); err != nil {
			return fmt.Errorf("stage %s %s/%s: %w", family, cell.GOOS, cell.GOARCH, err)
		}
		entry := releaseSetCell{
			Family: cell.Family, GOOS: cell.GOOS, GOARCH: cell.GOARCH,
			ArchiveFilename: asset.Name, ArchiveSHA256: asset.SHA256, ArchiveSizeBytes: asset.SizeBytes,
			StagingPath: relative, PackageState: "unbuilt", SigningState: "not_performed",
			PublicationState: "not_performed", LifecycleState: "not_verified",
		}
		if err := verifyReleaseSetCell(ctx, temporary, facts.version, entry, &entry.StagingManifestSHA256); err != nil {
			return fmt.Errorf("verify %s staging: %w", relative, err)
		}
		plan.Cells = append(plan.Cells, entry)
	}
	for _, cell := range plan.Cells {
		if err := checkReleaseSetArchive(releaseRoot, assets[cell.ArchiveFilename]); err != nil {
			return fmt.Errorf("recheck %s source archive: %w", cell.StagingPath, err)
		}
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal release-bound input plan: %w", err)
	}
	data = append(data, '\n')
	manifestInfo, err := writeReleaseSetManifest(temporary, data)
	if err != nil {
		return err
	}

	// Reserve the final directory exclusively. The manifest is linked into it
	// only after all eleven moved trees and the live release are rechecked.
	if err := parent.Mkdir(outputName, 0o700); err != nil {
		return fmt.Errorf("reserve new output directory: %w", err)
	}
	created, err := parent.Lstat(outputName)
	if err != nil {
		return fmt.Errorf("inspect reserved output: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			if current, err := parent.Lstat(outputName); err == nil && os.SameFile(created, current) {
				_ = fileinput.RemoveAllInRoot(parent, outputName)
			}
		}
	}()
	for _, family := range families {
		if err := fileinput.RenameInRoot(parent, filepath.Join(temporaryName, family), filepath.Join(outputName, family)); err != nil {
			return fmt.Errorf("move %s staging into reserved output: %w", family, err)
		}
	}
	finalRoot, err := parent.OpenRoot(outputName)
	if err != nil {
		return fmt.Errorf("open reserved output: %w", err)
	}
	defer finalRoot.Close()
	for _, cell := range plan.Cells {
		want := cell.StagingManifestSHA256
		if err := verifyReleaseSetCell(ctx, finalRoot, facts.version, cell, &want); err != nil {
			return fmt.Errorf("recheck published %s staging: %w", cell.StagingPath, err)
		}
	}
	if err := recheck(ctx); err != nil {
		return fmt.Errorf("recheck live release before completing package inputs: %w", err)
	}
	// A live recheck can take long enough for a mutable staging path to change.
	// Reverify the moved trees and repeat the release recheck before linking the
	// plan that marks this directory complete.
	for _, cell := range plan.Cells {
		want := cell.StagingManifestSHA256
		if err := verifyReleaseSetCell(ctx, finalRoot, facts.version, cell, &want); err != nil {
			return fmt.Errorf("final recheck of %s staging: %w", cell.StagingPath, err)
		}
	}
	if err := recheck(ctx); err != nil {
		return fmt.Errorf("final live release recheck: %w", err)
	}
	if err := fileinput.LinkInRoot(parent, filepath.Join(temporaryName, releaseSetManifestName), filepath.Join(outputName, releaseSetManifestName)); err != nil {
		return fmt.Errorf("publish input plan exclusively: %w", err)
	}
	if err := checkReleaseSetPublished(parent, outputAbsolute, outputName, created, manifestInfo, data); err != nil {
		return fmt.Errorf("published package inputs changed: %w", err)
	}
	complete = true
	return nil
}

func pathWithin(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

func checkReleaseSetArchive(root *os.Root, asset releaseassessment.PublishedAsset) error {
	data, err := fileinput.ReadRegularBoundedFromRoot(root, asset.Name, maxArchiveSize)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if int64(len(data)) != asset.SizeBytes || hex.EncodeToString(hash[:]) != asset.SHA256 {
		return errors.New("source archive bytes differ from the authenticated published release asset")
	}
	return nil
}

func verifyReleaseSetCell(ctx context.Context, setRoot *os.Root, version string, cell releaseSetCell, digest *string) error {
	if digest == nil {
		return errors.New("staging digest destination is required")
	}
	root, err := setRoot.OpenRoot(filepath.FromSlash(cell.StagingPath))
	if err != nil {
		return err
	}
	defer root.Close()
	manifest, err := nativepackage.VerifyStagingRootContext(ctx, root)
	if err != nil {
		return err
	}
	if manifest.Version != version || manifest.Package.Family != cell.Family ||
		manifest.Target.GOOS != cell.GOOS || manifest.Target.GOARCH != cell.GOARCH ||
		manifest.SourceArtifact.Filename != cell.ArchiveFilename ||
		manifest.SourceArtifact.SHA256 != cell.ArchiveSHA256 {
		return errors.New("staging identity differs from authenticated release cell")
	}
	data, err := fileinput.ReadRegularBoundedFromRoot(root, nativepackage.StagingManifestName, nativepackage.MaximumManifestSize)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	got := hex.EncodeToString(hash[:])
	if *digest != "" && *digest != got {
		return errors.New("staging manifest changed after input plan construction")
	}
	*digest = got
	return nil
}

func writeReleaseSetManifest(root *os.Root, data []byte) (os.FileInfo, error) {
	file, err := root.OpenFile(releaseSetManifestName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create private input plan: %w", err)
	}
	if written, err := file.Write(data); err != nil || written != len(data) {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("write private input plan: %w", err)
		}
		return nil, io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync private input plan: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect private input plan: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close private input plan: %w", err)
	}
	return info, nil
}

func checkReleaseSetPublished(parent *os.Root, outputAbsolute, outputName string, created, manifestInfo os.FileInfo, want []byte) error {
	current, err := parent.Lstat(outputName)
	if err != nil || !current.IsDir() || !os.SameFile(created, current) {
		return errors.New("reserved output directory identity changed")
	}
	visible, err := os.Lstat(outputAbsolute)
	if err != nil || !os.SameFile(created, visible) {
		return errors.New("published output path no longer names the reserved directory")
	}
	root, err := parent.OpenRoot(outputName)
	if err != nil {
		return err
	}
	defer root.Close()
	linked, err := root.Lstat(releaseSetManifestName)
	if err != nil || !linked.Mode().IsRegular() || !os.SameFile(manifestInfo, linked) || linked.Size() != int64(len(want)) {
		return errors.New("published input plan identity changed")
	}
	data, err := fileinput.ReadRegularBoundedFromRoot(root, releaseSetManifestName, int64(len(want)))
	if err != nil || !bytes.Equal(data, want) {
		return errors.New("published input plan bytes changed")
	}
	return nil
}
