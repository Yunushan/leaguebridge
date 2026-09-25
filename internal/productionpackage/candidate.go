// Package productionpackage verifies score-free native package candidate
// metadata against a live, authenticated release and a complete staging tree.
// VerifyPayloadSet additionally inspects the native archive payload. This
// package does not authenticate a publisher, establish publication, or attest
// to native installation.
package productionpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

const (
	candidateType       = "leaguebridge.production-package-candidate.v1"
	validationScope     = "candidate-integrity-only"
	maximumCandidate    = int64(16 << 10)
	maximumPackage      = int64(256 << 20)
	maximumReleaseAsset = int64(512 << 20)
	maximumUncompressed = int64(256 << 20)
)

var (
	objectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Cell is one proposed production package family and target. The eleven-cell
// inventory matches the hosted CI package smoke matrix; that synthetic CI
// evidence does not establish stable-release package publication.
type Cell struct {
	Family nativepackage.Family
	GOOS   string
	GOARCH string
}

var productionCells = [...]Cell{
	{nativepackage.FamilyDebian, "linux", "amd64"},
	{nativepackage.FamilyDebian, "linux", "arm64"},
	{nativepackage.FamilyRPM, "linux", "amd64"},
	{nativepackage.FamilyRPM, "linux", "arm64"},
	{nativepackage.FamilyFreeBSD, "freebsd", "amd64"},
	{nativepackage.FamilyFreeBSD, "freebsd", "arm64"},
	{nativepackage.FamilyOpenBSD, "openbsd", "amd64"},
	{nativepackage.FamilyOpenBSD, "openbsd", "arm64"},
	{nativepackage.FamilyPkgsrc, "netbsd", "amd64"},
	{nativepackage.FamilyPkgsrc, "netbsd", "arm64"},
	{nativepackage.FamilyDPorts, "dragonfly", "amd64"},
}

// ExpectedCells returns a copy of the complete proposed production inventory.
// No readiness point is derived from this list or a candidate record.
func ExpectedCells() []Cell { return append([]Cell(nil), productionCells[:]...) }

type candidate struct {
	SchemaVersion   int              `json:"schema_version"`
	CandidateType   string           `json:"candidate_type"`
	ValidationScope string           `json:"validation_scope"`
	Release         candidateRelease `json:"release"`
	Package         candidatePackage `json:"package"`
}

type candidateRelease struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	Tree             string `json:"tree"`
	ReleaseID        int64  `json:"release_id"`
	ArchiveFilename  string `json:"archive_filename"`
	ArchiveSHA256    string `json:"archive_sha256"`
	ArchiveSizeBytes int64  `json:"archive_size_bytes"`
	ExecutableSHA256 string `json:"executable_sha256"`
}

type candidatePackage struct {
	Family                nativepackage.Family `json:"family"`
	GOOS                  string               `json:"goos"`
	GOARCH                string               `json:"goarch"`
	Architecture          string               `json:"architecture"`
	Format                string               `json:"format"`
	Filename              string               `json:"filename"`
	SizeBytes             int64                `json:"size_bytes"`
	SHA256                string               `json:"sha256"`
	StagingManifestSHA256 string               `json:"staging_manifest_sha256"`
}

type releaseFacts struct {
	Version   string
	Commit    string
	Tree      string
	ReleaseID int64
	Assets    []releaseassessment.PublishedAsset
}

// Summary is descriptive, score-free output from a fully matched candidate.
// It is not a package signature or publication receipt.
type Summary struct {
	Version               string
	Commit                string
	Tree                  string
	ReleaseID             int64
	Family                nativepackage.Family
	GOOS                  string
	GOARCH                string
	Architecture          string
	Format                string
	PackageFilename       string
	ArchiveFilename       string
	ArchiveSHA256         string
	ExecutableSHA256      string
	PackageSHA256         string
	StagingManifestSHA256 string
	CandidateSHA256       string
}

// VerifiedCandidate has an invalid zero value and can only be obtained from
// Verify. It cannot itself award either native package readiness row.
type VerifiedCandidate struct {
	valid   bool
	summary Summary
}

func (value VerifiedCandidate) Valid() bool { return value.valid }

// Summary returns the matched digests for later independent production checks.
func (value VerifiedCandidate) Summary() (Summary, error) {
	if !value.valid {
		return Summary{}, errors.New("production package candidate has not been verified")
	}
	return value.summary, nil
}

// Build constructs canonical candidate metadata from an opaque live release,
// a verified staging tree, and regular package bytes. The result is a claim to
// be authenticated by a separately governed production publisher.
func Build(ctx context.Context, release releaseassessment.VerifiedRelease, archivePath, stagingDir, packagePath string) ([]byte, error) {
	facts, err := factsFromRelease(release)
	if err != nil {
		return nil, err
	}
	value, err := derive(ctx, facts, archivePath, stagingDir, packagePath)
	if err != nil {
		return nil, err
	}
	return marshal(value)
}

// Verify strictly decodes the candidate file and rederives every field from
// the opaque live release, complete staging tree, and current package bytes.
// VerifyPayloadSet additionally checks native package format and payload. A
// full assessor must independently verify publisher signatures, live indexes,
// and installation, then recheck mutable state.
func Verify(ctx context.Context, release releaseassessment.VerifiedRelease, candidatePath, archivePath, stagingDir, packagePath string) (VerifiedCandidate, error) {
	facts, err := factsFromRelease(release)
	if err != nil {
		return VerifiedCandidate{}, err
	}
	data, err := readRegularBounded(ctx, candidatePath, maximumCandidate)
	if err != nil {
		return VerifiedCandidate{}, fmt.Errorf("read candidate metadata: %w", err)
	}
	return verifyBytes(ctx, facts, data, archivePath, stagingDir, packagePath)
}

func factsFromRelease(release releaseassessment.VerifiedRelease) (releaseFacts, error) {
	assessment, err := release.Assessment()
	if err != nil {
		return releaseFacts{}, fmt.Errorf("verified live release is required: %w", err)
	}
	assets, err := release.PublishedAssets()
	if err != nil {
		return releaseFacts{}, err
	}
	return releaseFacts{assessment.Version, assessment.Commit, assessment.Tree, assessment.ReleaseID, assets}, nil
}

func verifyBytes(ctx context.Context, facts releaseFacts, data []byte, archivePath, stagingDir, packagePath string) (VerifiedCandidate, error) {
	value, err := unmarshal(data)
	if err != nil {
		return VerifiedCandidate{}, err
	}
	expected, err := derive(ctx, facts, archivePath, stagingDir, packagePath)
	if err != nil {
		return VerifiedCandidate{}, err
	}
	if !reflect.DeepEqual(value, expected) {
		return VerifiedCandidate{}, errors.New("candidate metadata does not match the verified release, staging tree, and package bytes")
	}
	return VerifiedCandidate{valid: true, summary: Summary{
		Version: value.Release.Version, Commit: value.Release.Commit, Tree: value.Release.Tree,
		ReleaseID: value.Release.ReleaseID,
		Family:    value.Package.Family, GOOS: value.Package.GOOS, GOARCH: value.Package.GOARCH,
		Architecture: value.Package.Architecture, Format: value.Package.Format, PackageFilename: value.Package.Filename,
		ArchiveFilename: value.Release.ArchiveFilename,
		ArchiveSHA256:   value.Release.ArchiveSHA256, ExecutableSHA256: value.Release.ExecutableSHA256,
		PackageSHA256: value.Package.SHA256, StagingManifestSHA256: value.Package.StagingManifestSHA256,
		CandidateSHA256: digest(data),
	}}, nil
}

func derive(ctx context.Context, facts releaseFacts, archivePath, stagingDir, packagePath string) (candidate, error) {
	if ctx == nil {
		return candidate{}, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return candidate{}, err
	}
	if !stableVersion(facts.Version) || !objectIDPattern.MatchString(facts.Commit) || !objectIDPattern.MatchString(facts.Tree) || facts.ReleaseID <= 0 {
		return candidate{}, errors.New("verified release identity is invalid")
	}
	root, err := fileinput.OpenDirectoryRoot(stagingDir)
	if err != nil {
		return candidate{}, fmt.Errorf("open native package staging: %w", err)
	}
	defer root.Close()
	manifestBefore, err := fileinput.ReadRegularBoundedFromRoot(root, nativepackage.StagingManifestName, nativepackage.MaximumManifestSize)
	if err != nil {
		return candidate{}, fmt.Errorf("read staging manifest: %w", err)
	}
	manifest, err := nativepackage.VerifyStagingRootContext(ctx, root)
	if err != nil {
		return candidate{}, fmt.Errorf("verify native package staging: %w", err)
	}
	manifestAfter, err := fileinput.ReadRegularBoundedFromRoot(root, nativepackage.StagingManifestName, nativepackage.MaximumManifestSize)
	if err != nil || !bytes.Equal(manifestBefore, manifestAfter) {
		return candidate{}, errors.New("staging manifest changed during verification")
	}
	if !supportedCell(Cell{manifest.Package.Family, manifest.Target.GOOS, manifest.Target.GOARCH}) {
		return candidate{}, errors.New("package family and target are outside the production inventory")
	}
	if manifest.Version != facts.Version || manifest.Package.Version != facts.Version {
		return candidate{}, errors.New("staging version does not match the verified stable release")
	}
	asset, err := matchingArchive(facts.Assets, manifest.SourceArtifact.Filename)
	if err != nil {
		return candidate{}, err
	}
	if asset.SHA256 != manifest.SourceArtifact.SHA256 {
		return candidate{}, errors.New("staged source archive does not match the published release asset")
	}
	if filepath.Base(archivePath) != asset.Name {
		return candidate{}, errors.New("source archive filename does not match the published release asset")
	}
	sourceData, err := sourceManifestFromPublishedArchive(ctx, archivePath, asset)
	if err != nil {
		return candidate{}, err
	}
	if err := exactjson.ValidateKeys(sourceData, packageinfo.Manifest{}); err != nil {
		return candidate{}, fmt.Errorf("source package manifest fields are invalid: %w", err)
	}
	var source packageinfo.Manifest
	if err := json.Unmarshal(sourceData, &source); err != nil {
		return candidate{}, fmt.Errorf("decode source package manifest: %w", err)
	}
	canonicalSource, err := packageinfo.Marshal(source)
	if err != nil || !bytes.Equal(sourceData, canonicalSource) {
		return candidate{}, errors.New("source package manifest is not canonical")
	}
	if source.Version != facts.Version || source.Provenance.SourceCommit != facts.Commit || source.Provenance.SourceTree != facts.Tree ||
		source.Artifact.Filename != asset.Name || source.Target.GOOS != manifest.Target.GOOS || source.Target.GOARCH != manifest.Target.GOARCH {
		return candidate{}, errors.New("source archive manifest does not match the verified release and target")
	}
	expectedStaging, err := nativepackage.Build(source, sourceData, asset.SHA256, manifest.Package.Family)
	if err != nil {
		return candidate{}, fmt.Errorf("reconstruct staging from release archive: %w", err)
	}
	expectedStagingData, err := nativepackage.Marshal(expectedStaging)
	if err != nil || !bytes.Equal(manifestBefore, expectedStagingData) {
		return candidate{}, errors.New("staging tree does not match the authenticated release archive")
	}
	binarySHA := ""
	for _, item := range expectedStaging.Payload {
		if item.SourcePath == "leaguebridge" {
			binarySHA = item.SHA256
			break
		}
	}
	if !digestPattern.MatchString(binarySHA) {
		return candidate{}, errors.New("staging executable is not content-addressed")
	}
	format, _ := packageFormatAndSuffix(manifest.Package.Family)
	expectedFilename, err := packageFilename(facts.Version, manifest.Package.Family, manifest.Target.GOOS, manifest.Target.GOARCH)
	if err != nil {
		return candidate{}, err
	}
	filename := filepath.Base(packagePath)
	if filename != expectedFilename {
		return candidate{}, errors.New("production package filename does not match the stable release, family, and target")
	}
	packageSHA, packageSize, err := hashRegular(ctx, packagePath, maximumPackage)
	if err != nil {
		return candidate{}, fmt.Errorf("hash production package candidate: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return candidate{}, err
	}
	return candidate{
		SchemaVersion: 1, CandidateType: candidateType, ValidationScope: validationScope,
		Release: candidateRelease{
			Version: facts.Version, Commit: facts.Commit, Tree: facts.Tree, ReleaseID: facts.ReleaseID,
			ArchiveFilename: asset.Name, ArchiveSHA256: asset.SHA256, ArchiveSizeBytes: asset.SizeBytes,
			ExecutableSHA256: binarySHA,
		},
		Package: candidatePackage{
			Family: manifest.Package.Family, GOOS: manifest.Target.GOOS, GOARCH: manifest.Target.GOARCH,
			Architecture: manifest.Package.Architecture, Format: format, Filename: filename,
			SizeBytes: packageSize, SHA256: packageSHA, StagingManifestSHA256: digest(manifestBefore),
		},
	}, nil
}

func sourceManifestFromPublishedArchive(ctx context.Context, archivePath string, asset releaseassessment.PublishedAsset) ([]byte, error) {
	return sourceManifestFromPublishedArchiveUsing(ctx, archivePath, asset, sourceManifestFromArchive)
}

func sourceManifestFromPublishedArchiveUsing(ctx context.Context, archivePath string, asset releaseassessment.PublishedAsset, parse func(context.Context, io.Reader) ([]byte, error)) ([]byte, error) {
	// Hash and parse one private snapshot. Re-reading a mutable file for the
	// manifest after authenticating its hash permits an A→B→A substitution.
	archiveData, err := readRegularBounded(ctx, archivePath, maximumReleaseAsset)
	if err != nil {
		return nil, fmt.Errorf("read authenticated source archive: %w", err)
	}
	if int64(len(archiveData)) != asset.SizeBytes || digest(archiveData) != asset.SHA256 {
		return nil, errors.New("source archive bytes do not match the published release asset")
	}
	return parse(ctx, bytes.NewReader(archiveData))
}

func sourceManifestFromArchive(ctx context.Context, source io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	zipped, err := gzip.NewReader(contextReader{ctx: ctx, reader: source})
	if err != nil {
		return nil, fmt.Errorf("open authenticated release archive: %w", err)
	}
	defer zipped.Close()
	archive := tar.NewReader(io.LimitReader(contextReader{ctx: ctx, reader: zipped}, maximumUncompressed+1))
	var manifest []byte
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read release archive member: %w", err)
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > nativepackage.MaximumPayloadSize {
			return nil, errors.New("release archive contains an invalid member")
		}
		total += header.Size
		if total > maximumUncompressed {
			return nil, errors.New("release archive exceeds the uncompressed size bound")
		}
		if header.Name == packageinfo.ManifestName {
			if manifest != nil || header.Size == 0 || header.Size > 1<<20 {
				return nil, errors.New("release archive has an invalid package manifest")
			}
			manifest, err = io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: archive}, header.Size+1))
			if err != nil || int64(len(manifest)) != header.Size {
				return nil, errors.New("read release archive package manifest")
			}
		} else if _, err := io.CopyN(io.Discard, contextReader{ctx: ctx, reader: archive}, header.Size); err != nil {
			return nil, fmt.Errorf("skip release archive member: %w", err)
		}
	}
	if manifest == nil {
		return nil, errors.New("release archive is missing PACKAGE-MANIFEST.json")
	}
	return manifest, nil
}

func matchingArchive(assets []releaseassessment.PublishedAsset, name string) (releaseassessment.PublishedAsset, error) {
	var found releaseassessment.PublishedAsset
	count := 0
	for _, asset := range assets {
		if asset.Name != name {
			continue
		}
		if !digestPattern.MatchString(asset.SHA256) || asset.SizeBytes <= 0 || asset.SizeBytes > maximumReleaseAsset {
			return found, errors.New("published source archive identity is invalid")
		}
		found = asset
		count++
	}
	if count != 1 {
		return found, fmt.Errorf("published release contains %d assets named %q; want exactly one", count, name)
	}
	return found, nil
}

func supportedCell(cell Cell) bool {
	for _, expected := range productionCells {
		if expected == cell {
			return true
		}
	}
	return false
}

func packageFormatAndSuffix(family nativepackage.Family) (format, suffix string) {
	switch family {
	case nativepackage.FamilyDebian:
		return "deb", ".deb"
	case nativepackage.FamilyRPM:
		return "rpm", ".rpm"
	case nativepackage.FamilyFreeBSD, nativepackage.FamilyDPorts:
		return "pkg", ".pkg"
	case nativepackage.FamilyOpenBSD, nativepackage.FamilyPkgsrc:
		return "pkg", ".tgz"
	default:
		return "", ""
	}
}

// packageFilename is the exact v1 candidate naming contract. The production
// publisher still has to prove that the package-manager metadata inside these
// bytes carries the same version, architecture, and payload identity.
func packageFilename(version string, family nativepackage.Family, goos, goarch string) (string, error) {
	if !stableVersion(version) || !supportedCell(Cell{family, goos, goarch}) {
		return "", errors.New("stable version or production package cell is invalid")
	}
	bare := strings.TrimPrefix(version, "v")
	switch family {
	case nativepackage.FamilyDebian:
		return "leaguebridge_" + bare + "_" + goarch + ".deb", nil
	case nativepackage.FamilyRPM:
		architecture := "x86_64"
		if goarch == "arm64" {
			architecture = "aarch64"
		}
		return "leaguebridge-" + bare + "-1." + architecture + ".rpm", nil
	case nativepackage.FamilyFreeBSD, nativepackage.FamilyDPorts:
		return "leaguebridge-" + bare + "-" + goos + "-" + goarch + ".pkg", nil
	case nativepackage.FamilyOpenBSD, nativepackage.FamilyPkgsrc:
		return "leaguebridge-" + bare + "-" + goos + "-" + goarch + ".tgz", nil
	default:
		return "", errors.New("unsupported production package family")
	}
}

func stableVersion(value string) bool {
	return len(value) <= 128 && releaseversion.Valid(value) && !strings.ContainsAny(value, "+-")
}

func marshal(value candidate) ([]byte, error) {
	if err := validate(value); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func unmarshal(data []byte) (candidate, error) {
	if len(data) == 0 || int64(len(data)) > maximumCandidate {
		return candidate{}, errors.New("candidate metadata size is outside its bound")
	}
	if err := exactjson.ValidateKeys(data, candidate{}); err != nil {
		return candidate{}, fmt.Errorf("candidate metadata fields are invalid: %w", err)
	}
	var value candidate
	if err := json.Unmarshal(data, &value); err != nil {
		return candidate{}, fmt.Errorf("decode candidate metadata: %w", err)
	}
	canonical, err := marshal(value)
	if err != nil {
		return candidate{}, err
	}
	if !bytes.Equal(data, canonical) {
		return candidate{}, errors.New("candidate metadata is not canonical")
	}
	return value, nil
}

func validate(value candidate) error {
	if value.SchemaVersion != 1 || value.CandidateType != candidateType || value.ValidationScope != validationScope {
		return errors.New("candidate metadata identity is invalid")
	}
	r := value.Release
	if !stableVersion(r.Version) || !objectIDPattern.MatchString(r.Commit) || !objectIDPattern.MatchString(r.Tree) ||
		r.ReleaseID <= 0 || !digestPattern.MatchString(r.ArchiveSHA256) || !digestPattern.MatchString(r.ExecutableSHA256) ||
		r.ArchiveSizeBytes <= 0 || r.ArchiveSizeBytes > maximumReleaseAsset {
		return errors.New("candidate release identity is invalid")
	}
	p := value.Package
	if !supportedCell(Cell{p.Family, p.GOOS, p.GOARCH}) || p.Architecture == "" ||
		p.SizeBytes <= 0 || p.SizeBytes > maximumPackage || !digestPattern.MatchString(p.SHA256) ||
		!digestPattern.MatchString(p.StagingManifestSHA256) {
		return errors.New("candidate package identity is invalid")
	}
	format, _ := packageFormatAndSuffix(p.Family)
	expectedFilename, err := packageFilename(r.Version, p.Family, p.GOOS, p.GOARCH)
	if err != nil || p.Format != format || p.Filename != expectedFilename {
		return errors.New("candidate package filename or format is invalid")
	}
	archiveName := "leaguebridge_" + strings.TrimPrefix(r.Version, "v") + "_" + p.GOOS + "_" + p.GOARCH + ".tar.gz"
	if r.ArchiveFilename != archiveName {
		return errors.New("candidate archive name does not match release version and target")
	}
	return nil
}

func readRegularBounded(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("regular metadata file size is outside its bound")
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != before.Size() {
		return nil, errors.New("metadata file size changed during reading")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, pathAfter) || after.Size() != int64(len(data)) || pathAfter.Size() != int64(len(data)) {
		return nil, errors.New("metadata file changed during reading")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func hashRegular(ctx context.Context, path string, maximum int64) (string, int64, error) {
	if ctx == nil {
		return "", 0, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return "", 0, errors.New("regular package file size is outside its bound")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil {
		return "", 0, err
	}
	if size != before.Size() {
		return "", 0, errors.New("package file size changed during hashing")
	}
	after, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, pathAfter) || after.Size() != size || pathAfter.Size() != size {
		return "", 0, errors.New("package file changed during hashing")
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (value contextReader) Read(data []byte) (int, error) {
	if err := value.ctx.Err(); err != nil {
		return 0, err
	}
	return value.reader.Read(data)
}

func digest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}
