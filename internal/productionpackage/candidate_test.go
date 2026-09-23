package productionpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

const (
	fixtureCommit = "0123456789abcdef0123456789abcdef01234567"
	fixtureTree   = "89abcdef0123456789abcdef0123456789abcdef"
)

type fixture struct {
	facts       releaseFacts
	archivePath string
	stagingDir  string
	packagePath string
	value       candidate
	data        []byte
	manifest    nativepackage.Manifest
}

func makeFixture(t *testing.T, cell Cell) fixture {
	t.Helper()
	names, err := packageinfo.ExpectedPayloadNames(cell.GOOS, cell.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte, len(names))
	for _, name := range names {
		bodies[name] = []byte("released source payload for " + name)
	}
	source, err := packageinfo.Build("v1.2.3", cell.GOOS, cell.GOARCH, 1787702400, fixtureCommit, fixtureTree, "go1.27.1", bodies)
	if err != nil {
		t.Fatal(err)
	}
	sourceData, err := packageinfo.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var archiveBuffer bytes.Buffer
	zipped := gzip.NewWriter(&archiveBuffer)
	archive := tar.NewWriter(zipped)
	archiveBodies := map[string][]byte{packageinfo.ManifestName: sourceData}
	for name, body := range bodies {
		archiveBodies[name] = body
	}
	for name, body := range archiveBodies {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipped.Close(); err != nil {
		t.Fatal(err)
	}
	archiveData := archiveBuffer.Bytes()
	archiveDigest := digest(archiveData)
	archivePath := filepath.Join(t.TempDir(), source.Artifact.Filename)
	if err := os.WriteFile(archivePath, archiveData, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := nativepackage.Build(source, sourceData, archiveDigest, cell.Family)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := nativepackage.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	stagingDir := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(stagingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, nativepackage.StagingManifestName), manifestData, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Payload {
		body := bodies[entry.SourcePath]
		if entry.SourcePath == packageinfo.ManifestName {
			body = sourceData
		}
		path := filepath.Join(stagingDir, "root", filepath.FromSlash(strings.TrimPrefix(entry.InstallPath, "/")))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if entry.Mode == "0755" {
			mode = 0o755
		}
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
	}
	packageName, err := packageFilename("v1.2.3", cell.Family, cell.GOOS, cell.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(t.TempDir(), packageName)
	if err := os.WriteFile(packagePath, []byte("unsigned native package candidate bytes for "+cell.GOOS+"/"+cell.GOARCH), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := releaseFacts{Version: "v1.2.3", Commit: fixtureCommit, Tree: fixtureTree, ReleaseID: 12345,
		Assets: []releaseassessment.PublishedAsset{{Name: source.Artifact.Filename, SHA256: archiveDigest, SizeBytes: int64(len(archiveData))}}}
	value, err := derive(context.Background(), facts, archivePath, stagingDir, packagePath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{facts, archivePath, stagingDir, packagePath, value, data, manifest}
}

func TestProductionInventoryIncludesEveryReleasedTarget(t *testing.T) {
	cells := ExpectedCells()
	if len(cells) != 11 {
		t.Fatalf("production package inventory has %d cells, want 11", len(cells))
	}
	seen := map[Cell]bool{}
	for _, cell := range cells {
		if seen[cell] {
			t.Fatalf("duplicate cell %+v", cell)
		}
		seen[cell] = true
	}
	for _, cell := range []Cell{{nativepackage.FamilyDebian, "linux", "arm64"}, {nativepackage.FamilyRPM, "linux", "arm64"}} {
		if !seen[cell] {
			t.Fatalf("Linux arm64 cell %+v is missing", cell)
		}
	}
	cells[0] = Cell{}
	if ExpectedCells()[0] == (Cell{}) {
		t.Fatal("caller mutated the fixed production inventory")
	}
}

func TestCandidateBindsEveryProductionCell(t *testing.T) {
	for _, cell := range ExpectedCells() {
		cell := cell
		t.Run(string(cell.Family)+"_"+cell.GOOS+"_"+cell.GOARCH, func(t *testing.T) {
			fixture := makeFixture(t, cell)
			verified, err := verifyBytes(context.Background(), fixture.facts, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath)
			if err != nil {
				t.Fatal(err)
			}
			if !verified.Valid() {
				t.Fatal("candidate verification returned invalid result")
			}
			summary, err := verified.Summary()
			if err != nil {
				t.Fatal(err)
			}
			if summary.Version != fixture.facts.Version || summary.Commit != fixture.facts.Commit || summary.Tree != fixture.facts.Tree ||
				summary.ReleaseID != fixture.facts.ReleaseID ||
				summary.Family != cell.Family || summary.GOOS != cell.GOOS || summary.GOARCH != cell.GOARCH ||
				summary.PackageFilename != filepath.Base(fixture.packagePath) || summary.ArchiveFilename != filepath.Base(fixture.archivePath) ||
				summary.Architecture != fixture.manifest.Package.Architecture || summary.Format != fixture.value.Package.Format ||
				summary.ArchiveSHA256 != fixture.value.Release.ArchiveSHA256 ||
				summary.ExecutableSHA256 != fixture.value.Release.ExecutableSHA256 ||
				summary.PackageSHA256 != fixture.value.Package.SHA256 || summary.CandidateSHA256 != digest(fixture.data) {
				t.Fatalf("verified summary has lost a release or package binding: %+v", summary)
			}
		})
	}
}

func TestCandidateRejectsSubstitutedMetadataAndBytes(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	tests := []struct {
		name   string
		mutate func(*candidate)
	}{
		{"release version", func(value *candidate) { value.Release.Version = "v1.2.4" }},
		{"release commit", func(value *candidate) { value.Release.Commit = strings.Repeat("a", 40) }},
		{"release tree", func(value *candidate) { value.Release.Tree = strings.Repeat("b", 40) }},
		{"release ID", func(value *candidate) { value.Release.ReleaseID++ }},
		{"source archive digest", func(value *candidate) { value.Release.ArchiveSHA256 = strings.Repeat("c", 64) }},
		{"source archive size", func(value *candidate) { value.Release.ArchiveSizeBytes++ }},
		{"executable digest", func(value *candidate) { value.Release.ExecutableSHA256 = strings.Repeat("d", 64) }},
		{"package family", func(value *candidate) {
			value.Package.Family = nativepackage.FamilyRPM
			value.Package.Format = "rpm"
			value.Package.Filename = "leaguebridge-1.2.3-1.x86_64.rpm"
		}},
		{"package target", func(value *candidate) { value.Package.GOARCH = "arm64" }},
		{"wrong-version filename", func(value *candidate) { value.Package.Filename = "leaguebridge_1.2.4_amd64.deb" }},
		{"wrong-target filename", func(value *candidate) { value.Package.Filename = "leaguebridge_1.2.3_arm64.deb" }},
		{"package digest", func(value *candidate) { value.Package.SHA256 = strings.Repeat("e", 64) }},
		{"staging digest", func(value *candidate) { value.Package.StagingManifestSHA256 = strings.Repeat("f", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := fixture.value
			test.mutate(&changed)
			data, err := marshal(changed)
			if err != nil {
				// Invalid syntax is also a correct rejection.
				return
			}
			if _, err := verifyBytes(context.Background(), fixture.facts, data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil {
				t.Fatal("substituted candidate metadata was accepted")
			}
		})
	}
	if err := os.WriteFile(fixture.packagePath, []byte("substituted package bytes of similar size"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBytes(context.Background(), fixture.facts, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil {
		t.Fatal("substituted package bytes were accepted")
	}
}

func TestCandidateRejectsChangedReleaseAndStaging(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	wrong := fixture.facts
	wrong.Commit = strings.Repeat("a", 40)
	if _, err := verifyBytes(context.Background(), wrong, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil {
		t.Fatal("different verified release commit was accepted")
	}
	wrong = fixture.facts
	wrong.Assets = nil
	if _, err := verifyBytes(context.Background(), wrong, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil {
		t.Fatal("missing published archive was accepted")
	}
	wrong = fixture.facts
	wrong.Assets = append(append([]releaseassessment.PublishedAsset(nil), wrong.Assets...), wrong.Assets[0])
	if _, err := verifyBytes(context.Background(), wrong, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil {
		t.Fatal("duplicate published archive was accepted")
	}
	for _, entry := range fixture.manifest.Payload {
		if entry.SourcePath != "leaguebridge" {
			continue
		}
		path := filepath.Join(fixture.stagingDir, "root", filepath.FromSlash(strings.TrimPrefix(entry.InstallPath, "/")))
		if err := os.WriteFile(path, []byte("modified staged executable"), 0o755); err != nil {
			t.Fatal(err)
		}
		break
	}
	if _, err := verifyBytes(context.Background(), fixture.facts, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil {
		t.Fatal("modified staged executable was accepted")
	}
}

func TestCandidateRejectsSelfConsistentStagingForgeryAndArchiveReplacement(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	changed := fixture.manifest
	for index := range changed.Payload {
		if changed.Payload[index].SourcePath != "leaguebridge" {
			continue
		}
		body := []byte("a substituted executable with a self-consistent staging digest")
		changed.Payload[index].Size = int64(len(body))
		changed.Payload[index].SHA256 = digest(body)
		path := filepath.Join(fixture.stagingDir, "root", filepath.FromSlash(strings.TrimPrefix(changed.Payload[index].InstallPath, "/")))
		if err := os.WriteFile(path, body, 0o755); err != nil {
			t.Fatal(err)
		}
		break
	}
	changedData, err := nativepackage.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.stagingDir, nativepackage.StagingManifestName), changedData, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBytes(context.Background(), fixture.facts, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil || !strings.Contains(err.Error(), "staging tree does not match the authenticated release archive") {
		t.Fatalf("self-consistent staging forgery was not rejected at the archive binding: %v", err)
	}

	fresh := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	archiveData, err := os.ReadFile(fresh.archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archiveData[len(archiveData)/2] ^= 1
	if err := os.WriteFile(fresh.archivePath, archiveData, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBytes(context.Background(), fresh.facts, fresh.data, fresh.archivePath, fresh.stagingDir, fresh.packagePath); err == nil || !strings.Contains(err.Error(), "source archive bytes do not match") {
		t.Fatalf("replaced release archive was not rejected by its published digest: %v", err)
	}
}

func TestPublishedArchiveParserUsesTheAuthenticatedSnapshot(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	original, err := os.ReadFile(fixture.archivePath)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)/2] ^= 1
	asset := fixture.facts.Assets[0]
	parsed, err := sourceManifestFromPublishedArchiveUsing(context.Background(), fixture.archivePath, asset,
		func(_ context.Context, source io.Reader) ([]byte, error) {
			// A mutable-file parser would now consume different bytes from those
			// whose digest matched the published release.
			if err := os.WriteFile(fixture.archivePath, mutated, 0o644); err != nil {
				return nil, err
			}
			data, err := io.ReadAll(source)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(fixture.archivePath, original, 0o644); err != nil {
				return nil, err
			}
			return data, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, original) {
		t.Fatal("archive parser received bytes other than the authenticated snapshot")
	}
}

func TestCandidateJSONRequiresExactCanonicalFields(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	if !bytes.HasSuffix(fixture.data, []byte("\n")) {
		t.Fatal("candidate metadata is not LF terminated")
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"duplicate key", bytes.Replace(fixture.data, []byte(`"schema_version": 1,`), []byte(`"schema_version": 1, "schema_version": 1,`), 1)},
		{"case variant", bytes.Replace(fixture.data, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)},
		{"unknown field", bytes.Replace(fixture.data, []byte(`"candidate_type"`), []byte(`"unknown": true, "candidate_type"`), 1)},
		{"noncanonical whitespace", append([]byte(" "), fixture.data...)},
		{"trailing object", append(append([]byte(nil), fixture.data...), []byte("{}")...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := unmarshal(test.data); err == nil {
				t.Fatal("invalid candidate JSON was accepted")
			}
		})
	}
}

func TestUnverifiedReleaseAndCanceledContextFailClosed(t *testing.T) {
	if _, err := Build(context.Background(), releaseassessment.VerifiedRelease{}, "unused", "unused", "unused"); err == nil {
		t.Fatal("Build accepted a zero-value release identity")
	}
	if _, err := Verify(context.Background(), releaseassessment.VerifiedRelease{}, "unused", "unused", "unused", "unused"); err == nil {
		t.Fatal("Verify accepted a zero-value release identity")
	}
	if (VerifiedCandidate{}).Valid() {
		t.Fatal("zero-value candidate result is valid")
	}
	if _, err := (VerifiedCandidate{}).Summary(); err == nil {
		t.Fatal("zero-value candidate returned a summary")
	}
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifyBytes(ctx, fixture.facts, fixture.data, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil {
		t.Fatal("canceled verification context was accepted")
	}
}

type testArchiveMember struct {
	name     string
	body     []byte
	typeflag byte
	size     int64
}

func testGzipTar(t *testing.T, members ...testArchiveMember) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zipped := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(zipped)
	complete := true
	for _, member := range members {
		size := int64(len(member.body))
		if member.size != 0 {
			size = member.size
		}
		kind := member.typeflag
		if kind == 0 {
			kind = tar.TypeReg
		}
		if err := archive.WriteHeader(&tar.Header{Name: member.name, Size: size, Mode: 0o644, Typeflag: kind}); err != nil {
			t.Fatal(err)
		}
		if len(member.body) > 0 {
			if _, err := archive.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
		if size != int64(len(member.body)) {
			complete = false
			break
		}
	}
	if complete {
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipped.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestArchiveParserRejectsUntrustedMembers(t *testing.T) {
	manifest := testArchiveMember{name: packageinfo.ManifestName, body: []byte("{}")}
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"not gzip", []byte("not a gzip stream"), "open authenticated release archive"},
		{"missing manifest", testGzipTar(t, testArchiveMember{name: "leaguebridge", body: []byte("binary")}), "missing PACKAGE-MANIFEST.json"},
		{"directory entry", testGzipTar(t, testArchiveMember{name: "unexpected/", typeflag: tar.TypeDir}), "invalid member"},
		{"duplicate manifest", testGzipTar(t, manifest, manifest), "invalid package manifest"},
		{"empty manifest", testGzipTar(t, testArchiveMember{name: packageinfo.ManifestName}), "invalid package manifest"},
		{"oversized manifest", testGzipTar(t, testArchiveMember{name: packageinfo.ManifestName, size: 1<<20 + 1}), "invalid package manifest"},
		{"oversized member", testGzipTar(t, testArchiveMember{name: "leaguebridge", size: nativepackage.MaximumPayloadSize + 1}), "invalid member"},
		{"short manifest", testGzipTar(t, testArchiveMember{name: packageinfo.ManifestName, body: []byte("abc"), size: 5}), "read release archive package manifest"},
		{"short other member", testGzipTar(t, testArchiveMember{name: "leaguebridge", body: []byte("abc"), size: 5}), "skip release archive member"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := sourceManifestFromArchive(context.Background(), bytes.NewReader(test.data)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("malformed release archive error = %v; want %q", err, test.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sourceManifestFromArchive(ctx, bytes.NewReader(testGzipTar(t, manifest))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled archive parser error = %v", err)
	}
}

func TestCandidateRejectsInvalidTrustedReleaseIdentityAndPublishedAsset(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	for _, test := range []struct {
		name   string
		mutate func(*releaseFacts)
		want   string
	}{
		{"prerelease", func(value *releaseFacts) { value.Version = "v1.2.3-rc1" }, "verified release identity is invalid"},
		{"uppercase commit", func(value *releaseFacts) { value.Commit = strings.Repeat("A", 40) }, "verified release identity is invalid"},
		{"missing tree", func(value *releaseFacts) { value.Tree = "" }, "verified release identity is invalid"},
		{"missing release ID", func(value *releaseFacts) { value.ReleaseID = 0 }, "verified release identity is invalid"},
		{"different stable version", func(value *releaseFacts) { value.Version = "v1.2.4" }, "staging version does not match"},
		{"asset digest malformed", func(value *releaseFacts) {
			value.Assets = append([]releaseassessment.PublishedAsset(nil), value.Assets...)
			value.Assets[0].SHA256 = "not-a-digest"
		}, "published source archive identity is invalid"},
		{"asset empty", func(value *releaseFacts) {
			value.Assets = append([]releaseassessment.PublishedAsset(nil), value.Assets...)
			value.Assets[0].SizeBytes = 0
		}, "published source archive identity is invalid"},
		{"asset digest substitution", func(value *releaseFacts) {
			value.Assets = append([]releaseassessment.PublishedAsset(nil), value.Assets...)
			value.Assets[0].SHA256 = strings.Repeat("a", 64)
		}, "staged source archive does not match"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := fixture.facts
			test.mutate(&facts)
			if _, err := derive(context.Background(), facts, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid release error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestCandidateRejectsUnsafePackageAndMetadataFiles(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, err := hashRegular(context.Background(), missing, maximumPackage); err == nil {
		t.Fatal("missing package file was accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashRegular(context.Background(), empty, maximumPackage); err == nil {
		t.Fatal("empty package file was accepted")
	}
	if _, err := readRegularBounded(context.Background(), empty, maximumCandidate); err == nil {
		t.Fatal("empty candidate metadata file was accepted")
	}
	if _, _, err := hashRegular(context.Background(), fixture.packagePath, 1); err == nil {
		t.Fatal("package above the configured size bound was accepted")
	}
	if _, err := readRegularBounded(context.Background(), fixture.archivePath, 1); err == nil {
		t.Fatal("metadata above the configured size bound was accepted")
	}
	if _, err := readRegularBounded(context.Background(), missing, maximumCandidate); err == nil {
		t.Fatal("missing candidate metadata file was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := hashRegular(ctx, fixture.packagePath, maximumPackage); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled package hash error = %v", err)
	}
	if _, err := readRegularBounded(ctx, fixture.archivePath, maximumReleaseAsset); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled bounded read error = %v", err)
	}
	wrongName := filepath.Join(t.TempDir(), "leaguebridge_1.2.4_amd64.deb")
	body, err := os.ReadFile(fixture.packagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrongName, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := derive(context.Background(), fixture.facts, fixture.archivePath, fixture.stagingDir, wrongName); err == nil || !strings.Contains(err.Error(), "filename does not match") {
		t.Fatalf("wrong package basename error = %v", err)
	}
}

func TestCandidateDocumentRejectsInvalidIdentityBeforeFilesystemUse(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	for _, test := range []struct {
		name   string
		mutate func(*candidate)
	}{
		{"wrong candidate type", func(value *candidate) { value.CandidateType = "hosted-ci-package" }},
		{"wrong scope", func(value *candidate) { value.ValidationScope = "published-and-signed" }},
		{"prerelease version", func(value *candidate) { value.Release.Version = "v1.2.3-ci" }},
		{"missing source tree", func(value *candidate) { value.Release.Tree = "" }},
		{"invalid executable digest", func(value *candidate) { value.Release.ExecutableSHA256 = "uppercase-digest" }},
		{"zero package size", func(value *candidate) { value.Package.SizeBytes = 0 }},
		{"unsupported family", func(value *candidate) { value.Package.Family = "unreviewed-family" }},
		{"wrong format", func(value *candidate) { value.Package.Format = "tar.gz" }},
		{"cross-target archive name", func(value *candidate) { value.Release.ArchiveFilename = "leaguebridge_1.2.3_linux_arm64.tar.gz" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := fixture.value
			test.mutate(&value)
			if _, err := marshal(value); err == nil {
				t.Fatal("untrusted candidate identity was serialized as valid")
			}
		})
	}
	tooLarge := bytes.Repeat([]byte("x"), int(maximumCandidate)+1)
	if _, err := unmarshal(tooLarge); err == nil {
		t.Fatal("oversized candidate metadata was accepted")
	}
	overflow := bytes.Replace(fixture.data, []byte(`"release_id": 12345`), []byte(`"release_id": 999999999999999999999999999999`), 1)
	if bytes.Equal(overflow, fixture.data) {
		t.Fatal("fixture release ID was not found")
	}
	if _, err := unmarshal(overflow); err == nil {
		t.Fatal("integer-overflow release ID was accepted")
	}
}

func TestCandidateRejectsMissingAndMisnamedInputRoots(t *testing.T) {
	fixture := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := derive(context.Background(), fixture.facts, fixture.archivePath, missing, fixture.packagePath); err == nil || !strings.Contains(err.Error(), "open native package staging") {
		t.Fatalf("missing staging root error = %v", err)
	}
	badManifest := filepath.Join(fixture.stagingDir, nativepackage.StagingManifestName)
	if err := os.WriteFile(badManifest, []byte("{not-json}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := derive(context.Background(), fixture.facts, fixture.archivePath, fixture.stagingDir, fixture.packagePath); err == nil || !strings.Contains(err.Error(), "verify native package staging") {
		t.Fatalf("corrupt staging manifest error = %v", err)
	}
	fresh := makeFixture(t, Cell{nativepackage.FamilyDebian, "linux", "amd64"})
	misnamedArchive := filepath.Join(t.TempDir(), "leaguebridge_1.2.4_linux_amd64.tar.gz")
	data, err := os.ReadFile(fresh.archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(misnamedArchive, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := derive(context.Background(), fresh.facts, misnamedArchive, fresh.stagingDir, fresh.packagePath); err == nil || !strings.Contains(err.Error(), "source archive filename") {
		t.Fatalf("misnamed archive error = %v", err)
	}
}

func TestContextReaderStopsBeforeConsumingCanceledInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := bytes.NewReader([]byte("package bytes"))
	buffer := make([]byte, 4)
	if n, err := (contextReader{ctx: ctx, reader: reader}).Read(buffer); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reader returned n=%d, err=%v", n, err)
	}
	if reader.Len() != len("package bytes") {
		t.Fatal("canceled reader consumed input")
	}
}
