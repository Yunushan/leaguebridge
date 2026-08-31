package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

func TestStageBuildsSafeDebianRootWithoutPortableScripts(t *testing.T) {
	fixture := makeArchiveFixture(t, "linux", "amd64")
	output := filepath.Join(t.TempDir(), "staging")
	if err := stage(fixture.archive, output, nativepackage.FamilyDebian); err != nil {
		t.Fatal(err)
	}
	manifestData, err := os.ReadFile(filepath.Join(output, "NATIVE-PACKAGE-MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest nativepackage.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if manifest.Package.Family != nativepackage.FamilyDebian || manifest.Package.InstallRoot != "/" {
		t.Fatalf("staging package = %+v", manifest.Package)
	}
	root := filepath.Join(output, "root")
	for _, relative := range []string{
		filepath.Join("usr", "bin", "leaguebridge"),
		filepath.Join("usr", "share", "doc", "leaguebridge", "LICENSE"),
		filepath.Join("usr", "share", "doc", "leaguebridge", "README.md"),
		filepath.Join("usr", "share", "doc", "leaguebridge", "SBOM.spdx.json"),
		filepath.Join("usr", "share", "doc", "leaguebridge", "PACKAGE-MANIFEST.json"),
	} {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			t.Errorf("staged file %s: %v", relative, err)
		}
	}
	for _, relative := range []string{
		filepath.Join("usr", "local", "bin", "leaguebridge"),
		filepath.Join("usr", "local", "share", "doc", "leaguebridge", "install.sh"),
		filepath.Join("usr", "local", "share", "doc", "leaguebridge", "uninstall.sh"),
	} {
		if _, err := os.Stat(filepath.Join(root, relative)); !os.IsNotExist(err) {
			t.Errorf("portable-only path %s exists or returned unexpected error: %v", relative, err)
		}
	}
	gotBinary, err := os.ReadFile(filepath.Join(root, "usr", "bin", "leaguebridge"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBinary, fixture.bodies["leaguebridge"]) {
		t.Fatal("staged executable differs from the source archive")
	}
}

func TestStagePreservesBSDInstallRoot(t *testing.T) {
	fixture := makeArchiveFixture(t, "freebsd", "amd64")
	output := filepath.Join(t.TempDir(), "staging")
	if err := stage(fixture.archive, output, nativepackage.FamilyFreeBSD); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "root", "usr", "local", "bin", "leaguebridge")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "root", "usr", "bin", "leaguebridge")); !os.IsNotExist(err) {
		t.Fatalf("BSD staging unexpectedly rewrote /usr/local: %v", err)
	}
}

func TestReadSourceArchiveRejectsSymlinksAndReorderedMembers(t *testing.T) {
	fixture := makeArchiveFixture(t, "linux", "amd64")
	symlinkArchive := filepath.Join(t.TempDir(), filepath.Base(fixture.archive))
	writeArchive(t, symlinkArchive, fixture.source, fixture.bodies, func(header *tar.Header, name string) {
		if name == "LICENSE" {
			header.Typeflag = tar.TypeSymlink
			header.Linkname = "outside"
			header.Size = 0
		}
	})
	if _, err := readSourceArchive(symlinkArchive, mustRead(t, symlinkArchive)); err == nil || !strings.Contains(err.Error(), "non-canonical file metadata") {
		t.Fatalf("symlink archive error = %v", err)
	}

	reorderedArchive := filepath.Join(t.TempDir(), filepath.Base(fixture.archive))
	writeArchiveWithOrder(t, reorderedArchive, fixture.source, fixture.bodies, []string{
		"LICENSE", "README.md", "PACKAGE-MANIFEST.json", "SBOM.spdx.json", "install.sh", "leaguebridge", "uninstall.sh",
	})
	if _, err := readSourceArchive(reorderedArchive, mustRead(t, reorderedArchive)); err == nil || !strings.Contains(err.Error(), "out of canonical order") {
		t.Fatalf("reordered archive error = %v", err)
	}
}

func TestStageRejectsExistingOutputAndUnsafePaths(t *testing.T) {
	fixture := makeArchiveFixture(t, "linux", "amd64")
	output := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := stage(fixture.archive, output, nativepackage.FamilyDebian); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output error = %v", err)
	}
	for _, installPath := range []string{"relative", "/", "/usr/../escape", "/usr//bin/leaguebridge", "/usr/bin/../leaguebridge"} {
		if _, err := rootedPath(t.TempDir(), installPath); err == nil {
			t.Errorf("rootedPath accepted unsafe install path %q", installPath)
		}
	}
}

func TestStageRejectsSymlinkedInputAndOutputParents(t *testing.T) {
	fixture := makeArchiveFixture(t, "linux", "amd64")
	root := t.TempDir()
	inputTarget := filepath.Join(root, "input-target")
	if err := os.Mkdir(inputTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	archiveBody := mustRead(t, fixture.archive)
	inputArchive := filepath.Join(inputTarget, filepath.Base(fixture.archive))
	if err := os.WriteFile(inputArchive, archiveBody, 0o644); err != nil {
		t.Fatal(err)
	}
	inputLink := filepath.Join(root, "input-link")
	if err := os.Symlink(inputTarget, inputLink); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	outputTarget := filepath.Join(root, "output-target")
	if err := os.Mkdir(outputTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	outputLink := filepath.Join(root, "output-link")
	if err := os.Symlink(outputTarget, outputLink); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	archivePath := filepath.Join(inputLink, filepath.Base(fixture.archive))
	if err := stage(archivePath, filepath.Join(root, "safe-output"), nativepackage.FamilyDebian); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("symlinked input parent error = %v; want parent rejection", err)
	}
	if err := stage(fixture.archive, filepath.Join(outputLink, "staging"), nativepackage.FamilyDebian); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("symlinked output parent error = %v; want parent rejection", err)
	}
}

type archiveFixture struct {
	archive string
	source  packageinfo.Manifest
	bodies  map[string][]byte
}

func makeArchiveFixture(t *testing.T, goos, goarch string) archiveFixture {
	t.Helper()
	names, err := packageinfo.ExpectedPayloadNames(goos, goarch)
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte, len(names))
	for _, name := range names {
		bodies[name] = []byte("native-package archive fixture: " + name)
	}
	source, err := packageinfo.Build("v1.2.3", goos, goarch, 1787702400, "0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef", "go1.27.0", bodies)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := packageinfo.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), source.Artifact.Filename)
	writeArchive(t, archive, source, bodies, nil)
	return archiveFixture{archive: archive, source: source, bodies: withManifest(bodies, manifestData)}
}

func writeArchive(t *testing.T, filename string, source packageinfo.Manifest, bodies map[string][]byte, mutate func(*tar.Header, string)) {
	t.Helper()
	order := []string{
		"LICENSE", "PACKAGE-MANIFEST.json", "README.md", "SBOM.spdx.json", "install.sh", "leaguebridge", "uninstall.sh",
	}
	if mutate == nil {
		writeArchiveWithOrder(t, filename, source, bodies, order)
		return
	}
	writeArchiveWithOrder(t, filename, source, bodies, order, mutate)
}

func writeArchiveWithOrder(t *testing.T, filename string, source packageinfo.Manifest, bodies map[string][]byte, order []string, mutations ...func(*tar.Header, string)) {
	t.Helper()
	manifestData, err := packageinfo.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	gzipWriter.Header = gzip.Header{OS: 255}
	tarWriter := tar.NewWriter(gzipWriter)
	modTime := time.Unix(source.Provenance.SourceDateEpoch, 0).UTC()
	for _, name := range order {
		body := bodies[name]
		if name == "PACKAGE-MANIFEST.json" {
			body = manifestData
		}
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: modTime, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if name == "install.sh" || name == "uninstall.sh" || name == "leaguebridge" {
			header.Mode = 0o755
		}
		for _, mutate := range mutations {
			mutate(header, name)
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tarWriter.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func withManifest(bodies map[string][]byte, manifest []byte) map[string][]byte {
	result := make(map[string][]byte, len(bodies)+1)
	for name, body := range bodies {
		result[name] = body
	}
	result["PACKAGE-MANIFEST.json"] = manifest
	return result
}

func mustRead(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
