package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

func TestVerifyAcceptsCanonicalStagingTree(t *testing.T) {
	root := makeStagingFixture(t)
	manifest, err := verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Package.Family != nativepackage.FamilyDebian || manifest.Target.GOOS != "linux" {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestVerifyRejectsTamperedAndUnexpectedStagingEntries(t *testing.T) {
	root := makeStagingFixture(t)
	file := filepath.Join(root, "root", "usr", "bin", "leaguebridge")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err := os.WriteFile(file, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(root); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered staging error = %v", err)
	}

	root = makeStagingFixture(t)
	extra := filepath.Join(root, "unexpected")
	if err := os.WriteFile(extra, []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(root); err == nil || !strings.Contains(err.Error(), "unexpected file") {
		t.Fatalf("unexpected staging entry error = %v", err)
	}
}

func TestVerifyRejectsDuplicateManifestKeys(t *testing.T) {
	root := makeStagingFixture(t)
	manifestPath := filepath.Join(root, nativepackage.StagingManifestName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("{\n"), []byte("{\n  \"$schema\": \""+nativepackage.SchemaID+"\",\n"), 1)
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(root); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate manifest error = %v", err)
	}
}

func TestVerifyRejectsSymlinkedStagingEntry(t *testing.T) {
	root := makeStagingFixture(t)
	file := filepath.Join(root, "root", "usr", "bin", "leaguebridge")
	target := filepath.Join(root, "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := verify(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked staging error = %v", err)
	}
}

func makeStagingFixture(t *testing.T) string {
	t.Helper()
	names, err := packageinfo.ExpectedPayloadNames("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte, len(names))
	for _, name := range names {
		bodies[name] = []byte("native-package-check fixture: " + name)
	}
	source, err := packageinfo.Build("v1.2.3", "linux", "amd64", 1787702400, strings.Repeat("0", 40), strings.Repeat("1", 40), "go1.27.0", bodies)
	if err != nil {
		t.Fatal(err)
	}
	sourceData, err := packageinfo.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	staging, err := nativepackage.Build(source, sourceData, strings.Repeat("a", 64), nativepackage.FamilyDebian)
	if err != nil {
		t.Fatal(err)
	}
	stagingData, err := nativepackage.Marshal(staging)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, nativepackage.StagingManifestName), stagingData, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, entry := range staging.Payload {
		relative := strings.TrimPrefix(entry.InstallPath, "/")
		path := filepath.Join(directory, "root", filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		body := sourceData
		if entry.SourcePath != "PACKAGE-MANIFEST.json" {
			body = bodies[entry.SourcePath]
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if entry.Mode == "0755" {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	return directory
}
