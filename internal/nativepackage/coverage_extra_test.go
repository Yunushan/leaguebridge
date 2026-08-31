package nativepackage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyStagingRootAcceptsCompleteTree(t *testing.T) {
	source, sourceData := sourceManifest(t, "linux", "amd64")
	manifest, err := Build(source, sourceData, strings.Repeat("a", 64), FamilyDebian)
	if err != nil {
		t.Fatal(err)
	}

	stagingPath := t.TempDir()
	packageRoot := filepath.Join(stagingPath, "root")
	if err := os.Mkdir(packageRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Payload {
		body := []byte("native-package fixture: " + entry.SourcePath)
		if entry.SourcePath == manifestFilename {
			body = sourceData
		}
		relative := filepath.FromSlash(strings.TrimPrefix(entry.InstallPath, "/"))
		path := filepath.Join(packageRoot, relative)
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
	stagingData, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingPath, StagingManifestName), stagingData, 0o644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(stagingPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := VerifyStagingRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Package != manifest.Package || got.SourceArtifact != manifest.SourceArtifact {
		t.Fatalf("verified manifest = %+v; want package=%+v source=%+v", got, manifest.Package, manifest.SourceArtifact)
	}
	if decoded, err := Unmarshal(stagingData); err != nil || decoded.Package != manifest.Package {
		t.Fatalf("Unmarshal() = %+v, %v", decoded, err)
	}
}

func TestUnmarshalRejectsDuplicateAndNonCanonicalStagingJSON(t *testing.T) {
	source, sourceData := sourceManifest(t, "linux", "amd64")
	manifest, err := Build(source, sourceData, strings.Repeat("a", 64), FamilyDebian)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(canonical, []byte("  \"name\": \"leaguebridge\",\n"), []byte("  \"name\": \"leaguebridge\",\n  \"name\": \"leaguebridge\",\n"), 1)
	if _, err := Unmarshal(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate JSON error = %v", err)
	}
	if _, err := Unmarshal(bytes.TrimSuffix(canonical, []byte("\n"))); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("non-canonical JSON error = %v", err)
	}
}

func TestStagingPathAndModeValidation(t *testing.T) {
	if got, err := stagingRelativePath("/usr/bin/leaguebridge"); err != nil || got != "usr/bin/leaguebridge" {
		t.Fatalf("stagingRelativePath() = %q, %v", got, err)
	}
	for _, path := range []string{"", "relative", "/", "/../escape", "/usr//bin", "/usr\\bin", "/usr/bin\x00"} {
		if _, err := stagingRelativePath(path); err == nil {
			t.Errorf("stagingRelativePath accepted unsafe path %q", path)
		}
	}
	for _, test := range []struct {
		raw  string
		want os.FileMode
	}{
		{raw: "0644", want: 0o644},
		{raw: "0755", want: 0o755},
	} {
		if got, err := parseStagingMode(test.raw); err != nil || got.Perm() != test.want {
			t.Errorf("parseStagingMode(%q) = %v, %v; want %04o", test.raw, got, err, test.want)
		}
	}
	if _, err := parseStagingMode("0600"); err == nil {
		t.Fatal("parseStagingMode accepted an unsupported mode")
	}
}
