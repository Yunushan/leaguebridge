package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const generatorTestCommit = "0123456789abcdef0123456789abcdef01234567"
const generatorTestTree = "89abcdef0123456789abcdef0123456789abcdef"

func TestGenerateReadsExactPayload(t *testing.T) {
	root := t.TempDir()
	names, err := packageinfo.ExpectedPayloadNames("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(root, name), []byte("content for "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(root, packageinfo.ManifestName)
	data, err := generate(root, output, "v1.2.3", "linux", "amd64", 1787702400, generatorTestCommit, generatorTestTree, "go1.27.0")
	if err != nil {
		t.Fatal(err)
	}
	var manifest packageinfo.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Target.GOOS != "linux" || len(manifest.Payload) != len(names) {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestGenerateRejectsOutputOutsideRoot(t *testing.T) {
	root := t.TempDir()
	_, err := generate(root, filepath.Join(t.TempDir(), packageinfo.ManifestName), "v1.2.3", "linux", "amd64", 1787702400, generatorTestCommit, generatorTestTree, "go1.27.0")
	if err == nil || !strings.Contains(err.Error(), "directly beneath root") {
		t.Fatalf("generate() error = %v", err)
	}
}

func TestReadRegularBoundedRejectsOversizeAndSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(path, 4); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversize error = %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(link, 10); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestPayloadSizeLimitsMatchMemberRoles(t *testing.T) {
	if payloadSizeLimit("leaguebridge") != maxBinarySize || payloadSizeLimit("leaguebridge.exe") != maxBinarySize {
		t.Fatal("binary payload limit is not applied to both executable names")
	}
	if payloadSizeLimit("SBOM.spdx.json") != maxMetadataSize {
		t.Fatal("SBOM metadata limit is not applied")
	}
	if payloadSizeLimit("README.md") != maxAuxiliarySize || payloadSizeLimit("install.sh") != maxAuxiliarySize {
		t.Fatal("auxiliary payload limit is not applied")
	}
}

func TestProductionBuilderIsExact(t *testing.T) {
	if err := validateProductionBuilder(packageinfo.ProductionBuilderGoVersion); err != nil {
		t.Fatalf("validateProductionBuilder(valid) error = %v", err)
	}
	for _, value := range []string{"", "go1.24.13", "go1.26.3", "go1.27.1"} {
		if err := validateProductionBuilder(value); err == nil {
			t.Errorf("validateProductionBuilder(%q) unexpectedly succeeded", value)
		}
	}
}

func TestWriteExclusiveDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), packageinfo.ManifestName)
	if err := writeExclusive(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(path, []byte("second")); err == nil {
		t.Fatal("writeExclusive() overwrote an existing manifest")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Fatalf("manifest content = %q", data)
	}
}
