package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testEpoch = int64(1787702401)

func TestCreateArchiveIsCanonicalAndReproducible(t *testing.T) {
	root := makePayload(t)
	first := filepath.Join(t.TempDir(), "first.zip")
	second := filepath.Join(t.TempDir(), "second.zip")
	if err := createArchive(root, first, testEpoch); err != nil {
		t.Fatal(err)
	}
	if err := createArchive(root, second, testEpoch); err != nil {
		t.Fatal(err)
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstData, secondData) {
		t.Fatal("canonical ZIP changed between identical builds")
	}

	archive, err := zip.OpenReader(first)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if archive.Comment != "" || len(archive.File) != len(canonicalMembers) {
		t.Fatalf("unexpected ZIP shape: comment=%q files=%d", archive.Comment, len(archive.File))
	}
	wantDate, wantTime := msDOSDateTime(time.Unix(testEpoch, 0))
	for index, file := range archive.File {
		member := canonicalMembers[index]
		if file.Name != member.name || file.Mode() != member.mode {
			t.Fatalf("member[%d] = %q mode %04o; want %q mode %04o", index, file.Name, file.Mode(), member.name, member.mode)
		}
		if file.Method != zip.Deflate || file.ModifiedDate != wantDate || file.ModifiedTime != wantTime || len(file.Extra) != 0 || file.Comment != "" {
			t.Fatalf("member %q has non-canonical metadata", file.Name)
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			reader.Close()
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if string(body) != "content for "+file.Name {
			t.Fatalf("member %q body = %q", file.Name, body)
		}
	}
}

func TestMemberSizeLimitsMatchRoles(t *testing.T) {
	if memberSizeLimit("leaguebridge.exe") != maxBinaryInput {
		t.Fatal("binary limit is not applied")
	}
	if memberSizeLimit("PACKAGE-MANIFEST.json") != maxMetadataInput || memberSizeLimit("SBOM.spdx.json") != maxMetadataInput {
		t.Fatal("metadata limit is not applied")
	}
	if memberSizeLimit("README.md") != maxAuxiliaryInput {
		t.Fatal("auxiliary limit is not applied")
	}
}

func TestCreateArchiveRefusesOverwriteAndUnsafeInputs(t *testing.T) {
	root := makePayload(t)
	output := filepath.Join(t.TempDir(), "release.zip")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createArchive(root, output, testEpoch); err == nil || !strings.Contains(err.Error(), "file exists") {
		t.Fatalf("overwrite error = %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatalf("existing output changed to %q", data)
	}

	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "payload-link")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		if err := createArchive(link, filepath.Join(t.TempDir(), "linked.zip"), testEpoch); err == nil || !strings.Contains(err.Error(), "non-symlink directory") {
			t.Fatalf("symlink-root error = %v", err)
		}
	}
}

func TestParseEpochIsBounded(t *testing.T) {
	if got, err := parseEpoch("1787702400"); err != nil || got != 1787702400 {
		t.Fatalf("parseEpoch(valid) = %d, %v", got, err)
	}
	for _, value := range []string{"", "-1", "+1", "abc", "0", "315532799", "4354819200"} {
		if _, err := parseEpoch(value); err == nil {
			t.Errorf("parseEpoch(%q) unexpectedly succeeded", value)
		}
	}
}

func makePayload(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, member := range canonicalMembers {
		if err := os.WriteFile(filepath.Join(root, member.name), []byte("content for "+member.name), member.mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
