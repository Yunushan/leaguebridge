package releasecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/target"
)

func assertExecutableInventory(t *testing.T, dir string, inventory ExecutableInventory) {
	t.Helper()
	if len(inventory.Entries) != 9 || len(inventory.Entries) != len(target.Ordered()) {
		t.Fatalf("inventory has %d entries; want nine canonical targets", len(inventory.Entries))
	}
	for index, cell := range target.Ordered() {
		entry := inventory.Entries[index]
		archiveName := fmt.Sprintf("leaguebridge_%s_%s_%s.tar.gz", strings.TrimPrefix(testVersion, "v"), cell.GOOS, cell.GOARCH)
		if entry.GOOS != cell.GOOS || entry.GOARCH != cell.GOARCH || entry.ArchiveName != archiveName || entry.ExecutableName != "leaguebridge" {
			t.Fatalf("entry %d = %+v; want canonical %s/%s %s", index, entry, cell.GOOS, cell.GOARCH, archiveName)
		}
		archiveBytes, err := os.ReadFile(filepath.Join(dir, archiveName))
		if err != nil {
			t.Fatal(err)
		}
		archiveDigest := sha256.Sum256(archiveBytes)
		if entry.ArchiveSHA256 != fmt.Sprintf("%x", archiveDigest) {
			t.Fatalf("%s archive digest = %q; want %x", archiveName, entry.ArchiveSHA256, archiveDigest)
		}
		gzipReader, err := gzip.NewReader(bytes.NewReader(archiveBytes))
		if err != nil {
			t.Fatal(err)
		}
		archiveReader := tar.NewReader(gzipReader)
		found := false
		for {
			header, err := archiveReader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if header.Name != entry.ExecutableName {
				continue
			}
			if header.Size <= 0 || header.Size > maxBinarySize {
				t.Fatalf("%s executable has invalid size %d", archiveName, header.Size)
			}
			digest := sha256.New()
			if _, err := io.CopyN(digest, archiveReader, header.Size); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("%x", digest.Sum(nil))
			if entry.ExecutableSHA256 != want {
				t.Fatalf("%s executable digest = %q; want %s", archiveName, entry.ExecutableSHA256, want)
			}
			found = true
			break
		}
		if err := gzipReader.Close(); err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatalf("%s is missing %s", archiveName, entry.ExecutableName)
		}
	}
}

func TestCheckWithExecutableInventoryRejectsWrongDuplicateAndMissingEntries(t *testing.T) {
	artifacts, err := expectedArtifacts(testVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*testing.T, string)
		want string
	}{
		{
			name: "wrong digest",
			edit: func(t *testing.T, dir string) {
				t.Helper()
				path := filepath.Join(dir, artifacts[0].name)
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("altered")); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
			want: "checksum mismatch",
		},
		{
			name: "duplicate digest entry",
			edit: func(t *testing.T, dir string) {
				t.Helper()
				path := filepath.Join(dir, "checksums.txt")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
				lines[1] = lines[0]
				if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "canonical entry",
		},
		{
			name: "missing digest entry",
			edit: func(t *testing.T, dir string) {
				t.Helper()
				path := filepath.Join(dir, "checksums.txt")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
				if err := os.WriteFile(path, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "has 8 entries; want 9",
		},
		{
			name: "missing archive",
			edit: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dir, artifacts[0].name)); err != nil {
					t.Fatal(err)
				}
			},
			want: "missing release file",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := makeStructuralReleaseFixture(t)
			test.edit(t, dir)
			inventory, err := CheckWithExecutableInventory(CheckRequest{
				Dir: dir, Version: testVersion, SourceDateEpoch: testEpoch,
				Commit: testCommit, Tree: testTree, BuilderGoVersion: productionBuilderGoVersion,
				ExpectedScorecard: readiness.EmbeddedJSON(),
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("CheckWithExecutableInventory() = %+v, %v; want %q", inventory, err, test.want)
			}
			if len(inventory.Entries) != 0 {
				t.Fatalf("failed check leaked a partial inventory: %+v", inventory)
			}
		})
	}
}
