package main

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type testTarMember struct {
	name     string
	typeFlag byte
	body     []byte
}

func candidateTarMembers(t *testing.T) []testTarMember {
	t.Helper()
	files, _, err := candidateArtifactInventory("v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	members := make([]testTarMember, 0, len(names))
	for _, name := range names {
		members = append(members, testTarMember{name: name, typeFlag: tar.TypeReg, body: []byte("candidate bytes: " + name)})
	}
	return members
}

func writeCandidateTar(t *testing.T, members []testTarMember) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "eleven-score-free-candidates.tar")
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(file)
	for _, member := range members {
		header := &tar.Header{Name: member.name, Typeflag: member.typeFlag, Mode: 0o600}
		if member.typeFlag == tar.TypeReg {
			header.Size = int64(len(member.body))
		}
		if member.typeFlag == tar.TypeSymlink {
			header.Linkname = "CANDIDATE-SET.json"
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if member.typeFlag == tar.TypeReg {
			if _, err := archive.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestExtractStableCandidateArtifactAcceptsOnlyFixedRegularFiles(t *testing.T) {
	members := candidateTarMembers(t)
	artifact := writeCandidateTar(t, members)
	root, cleanup, err := extractStableCandidateArtifact(context.Background(), "v0.1.0", artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range members {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(member.name)))
		if err != nil || string(data) != string(member.body) {
			t.Fatalf("extracted %q = %q, %v", member.name, data, err)
		}
	}
	cleanup()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("private candidate extraction remained after cleanup: %v", err)
	}
}

func TestExtractStableCandidateArtifactRejectsUntrustedTarMembers(t *testing.T) {
	base := candidateTarMembers(t)
	for _, test := range []struct {
		name   string
		change func([]testTarMember) []testTarMember
	}{
		{"missing package", func(items []testTarMember) []testTarMember { return items[:len(items)-1] }},
		{"duplicate", func(items []testTarMember) []testTarMember { return append(items, items[0]) }},
		{"extra file", func(items []testTarMember) []testTarMember {
			return append(items, testTarMember{name: "extra", typeFlag: tar.TypeReg, body: []byte("x")})
		}},
		{"path traversal", func(items []testTarMember) []testTarMember {
			return append(items, testTarMember{name: "../escape", typeFlag: tar.TypeReg, body: []byte("x")})
		}},
		{"symlink", func(items []testTarMember) []testTarMember {
			return append(items, testTarMember{name: "merged-packages/alias", typeFlag: tar.TypeSymlink})
		}},
		{"extra directory", func(items []testTarMember) []testTarMember {
			return append(items, testTarMember{name: "unreviewed/", typeFlag: tar.TypeDir})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			items := append([]testTarMember(nil), base...)
			artifact := writeCandidateTar(t, test.change(items))
			root, cleanup, err := extractStableCandidateArtifact(context.Background(), "v0.1.0", artifact)
			if cleanup != nil {
				cleanup()
			}
			if err == nil {
				t.Fatalf("unsafe tar accepted at %s", root)
			}
		})
	}
}

func TestExtractStableCandidateArtifactRejectsExtendedOversizedAndTruncatedHeaders(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"extended header", func(t *testing.T, name string) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			data[156] = tar.TypeXHeader
			if err := os.WriteFile(name, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized record", func(t *testing.T, name string) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			copy(data[124:136], []byte("000040000000"))
			if err := os.WriteFile(name, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated payload", func(t *testing.T, name string) {
			if err := os.Truncate(name, 600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := writeCandidateTar(t, candidateTarMembers(t))
			test.mutate(t, name)
			root, cleanup, err := extractStableCandidateArtifact(context.Background(), "v0.1.0", name)
			if cleanup != nil {
				cleanup()
			}
			if err == nil {
				t.Fatalf("invalid tar accepted at %s", root)
			}
		})
	}
}
