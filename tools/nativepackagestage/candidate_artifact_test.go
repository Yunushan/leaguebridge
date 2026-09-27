package main

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type testTarMember struct {
	name     string
	typeFlag byte
	body     []byte
	format   tar.Format
}

func candidateTarMembers(t *testing.T) []testTarMember {
	return candidateTarMembersForVersion(t, "v0.1.0", 0)
}

func candidateTarMembersForVersion(t *testing.T, version string, format tar.Format) []testTarMember {
	t.Helper()
	files, _, err := candidateArtifactInventory(version)
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
		members = append(members, testTarMember{name: name, typeFlag: tar.TypeReg, body: []byte("candidate bytes: " + name), format: format})
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
		header := &tar.Header{Name: member.name, Typeflag: member.typeFlag, Mode: 0o600, Format: member.format}
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

func TestExtractStableCandidateArtifactGNUWorkflowTarVersionBoundary(t *testing.T) {
	if output, err := exec.Command("tar", "--version").Output(); err != nil || !bytes.Contains(output, []byte("GNU tar")) {
		t.Skip("GNU tar is required to exercise the workflow archive format")
	}
	for _, test := range []struct {
		name    string
		version string
	}{
		{"100-byte package path", "v" + strings.Repeat("9", 9) + ".2.3"},
		{"101-byte package path", "v" + strings.Repeat("9", 10) + ".2.3"},
		{"maximum stable version", "v" + strings.Repeat("9", 123) + ".2.3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			if err := os.Mkdir(source, 0o700); err != nil {
				t.Fatal(err)
			}
			members := candidateTarMembersForVersion(t, test.version, 0)
			for _, member := range members {
				file := filepath.Join(source, filepath.FromSlash(member.name))
				if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, member.body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			archive := filepath.Join(root, "eleven-score-free-candidates.tar")
			command := exec.Command("tar", "-C", source, "-cpf", archive, "CANDIDATE-SET.json", "merged-packages")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("workflow tar command: %v: %s", err, output)
			}
			extracted, cleanup, err := extractStableCandidateArtifact(context.Background(), test.version, archive)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			for _, member := range members {
				data, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(member.name)))
				if err != nil || !bytes.Equal(data, member.body) {
					t.Fatalf("extracted %q = %q, %v", member.name, data, err)
				}
			}
		})
	}
}

func firstGNULongName(t *testing.T, data []byte) (offset, size, next int) {
	t.Helper()
	for offset+512 <= len(data) {
		block := data[offset : offset+512]
		if bytes.Equal(block, make([]byte, 512)) {
			break
		}
		parsed, err := strconv.ParseInt(strings.Trim(string(block[124:136]), " \x00"), 8, 64)
		if err != nil || parsed < 0 {
			t.Fatalf("invalid generated tar member size at %d: %v", offset, err)
		}
		size = int(parsed)
		next = offset + 512 + (size+511)/512*512
		if block[156] == tar.TypeGNULongName {
			return offset, size, next
		}
		offset = next
	}
	t.Fatal("generated GNU tar did not contain a long-name header")
	return 0, 0, 0
}

func TestExtractStableCandidateArtifactRejectsMalformedGNULongNames(t *testing.T) {
	version := "v" + strings.Repeat("9", 123) + ".2.3"
	archive := writeCandidateTar(t, candidateTarMembersForVersion(t, version, tar.FormatGNU))
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func([]byte) []byte
		want   string
	}{
		{"unknown path", func(data []byte) []byte {
			offset, _, _ := firstGNULongName(t, data)
			data[offset+512] = 'x'
			return data
		}, "not one expected package file"},
		{"interior NUL", func(data []byte) []byte {
			offset, _, _ := firstGNULongName(t, data)
			data[offset+512+10] = 0
			return data
		}, "not one terminated path"},
		{"missing terminator", func(data []byte) []byte {
			offset, size, _ := firstGNULongName(t, data)
			data[offset+512+size-1] = 'x'
			return data
		}, "not one terminated path"},
		{"oversized extension", func(data []byte) []byte {
			offset, _, _ := firstGNULongName(t, data)
			copy(data[offset+124:offset+136], []byte("00000001000\x00"))
			return data
		}, "invalid GNU long-name header"},
		{"double extension", func(data []byte) []byte {
			offset, _, next := firstGNULongName(t, data)
			result := append([]byte(nil), data[:next]...)
			result = append(result, data[offset:next]...)
			return append(result, data[next:]...)
		}, "invalid GNU long-name header"},
		{"dangling extension", func(data []byte) []byte {
			_, _, next := firstGNULongName(t, data)
			return append(append([]byte(nil), data[:next]...), make([]byte, 1024)...)
		}, "dangling GNU long-name header"},
		{"long link extension", func(data []byte) []byte {
			offset, _, _ := firstGNULongName(t, data)
			data[offset+156] = tar.TypeGNULongLink
			return data
		}, "unsafe or duplicate member"},
		{"directory after extension", func(data []byte) []byte {
			_, _, next := firstGNULongName(t, data)
			data[next+156] = tar.TypeDir
			return data
		}, "does not match its regular file header"},
		{"raw header prefix mismatch", func(data []byte) []byte {
			_, _, next := firstGNULongName(t, data)
			data[next] = 'x'
			return data
		}, "does not match its regular file header"},
		{"duplicate long package", func(data []byte) []byte {
			offset, _, next := firstGNULongName(t, data)
			parsed, err := strconv.ParseInt(strings.Trim(string(data[next+124:next+136]), " \x00"), 8, 64)
			if err != nil {
				t.Fatal(err)
			}
			end := next + 512 + (int(parsed)+511)/512*512
			result := append([]byte(nil), data[:end]...)
			result = append(result, data[offset:end]...)
			return append(result, data[end:]...)
		}, "not one expected package file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := test.change(append([]byte(nil), original...))
			name := filepath.Join(t.TempDir(), "bad.tar")
			if err := os.WriteFile(name, data, 0o600); err != nil {
				t.Fatal(err)
			}
			root, cleanup, err := extractStableCandidateArtifact(context.Background(), version, name)
			if cleanup != nil {
				cleanup()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("malformed GNU tar accepted or wrong failure at %q: %v, want %q", root, err, test.want)
			}
		})
	}
}
