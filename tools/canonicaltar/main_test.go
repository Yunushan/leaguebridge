package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const testEpoch = int64(1787702401)

func TestCreateArchiveIsCanonicalAndReproducible(t *testing.T) {
	root := makePayload(t)
	first := filepath.Join(t.TempDir(), "first.tar.gz")
	second := filepath.Join(t.TempDir(), "second.tar.gz")
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
		t.Fatal("canonical tar.gz changed between identical builds")
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(firstData))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	if !gzipReader.ModTime.IsZero() || gzipReader.Name != "" || gzipReader.Comment != "" || len(gzipReader.Extra) != 0 || gzipReader.OS != 255 {
		t.Fatalf("non-canonical gzip header: %+v", gzipReader.Header)
	}
	archive := tar.NewReader(gzipReader)
	for index, member := range canonicalMembers {
		header, err := archive.Next()
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != member.name || header.FileInfo().Mode() != member.mode || header.Format != tar.FormatUSTAR || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || header.ModTime.Unix() != testEpoch {
			t.Fatalf("member[%d] is not canonical: %+v", index, header)
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "content for "+member.name {
			t.Fatalf("member %q body = %q", member.name, body)
		}
	}
	if header, err := archive.Next(); err != io.EOF || header != nil {
		t.Fatalf("unexpected trailing tar member: %+v, %v", header, err)
	}
}

func TestCreateArchiveRefusesOverwriteAndInvalidEpoch(t *testing.T) {
	root := makePayload(t)
	output := filepath.Join(t.TempDir(), "release.tar.gz")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createArchive(root, output, testEpoch); err == nil {
		t.Fatal("createArchive overwrote an existing output")
	}
	for _, value := range []string{"", "-1", "+1", "0", "4354819200"} {
		if _, err := parseEpoch(value); err == nil {
			t.Fatalf("parseEpoch(%q) unexpectedly succeeded", value)
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
