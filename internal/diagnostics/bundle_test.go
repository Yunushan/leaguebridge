package diagnostics

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestWriteBundleContainsOnlyGeneratedPrivateFiles(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "support.zip")
	report := fixedReport()
	report.Checks[0].Detail = `password=do-not-share peer=10.20.30.40 home=C:\Users\Alice`

	if err := WriteBundle(destination, report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports synthesized 0666 mode bits even for a file created with
	// 0600; access there is governed by the parent directory's ACL.
	if permissions := info.Mode().Perm(); runtime.GOOS != "windows" && permissions&0o077 != 0 {
		t.Fatalf("bundle permissions are too broad: %04o", permissions)
	}
	if info.Size() > MaxBundleSize {
		t.Fatalf("bundle is too large: %d", info.Size())
	}

	reader, err := zip.OpenReader(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 2 {
		t.Fatalf("bundle has %d entries, want 2", len(reader.File))
	}
	names := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
		if !validArchiveName(file.Name) {
			t.Fatalf("unsafe archive entry %q", file.Name)
		}
		if permissions := file.Mode().Perm(); permissions&0o077 != 0 {
			t.Fatalf("entry %q permissions are too broad: %04o", file.Name, permissions)
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(io.LimitReader(entry, MaxReportSize+1))
		closeErr := entry.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		for _, leaked := range []string{"do-not-share", "10.20.30.40", "Alice"} {
			if bytes.Contains(contents, []byte(leaked)) {
				t.Fatalf("entry %q leaked %q: %s", file.Name, leaked, contents)
			}
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "README.txt,report.json" {
		t.Fatalf("unexpected archive entries: %v", names)
	}
	assertNoTemporaryBundles(t, directory)
}

func TestBuildBundleIsDeterministic(t *testing.T) {
	first, err := buildBundle(fixedReport())
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildBundle(fixedReport())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("bundle bytes changed for an identical report")
	}
}

func TestWriteBundleRejectsOverwrite(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "support.zip")
	original := []byte("keep this file")
	if err := os.WriteFile(destination, original, 0o600); err != nil {
		t.Fatal(err)
	}

	err := WriteBundle(destination, fixedReport())
	if !errors.Is(err, ErrBundleExists) {
		t.Fatalf("expected ErrBundleExists, got %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing destination changed: %q", got)
	}
	assertNoTemporaryBundles(t, directory)
}

func TestWriteBundleRejectsSymlinkedParent(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "bundle-parent-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	destination := filepath.Join(link, "support.zip")
	if err := WriteBundle(destination, fixedReport()); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("WriteBundle(%q) = %v; want parent-symlink rejection", destination, err)
	}
	if entries, err := os.ReadDir(target); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("redirected output directory was modified: %v", entries)
	}
}

func TestWriteBundleConcurrentWritersAreExclusive(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "support.zip")
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- WriteBundle(destination, fixedReport())
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var successes, existsFailures int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrBundleExists):
			existsFailures++
		default:
			t.Fatalf("unexpected concurrent writer error: %v", err)
		}
	}
	if successes != 1 || existsFailures != 1 {
		t.Fatalf("got %d successes and %d exists failures", successes, existsFailures)
	}
	assertNoTemporaryBundles(t, directory)
}

func TestWriteBundleCleansPartialPublicationFailure(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "support.zip")
	publisherSawCompleteTemp := false
	injected := errors.New("injected publication failure")
	err := writeBundle(destination, fixedReport(), func(_ *os.Root, oldPath, newPath string) error {
		info, statErr := os.Stat(oldPath)
		if statErr == nil && info.Size() > 0 && newPath == destination {
			publisherSawCompleteTemp = true
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected error, got %v", err)
	}
	if !publisherSawCompleteTemp {
		t.Fatal("publisher did not receive a complete temporary bundle")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination remains after failure: %v", err)
	}
	assertNoTemporaryBundles(t, directory)
}

func TestWriteBundleInvalidReportCreatesNothing(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "support.zip")
	report := fixedReport()
	report.Checks[0].Detail = strings.Repeat("x", MaxDetailBytes+1)
	if err := WriteBundle(destination, report); err == nil {
		t.Fatal("expected validation error")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid report created filesystem entries: %v", entries)
	}
}

func TestValidArchiveNameRejectsTraversal(t *testing.T) {
	valid := []string{"README.txt", "report.json"}
	for _, name := range valid {
		if !validArchiveName(name) {
			t.Errorf("validArchiveName(%q) = false", name)
		}
	}
	invalid := []string{
		"", ".", "..", "../report.json", "a/../report.json", "/report.json",
		`..\report.json`, `directory\report.json`, "directory/report.json", "C:/report.json",
		string([]byte{'b', 'a', 'd', 0xff}),
	}
	for _, name := range invalid {
		if validArchiveName(name) {
			t.Errorf("validArchiveName(%q) = true", name)
		}
	}
}

func TestBoundedBufferRejectsOverflowWithoutPartialWrite(t *testing.T) {
	buffer := &boundedBuffer{max: 4}
	if n, err := buffer.Write([]byte("1234")); n != 4 || err != nil {
		t.Fatalf("initial write = (%d, %v)", n, err)
	}
	if n, err := buffer.Write([]byte("5")); n != 0 || !errors.Is(err, errBundleTooBig) {
		t.Fatalf("overflow write = (%d, %v)", n, err)
	}
	if got := buffer.String(); got != "1234" {
		t.Fatalf("overflow modified buffer: %q", got)
	}
}

func assertNoTemporaryBundles(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".leaguebridge-support-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary bundles remain: %v", matches)
	}
}
