package fileinput

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureDirectoryTreeCreatesMissingComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper")
	if err := EnsureDirectoryTree(path, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("EnsureDirectoryTree(%q) created a non-directory", path)
	}
	if err := EnsureDirectoryTree(path, 0o700); err != nil {
		t.Fatalf("EnsureDirectoryTree() did not accept its existing directory: %v", err)
	}
}

func TestEnsureDirectoryTreeRejectsNonDirectoryParent(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := EnsureDirectoryTree(filepath.Join(blocker, "child"), 0o700)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("EnsureDirectoryTree() error = %v; want non-directory rejection", err)
	}
}

func TestOpenDirectoryRootAndCreateTempFile(t *testing.T) {
	directory := t.TempDir()
	root, err := OpenDirectoryRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	file, name, err := CreateTempFile(root, ".fixture-", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" || strings.ContainsAny(name, `/\`) {
		t.Fatalf("temporary name = %q; want one relative name", name)
	}
	if _, err := file.Write([]byte("payload")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("temporary file mode = %v; want regular file", info.Mode())
	}
	if err := root.Remove(name); err != nil {
		t.Fatal(err)
	}
}

func TestReadRegularBoundedFromRoot(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "payload")
	contents := []byte("root-bound payload\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenDirectoryRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := ReadRegularBoundedFromRoot(root, "payload", int64(len(contents)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(contents) {
		t.Fatalf("ReadRegularBoundedFromRoot() = %q; want %q", got, contents)
	}
	for _, name := range []string{"", ".", "..", "../payload", "nested/payload", `nested\payload`} {
		if _, err := ReadRegularBoundedFromRoot(root, name, 100); err == nil {
			t.Errorf("ReadRegularBoundedFromRoot() accepted unsafe name %q", name)
		}
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ReadRegularBoundedFromRoot(root, "link", 100); err == nil || !strings.Contains(err.Error(), "not a regular") {
		t.Fatalf("ReadRegularBoundedFromRoot() symlink error = %v", err)
	}
}

func TestCreateTempDirectory(t *testing.T) {
	parent, err := OpenDirectoryRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()

	child, name, err := CreateTempDirectory(parent, ".fixture-dir-", 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if name == "" || strings.ContainsAny(name, `/\`) {
		t.Fatalf("temporary directory name = %q; want one relative name", name)
	}
	info, err := parent.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("temporary directory mode = %v; want directory", info.Mode())
	}
	if err := child.Mkdir("nested", 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDirectoryRootRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "directory-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if _, err := OpenDirectoryRoot(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("OpenDirectoryRoot(%q) error = %v; want symlink rejection", link, err)
	}
}

func TestCreateTempFileRejectsUnsafePrefix(t *testing.T) {
	root, err := OpenDirectoryRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, prefix := range []string{"", ".", "..", "../escape", `..\escape`} {
		if _, _, err := CreateTempFile(root, prefix, 0o600); err == nil {
			t.Errorf("CreateTempFile() accepted unsafe prefix %q", prefix)
		}
	}
}

func TestCreateTempDirectoryRejectsUnsafePrefix(t *testing.T) {
	root, err := OpenDirectoryRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, prefix := range []string{"", ".", "..", "../escape", `..\escape`} {
		if _, _, err := CreateTempDirectory(root, prefix, 0o700); err == nil {
			t.Errorf("CreateTempDirectory() accepted unsafe prefix %q", prefix)
		}
	}
}
