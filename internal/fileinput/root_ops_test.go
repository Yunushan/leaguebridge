package fileinput

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTestRoot(t *testing.T) (*os.Root, string) {
	t.Helper()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, directory
}

func TestRootOperationsRejectNilRoot(t *testing.T) {
	for name, err := range map[string]error{
		"link":       LinkInRoot(nil, "a", "b"),
		"rename":     RenameInRoot(nil, "a", "b"),
		"remove all": RemoveAllInRoot(nil, "a"),
	} {
		if err == nil || !strings.Contains(err.Error(), "root is nil") {
			t.Errorf("%s error = %v, want nil-root rejection", name, err)
		}
	}
}

func TestRootOperationsStayBeneathRoot(t *testing.T) {
	root, directory := openTestRoot(t)
	if err := root.WriteFile("source.txt", []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := LinkInRoot(root, "source.txt", "linked.txt"); err != nil {
		t.Fatalf("LinkInRoot() = %v", err)
	}
	source, err := root.Stat("source.txt")
	if err != nil {
		t.Fatal(err)
	}
	linked, err := root.Stat("linked.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(source, linked) {
		t.Fatal("LinkInRoot did not create a hard link to the same file")
	}

	if err := RenameInRoot(root, "linked.txt", "renamed.txt"); err != nil {
		t.Fatalf("RenameInRoot() = %v", err)
	}
	if _, err := root.Stat("linked.txt"); !os.IsNotExist(err) {
		t.Fatalf("renamed source still exists: %v", err)
	}
	if data, err := root.ReadFile("renamed.txt"); err != nil || string(data) != "payload" {
		t.Fatalf("renamed file = %q, %v", data, err)
	}

	if err := root.MkdirAll(filepath.Join("tree", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(filepath.Join("tree", "nested", "leaf.txt"), []byte("leaf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAllInRoot(root, "tree"); err != nil {
		t.Fatalf("RemoveAllInRoot() = %v", err)
	}
	if _, err := root.Stat("tree"); !os.IsNotExist(err) {
		t.Fatalf("removed tree still exists: %v", err)
	}

	outside := filepath.Join(filepath.Dir(directory), filepath.Base(directory)+"-outside")
	if err := LinkInRoot(root, "source.txt", filepath.Join("..", filepath.Base(outside))); err == nil {
		t.Fatal("LinkInRoot created a link outside the root")
	}
	if err := RenameInRoot(root, "source.txt", filepath.Join("..", filepath.Base(outside))); err == nil {
		t.Fatal("RenameInRoot moved a file outside the root")
	}
	if err := RemoveAllInRoot(root, filepath.Join("..", filepath.Base(directory))); err == nil {
		t.Fatal("RemoveAllInRoot removed a path outside the root")
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Fatalf("escape target exists: %v", err)
	}
	if _, err := root.Stat("source.txt"); err != nil {
		t.Fatalf("source was moved or removed by a rejected escape: %v", err)
	}
}

func TestCreateTempFileValidatesInputsAndCreatesRegularFile(t *testing.T) {
	if _, _, err := CreateTempFile(nil, "tmp-", 0o600); err == nil || !strings.Contains(err.Error(), "root is nil") {
		t.Fatalf("nil root error = %v", err)
	}
	root, _ := openTestRoot(t)
	for _, prefix := range []string{"", "  ", ".", "..", "a/b", `a\b`} {
		if _, _, err := CreateTempFile(root, prefix, 0o600); err == nil || !strings.Contains(err.Error(), "prefix is unsafe") {
			t.Errorf("prefix %q error = %v", prefix, err)
		}
	}
	if _, _, err := CreateTempFile(root, "tmp-", os.ModeSetuid|0o600); err == nil || !strings.Contains(err.Error(), "unsupported bits") {
		t.Fatalf("mode error = %v", err)
	}

	file, name, err := CreateTempFile(root, "tmp-", 0o600)
	if err != nil {
		t.Fatalf("CreateTempFile() = %v", err)
	}
	defer file.Close()
	if !strings.HasPrefix(name, "tmp-") || len(name) != len("tmp-")+32 {
		t.Fatalf("temporary name = %q", name)
	}
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("temporary file = %+v, %v", info, err)
	}
}

func TestCreateTempDirectoryValidatesInputsAndOpensCreatedDirectory(t *testing.T) {
	if _, _, err := CreateTempDirectory(nil, "dir-", 0o700); err == nil || !strings.Contains(err.Error(), "root is nil") {
		t.Fatalf("nil root error = %v", err)
	}
	root, _ := openTestRoot(t)
	for _, prefix := range []string{"", ".", "..", "a/b", `a\b`} {
		if _, _, err := CreateTempDirectory(root, prefix, 0o700); err == nil || !strings.Contains(err.Error(), "prefix is unsafe") {
			t.Errorf("prefix %q error = %v", prefix, err)
		}
	}
	if _, _, err := CreateTempDirectory(root, "dir-", os.ModeSticky|0o700); err == nil || !strings.Contains(err.Error(), "unsupported bits") {
		t.Fatalf("mode error = %v", err)
	}

	child, name, err := CreateTempDirectory(root, "dir-", 0o700)
	if err != nil {
		t.Fatalf("CreateTempDirectory() = %v", err)
	}
	defer child.Close()
	if err := child.WriteFile("inside.txt", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat(filepath.Join(name, "inside.txt")); err != nil {
		t.Fatalf("child root does not refer to the created directory: %v", err)
	}
}

func TestEnsureDirectoryTreeCreatesNestedDirectoriesAndRejectsFiles(t *testing.T) {
	if err := EnsureDirectoryTree("  ", 0o700); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty path error = %v", err)
	}
	base := t.TempDir()
	target := filepath.Join(base, "one", "two", "three")
	if err := EnsureDirectoryTree(target, 0o700); err != nil {
		t.Fatalf("EnsureDirectoryTree() = %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("created tree = %+v, %v", info, err)
	}
	if err := EnsureDirectoryTree(target, 0o700); err != nil {
		t.Fatalf("existing tree was rejected: %v", err)
	}

	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDirectoryTree(file, 0o700); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file anchor error = %v", err)
	}
	if err := EnsureDirectoryTree(filepath.Join(file, "child"), 0o700); err == nil {
		t.Fatal("EnsureDirectoryTree created a directory beneath a regular file")
	}
}
