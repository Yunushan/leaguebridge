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

func TestOpenRegularFromRoot(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join("nested", "payload")
	if err := os.WriteFile(filepath.Join(directory, name), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenDirectoryRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := OpenRegularFromRoot(root, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"", ".", "..", filepath.Join("..", "payload"), filepath.Join(directory, name), "nested"} {
		if file, err := OpenRegularFromRoot(root, unsafe); err == nil {
			_ = file.Close()
			t.Errorf("accepted unsafe or non-regular path %q", unsafe)
		}
	}
	if _, err := OpenRegularFromRoot(nil, name); err == nil {
		t.Fatal("accepted nil root")
	}
	if err := os.Symlink("nested", filepath.Join(directory, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if file, err := OpenRegularFromRoot(root, filepath.Join("linked", "payload")); err == nil {
		_ = file.Close()
		t.Fatal("accepted symlinked parent within root")
	}
}

func TestOpenRegularFromRootRejectsRedirectToSameFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenDirectoryRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var replacementErr error
	file, err := openRegularFromRoot(root, "input", func() {
		if replacementErr = os.Rename(path, filepath.Join(directory, "original")); replacementErr == nil {
			replacementErr = os.Symlink("original", path)
		}
	}, nil)
	if file != nil {
		_ = file.Close()
	}
	if replacementErr != nil {
		t.Skipf("symlink replacement unavailable: %v", replacementErr)
	}
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("accepted symlink redirection to original file: %v", err)
	}
}

func TestOpenRegularFromRootRejectsChangedAncestors(t *testing.T) {
	for _, phase := range []string{"before open", "after open"} {
		for _, change := range []string{"symlink to original", "replacement with same leaf", "moved outside root"} {
			for _, depth := range []string{"ancestor", "immediate parent"} {
				t.Run(phase+"/"+change+"/"+depth, func(t *testing.T) {
					directory := t.TempDir()
					name := filepath.Join("nested", "deeper", "payload")
					if err := os.MkdirAll(filepath.Dir(filepath.Join(directory, name)), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(directory, name), []byte("original payload"), 0o600); err != nil {
						t.Fatal(err)
					}
					parentName, leafName := "nested", filepath.Join("deeper", "payload")
					if depth == "immediate parent" {
						parentName, leafName = filepath.Join("nested", "deeper"), "payload"
					}
					parentPath := filepath.Join(directory, parentName)
					movedPath := filepath.Join(directory, "moved")
					if change == "moved outside root" {
						movedPath = filepath.Join(t.TempDir(), "moved")
					}
					root, err := OpenDirectoryRoot(directory)
					if err != nil {
						t.Fatal(err)
					}
					defer root.Close()
					var replacementErr error
					replace := func() {
						if replacementErr = os.Rename(parentPath, movedPath); replacementErr != nil {
							return
						}
						switch change {
						case "symlink to original":
							// Keep the redirected leaf's inode unchanged. Checking
							// only the final file would accept this parent symlink.
							var target string
							target, replacementErr = filepath.Rel(filepath.Dir(parentPath), movedPath)
							if replacementErr == nil {
								replacementErr = os.Symlink(target, parentPath)
							}
						case "replacement with same leaf":
							if replacementErr = os.MkdirAll(filepath.Dir(filepath.Join(parentPath, leafName)), 0o700); replacementErr == nil {
								replacementErr = os.Link(filepath.Join(movedPath, leafName), filepath.Join(parentPath, leafName))
							}
						case "moved outside root":
							// A held child root still names the moved directory.
							// The original root must remain the final-open boundary.
							replacementErr = os.Symlink(movedPath, parentPath)
						}
					}
					beforeOpen, afterOpen := replace, (func())(nil)
					if phase == "after open" {
						beforeOpen, afterOpen = nil, replace
					}
					file, err := openRegularFromRoot(root, name, beforeOpen, afterOpen)
					if file != nil {
						_ = file.Close()
					}
					if replacementErr != nil {
						t.Skipf("directory replacement unavailable: %v", replacementErr)
					}
					if file != nil || err == nil || !strings.Contains(err.Error(), "root-relative parent") {
						t.Fatalf("accepted changed ancestor: file=%v, error=%v", file, err)
					}
				})
			}
		}
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

func TestNestedRootCloseDoesNotInvalidateParentRoot(t *testing.T) {
	parent, err := OpenDirectoryRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()

	child, _, err := CreateTempDirectory(parent, ".fixture-dir-", 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()

	if err := child.Mkdir("payload", 0o700); err != nil {
		t.Fatal(err)
	}
	payloadRoot, err := child.OpenRoot("payload")
	if err != nil {
		t.Fatal(err)
	}
	payloadFile, err := payloadRoot.OpenFile("file", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		payloadRoot.Close()
		t.Fatal(err)
	}
	if _, err := payloadFile.Write([]byte("payload\n")); err != nil {
		payloadFile.Close()
		payloadRoot.Close()
		t.Fatal(err)
	}
	if err := payloadFile.Close(); err != nil {
		payloadRoot.Close()
		t.Fatal(err)
	}
	if err := payloadRoot.Close(); err != nil {
		t.Fatal(err)
	}

	file, err := child.OpenFile("manifest", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("manifest\n")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := ReadRegularBoundedFromRoot(child, "manifest", 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "manifest\n" {
		t.Fatalf("manifest contents = %q; want %q", got, "manifest\n")
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
