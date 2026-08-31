package vendorintegrity

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyRepositoryVendorLock(t *testing.T) {
	if err := Verify(repositoryRoot(t)); err != nil {
		t.Fatalf("Verify(repository) error = %v", err)
	}
}

func TestStaticAggregateLock(t *testing.T) {
	if digest := lockDigest(expectedMetadata, expectedFiles); digest != ExpectedLockSHA256 {
		t.Fatalf("static aggregate digest = %s; want %s", digest, ExpectedLockSHA256)
	}
}

func TestVendoredModeRejectsSymlink(t *testing.T) {
	err := rejectVendoredSymlink("dependency/link", os.ModeSymlink|0o777)
	if err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Fatalf("rejectVendoredSymlink error = %v", err)
	}
	if err := rejectVendoredSymlink("dependency/file", 0o644); err != nil {
		t.Fatalf("regular mode rejected: %v", err)
	}
}

func TestVerifyRejectsVendorAndMetadataMutations(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*testing.T, string)
		wantError string
	}{
		{
			name: "vendored content",
			mutate: func(t *testing.T, root string) {
				name := filepath.Join(root, "vendor", "filippo.io", "edwards25519", "doc.go")
				body := mustRead(t, name)
				body[0] ^= 1
				mustWrite(t, name, body)
			},
			wantError: `vendored file "filippo.io/edwards25519/doc.go" has SHA-256`,
		},
		{
			name: "missing file",
			mutate: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "vendor", "filippo.io", "edwards25519", "tables.go")); err != nil {
					t.Fatal(err)
				}
			},
			wantError: `missing vendored file "filippo.io/edwards25519/tables.go"`,
		},
		{
			name: "extra file",
			mutate: func(t *testing.T, root string) {
				mustWrite(t, filepath.Join(root, "vendor", "unexpected.txt"), []byte("unexpected"))
			},
			wantError: `unexpected vendored file "unexpected.txt"`,
		},
		{
			name: "extra empty directory",
			mutate: func(t *testing.T, root string) {
				if err := os.Mkdir(filepath.Join(root, "vendor", "unexpected"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantError: `unexpected vendored directory "unexpected"`,
		},
		{
			name: "wrong vendor path",
			mutate: func(t *testing.T, root string) {
				if err := os.Rename(filepath.Join(root, "vendor", "filippo.io"), filepath.Join(root, "vendor", "filippo.invalid")); err != nil {
					t.Fatal(err)
				}
			},
			wantError: `inspect directory "vendor/filippo.io"`,
		},
		{
			name: "wrong required version",
			mutate: func(t *testing.T, root string) {
				replaceInFile(t, filepath.Join(root, "go.mod"), ModuleVersion, "v1.2.1")
			},
			wantError: "want v1.2.0",
		},
		{
			name: "replacement directive",
			mutate: func(t *testing.T, root string) {
				name := filepath.Join(root, "go.mod")
				body := append(mustRead(t, name), []byte("replace "+ModulePath+" => ./local-edwards\n")...)
				mustWrite(t, name, body)
			},
			wantError: "replace directive is not permitted",
		},
		{
			name: "wrong upstream sum",
			mutate: func(t *testing.T, root string) {
				replaceInFile(t, filepath.Join(root, "go.sum"), ModuleSum, "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			},
			wantError: "module sum for filippo.io/edwards25519 v1.2.0",
		},
		{
			name: "wrong module metadata version",
			mutate: func(t *testing.T, root string) {
				replaceInFile(t, filepath.Join(root, "vendor", "modules.txt"), "# "+ModulePath+" "+ModuleVersion, "# "+ModulePath+" v1.2.1")
			},
			wantError: "module header",
		},
		{
			name: "wrong module package inventory",
			mutate: func(t *testing.T, root string) {
				replaceInFile(t, filepath.Join(root, "vendor", "modules.txt"), ModulePath+"/field", ModulePath+"/fields")
			},
			wantError: "metadata stanza line",
		},
		{
			name: "unrelated module metadata change",
			mutate: func(t *testing.T, root string) {
				replaceInFile(t, filepath.Join(root, "go.mod"), "golang.org/x/text v0.14.0", "golang.org/x/text v0.14.1")
			},
			wantError: `metadata file "go.mod" has SHA-256`,
		},
		{
			name: "missing bundled dependency license notice",
			mutate: func(t *testing.T, root string) {
				replaceInFile(t, filepath.Join(root, "LICENSE"), thirdPartyMarker, "Third-party notice removed\n\n")
			},
			wantError: "exact third-party license markers; want 1",
		},
		{
			name: "modified bundled dependency license text",
			mutate: func(t *testing.T, root string) {
				replaceInFile(t, filepath.Join(root, "LICENSE"), "Copyright (c) 2009 The Go Authors.", "Copyright (c) 2010 The Go Authors.")
			},
			wantError: "does not exactly match the locked upstream LICENSE",
		},
		{
			name: "file replaced by directory",
			mutate: func(t *testing.T, root string) {
				name := filepath.Join(root, "vendor", "filippo.io", "edwards25519", "tables.go")
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "is a directory; want a regular file",
		},
		{
			name: "delete locked gitmodules data",
			mutate: func(t *testing.T, root string) {
				name := filepath.Join(root, "vendor", "github.com", "santhosh-tekuri", "jsonschema", "v6", ".gitmodules")
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			},
			wantError: `missing vendored file "github.com/santhosh-tekuri/jsonschema/v6/.gitmodules"`,
		},
		{
			name: "mutate locked gitmodules data",
			mutate: func(t *testing.T, root string) {
				name := filepath.Join(root, "vendor", "github.com", "santhosh-tekuri", "jsonschema", "v6", ".gitmodules")
				body := mustRead(t, name)
				body[0] ^= 1
				mustWrite(t, name, body)
			},
			wantError: `vendored file "github.com/santhosh-tekuri/jsonschema/v6/.gitmodules" has SHA-256`,
		},
		{
			name: "replace locked gitmodules with directory",
			mutate: func(t *testing.T, root string) {
				name := filepath.Join(root, "vendor", "github.com", "santhosh-tekuri", "jsonschema", "v6", ".gitmodules")
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantError: `vendored path "github.com/santhosh-tekuri/jsonschema/v6/.gitmodules" is a directory; want a regular file`,
		},
		{
			name: "add second gitmodules file",
			mutate: func(t *testing.T, root string) {
				mustWrite(t, filepath.Join(root, "vendor", "filippo.io", ".gitmodules"), []byte("[submodule \"unexpected\"]\n"))
			},
			wantError: `unexpected vendored file "filippo.io/.gitmodules"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyLockedSnapshot(t)
			test.mutate(t, root)
			err := Verify(root)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Verify error = %v; want substring %q", err, test.wantError)
			}
		})
	}
}

func TestVerifyRejectsSymlinkedVendorFile(t *testing.T) {
	root := copyLockedSnapshot(t)
	name := filepath.Join(root, "vendor", "filippo.io", "edwards25519", "README.md")
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("doc.go", name); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	err := Verify(root)
	if err == nil || !strings.Contains(err.Error(), `vendored path "filippo.io/edwards25519/README.md" is a symbolic link`) {
		t.Fatalf("Verify error = %v", err)
	}
}

func TestVerifyRejectsSymlinkedSnapshotRoot(t *testing.T) {
	root := copyLockedSnapshot(t)
	link := filepath.Join(t.TempDir(), "snapshot-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	err := Verify(link)
	if err == nil || !strings.Contains(err.Error(), "snapshot root is a symbolic link") {
		t.Fatalf("Verify error = %v", err)
	}
}

func TestVerifyRejectsSymlinkedSnapshotRootParent(t *testing.T) {
	root := copyLockedSnapshot(t)
	parent := t.TempDir()
	link := filepath.Join(parent, "snapshot-parent-link")
	if err := os.Symlink(filepath.Dir(root), link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	redirected := filepath.Join(link, filepath.Base(root))
	err := Verify(redirected)
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("Verify accepted symlinked snapshot root parent: %v", err)
	}
}

func copyLockedSnapshot(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	destination := t.TempDir()
	for _, name := range []string{"LICENSE", "go.mod", "go.sum"} {
		mustWrite(t, filepath.Join(destination, name), mustRead(t, filepath.Join(source, name)))
	}
	sourceVendor := filepath.Join(source, "vendor")
	err := filepath.WalkDir(sourceVendor, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errorsForTest("source vendor tree contains symbolic link %q", relative)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return errorsForTest("source vendor path %q is not regular", relative)
		}
		return os.WriteFile(target, mustRead(t, name), 0o644)
	})
	if err != nil {
		t.Fatalf("copy locked snapshot: %v", err)
	}
	return destination
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustWrite(t *testing.T, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(name, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func replaceInFile(t *testing.T, name, old, replacement string) {
	t.Helper()
	body := string(mustRead(t, name))
	if !strings.Contains(body, old) {
		t.Fatalf("%q does not contain %q", name, old)
	}
	mustWrite(t, name, []byte(strings.Replace(body, old, replacement, 1)))
}

func errorsForTest(format string, arguments ...any) error {
	return fmt.Errorf(format, arguments...)
}
