package fileinput

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenRegularAcceptsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := OpenRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
}

func TestOpenRegularRejectsDirectory(t *testing.T) {
	_, err := OpenRegular(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("OpenRegular(directory) = %v", err)
	}
}

func TestOpenRegularRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := OpenRegular(link)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("OpenRegular(symlink) = %v", err)
	}
}

func TestOpenRegularRejectsSymlinkedParent(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "payload"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(t.TempDir(), "redirect")
	if err := os.Symlink(target, linkParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(linkParent, "payload")
	_, err := OpenRegular(path)
	if err == nil || !strings.Contains(err.Error(), "parent") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("OpenRegular(%q) = %v; want parent-symlink rejection", path, err)
	}
}

func TestRejectSymlinkedParents(t *testing.T) {
	target := t.TempDir()
	linkParent := filepath.Join(t.TempDir(), "redirect")
	if err := os.Symlink(target, linkParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(linkParent, "missing", "payload")
	if err := RejectSymlinkedParents(path); err == nil || !strings.Contains(err.Error(), "parent") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("RejectSymlinkedParents(%q) = %v", path, err)
	}
}
