//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package fileinput

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOpenRegularRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenRegular(path)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("OpenRegular(FIFO) = %v", err)
	}
}

func TestOpenRegularRejectsPathRedirectAfterOpen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	var replacementErr error
	file, err := openRegular(path, func() {
		if removeErr := os.Remove(path); removeErr != nil {
			replacementErr = removeErr
			return
		}
		replacementErr = os.Symlink(target, path)
	})
	if replacementErr != nil {
		t.Skipf("pathname replacement unavailable: %v", replacementErr)
	}
	if file != nil {
		_ = file.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "changed or is not a regular file") {
		t.Fatalf("OpenRegular(path redirected after open) = (%v, %v)", file, err)
	}
}
