//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package fileinput

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestOpenRegularFromRootRejectsRacedFIFOWithoutBlocking(t *testing.T) {
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

	type result struct {
		openErr        error
		replacementErr error
	}
	finished := make(chan result, 1)
	go func() {
		var replacementErr error
		file, openErr := openRegularFromRoot(root, "input", func() {
			if replacementErr = os.Remove(path); replacementErr == nil {
				replacementErr = syscall.Mkfifo(path, 0o600)
			}
		})
		if file != nil {
			_ = file.Close()
		}
		finished <- result{openErr: openErr, replacementErr: replacementErr}
	}()

	select {
	case got := <-finished:
		if got.replacementErr != nil {
			t.Fatalf("replace inspected file with FIFO: %v", got.replacementErr)
		}
		if got.openErr == nil || !strings.Contains(got.openErr.Error(), "not a regular file") {
			t.Fatalf("open rooted input replaced by FIFO = %v", got.openErr)
		}
	case <-time.After(2 * time.Second):
		// If a regression reintroduces a blocking open, release its reader so
		// the test can fail without leaving a blocked goroutine or test process.
		writer, releaseErr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if releaseErr == nil {
			_ = writer.Close()
			select {
			case <-finished:
			case <-time.After(time.Second):
			}
		}
		t.Fatalf("rooted input open blocked on raced FIFO; release error: %v", releaseErr)
	}
}
