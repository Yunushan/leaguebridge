// Package fileinput opens bounded user-selected inputs without following
// symlinks or accepting devices, sockets, pipes, or directories.
package fileinput

import (
	"fmt"
	"os"
)

// OpenRegular opens path for reading only when it names the same regular file
// before and after the open. Unix uses O_NONBLOCK so a raced-in FIFO cannot
// hang before the post-open type check.
func OpenRegular(path string) (*os.File, error) {
	return openRegular(path, nil)
}

// openRegular contains the implementation behind OpenRegular. The hook is
// test-only and lets the package exercise pathname replacement deterministically
// between the open and final Lstat checks.
func openRegular(path string, afterOpen func()) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	file, err := openReadOnly(path)
	if err != nil {
		return nil, err
	}
	if afterOpen != nil {
		afterOpen()
	}
	after, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect opened file: %w", statErr)
	}
	// Re-check the pathname itself after opening. An attacker racing the
	// open could replace a regular pathname with a symlink to the original
	// file; an identity-only comparison would accept that redirected name.
	pathAfter, pathErr := os.Lstat(path)
	if pathErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("reinspect input path: %w", pathErr)
	}
	if !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, pathAfter) {
		_ = file.Close()
		return nil, fmt.Errorf("%s changed or is not a regular file", path)
	}
	return file, nil
}
