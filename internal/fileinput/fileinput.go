// Package fileinput opens bounded user-selected inputs without following
// symlinks or accepting devices, sockets, pipes, or directories.
package fileinput

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RejectSymlinkedParents verifies the existing directory components above
// path. The final file or directory is checked by the caller. Missing
// components are left to the caller's subsequent filesystem operation, but
// existing ancestors are still walked so a redirecting symlink cannot hide
// above a missing component.
func RejectSymlinkedParents(path string) error {
	if path == "" {
		return errors.New("path is empty")
	}
	current := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(current)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("path parent %q is a symlink", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("path parent %q is not a directory", current)
			}
		case os.IsNotExist(err):
			// Let the final operation report a missing component while still
			// checking any existing ancestor for a redirecting symlink.
		default:
			return fmt.Errorf("inspect path parent %q: %w", current, err)
		}
		next := filepath.Dir(current)
		if next == current {
			return nil
		}
		current = next
	}
}

// OpenDirectoryRoot opens an existing, regular directory after rejecting
// symlinked parents and pins that directory for subsequent Root operations.
// A caller can therefore continue creating or publishing files even if the
// caller-visible directory path is renamed or replaced after this function
// returns.
func OpenDirectoryRoot(path string) (*os.Root, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("directory path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve directory path: %w", err)
	}
	clean := filepath.Clean(absolute)
	if err := RejectSymlinkedParents(clean); err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("inspect directory %q: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("directory %q is a symlink", clean)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("directory %q is not a directory", clean)
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return nil, fmt.Errorf("open directory %q: %w", clean, err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("inspect opened directory %q: %w", clean, err)
	}
	if !opened.IsDir() || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, fmt.Errorf("directory %q changed while opening", clean)
	}
	return root, nil
}

// CreateTempFile creates a regular, exclusive temporary file beneath a
// pinned directory root. The returned name is relative to root and contains
// only a caller-provided prefix plus cryptographic randomness.
func CreateTempFile(root *os.Root, prefix string, perm os.FileMode) (*os.File, string, error) {
	if root == nil {
		return nil, "", errors.New("directory root is nil")
	}
	if strings.TrimSpace(prefix) == "" || prefix == "." || prefix == ".." || strings.ContainsAny(prefix, `/\`) {
		return nil, "", errors.New("temporary-file prefix is unsafe")
	}
	if perm&^os.FileMode(0o777) != 0 {
		return nil, "", errors.New("temporary-file mode contains unsupported bits")
	}
	var randomBytes [16]byte
	for range 100 {
		if _, err := rand.Read(randomBytes[:]); err != nil {
			return nil, "", fmt.Errorf("generate temporary-file name: %w", err)
		}
		name := prefix + hex.EncodeToString(randomBytes[:])
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			_ = root.Remove(name)
			return nil, "", fmt.Errorf("inspect temporary file: %w", statErr)
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			_ = root.Remove(name)
			return nil, "", errors.New("created temporary file is not regular")
		}
		return file, name, nil
	}
	return nil, "", errors.New("could not create an exclusive temporary file after 100 attempts")
}

// CreateTempDirectory creates and opens a private directory beneath a pinned
// directory root. The returned name is relative to root and contains only a
// caller-provided prefix plus cryptographic randomness.
func CreateTempDirectory(root *os.Root, prefix string, perm os.FileMode) (*os.Root, string, error) {
	if root == nil {
		return nil, "", errors.New("directory root is nil")
	}
	if strings.TrimSpace(prefix) == "" || prefix == "." || prefix == ".." || strings.ContainsAny(prefix, `/\\`) {
		return nil, "", errors.New("temporary-directory prefix is unsafe")
	}
	if perm&^os.FileMode(0o777) != 0 {
		return nil, "", errors.New("temporary-directory mode contains unsupported bits")
	}
	var randomBytes [16]byte
	for range 100 {
		if _, err := rand.Read(randomBytes[:]); err != nil {
			return nil, "", fmt.Errorf("generate temporary-directory name: %w", err)
		}
		name := prefix + hex.EncodeToString(randomBytes[:])
		if err := root.Mkdir(name, perm); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return nil, "", err
		}
		created, err := root.Lstat(name)
		if err != nil {
			return nil, "", fmt.Errorf("inspect temporary directory: %w", err)
		}
		if created.Mode()&os.ModeSymlink != 0 || !created.IsDir() {
			return nil, "", errors.New("created temporary directory is not a directory")
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return nil, "", fmt.Errorf("open temporary directory: %w", err)
		}
		opened, err := child.Stat(".")
		if err != nil {
			_ = child.Close()
			return nil, "", fmt.Errorf("inspect opened temporary directory: %w", err)
		}
		if !opened.IsDir() || !os.SameFile(created, opened) {
			_ = child.Close()
			return nil, "", errors.New("temporary directory changed while opening")
		}
		return child, name, nil
	}
	return nil, "", errors.New("could not create an exclusive temporary directory after 100 attempts")
}

// EnsureDirectoryTree creates path with the requested mode while rejecting
// symlinks and non-directory components. It pins the nearest existing
// ancestor before creating missing components, keeping creation beneath the
// directory that was inspected even if the caller-visible path is renamed.
func EnsureDirectoryTree(path string, perm os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("directory path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve directory path: %w", err)
	}
	clean := filepath.Clean(absolute)
	if err := RejectSymlinkedParents(clean); err != nil {
		return err
	}

	anchor := clean
	for {
		info, statErr := os.Lstat(anchor)
		switch {
		case statErr == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("directory %q is a symlink", anchor)
			}
			if !info.IsDir() {
				return fmt.Errorf("directory %q is not a directory", anchor)
			}
			goto foundAnchor
		case os.IsNotExist(statErr):
			parent := filepath.Dir(anchor)
			if parent == anchor {
				return fmt.Errorf("cannot find an existing ancestor for %q", clean)
			}
			anchor = parent
		default:
			return fmt.Errorf("inspect directory %q: %w", anchor, statErr)
		}
	}

foundAnchor:
	root, err := OpenDirectoryRoot(anchor)
	if err != nil {
		return fmt.Errorf("open directory anchor %q: %w", anchor, err)
	}
	defer root.Close()

	relative, err := filepath.Rel(anchor, clean)
	if err != nil {
		return fmt.Errorf("relativize directory path: %w", err)
	}
	if relative == "." {
		return nil
	}
	current := ""
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("directory path %q contains an unsafe component", clean)
		}
		if current == "" {
			current = component
		} else {
			current = filepath.Join(current, component)
		}
		info, statErr := root.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("directory %q is a symlink", filepath.Join(anchor, current))
			}
			if !info.IsDir() {
				return fmt.Errorf("directory %q is not a directory", filepath.Join(anchor, current))
			}
			continue
		}
		if !os.IsNotExist(statErr) {
			return fmt.Errorf("inspect directory %q: %w", filepath.Join(anchor, current), statErr)
		}
		if mkdirErr := root.Mkdir(current, perm); mkdirErr != nil && !os.IsExist(mkdirErr) {
			return fmt.Errorf("create directory %q: %w", filepath.Join(anchor, current), mkdirErr)
		}
		created, statErr := root.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("inspect created directory %q: %w", filepath.Join(anchor, current), statErr)
		}
		if created.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("directory %q is a symlink", filepath.Join(anchor, current))
		}
		if !created.IsDir() {
			return fmt.Errorf("directory %q is not a directory", filepath.Join(anchor, current))
		}
	}
	return nil
}

// OpenRegular opens path for reading only when it names the same regular file
// before and after the open. Unix uses O_NONBLOCK so a raced-in FIFO cannot
// hang before the post-open type check.
func OpenRegular(path string) (*os.File, error) {
	return openRegular(path, nil)
}

// OpenRegularFromRoot opens a regular file beneath a held directory root.
// Every path component must be non-symlinked, and the final file must keep its
// identity across opening. Unix opens are nonblocking so a raced-in FIFO is
// rejected before it can wait for a writer.
func OpenRegularFromRoot(root *os.Root, name string) (*os.File, error) {
	return openRegularFromRoot(root, name, nil)
}

// beforeOpen is test-only and permits deterministic replacement after path
// inspection but before opening. Production callers always pass nil.
func openRegularFromRoot(root *os.Root, name string, beforeOpen func()) (*os.File, error) {
	if root == nil {
		return nil, errors.New("directory root is nil")
	}
	clean := filepath.Clean(name)
	if name == "" || filepath.IsAbs(name) || filepath.VolumeName(name) != "" || clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("root-relative file path %q is unsafe", name)
	}
	components := strings.Split(clean, string(filepath.Separator))
	current := ""
	var before os.FileInfo
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("root-relative path %q is a symlink", current)
		}
		if index < len(components)-1 {
			if !info.IsDir() {
				return nil, fmt.Errorf("root-relative parent %q is not a directory", current)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("root-relative path %q is not a regular file", current)
		}
		before = info
	}
	if beforeOpen != nil {
		beforeOpen()
	}
	file, err := openReadOnlyFromRoot(root, clean)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect opened rooted file: %w", err)
	}
	pathAfter, err := root.Lstat(clean)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("reinspect rooted input path: %w", err)
	}
	if !opened.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, pathAfter) {
		_ = file.Close()
		return nil, fmt.Errorf("root-relative file %q changed or is not a regular file", clean)
	}
	return file, nil
}

// ReadRegularBoundedFromRoot reads one regular, non-symlink file beneath a
// pinned directory root. The name must identify a single child of root; the
// file identity and size are checked before and after the read.
func ReadRegularBoundedFromRoot(root *os.Root, name string, maximum int64) ([]byte, error) {
	if root == nil {
		return nil, errors.New("directory root is nil")
	}
	if maximum < 0 {
		return nil, errors.New("file size limit is negative")
	}
	if strings.TrimSpace(name) == "" || name == "." || name == ".." || filepath.IsAbs(name) || filepath.VolumeName(name) != "" || filepath.Base(name) != name || filepath.Clean(name) != name || strings.ContainsAny(name, `/\`+"\x00\r\n") {
		return nil, fmt.Errorf("root-relative file name %q is unsafe", name)
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("not a regular, non-symlink file")
	}
	if before.Size() > maximum {
		return nil, fmt.Errorf("size %d exceeds limit %d", before.Size(), maximum)
	}
	file, err := OpenRegularFromRoot(root, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || opened.Size() > maximum || !os.SameFile(before, opened) {
		return nil, errors.New("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("content exceeds limit %d", maximum)
	}
	opened, err = file.Stat()
	if err != nil {
		return nil, err
	}
	finalPath, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || finalPath.Mode()&os.ModeSymlink != 0 || !finalPath.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, finalPath) || opened.Size() != int64(len(data)) || finalPath.Size() != int64(len(data)) {
		return nil, errors.New("file changed while reading")
	}
	return data, nil
}

// openRegular contains the implementation behind OpenRegular. The hook is
// test-only and lets the package exercise pathname replacement deterministically
// between the open and final Lstat checks.
func openRegular(path string, afterOpen func()) (*os.File, error) {
	if err := RejectSymlinkedParents(path); err != nil {
		return nil, err
	}
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
