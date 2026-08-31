//go:build !go1.25

package fileinput

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Go 1.24 introduced os.Root but not its Link, Rename, or RemoveAll methods.
// Keep the source-compatibility path available for the minimum toolchain.
// The release builder is Go 1.27 and uses the handle-backed implementation in
// root_ops_go125.go.
func rootedOperationPath(root *os.Root, name string) (string, error) {
	if root == nil {
		return "", errors.New("directory root is nil")
	}
	clean := filepath.Clean(name)
	if name == "" || filepath.IsAbs(name) || clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("root-relative path %q is unsafe", name)
	}
	return filepath.Join(root.Name(), name), nil
}

func LinkInRoot(root *os.Root, oldName, newName string) error {
	oldPath, err := rootedOperationPath(root, oldName)
	if err != nil {
		return err
	}
	newPath, err := rootedOperationPath(root, newName)
	if err != nil {
		return err
	}
	return os.Link(oldPath, newPath)
}

func RenameInRoot(root *os.Root, oldName, newName string) error {
	oldPath, err := rootedOperationPath(root, oldName)
	if err != nil {
		return err
	}
	newPath, err := rootedOperationPath(root, newName)
	if err != nil {
		return err
	}
	return os.Rename(oldPath, newPath)
}

func RemoveAllInRoot(root *os.Root, name string) error {
	path, err := rootedOperationPath(root, name)
	if err != nil {
		return err
	}
	return os.RemoveAll(path)
}
