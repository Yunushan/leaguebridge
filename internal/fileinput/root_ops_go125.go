//go:build go1.25

package fileinput

import (
	"errors"
	"os"
)

// LinkInRoot creates a hard link between two paths beneath root. Go 1.25 and
// newer provide the operation directly on os.Root, so the directory handle
// remains the authority even if its visible pathname changes.
func LinkInRoot(root *os.Root, oldName, newName string) error {
	if root == nil {
		return errors.New("directory root is nil")
	}
	return root.Link(oldName, newName)
}

// RenameInRoot renames two paths beneath root without resolving the root via
// its caller-visible pathname.
func RenameInRoot(root *os.Root, oldName, newName string) error {
	if root == nil {
		return errors.New("directory root is nil")
	}
	return root.Rename(oldName, newName)
}

// RemoveAllInRoot removes a path beneath root without allowing traversal out
// of the pinned directory tree.
func RemoveAllInRoot(root *os.Root, name string) error {
	if root == nil {
		return errors.New("directory root is nil")
	}
	return root.RemoveAll(name)
}
