//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package probe

// systemPrivilegeInfo is deliberately conservative on targets where this
// package does not have a portable effective-UID API. None of the supported
// Linux/BSD client targets use this implementation.
type systemPrivilegeInfo struct{}

func (systemPrivilegeInfo) IsRoot() bool { return false }
