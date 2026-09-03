//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package probe

import "os"

type systemPrivilegeInfo struct{}

func (systemPrivilegeInfo) IsRoot() bool { return os.Geteuid() == 0 }
