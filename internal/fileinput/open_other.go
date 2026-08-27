//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package fileinput

import "os"

func openReadOnly(path string) (*os.File, error) {
	return os.Open(path)
}
