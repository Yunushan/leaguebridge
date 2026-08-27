//go:build !windows

package probe

import (
	"errors"
	"runtime"
)

func (systemPlatformInfo) NativeArchitecture() (string, bool) {
	return runtime.GOARCH, true
}

func trustedSystemExecutable(string) (string, error) {
	return "", errors.New("Windows system query is unavailable")
}
