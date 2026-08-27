//go:build windows

package probe

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32WindowsTool  = syscall.NewLazyDLL("kernel32.dll")
	getWindowsDirectoryW = kernel32WindowsTool.NewProc("GetWindowsDirectoryW")
	isWow64Process2      = kernel32WindowsTool.NewProc("IsWow64Process2")
)

type windowsLazyProcedure struct {
	procedure *syscall.LazyProc
}

func (p windowsLazyProcedure) Find() error {
	if p.procedure == nil {
		return errors.New("Windows procedure is unavailable")
	}
	return p.procedure.Find()
}

func (p windowsLazyProcedure) Query(process uintptr, processMachine, nativeMachine *uint16) bool {
	if p.procedure == nil || processMachine == nil || nativeMachine == nil {
		return false
	}
	// Keep pointer-to-uintptr conversion in this direct LazyProc.Call expression.
	// syscall marks Call with uintptrescapes so both output buffers remain valid
	// even if procedure loading or the syscall grows the goroutine stack.
	succeeded, _, _ := p.procedure.Call(
		process,
		uintptr(unsafe.Pointer(processMachine)),
		uintptr(unsafe.Pointer(nativeMachine)),
	)
	return succeeded != 0
}

func (systemPlatformInfo) NativeArchitecture() (string, bool) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return "", false
	}
	return queryNativeWindowsArchitecture(windowsLazyProcedure{procedure: isWow64Process2}, uintptr(process))
}

// trustedSystemExecutable resolves Windows' real system directory through the
// kernel instead of trusting a mutable PATH or SystemRoot environment value.
func trustedSystemExecutable(base string) (string, error) {
	buffer := make([]uint16, syscall.MAX_PATH+1)
	length, _, _ := getWindowsDirectoryW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", errors.New("Windows system directory is unavailable")
	}
	root := syscall.UTF16ToString(buffer[:length])
	if !filepath.IsAbs(root) {
		return "", errors.New("Windows system directory is unavailable")
	}
	path := filepath.Join(root, "System32", base)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&os.ModeType != 0 {
		return "", errors.New("trusted Windows system query tool is unavailable")
	}
	return path, nil
}
