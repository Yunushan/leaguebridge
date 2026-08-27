//go:build windows

package probe

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	serviceControlManagerConnect = 0x0001
	serviceQueryStatusAccess     = 0x0004
	windowsServiceRunning        = 0x00000004
	windowsServiceDoesNotExist   = syscall.Errno(1060)
)

var (
	serviceAdvapi32           = syscall.NewLazyDLL("advapi32.dll")
	openServiceControlManager = serviceAdvapi32.NewProc("OpenSCManagerW")
	openService               = serviceAdvapi32.NewProc("OpenServiceW")
	queryServiceStatus        = serviceAdvapi32.NewProc("QueryServiceStatus")
	closeServiceHandle        = serviceAdvapi32.NewProc("CloseServiceHandle")
)

type windowsServiceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

func (systemServices) Query(name string) (registered, running bool, err error) {
	if !serviceQueryAllowed(name) {
		return false, false, errors.New("service is not allowlisted")
	}
	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, false, errors.New("service name is invalid")
	}

	manager, _, _ := openServiceControlManager.Call(0, 0, serviceControlManagerConnect)
	if manager == 0 {
		return false, false, errors.New("Windows service manager is unavailable")
	}
	defer closeServiceHandle.Call(manager)

	service, _, openErr := openService.Call(manager, uintptr(unsafe.Pointer(namePointer)), serviceQueryStatusAccess)
	if service == 0 {
		if errno, ok := openErr.(syscall.Errno); ok && errno == windowsServiceDoesNotExist {
			return false, false, nil
		}
		return false, false, errors.New("Windows service status is unavailable")
	}
	defer closeServiceHandle.Call(service)

	var status windowsServiceStatus
	success, _, _ := queryServiceStatus.Call(service, uintptr(unsafe.Pointer(&status)))
	if success == 0 {
		return true, false, errors.New("Windows service running state is unavailable")
	}
	return true, status.currentState == windowsServiceRunning, nil
}
