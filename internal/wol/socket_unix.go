//go:build !windows

package wol

import "syscall"

func setBroadcastSocket(raw syscall.RawConn) error {
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}
	return socketErr
}
