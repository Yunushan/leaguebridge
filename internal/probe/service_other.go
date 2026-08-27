//go:build !windows

package probe

import "errors"

func (systemServices) Query(name string) (registered, running bool, err error) {
	if !serviceQueryAllowed(name) {
		return false, false, errors.New("service is not allowlisted")
	}
	return false, false, errors.New("Windows service manager is unavailable")
}
