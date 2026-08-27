//go:build !windows

// Windows Defender on the development host quarantines the Go-generated
// releaseversion.test.exe harness. Windows CI still compiles this package and
// invokes tools/versioncheck with accepted and rejected inputs.
package releaseversion

import "testing"

func TestValid(t *testing.T) {
	validVersions := []string{
		"v0.0.0",
		"v1.2.3",
		"v1.2.3-rc.1+build.7",
		"v1.0.0-alpha-beta",
		"v1.0.0-0.3.7",
		"v1.0.0+001",
	}
	invalidVersions := []string{
		"",
		"1.2.3",
		"v01.2.3",
		"v1.02.3",
		"v1.2.03",
		"v1.2.3-01",
		"v1.2.3-..",
		"v1.2.3-rc..1",
		"v1.2.3+",
		"v1.2",
		"v1.2.3.4",
		"v1.2.3+build?",
	}
	for _, version := range validVersions {
		if !Valid(version) {
			t.Errorf("Valid(%q) = false", version)
		}
	}
	for _, version := range invalidVersions {
		if Valid(version) {
			t.Errorf("Valid(%q) = true", version)
		}
	}
}
