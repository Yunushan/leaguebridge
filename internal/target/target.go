// Package target defines the canonical Linux/BSD client and release target
// contract. Keeping this list in one package prevents the launcher, evidence
// validators, release tooling, and documentation generators from drifting.
package target

import "strings"

// Target is a canonical Go target supported by the LeagueBridge client and
// portable release archives.
type Target struct {
	GOOS   string
	GOARCH string
}

// Ordered returns the production target order used by release archives and
// attestations. DragonFly remains x86-64-only because its supported hosted
// guest/runtime path is x86-64; the other supported Unix targets cover amd64
// and arm64.
func Ordered() []Target {
	return []Target{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
		{GOOS: "freebsd", GOARCH: "amd64"},
		{GOOS: "freebsd", GOARCH: "arm64"},
		{GOOS: "openbsd", GOARCH: "amd64"},
		{GOOS: "openbsd", GOARCH: "arm64"},
		{GOOS: "netbsd", GOARCH: "amd64"},
		{GOOS: "netbsd", GOARCH: "arm64"},
		{GOOS: "dragonfly", GOARCH: "amd64"},
	}
}

// IsSupported reports whether goos/goarch is a canonical client/release
// target. Inputs are normalized only for harmless case and common machine
// aliases; callers still receive canonical values from their own data model.
func IsSupported(goos, goarch string) bool {
	goos = strings.ToLower(strings.TrimSpace(goos))
	goarch = NormalizeArchitecture(goarch)
	for _, candidate := range Ordered() {
		if candidate.GOOS == goos && candidate.GOARCH == goarch {
			return true
		}
	}
	return false
}

// NormalizeArchitecture maps common uname/evidence spellings to Go's
// canonical architecture names.
func NormalizeArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86_64", "x64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

// Architectures returns the allowed architectures for a canonical GOOS in
// deterministic order. An unknown GOOS returns nil.
func Architectures(goos string) []string {
	goos = strings.ToLower(strings.TrimSpace(goos))
	var result []string
	for _, candidate := range Ordered() {
		if candidate.GOOS == goos {
			result = append(result, candidate.GOARCH)
		}
	}
	return result
}

// EvidencePlatform converts a Go operating-system name to the evidence
// platform spelling used by validation-evidence records.
func EvidencePlatform(goos string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "linux", "freebsd", "openbsd", "netbsd":
		return strings.ToLower(strings.TrimSpace(goos)), true
	case "dragonfly":
		return "dragonflybsd", true
	default:
		return "", false
	}
}

// GOOS returns the canonical Go operating-system name for an evidence
// platform. It is the inverse of EvidencePlatform for supported client
// platforms.
func GOOS(platform string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "linux", "freebsd", "openbsd", "netbsd":
		return strings.ToLower(strings.TrimSpace(platform)), true
	case "dragonfly", "dragonflybsd":
		return "dragonfly", true
	default:
		return "", false
	}
}

// IsSupportedEvidencePlatform reports whether a platform/architecture pair
// is valid for a Linux/BSD client or session evidence record.
func IsSupportedEvidencePlatform(platform, architecture string) bool {
	goos, ok := GOOS(platform)
	canonicalArchitecture := strings.ToLower(strings.TrimSpace(architecture))
	return ok && (canonicalArchitecture == "amd64" || canonicalArchitecture == "arm64") && IsSupported(goos, canonicalArchitecture)
}
