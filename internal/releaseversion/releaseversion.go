// Package releaseversion validates v-prefixed Semantic Versions used by the
// release tooling. It deliberately has no dependency on a shell regex engine.
package releaseversion

import "strings"

// Valid reports whether value is a complete Semantic Version 2.0.0 string with
// the repository's required leading v.
func Valid(value string) bool {
	if len(value) < 2 || value[0] != 'v' {
		return false
	}
	withoutPrefix := value[1:]
	coreAndPrerelease, build, hasBuild := strings.Cut(withoutPrefix, "+")
	if hasBuild && !validIdentifiers(build, false) {
		return false
	}
	core, prerelease, hasPrerelease := strings.Cut(coreAndPrerelease, "-")
	if hasPrerelease && !validIdentifiers(prerelease, true) {
		return false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !validNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for i := 0; i < len(identifier); i++ {
			character := identifier[i]
			if character < '0' || character > '9' {
				numeric = false
			}
			if !((character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '-') {
				return false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func validNumericIdentifier(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
