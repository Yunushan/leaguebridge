package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These action commits were resolved against GitHub before being accepted.
// Keeping the complete allowlist here prevents an invalid or floating action
// reference from breaking the only workflow that can produce attestations.
func TestWorkflowsUseOnlyResolvedActionPins(t *testing.T) {
	expected := map[string]string{
		"actions/checkout":              "3d3c42e5aac5ba805825da76410c181273ba90b1",
		"actions/setup-go":              "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
		"actions/upload-artifact":       "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
		"actions/download-artifact":     "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
		"actions/attest":                "1e69f48acb82d1966a394da916b4c1698aa569d6",
		"cross-platform-actions/action": "faa0c6197e94aacf1c5956460152c8380d3560a5",
		"vmactions/dragonflybsd-vm":     "7cd7c9b7f2b06e8e03d2337a9476995f3c112acf",
	}
	workflowFiles := []string{
		filepath.Join("..", "..", ".github", "workflows", "ci.yml"),
		filepath.Join("..", "..", ".github", "workflows", "evidence-freshness.yml"),
		filepath.Join("..", "..", ".github", "workflows", "release.yml"),
	}
	seen := make(map[string]bool, len(expected))
	for _, relative := range workflowFiles {
		data, err := os.ReadFile(relative)
		if err != nil {
			t.Fatal(err)
		}
		for lineNumber, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "uses:" {
				continue
			}
			reference := fields[1]
			separator := strings.LastIndexByte(reference, '@')
			if separator <= 0 || separator == len(reference)-1 {
				t.Errorf("%s:%d has an unpinned or malformed action reference %q", relative, lineNumber+1, reference)
				continue
			}
			repository := reference[:separator]
			sha := reference[separator+1:]
			want, ok := expected[repository]
			if !ok {
				t.Errorf("%s:%d uses an unapproved action %q", relative, lineNumber+1, repository)
				continue
			}
			seen[repository] = true
			if sha != want {
				t.Errorf("%s:%d pins %s to %s; want externally resolved %s", relative, lineNumber+1, repository, sha, want)
			}
		}
	}
	for repository := range expected {
		if !seen[repository] {
			t.Errorf("resolved action %s is not used by any workflow", repository)
		}
	}
}
