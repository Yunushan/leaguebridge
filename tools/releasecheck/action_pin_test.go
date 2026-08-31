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
		"actions/checkout":              "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
		"actions/setup-go":              "924ae3a1cded613372ab5595356fb5720e22ba16",
		"actions/upload-artifact":       "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
		"actions/download-artifact":     "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
		"actions/attest":                "59d89421af93a897026c735860bf21b6eb4f7b26",
		"cross-platform-actions/action": "24ef01df165c76df1ed2b9f9e9212e78dc2fc963",
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
