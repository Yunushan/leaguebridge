package packageinfo

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"
const testTree = "89abcdef0123456789abcdef0123456789abcdef"

func TestBuildBindsEveryUnixPayloadAndTarget(t *testing.T) {
	bodies := unixBodies()
	manifest, err := Build("v1.2.3", "freebsd", "amd64", 1787702400, testCommit, testTree, "go1.27.0", bodies)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Target.RequiredKernel != "FreeBSD" || manifest.Artifact.Filename != "leaguebridge_1.2.3_freebsd_amd64.tar.gz" {
		t.Fatalf("manifest is not target-bound: %+v", manifest)
	}
	if manifest.ValidationScope != "artifact-integrity-only" {
		t.Fatalf("validation scope = %q", manifest.ValidationScope)
	}
	if manifest.Provenance.SourceTree != testTree || manifest.Provenance.BuildEnvironment.GOAMD64 != "v1" || manifest.Provenance.BuildEnvironment.GOFIPS140 != "off" || manifest.Provenance.BuildEnvironment.GOCACHEPROG != "" || manifest.Provenance.BuildEnvironment.GOExtlink != "0" || manifest.Provenance.BuildEnvironment.GONOPROXY != "" || manifest.Provenance.BuildEnvironment.GONOSUMDB != "" || manifest.Provenance.BuildEnvironment.GOVCS != "*:off" {
		t.Fatalf("manifest does not bind the source tree and amd64 build environment: %+v", manifest.Provenance)
	}
	if len(manifest.Payload) != len(bodies) {
		t.Fatalf("payload entries = %d; want %d", len(manifest.Payload), len(bodies))
	}
	wantOrder := []string{"LICENSE", "README.md", "SBOM.spdx.json", "install.sh", "leaguebridge", "linux-bsd-client-smoke.sh", "linux-bsd-remote-session.sh", "uninstall.sh"}
	for _, entry := range manifest.Payload {
		if entry.Size != int64(len(bodies[entry.ArchivePath])) || len(entry.SHA256) != 64 {
			t.Fatalf("entry is not content-bound: %+v", entry)
		}
	}
	for index, name := range wantOrder {
		if manifest.Payload[index].ArchivePath != name {
			t.Fatalf("payload[%d] = %q; want %q", index, manifest.Payload[index].ArchivePath, name)
		}
	}
}

func TestBuildBindsArm64BuildEnvironment(t *testing.T) {
	manifest, err := Build("v1.2.3", "linux", "arm64", 1787702400, testCommit, testTree, "go1.27.0", unixBodies())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Target.RequiredKernel != "Linux" || manifest.Artifact.Filename != "leaguebridge_1.2.3_linux_arm64.tar.gz" {
		t.Fatalf("manifest is not target-bound: %+v", manifest)
	}
	environment := manifest.Provenance.BuildEnvironment
	if environment.GOARM64 != "v8.0" || environment.GOAMD64 != "" {
		t.Fatalf("manifest does not bind the arm64 build environment: %+v", environment)
	}
}

func TestBuildRejectsMissingUnexpectedAndUnsupportedPayload(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		goarch string
		bodies map[string][]byte
		want   string
	}{
		{name: "missing", goos: "linux", goarch: "amd64", bodies: map[string][]byte{}, want: "want 8"},
		{name: "unexpected", goos: "linux", goarch: "amd64", bodies: withExtra(unixBodies()), want: "want 8"},
		{name: "replaced", goos: "linux", goarch: "amd64", bodies: withReplacement(unixBodies()), want: `missing "LICENSE"`},
		{name: "operating system", goos: "solaris", goarch: "amd64", bodies: unixBodies(), want: "unsupported operating system"},
		{name: "unsupported target", goos: "dragonfly", goarch: "arm64", bodies: unixBodies(), want: "unsupported target"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Build("v1.2.3", test.goos, test.goarch, 1787702400, testCommit, testTree, "go1.27.0", test.bodies)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build() error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestBuildRejectsInvalidBuilderVersion(t *testing.T) {
	for _, value := range []string{"", "1.27.0", "go1.27", "go2.0.0", "go1.27.0-rc1", "go1.27.0 toolchain"} {
		if _, err := Build("v1.2.3", "linux", "amd64", 1787702400, testCommit, testTree, value, unixBodies()); err == nil {
			t.Errorf("Build(builder=%q) unexpectedly succeeded", value)
		}
	}
}

func TestBuildRejectsInvalidCommitAndTree(t *testing.T) {
	for _, test := range []struct {
		commit string
		tree   string
	}{
		{commit: strings.Repeat("A", 40), tree: testTree},
		{commit: testCommit, tree: strings.Repeat("g", 40)},
		{commit: testCommit, tree: strings.Repeat("a", 39)},
	} {
		if _, err := Build("v1.2.3", "linux", "amd64", 1787702400, test.commit, test.tree, "go1.27.0", unixBodies()); err == nil {
			t.Errorf("Build(commit=%q, tree=%q) unexpectedly succeeded", test.commit, test.tree)
		}
	}
}

func TestBuildRejectsEpochOutsideReleaseRange(t *testing.T) {
	for _, epoch := range []int64{-1, 0, minimumEpoch - 1, maximumEpoch + 1} {
		if _, err := Build("v1.2.3", "linux", "amd64", epoch, testCommit, testTree, "go1.27.0", unixBodies()); err == nil {
			t.Errorf("Build(epoch=%d) unexpectedly succeeded", epoch)
		}
	}
}

func TestMarshalIsCanonicalAndNewlineTerminated(t *testing.T) {
	manifest, err := Build("v1.2.3", "linux", "amd64", 1787702400, testCommit, testTree, "go1.27.0", unixBodies())
	if err != nil {
		t.Fatal(err)
	}
	first, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || len(first) == 0 || first[len(first)-1] != '\n' || bytes.ContainsRune(first, '\r') {
		t.Fatal("manifest encoding is not stable canonical LF-terminated JSON")
	}
	var decoded Manifest
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Artifact != manifest.Artifact || decoded.Provenance != manifest.Provenance {
		t.Fatalf("round trip changed identity: %+v", decoded)
	}
}

func unixBodies() map[string][]byte {
	return map[string][]byte{
		"LICENSE":                     []byte("license"),
		"README.md":                   []byte("readme"),
		"SBOM.spdx.json":              []byte("sbom"),
		"install.sh":                  []byte("install"),
		"leaguebridge":                []byte("binary"),
		"linux-bsd-client-smoke.sh":   []byte("client smoke"),
		"linux-bsd-remote-session.sh": []byte("remote session"),
		"uninstall.sh":                []byte("uninstall"),
	}
}

func withExtra(input map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(input)+1)
	for name, body := range input {
		result[name] = body
	}
	result["unexpected"] = []byte("unexpected")
	return result
}

func withReplacement(input map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(input))
	for name, body := range input {
		if name != "LICENSE" {
			result[name] = body
		}
	}
	result["unexpected"] = []byte("unexpected")
	return result
}
