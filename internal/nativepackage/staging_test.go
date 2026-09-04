package nativepackage

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const (
	testCommit = "0123456789abcdef0123456789abcdef01234567"
	testTree   = "89abcdef0123456789abcdef0123456789abcdef"
)

func TestBuildMapsPortablePathsForEveryNativeFamily(t *testing.T) {
	tests := []struct {
		goos, goarch string
		family       Family
		root         string
		architecture string
	}{
		{goos: "linux", goarch: "amd64", family: FamilyDebian, root: "/", architecture: "amd64"},
		{goos: "linux", goarch: "amd64", family: FamilyRPM, root: "/", architecture: "x86_64"},
		{goos: "freebsd", goarch: "amd64", family: FamilyFreeBSD, root: "/usr/local", architecture: "amd64"},
		{goos: "freebsd", goarch: "arm64", family: FamilyFreeBSD, root: "/usr/local", architecture: "aarch64"},
		{goos: "openbsd", goarch: "amd64", family: FamilyOpenBSD, root: "/usr/local", architecture: "amd64"},
		{goos: "openbsd", goarch: "arm64", family: FamilyOpenBSD, root: "/usr/local", architecture: "arm64"},
		{goos: "netbsd", goarch: "amd64", family: FamilyPkgsrc, root: "/usr/local", architecture: "amd64"},
		{goos: "netbsd", goarch: "arm64", family: FamilyPkgsrc, root: "/usr/local", architecture: "aarch64"},
		{goos: "dragonfly", goarch: "amd64", family: FamilyDPorts, root: "/usr/local", architecture: "amd64"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.goos+"_"+test.goarch+"_"+string(test.family), func(t *testing.T) {
			source, sourceData := sourceManifest(t, test.goos, test.goarch)
			manifest, err := Build(source, sourceData, strings.Repeat("a", 64), test.family)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Package.InstallRoot != test.root || manifest.Package.Architecture != test.architecture {
				t.Fatalf("package identity = %+v; want root=%q architecture=%q", manifest.Package, test.root, test.architecture)
			}
			if len(manifest.Payload) != 7 || manifest.Payload[4].InstallPath != expectedBinaryPath(test.root) || manifest.Payload[5].InstallPath != expectedClientSmokePath(test.root) || manifest.Payload[6].InstallPath != expectedRemoteSessionPath(test.root) {
				t.Fatalf("staged payload = %+v", manifest.Payload)
			}
			if manifest.Payload[1].SourcePath != "PACKAGE-MANIFEST.json" || manifest.Payload[1].SHA256 == "" {
				t.Fatalf("staged manifest payload is not content-addressed: %+v", manifest.Payload[1])
			}
			if err := manifest.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBuildRejectsMismatchedFamilyAndUnsafeSource(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		family Family
		digest string
		want   string
	}{
		{name: "BSD family on Linux", goos: "linux", family: FamilyFreeBSD, digest: strings.Repeat("a", 64), want: "does not support linux/amd64"},
		{name: "Debian family on FreeBSD source", goos: "freebsd", family: FamilyDebian, digest: strings.Repeat("a", 64), want: "does not support freebsd/amd64"},
		{name: "bad digest", goos: "linux", family: FamilyDebian, digest: "ABC", want: "source archive digest"},
		{name: "non-canonical manifest", goos: "linux", family: FamilyDebian, digest: strings.Repeat("a", 64), want: "not canonical"},
		{name: "unknown family", goos: "linux", family: Family("unknown"), digest: strings.Repeat("a", 64), want: "unsupported native package family"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			source, sourceData := sourceManifest(t, test.goos, "amd64")
			data := sourceData
			if test.name == "non-canonical manifest" {
				data = append([]byte("\n"), sourceData...)
			}
			_, err := Build(source, data, test.digest, test.family)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build() error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestMarshalIsCanonicalAndValidatesIdentity(t *testing.T) {
	source, sourceData := sourceManifest(t, "linux", "amd64")
	manifest, err := Build(source, sourceData, strings.Repeat("a", 64), FamilyDebian)
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
		t.Fatal("staging manifest encoding is not canonical")
	}
	manifest.Package.Version = "v9.9.9"
	if _, err := Marshal(manifest); err == nil {
		t.Fatal("Marshal() accepted a package version detached from the source version")
	}
}

func TestPackageFamiliesForTargetAreStable(t *testing.T) {
	if got := PackageFamiliesForTarget("linux", "amd64"); !sameFamilies(got, []Family{FamilyDebian, FamilyRPM}) {
		t.Fatalf("Linux families = %v", got)
	}
	for _, test := range []struct {
		goos string
		want []Family
	}{
		{goos: "freebsd", want: []Family{FamilyFreeBSD}},
		{goos: "openbsd", want: []Family{FamilyOpenBSD}},
		{goos: "netbsd", want: []Family{FamilyPkgsrc}},
	} {
		if got := PackageFamiliesForTarget(test.goos, "arm64"); !sameFamilies(got, test.want) {
			t.Fatalf("%s/arm64 families = %v; want %v", test.goos, got, test.want)
		}
	}
	if got := PackageFamiliesForTarget("linux", "arm64"); len(got) != 0 {
		t.Fatalf("Linux/arm64 families = %v; want none", got)
	}
}

func sourceManifest(t *testing.T, goos, goarch string) (packageinfo.Manifest, []byte) {
	t.Helper()
	names, err := packageinfo.ExpectedPayloadNames(goos, goarch)
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte, len(names))
	for _, name := range names {
		bodies[name] = []byte("native-package fixture: " + name)
	}
	manifest, err := packageinfo.Build("v1.2.3", goos, goarch, 1787702400, testCommit, testTree, "go1.27.1", bodies)
	if err != nil {
		t.Fatal(err)
	}
	data, err := packageinfo.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, data
}

func expectedBinaryPath(root string) string {
	if root == "/" {
		return "/usr/bin/leaguebridge"
	}
	return "/usr/local/bin/leaguebridge"
}

func expectedRemoteSessionPath(root string) string {
	if root == "/" {
		return "/usr/libexec/leaguebridge/linux-bsd-remote-session.sh"
	}
	return "/usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh"
}

func expectedClientSmokePath(root string) string {
	if root == "/" {
		return "/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh"
	}
	return "/usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh"
}

func sameFamilies(got, want []Family) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
