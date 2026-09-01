package target

import "testing"

func TestOrdered(t *testing.T) {
	want := []Target{
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
	got := Ordered()
	if len(got) != len(want) {
		t.Fatalf("Ordered() has %d targets, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("Ordered()[%d] = %+v, want %+v", index, got[index], want[index])
		}
	}
	got[0].GOOS = "mutated"
	if Ordered()[0].GOOS != "linux" {
		t.Fatal("Ordered() returned shared mutable state")
	}
}

func TestIsSupported(t *testing.T) {
	tests := []struct {
		goos, goarch string
		want         bool
	}{
		{"linux", "amd64", true},
		{"linux", "aarch64", true},
		{"freebsd", "arm64", true},
		{"openbsd", "x86_64", true},
		{"netbsd", "arm64", true},
		{"dragonfly", "amd64", true},
		{"dragonfly", "arm64", false},
		{"windows", "amd64", false},
		{"linux", "386", false},
	}
	for _, test := range tests {
		if got := IsSupported(test.goos, test.goarch); got != test.want {
			t.Errorf("IsSupported(%q, %q) = %v, want %v", test.goos, test.goarch, got, test.want)
		}
	}
}

func TestEvidencePlatform(t *testing.T) {
	for _, test := range []struct {
		goos, platform string
	}{
		{"linux", "linux"},
		{"freebsd", "freebsd"},
		{"openbsd", "openbsd"},
		{"netbsd", "netbsd"},
		{"dragonfly", "dragonflybsd"},
	} {
		platform, ok := EvidencePlatform(test.goos)
		if !ok || platform != test.platform {
			t.Errorf("EvidencePlatform(%q) = %q, %v; want %q, true", test.goos, platform, ok, test.platform)
		}
		gotGOOS, ok := GOOS(platform)
		if !ok || gotGOOS != test.goos {
			t.Errorf("GOOS(%q) = %q, %v; want %q, true", platform, gotGOOS, ok, test.goos)
		}
	}
	if _, ok := EvidencePlatform("windows"); ok {
		t.Fatal("EvidencePlatform(windows) unexpectedly succeeded")
	}
	if !IsSupportedEvidencePlatform("dragonflybsd", "amd64") || IsSupportedEvidencePlatform("dragonflybsd", "arm64") {
		t.Fatal("DragonFly evidence architecture contract is incorrect")
	}
}
