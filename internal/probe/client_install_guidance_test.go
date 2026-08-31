package probe

import (
	"strings"
	"testing"
)

func TestMoonlightInstallGuidanceNamesSupportedUnixSources(t *testing.T) {
	t.Parallel()
	tests := []struct {
		goos string
		want []string
	}{
		{goos: "linux", want: []string{"distribution's signed package repository", "flatpak install flathub com.moonlight_stream.Moonlight"}},
		{goos: "freebsd", want: []string{"pkg install moonlight-qt", "pkg install moonlight-embedded", "games/moonlight-embedded", "FreeBSD's official ports tree"}},
		{goos: "openbsd", want: []string{"pkg_add moonlight-qt", "OpenBSD's official ports tree"}},
		{goos: "netbsd", want: []string{"pkgin install moonlight-qt", "NetBSD's official pkgsrc tree"}},
		{goos: "dragonfly", want: []string{"pkg install moonlight-qt", "pkg install moonlight-embedded", "games/moonlight-embedded", "DragonFly's DPorts tree"}},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			t.Parallel()
			guidance := moonlightInstallGuidance(tt.goos)
			for _, want := range tt.want {
				if !strings.Contains(guidance, want) {
					t.Fatalf("guidance %q does not contain %q", guidance, want)
				}
			}
		})
	}
}

func TestMoonlightInstallGuidanceDoesNotSuggestUnsupportedNativeTargets(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "freebsd", "openbsd", "netbsd", "dragonfly"} {
		guidance := moonlightInstallGuidance(goos)
		for _, forbidden := range []string{"Windows package", "macOS package", "League installer", "Riot Client"} {
			if strings.Contains(guidance, forbidden) {
				t.Fatalf("%s guidance contains out-of-scope installation advice %q: %s", goos, forbidden, guidance)
			}
		}
	}
}

func TestMoonlightInstallGuidanceKeepsUnsupportedHostsOutOfProductScope(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"windows", "darwin", "plan9"} {
		guidance := moonlightInstallGuidance(goos)
		if !strings.Contains(guidance, "external physical-host destinations") {
			t.Fatalf("%s guidance does not identify the host-only scope: %s", goos, guidance)
		}
		for _, forbidden := range []string{"Install Moonlight", "League installer", "Riot Client"} {
			if strings.Contains(guidance, forbidden) {
				t.Fatalf("%s guidance contains product installation advice %q: %s", goos, forbidden, guidance)
			}
		}
	}
}
