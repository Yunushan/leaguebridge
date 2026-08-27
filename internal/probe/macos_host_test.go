package probe

import (
	"context"
	"io/fs"
	"testing"
)

func TestMacOSHostSupportsDarwinArchitecturesWithoutClaimingReadiness(t *testing.T) {
	t.Parallel()
	for _, architecture := range []string{"amd64", "arm64"} {
		architecture := architecture
		t.Run(architecture, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{}
			applications := fixtureModes(fs.ModeDir|0o755, rioClientAppPath, leagueAppPath, sunshineAppPath)
			report := fixtureProber("darwin", architecture, nil, nil, commands, applications).MacOSHost(context.Background())
			if got := checkStatus(t, report, "host.platform"); got != StatusPass {
				t.Fatalf("platform status = %q", got)
			}
			for _, id := range []string{"host.riot-client", "host.league", "host.sunshine"} {
				if got := checkStatus(t, report, id); got != StatusPass {
					t.Errorf("%s status = %q", id, got)
				}
			}
			if report.Status != StatusWarn || report.Ready() {
				t.Fatalf("report = %+v; macOS host inventory must remain unvalidated", report)
			}
			if calls := commands.recordedCalls(); len(calls) != 0 {
				t.Fatalf("macOS host probe executed commands: %#v", calls)
			}
		})
	}
}

func TestMacOSHostRejectsOtherPlatformsAndArchitecturesBeforeFileAccess(t *testing.T) {
	t.Parallel()
	for _, target := range []struct {
		goos   string
		goarch string
	}{
		{goos: "linux", goarch: "amd64"},
		{goos: "windows", goarch: "amd64"},
		{goos: "darwin", goarch: "386"},
	} {
		filesystem := &recordingProbeFS{}
		commands := &fixtureCommands{paths: map[string]bool{"sunshine": true}}
		prober := New(Dependencies{FS: filesystem, Env: fixtureEnv{}, Commands: commands, Services: commands, GOOS: target.goos, GOARCH: target.goarch})
		report := prober.MacOSHost(context.Background())
		if report.Status != StatusFail || report.Ready() {
			t.Errorf("%s/%s report = %+v", target.goos, target.goarch, report)
		}
		if calls := filesystem.recorded(); len(calls) != 0 {
			t.Errorf("%s/%s inspected files: %#v", target.goos, target.goarch, calls)
		}
		if calls := commands.recordedCalls(); len(calls) != 0 {
			t.Errorf("%s/%s executed commands: %#v", target.goos, target.goarch, calls)
		}
	}
}

func TestMacOSHostRequiresApplicationDirectoriesAndKeepsManualGates(t *testing.T) {
	t.Parallel()
	symlinks := fixtureModes(fs.ModeSymlink|0o777, rioClientAppPath, leagueAppPath, sunshineAppPath)
	report := fixtureProber("darwin", "arm64", nil, nil, &fixtureCommands{}, symlinks).Run(context.Background(), ProfileMacOSHost)
	for _, id := range []string{"host.riot-client", "host.league", "host.sunshine"} {
		if got := checkStatus(t, report, id); got != StatusFail {
			t.Errorf("%s status = %q; a symlink must not satisfy application discovery", id, got)
		}
	}
	for _, id := range []string{"host.macos-version", "host.physical-machine", "host.hardware-requirements", "host.remote-behavior", "host.local-practice-tool"} {
		if got := checkStatus(t, report, id); got != StatusWarn {
			t.Errorf("%s status = %q", id, got)
		}
	}
}
