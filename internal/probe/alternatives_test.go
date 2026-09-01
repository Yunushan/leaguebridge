package probe

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompatibilityAuditIsReadOnlyAndFailClosed(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		goos  string
		arch  string
		paths map[string]bool
		want  map[string]Status
	}{
		{
			name:  "nothing installed",
			goos:  "linux",
			arch:  "amd64",
			paths: nil,
			want: map[string]Status{
				"compatibility.platform":        StatusPass,
				"compatibility.wine":            StatusWarn,
				"compatibility.proton":          StatusWarn,
				"compatibility.lutris":          StatusWarn,
				"compatibility.virtual-machine": StatusWarn,
				"compatibility.other-layers":    StatusWarn,
				"compatibility.native-vanguard": StatusFail,
			},
		},
		{
			name: "all alternatives present",
			goos: "linux",
			arch: "amd64",
			paths: map[string]bool{
				"wine":     true,
				"proton":   true,
				"lutris":   true,
				"docker":   true,
				"darling":  true,
				"parsec":   true,
				"waydroid": true,
			},
			want: map[string]Status{
				"compatibility.platform":        StatusPass,
				"compatibility.wine":            StatusWarn,
				"compatibility.proton":          StatusWarn,
				"compatibility.lutris":          StatusWarn,
				"compatibility.virtual-machine": StatusWarn,
				"compatibility.other-layers":    StatusWarn,
				"compatibility.native-vanguard": StatusFail,
			},
		},
		{
			name:  "unsupported host",
			goos:  "plan9",
			arch:  "amd64",
			paths: map[string]bool{"qemu-system-x86_64": true},
			want: map[string]Status{
				"compatibility.platform":        StatusFail,
				"compatibility.wine":            StatusWarn,
				"compatibility.proton":          StatusWarn,
				"compatibility.lutris":          StatusWarn,
				"compatibility.virtual-machine": StatusWarn,
				"compatibility.other-layers":    StatusWarn,
				"compatibility.native-vanguard": StatusFail,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{paths: tt.paths}
			report := fixtureProber(tt.goos, tt.arch, nil, nil, commands).Compatibility(context.Background())
			if report.Profile != ProfileCompatibility || report.Status != StatusFail || report.Ready() {
				t.Fatalf("compatibility report must remain blocked: %+v", report)
			}
			if len(report.Checks) != len(tt.want) {
				t.Fatalf("check count = %d, want %d", len(report.Checks), len(tt.want))
			}
			for id, want := range tt.want {
				if got := checkStatus(t, report, id); got != want {
					t.Errorf("%s status = %q, want %q", id, got, want)
				}
			}
			if calls := commands.recordedCalls(); len(calls) != 0 {
				t.Fatalf("compatibility audit executed a command: %+v", calls)
			}
		})
	}
}

func TestCompatibilityAuditMessagesNameUnsupportedPaths(t *testing.T) {
	t.Parallel()
	commands := &fixtureCommands{paths: map[string]bool{
		"wine":   true,
		"proton": true,
		"lutris": true,
		"wsl":    true,
	}}
	report := fixtureProber("linux", "amd64", nil, nil, commands).Run(context.Background(), ProfileCompatibility)
	for _, id := range []string{
		"compatibility.wine",
		"compatibility.proton",
		"compatibility.lutris",
		"compatibility.virtual-machine",
		"compatibility.other-layers",
		"compatibility.native-vanguard",
	} {
		check, ok := report.Check(id)
		if !ok || strings.TrimSpace(check.Summary) == "" || strings.TrimSpace(check.Guidance) == "" {
			t.Fatalf("%s lacks bounded summary/guidance: %+v", id, check)
		}
	}
}

func TestCompatibilityProfileDispatch(t *testing.T) {
	t.Parallel()
	report := fixtureProber("freebsd", "amd64", nil, nil, nil).Run(context.Background(), ProfileCompatibility)
	if report.SchemaVersion != 2 || report.Profile != ProfileCompatibility || report.Status != StatusFail || len(report.Checks) != 7 {
		t.Fatalf("unexpected compatibility dispatch report: %+v", report)
	}
}

func TestCompatibilityAuditNamesExtendedAlternatives(t *testing.T) {
	t.Parallel()
	commands := &fixtureCommands{paths: map[string]bool{
		"crossover": true,
		"steam":     true,
		"vmd":       true,
		"parsec":    true,
		"waydroid":  true,
	}}
	report := fixtureProber("linux", "amd64", nil, nil, commands).Compatibility(context.Background())
	wine, _ := report.Check("compatibility.wine")
	if !strings.Contains(wine.Summary, "crossover") {
		t.Fatalf("Wine frontend was not named: %+v", wine)
	}
	proton, _ := report.Check("compatibility.proton")
	if !strings.Contains(proton.Summary, "steam") {
		t.Fatalf("Proton-capable launcher was not named: %+v", proton)
	}
	vm, _ := report.Check("compatibility.virtual-machine")
	if !strings.Contains(vm.Summary, "vmd") {
		t.Fatalf("OpenBSD VMM launcher was not named: %+v", vm)
	}
	other, _ := report.Check("compatibility.other-layers")
	if !strings.Contains(other.Summary, "Waydroid") {
		t.Fatalf("other compatibility layer was not named: %+v", other)
	}
	if !strings.Contains(other.Summary, "Parsec") {
		t.Fatalf("Parsec was not named: %+v", other)
	}
	if calls := commands.recordedCalls(); len(calls) != 0 {
		t.Fatalf("extended compatibility audit executed a command: %+v", calls)
	}
}

func TestCompatibilityAuditDetectsContainerAndMicroVMLaunchers(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"containerd", "nerdctl", "lxc", "incus", "firecracker", "cloud-hypervisor", "virtctl", "multipass"} {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{paths: map[string]bool{command: true}}
			report := fixtureProber("linux", "amd64", nil, nil, commands).Compatibility(context.Background())
			check, ok := report.Check("compatibility.virtual-machine")
			if !ok || check.Status != StatusWarn || !strings.Contains(check.Summary, command) {
				t.Fatalf("launcher %q was not classified as a named warning: %+v", command, check)
			}
			if calls := commands.recordedCalls(); len(calls) != 0 {
				t.Fatalf("container/VM audit executed a command: %+v", calls)
			}
		})
	}
}

func TestCompatibilityAuditDetectsStandardFlatpakAlternatives(t *testing.T) {
	t.Parallel()
	root := string(filepath.Separator)
	flatpakDirectories := []string{
		filepath.Join(root, "var", "lib", "flatpak", "app", "com.usebottles.bottles"),
		filepath.Join(root, "var", "lib", "flatpak", "app", "com.valvesoftware.Steam"),
		filepath.Join(root, "var", "lib", "flatpak", "app", "net.lutris.Lutris"),
		filepath.Join(root, "var", "lib", "flatpak", "app", "org.gnome.Boxes"),
	}
	directoryModes := fixtureModes(fs.ModeDir|0o755, flatpakDirectories...)
	commands := &fixtureCommands{}
	report := fixtureProber("linux", "amd64", nil, nil, commands, directoryModes).Compatibility(context.Background())
	for _, id := range []string{
		"compatibility.wine",
		"compatibility.proton",
		"compatibility.lutris",
		"compatibility.virtual-machine",
	} {
		check, ok := report.Check(id)
		if !ok || check.Status != StatusWarn {
			t.Fatalf("Flatpak alternative %s was not audited as a warning: %+v", id, check)
		}
	}
	for _, want := range []string{"Bottles", "Steam", "Lutris", "GNOME Boxes"} {
		found := false
		for _, check := range report.Checks {
			if strings.Contains(check.Summary, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Flatpak app %q was not named in report: %+v", want, report)
		}
	}
	if calls := commands.recordedCalls(); len(calls) != 0 {
		t.Fatalf("flatpak compatibility audit executed a command: %+v", calls)
	}
}

func TestCompatibilityAuditDetectsXDGDataDirsFlatpakAlternatives(t *testing.T) {
	t.Parallel()
	root := string(filepath.Separator)
	appPath := filepath.Join(root, "opt", "share", "flatpak", "app", "com.usebottles.bottles")
	commands := &fixtureCommands{}
	prober := fixtureProber("linux", "amd64", nil, fixtureEnv{
		"XDG_DATA_DIRS": filepath.Join(root, "opt", "share") + ":" + filepath.Join(root, "usr", "share"),
	}, commands, fixtureModes(fs.ModeDir|0o755, appPath))
	report := prober.Compatibility(context.Background())
	wine, ok := report.Check("compatibility.wine")
	if !ok || wine.Status != StatusWarn || !strings.Contains(wine.Summary, "Bottles") {
		t.Fatalf("XDG_DATA_DIRS Flatpak app was not audited: %+v", wine)
	}
	if calls := commands.recordedCalls(); len(calls) != 0 {
		t.Fatalf("XDG_DATA_DIRS Flatpak audit executed a command: %+v", calls)
	}
}

func TestCompatibilityAuditRejectsUnsafeFlatpakEnvironmentRoots(t *testing.T) {
	t.Parallel()
	marker := "leaguebridge-flatpak-unsafe"
	fs := &recordingProbeFS{}
	prober := fixtureProber("linux", "amd64", nil, fixtureEnv{
		"HOME":          "//" + marker + "/home",
		"XDG_DATA_HOME": "\\\\" + marker + "\\data",
		"XDG_DATA_DIRS": "//" + marker + "/dirs",
	}, nil)
	prober.fs = fs
	if _, ok := prober.lookupFlatpakApp(map[string]string{"com.usebottles.bottles": "Bottles"}); ok {
		t.Fatal("unsafe Flatpak root produced app evidence")
	}
	assertNoUnsafeStat(t, fs.recorded(), marker)
}
