package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/config"
)

func TestRemoteMouseFlagsForwardToMoonlightQt(t *testing.T) {
	for _, tt := range []struct {
		name string
		flag string
		want string
	}{
		{name: "absolute", flag: "--absolute-mouse", want: "-absolute-mouse"},
		{name: "relative", flag: "--no-absolute-mouse", want: "-no-absolute-mouse"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, _, runner := newTestApp(t)
			args := []string{
				"remote", "stream", "--host", "gaming-pc.local", tt.flag,
				"--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json",
			}
			if code := a.Run(context.Background(), args); code != ExitOK {
				t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			envelope := decodeEnvelope(t, out.Bytes())
			plan := envelope.Data.(map[string]any)
			arguments := plan["arguments"].([]any)
			want := []any{"stream", tt.want, "gaming-pc.local", config.DefaultRemoteApplication}
			if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
				t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
			}
		})
	}
}

func TestRemoteStreamDefaultsToRelativeMouseCaptureOnQtAndFlatpak(t *testing.T) {
	for _, tt := range []struct {
		name     string
		client   string
		env      fakeRemoteEnvironment
		wantArgs []any
	}{
		{
			name:   "Qt",
			client: "moonlight-qt",
			env:    fakeRemoteEnvironment{paths: map[string]string{"moonlight-qt": "/fixture/moonlight-qt"}},
			wantArgs: []any{
				"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication,
			},
		},
		{
			name:   "Flatpak",
			client: "flatpak",
			env:    fakeRemoteEnvironment{paths: map[string]string{"flatpak": "/fixture/flatpak"}},
			wantArgs: []any{
				"run", "com.moonlight_stream.Moonlight", "stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, _, runner := newTestApp(t)
			a.RemoteEnv = tt.env
			args := []string{
				"remote", "stream", "--client", tt.client, "--host", "gaming-pc.local",
				"--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json",
			}
			if code := a.Run(context.Background(), args); code != ExitOK {
				t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			envelope := decodeEnvelope(t, out.Bytes())
			plan := envelope.Data.(map[string]any)
			arguments := plan["arguments"].([]any)
			if !reflect.DeepEqual(arguments, tt.wantArgs) || runner.called != 0 {
				t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, tt.wantArgs)
			}
		})
	}
}

func TestRemoteMouseFlagsRejectConflictsAndNonStreamUse(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "conflict",
			args: []string{"remote", "stream", "--absolute-mouse", "--no-absolute-mouse", "--dry-run"},
			want: "cannot combine",
		},
		{
			name: "pair",
			args: []string{"remote", "pair", "--absolute-mouse", "--dry-run"},
			want: "require the stream operation",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), tt.args); code != ExitUsage {
				t.Fatalf("code = %d; stderr=%q", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), tt.want) {
				t.Fatalf("stderr=%q; want %q", errOut.String(), tt.want)
			}
		})
	}
}

func TestRemoteAudioAndControllerFlagsForwardToSupportedMoonlightClients(t *testing.T) {
	t.Run("Qt and Flatpak controls", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--audio-on-host",
			"--multi-controller", "--mouse-buttons-swap", "--touchscreen-trackpad",
			"--mute-on-focus-loss", "--background-gamepad", "--reverse-scroll-direction",
			"--swap-gamepad-buttons", "--performance-overlay", "--hdr", "--yuv444",
			"--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{
			"stream", "-audio-on-host", "-no-absolute-mouse", "-multi-controller", "-mouse-buttons-swap",
			"-touchscreen-trackpad", "-mute-on-focus-loss", "-background-gamepad",
			"-reverse-scroll-direction", "-swap-gamepad-buttons", "-performance-overlay",
			"-hdr", "-yuv444", "gaming-pc.local", config.DefaultRemoteApplication,
		}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("Embedded audio and mouse-emulation controls", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
		args := []string{
			"remote", "stream", "--client", "moonlight-embedded", "--host", "gaming-pc.local",
			"--audio-on-host", "--audio-device", "hw:0,0", "--input-device", "/dev/input/event0", "--input-device", "/dev/input/event4",
			"--input-mapping", "/etc/moonlight/gamecontrollerdb.txt",
			"--disable-gamepad-mouse-emulation", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-localaudio", "-audio", "hw:0,0", "-nomouseemulation", "-input", "/dev/input/event0", "-input", "/dev/input/event4", "-mapping", "/etc/moonlight/gamecontrollerdb.txt", "-app", config.DefaultRemoteApplication, "gaming-pc.local"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})
}

func TestRemoteInputMappingFilePreflight(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "mapping.db")
	if err := os.WriteFile(valid, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRemoteInputMappingFile(valid); err != nil {
		t.Fatalf("valid mapping file rejected: %v", err)
	}

	missing := filepath.Join(directory, "missing.db")
	if err := validateRemoteInputMappingFile(missing); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("missing mapping file error = %v; want unreadable-file error", err)
	}
	if err := validateRemoteInputMappingFile(directory); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("mapping directory error = %v; want regular-file error", err)
	}

	oversized := filepath.Join(directory, "oversized.db")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(remoteInputMappingFileLimit) + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateRemoteInputMappingFile(oversized); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized mapping file error = %v; want size-limit error", err)
	}
}

func TestRemoteInputDevicePreflight(t *testing.T) {
	if runtime.GOOS != "windows" {
		// /dev/null exercises the same nonblocking read/write character-device
		// open used to catch evdev permission failures before Moonlight starts.
		if err := validateRemoteInputDevice(os.DevNull); err != nil {
			t.Fatalf("character device %q rejected: %v", os.DevNull, err)
		}
	}

	directory := t.TempDir()
	missing := filepath.Join(directory, "missing-event")
	if err := validateRemoteInputDevice(missing); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("missing input device error = %v; want unreadable-device error", err)
	}
	regular := filepath.Join(directory, "regular-file")
	if err := os.WriteFile(regular, []byte("not an input device"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRemoteInputDevice(regular); err == nil || !strings.Contains(err.Error(), "character device") {
		t.Fatalf("regular input path error = %v; want character-device error", err)
	}
}

func TestRemoteInputDevicesPreflightReportsDeviceIndex(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose a portable character-device fixture")
	}
	regular := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(regular, []byte("not an input device"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := validateRemoteInputDevices([]string{os.DevNull, regular})
	if err == nil || !strings.Contains(err.Error(), "input device 2") || !strings.Contains(err.Error(), "character device") {
		t.Fatalf("multiple-device preflight error = %v; want indexed character-device error", err)
	}
}

func TestRemoteLiveStreamPreflightsExplicitLocalSelectors(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "input device",
			args: []string{"--input-device", "/dev/input/event999999999"},
			want: "input device",
		},
		{
			name: "input mapping",
			args: []string{"--input-mapping", "/var/lib/leaguebridge/missing-mapping.db"},
			want: "input mapping",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, _, errOut, _, runner := newTestApp(t)
			a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
			args := append([]string{"remote", "stream", "--client", "moonlight-embedded", "--host", "gaming-pc.local"}, tt.args...)
			args = append(args, "--confirm-physical-host", "--acknowledge-unverified-handoff")
			if code := a.Run(context.Background(), args); code != ExitUsage {
				t.Fatalf("code = %d; stderr=%q", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), tt.want) || runner.called != 0 {
				t.Fatalf("stderr=%q runner.called=%d; want %q and no process", errOut.String(), runner.called, tt.want)
			}
		})
	}
}
