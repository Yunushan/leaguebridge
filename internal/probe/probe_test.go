package probe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureFS struct {
	paths  map[string]bool
	modes  map[string]fs.FileMode
	errors map[string]error
}

func (f fixtureFS) Stat(name string) (fs.FileInfo, error) {
	key := fixturePath(name)
	if err := f.errors[key]; err != nil {
		return nil, err
	}
	if mode, ok := f.modes[key]; ok {
		return fixtureInfo{name: filepath.Base(name), mode: mode}, nil
	}
	if f.paths[key] {
		return fixtureInfo{name: filepath.Base(name), mode: 0o644}, nil
	}
	return nil, fs.ErrNotExist
}

type resolvedFixtureFS struct {
	fixtureFS
	resolvedModes map[string]fs.FileMode
}

func (f resolvedFixtureFS) StatResolved(name string) (fs.FileInfo, error) {
	key := fixturePath(name)
	if mode, ok := f.resolvedModes[key]; ok {
		return fixtureInfo{name: filepath.Base(name), mode: mode}, nil
	}
	return f.fixtureFS.Stat(name)
}

type fixtureWritableFS struct {
	fixtureFS
	openReadWriteErrors map[string]error
}

func (f fixtureWritableFS) OpenReadWrite(name string) (io.Closer, error) {
	if err := f.openReadWriteErrors[fixturePath(name)]; err != nil {
		return nil, err
	}
	return io.NopCloser(strings.NewReader("")), nil
}

type fixtureInfo struct {
	name string
	mode fs.FileMode
}

func (f fixtureInfo) Name() string      { return f.name }
func (fixtureInfo) Size() int64         { return 0 }
func (f fixtureInfo) Mode() fs.FileMode { return f.mode }
func (fixtureInfo) ModTime() time.Time  { return time.Time{} }
func (f fixtureInfo) IsDir() bool       { return f.mode.IsDir() }
func (fixtureInfo) Sys() any            { return nil }
func fixturePath(path string) string    { return strings.ToLower(filepath.Clean(path)) }
func fixturePaths(paths ...string) map[string]bool {
	result := make(map[string]bool, len(paths))
	for _, path := range paths {
		result[fixturePath(path)] = true
	}
	return result
}

func fixtureModes(mode fs.FileMode, paths ...string) map[string]fs.FileMode {
	result := make(map[string]fs.FileMode, len(paths))
	for _, path := range paths {
		result[fixturePath(path)] = mode
	}
	return result
}

func fixtureDeviceModes(paths ...string) map[string]fs.FileMode {
	return fixtureModes(fs.ModeDevice|fs.ModeCharDevice, paths...)
}

type fixtureEnv map[string]string

func (f fixtureEnv) LookupEnv(key string) (string, bool) {
	value, ok := f[key]
	return value, ok
}

type fixturePlatformInfo struct {
	architecture string
	known        bool
}

func (f fixturePlatformInfo) NativeArchitecture() (string, bool) {
	return f.architecture, f.known
}

type fixturePrivilegeInfo struct {
	root bool
}

func (f fixturePrivilegeInfo) IsRoot() bool { return f.root }

type commandCall struct {
	name string
	args []string
}

type fixtureCommands struct {
	mu            sync.Mutex
	paths         map[string]bool
	results       map[string]CommandResult
	errors        map[string]error
	serviceStates map[string]observedServiceState
	serviceErrors map[string]error
	calls         []commandCall
	block         bool
}

func (f *fixtureCommands) LookPath(name string) (string, error) {
	if f.paths[strings.ToLower(name)] {
		return filepath.Join("fixture-bin", name), nil
	}
	return "", fs.ErrNotExist
}

func (f *fixtureCommands) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, commandCall{name: name, args: append([]string(nil), args...)})
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return CommandResult{ExitCode: -1}, ctx.Err()
	}
	key := commandKey(name, args...)
	if err := f.errors[key]; err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	if result, ok := f.results[key]; ok {
		return result, nil
	}
	return CommandResult{ExitCode: 1}, nil
}

func (f *fixtureCommands) Query(name string) (registered, running bool, err error) {
	key := strings.ToLower(name)
	if err := f.serviceErrors[key]; err != nil {
		return false, false, err
	}
	switch f.serviceStates[key] {
	case serviceRegistered:
		return true, false, nil
	case serviceRunning:
		return true, true, nil
	default:
		return false, false, nil
	}
}

func (f *fixtureCommands) recordedCalls() []commandCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]commandCall, len(f.calls))
	copy(result, f.calls)
	return result
}

func commandKey(name string, args ...string) string {
	return strings.ToLower(name) + "\x00" + strings.Join(args, "\x00")
}

func fixtureProber(goos, goarch string, files map[string]bool, env fixtureEnv, commands *fixtureCommands, modes ...map[string]fs.FileMode) *Prober {
	return fixtureProberWithRoot(goos, goarch, files, env, commands, true, modes...)
}

func fixtureProberWithRoot(goos, goarch string, files map[string]bool, env fixtureEnv, commands *fixtureCommands, root bool, modes ...map[string]fs.FileMode) *Prober {
	if files == nil {
		files = map[string]bool{}
	}
	if env == nil {
		env = fixtureEnv{}
	}
	if commands == nil {
		commands = &fixtureCommands{}
	}
	var fileModes map[string]fs.FileMode
	if len(modes) > 0 {
		fileModes = modes[0]
	}
	return New(Dependencies{
		FS:             fixtureFS{paths: files, modes: fileModes},
		Env:            env,
		Commands:       commands,
		Services:       commands,
		Platform:       fixturePlatformInfo{architecture: goarch, known: true},
		Privilege:      fixturePrivilegeInfo{root: root},
		GOOS:           goos,
		GOARCH:         goarch,
		CommandTimeout: 50 * time.Millisecond,
	})
}

func checkStatus(t *testing.T, report Report, id string) Status {
	t.Helper()
	check, ok := report.Check(id)
	if !ok {
		t.Fatalf("missing check %q in %+v", id, report.Checks)
	}
	return check.Status
}

func checkSummary(t *testing.T, report Report, id string) string {
	t.Helper()
	check, ok := report.Check(id)
	if !ok {
		t.Fatalf("missing check %q in %+v", id, report.Checks)
	}
	return check.Summary
}

func TestClientPlatformEligibility(t *testing.T) {
	t.Parallel()
	tests := []struct {
		goos   string
		goarch string
		want   Status
	}{
		{"linux", "amd64", StatusPass},
		{"freebsd", "amd64", StatusPass},
		{"openbsd", "amd64", StatusPass},
		{"netbsd", "amd64", StatusPass},
		{"dragonfly", "amd64", StatusPass},
		{"linux", "arm64", StatusPass},
		{"dragonfly", "arm64", StatusFail},
		{"windows", "amd64", StatusFail},
		{"plan9", "amd64", StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.goos+"-"+tt.goarch, func(t *testing.T) {
			t.Parallel()
			prober := fixtureProber(tt.goos, tt.goarch, nil, fixtureEnv{"DISPLAY": ":0", "PULSE_SERVER": "fixture"}, &fixtureCommands{paths: map[string]bool{"moonlight": true, "ffmpeg": true}})
			got := checkStatus(t, prober.Client(context.Background()), "client.platform")
			if got != tt.want {
				t.Fatalf("platform status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGraphicalSessionChecks(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		goos  string
		files map[string]bool
		modes map[string]fs.FileMode
		env   fixtureEnv
		want  Status
	}{
		{name: "wayland", modes: fixtureModes(fs.ModeSocket, targetPathJoin("linux", "/run/user/1000", "wayland-0")), env: fixtureEnv{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, want: StatusPass},
		{name: "wayland-without-runtime-root", env: fixtureEnv{"WAYLAND_DISPLAY": "wayland-0"}, want: StatusPass},
		{name: "wayland-runtime-socket-missing", env: fixtureEnv{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, want: StatusWarn},
		{name: "x11", modes: fixtureModes(fs.ModeSocket, targetPathJoin("linux", "/tmp/.X11-unix/X0")), env: fixtureEnv{"DISPLAY": ":0"}, want: StatusPass},
		{name: "x11-abstract-or-remote", env: fixtureEnv{"DISPLAY": "localhost:10.0"}, want: StatusPass},
		{name: "malformed-wayland", env: fixtureEnv{"WAYLAND_DISPLAY": "../wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, want: StatusWarn},
		{name: "malformed-x11", env: fixtureEnv{"DISPLAY": ":not-a-display"}, want: StatusWarn},
		{name: "sdl-kmsdrm", files: fixturePaths(filepath.FromSlash("/dev/dri/card0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusPass},
		{name: "qt-eglfs", files: fixturePaths(filepath.FromSlash("/dev/dri/card0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0")), env: fixtureEnv{"QT_QPA_PLATFORM": "eglfs"}, want: StatusPass},
		{name: "qt-linuxfb", files: fixturePaths(filepath.FromSlash("/dev/fb0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/fb0")), env: fixtureEnv{"QT_QPA_PLATFORM": "linuxfb"}, want: StatusPass},
		{name: "qt-linuxfb-graphics-fallback", files: fixturePaths(filepath.FromSlash("/dev/graphics/fb0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/graphics/fb0")), env: fixtureEnv{"QT_QPA_PLATFORM": "linuxfb"}, want: StatusPass},
		{name: "regular-placeholder-is-not-a-device", files: fixturePaths(filepath.FromSlash("/dev/dri/card0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusFail},
		{name: "netbsd-sdl-kmsdrm-unsupported", goos: "netbsd", files: fixturePaths(filepath.FromSlash("/dev/dri/card0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusFail},
		{name: "netbsd-sdl-kmsdrm-unsupported-even-with-x11", goos: "netbsd", files: fixturePaths(filepath.FromSlash("/dev/dri/card0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0")), env: fixtureEnv{"DISPLAY": ":0", "SDL_VIDEODRIVER": "kmsdrm"}, want: StatusFail},
		{name: "direct-backend-without-device", env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusFail},
		{name: "type-only", env: fixtureEnv{"XDG_SESSION_TYPE": "wayland"}, want: StatusWarn},
		{name: "headless", want: StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			goos := tt.goos
			if goos == "" {
				goos = "linux"
			}
			got := checkStatus(t, fixtureProber(goos, "amd64", tt.files, tt.env, nil, tt.modes).Client(context.Background()), "client.graphical-session")
			if got != tt.want {
				t.Fatalf("session status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWaylandDisplayCheckFollowsFinalDisplaySymlink(t *testing.T) {
	t.Parallel()
	endpoint := targetPathJoin("linux", "/run/user/1000", "wayland-0")
	prober := New(Dependencies{
		FS: resolvedFixtureFS{
			fixtureFS:     fixtureFS{modes: fixtureModes(fs.ModeSymlink, endpoint)},
			resolvedModes: fixtureModes(fs.ModeSocket, endpoint),
		},
		Env:       fixtureEnv{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"},
		Commands:  &fixtureCommands{},
		Platform:  fixturePlatformInfo{architecture: "amd64", known: true},
		Privilege: fixturePrivilegeInfo{root: true},
		GOOS:      "linux",
		GOARCH:    "amd64",
	})
	report := prober.ClientForStreamWithQtPlatform(context.Background(), "", "", "wayland")
	if got := checkStatus(t, report, "client.graphical-session"); got != StatusPass {
		t.Fatalf("Wayland symlink endpoint status = %q, want %q", got, StatusPass)
	}
	if got := checkStatus(t, report, "client.input"); got != StatusPass {
		t.Fatalf("Wayland symlink input status = %q, want %q", got, StatusPass)
	}
}

func TestStreamPlatformPreflightUsesSelectedEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		goos        string
		platform    string
		files       map[string]bool
		modes       map[string]fs.FileMode
		env         fixtureEnv
		wantDisplay Status
		wantInput   Status
	}{
		{
			name:        "x11 rejects wayland-only session",
			platform:    "x11",
			env:         fixtureEnv{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"},
			wantDisplay: StatusFail,
			wantInput:   StatusFail,
		},
		{
			name:        "x11 uses display-backed input without evdev",
			platform:    "x11",
			env:         fixtureEnv{"DISPLAY": ":0"},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "x11 accepts its endpoint with evdev",
			platform:    "x11",
			files:       fixturePaths(filepath.FromSlash("/dev/input/event0")),
			modes:       fixtureDeviceModes(filepath.FromSlash("/dev/input/event0")),
			env:         fixtureEnv{"DISPLAY": ":0"},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "x11 vaapi uses display-backed input without evdev",
			platform:    "x11_vaapi",
			env:         fixtureEnv{"DISPLAY": ":0"},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "x11 vdpau uses display-backed input without evdev",
			platform:    "x11_vdpau",
			env:         fixtureEnv{"DISPLAY": ":0"},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "sdl kmsdrm requires a device",
			platform:    "sdl",
			env:         fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"},
			wantDisplay: StatusFail,
			wantInput:   StatusFail,
		},
		{
			name:        "sdl kmsdrm accepts direct linux endpoints",
			platform:    "sdl",
			files:       fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			modes:       fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			env:         fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "sdl kmsdrm rejects netbsd",
			goos:        "netbsd",
			platform:    "sdl",
			files:       fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			modes:       fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			env:         fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"},
			wantDisplay: StatusFail,
			wantInput:   StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			goos := tt.goos
			if goos == "" {
				goos = "linux"
			}
			report := fixtureProber(goos, "amd64", tt.files, tt.env, nil, tt.modes).ClientForStream(context.Background(), "", tt.platform)
			if got := checkStatus(t, report, "client.graphical-session"); got != tt.wantDisplay {
				t.Fatalf("graphical-session status = %q, want %q", got, tt.wantDisplay)
			}
			if got := checkStatus(t, report, "client.input"); got != tt.wantInput {
				t.Fatalf("input status = %q, want %q", got, tt.wantInput)
			}
		})
	}
}

func TestDragonFlyKMSDRMRequiresRoot(t *testing.T) {
	t.Parallel()
	files := fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0"))
	modes := fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0"))
	report := fixtureProberWithRoot("dragonfly", "amd64", files, fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, nil, false, modes).ClientForStream(context.Background(), "moonlight-embedded", "sdl")
	if got := checkStatus(t, report, "client.graphical-session"); got != StatusFail {
		t.Fatalf("DragonFly non-root graphical-session status = %q, want %q", got, StatusFail)
	}
	if got := checkSummary(t, report, "client.graphical-session"); !strings.Contains(got, "requires the root user") {
		t.Fatalf("DragonFly non-root summary = %q; want root requirement", got)
	}

	rootReport := fixtureProberWithRoot("dragonfly", "amd64", files, fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, nil, true, modes).ClientForStream(context.Background(), "moonlight-embedded", "sdl")
	if got := checkStatus(t, rootReport, "client.graphical-session"); got != StatusPass {
		t.Fatalf("DragonFly root graphical-session status = %q, want %q", got, StatusPass)
	}
}

func TestQtPlatformPreflightUsesSelectedEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		qtPlatform  string
		files       map[string]bool
		modes       map[string]fs.FileMode
		env         fixtureEnv
		wantDisplay Status
		wantInput   Status
	}{
		{
			name:        "xcb ignores stale Wayland endpoint",
			qtPlatform:  "xcb",
			modes:       fixtureModes(fs.ModeSocket, targetPathJoin("linux", "/tmp/.X11-unix/X0")),
			env:         fixtureEnv{"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "wayland requires its selected socket",
			qtPlatform:  "wayland",
			env:         fixtureEnv{"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"},
			wantDisplay: StatusWarn,
			wantInput:   StatusWarn,
		},
		{
			name:        "eglfs accepts DRM and evdev",
			qtPlatform:  "eglfs",
			files:       fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			modes:       fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "linuxfb accepts framebuffer and evdev",
			qtPlatform:  "linuxfb",
			files:       fixturePaths(filepath.FromSlash("/dev/fb0"), filepath.FromSlash("/dev/input/event0")),
			modes:       fixtureDeviceModes(filepath.FromSlash("/dev/fb0"), filepath.FromSlash("/dev/input/event0")),
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "eglfs fails without a display device",
			qtPlatform:  "eglfs",
			wantDisplay: StatusFail,
			wantInput:   StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			report := fixtureProber("linux", "amd64", tt.files, tt.env, nil, tt.modes).ClientForStreamWithQtPlatform(context.Background(), "", "", tt.qtPlatform)
			if got := checkStatus(t, report, "client.graphical-session"); got != tt.wantDisplay {
				t.Fatalf("graphical-session status = %q, want %q", got, tt.wantDisplay)
			}
			if got := checkStatus(t, report, "client.input"); got != tt.wantInput {
				t.Fatalf("input status = %q, want %q", got, tt.wantInput)
			}
		})
	}
}

func TestAmbientQtPlatformPreflightUsesSelectedClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		preferred   string
		qtPlatform  string
		files       map[string]bool
		modes       map[string]fs.FileMode
		env         fixtureEnv
		commands    map[string]bool
		wantDisplay Status
		wantInput   Status
	}{
		{
			name:        "Qt rejects a headless ambient backend despite X11",
			preferred:   "moonlight-qt",
			env:         fixtureEnv{"DISPLAY": ":0", "QT_QPA_PLATFORM": "offscreen"},
			commands:    map[string]bool{"moonlight-qt": true},
			wantDisplay: StatusFail,
			wantInput:   StatusFail,
		},
		{
			name:        "Qt ambient xcb ignores stale Wayland",
			preferred:   "moonlight-qt",
			env:         fixtureEnv{"DISPLAY": ":0", "WAYLAND_DISPLAY": "../wayland-0", "QT_QPA_PLATFORM": "xcb"},
			commands:    map[string]bool{"moonlight-qt": true},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
		{
			name:        "auto follows the discovered Qt launcher",
			preferred:   "auto",
			env:         fixtureEnv{"DISPLAY": ":0", "QT_QPA_PLATFORM": "offscreen"},
			commands:    map[string]bool{"moonlight-qt": true},
			wantDisplay: StatusFail,
			wantInput:   StatusFail,
		},
		{
			name:        "auto follows the installed Flatpak launcher",
			preferred:   "auto",
			files:       fixturePaths(filepath.Join(string(filepath.Separator), "var", "lib", "flatpak", "app", "com.moonlight_stream.Moonlight")),
			modes:       fixtureModes(fs.ModeDir|0o755, filepath.Join(string(filepath.Separator), "var", "lib", "flatpak", "app", "com.moonlight_stream.Moonlight")),
			env:         fixtureEnv{"DISPLAY": ":0", "QT_QPA_PLATFORM": "offscreen"},
			commands:    map[string]bool{"flatpak": true},
			wantDisplay: StatusFail,
			wantInput:   StatusFail,
		},
		{
			name:        "Embedded ignores Qt ambient backend",
			preferred:   "moonlight-embedded",
			env:         fixtureEnv{"DISPLAY": ":0", "QT_QPA_PLATFORM": "offscreen"},
			commands:    map[string]bool{"moonlight-embedded": true},
			wantDisplay: StatusPass,
			wantInput:   StatusPass,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{paths: tt.commands}
			report := fixtureProber("linux", "amd64", tt.files, tt.env, commands, tt.modes).ClientForStreamWithQtPlatform(context.Background(), tt.preferred, "", tt.qtPlatform)
			if got := checkStatus(t, report, "client.graphical-session"); got != tt.wantDisplay {
				t.Fatalf("graphical-session status = %q, want %q", got, tt.wantDisplay)
			}
			if got := checkStatus(t, report, "client.input"); got != tt.wantInput {
				t.Fatalf("input status = %q, want %q", got, tt.wantInput)
			}
		})
	}
}

func TestInputPathChecks(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		goos  string
		files map[string]bool
		modes map[string]fs.FileMode
		env   fixtureEnv
		want  Status
	}{
		{name: "wayland", modes: fixtureModes(fs.ModeSocket, targetPathJoin("linux", "/run/user/1000", "wayland-0")), env: fixtureEnv{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, want: StatusPass},
		{name: "wayland-without-runtime-root", env: fixtureEnv{"WAYLAND_DISPLAY": "wayland-0"}, want: StatusPass},
		{name: "wayland-runtime-socket-missing", env: fixtureEnv{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, want: StatusWarn},
		{name: "x11", modes: fixtureModes(fs.ModeSocket, targetPathJoin("linux", "/tmp/.X11-unix/X0")), env: fixtureEnv{"DISPLAY": ":0"}, want: StatusPass},
		{name: "malformed-wayland", env: fixtureEnv{"WAYLAND_DISPLAY": "../wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, want: StatusWarn},
		{name: "malformed-x11", env: fixtureEnv{"DISPLAY": ":not-a-display"}, want: StatusWarn},
		{name: "sdl-kmsdrm-with-evdev", files: fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusPass},
		{name: "freebsd-sdl-kmsdrm-wscons-only", goos: "freebsd", files: fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusWarn},
		{name: "openbsd-sdl-kmsdrm-with-wscons", goos: "openbsd", files: fixturePaths(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusPass},
		{name: "openbsd-sdl-kmsdrm-without-wscons-mouse", goos: "openbsd", files: fixturePaths(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusWarn},
		{name: "netbsd-sdl-kmsdrm-unsupported", goos: "netbsd", files: fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusWarn},
		{name: "sdl-kmsdrm-without-evdev", files: fixturePaths(filepath.FromSlash("/dev/dri/card0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: StatusWarn},
		{name: "type-only", env: fixtureEnv{"XDG_SESSION_TYPE": "wayland"}, want: StatusWarn},
		{name: "headless", want: StatusWarn},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			goos := tt.goos
			if goos == "" {
				goos = "linux"
			}
			got := checkStatus(t, fixtureProber(goos, "amd64", tt.files, tt.env, nil, tt.modes).Client(context.Background()), "client.input")
			if got != tt.want {
				t.Fatalf("input status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDirectDeviceChecksRequireReadWriteAccess(t *testing.T) {
	t.Parallel()
	newWritableProber := func(goos string, env fixtureEnv, paths []string, denied ...string) *Prober {
		openErrors := make(map[string]error, len(denied))
		for _, path := range denied {
			openErrors[fixturePath(path)] = errors.New("permission denied")
		}
		return New(Dependencies{
			FS: fixtureWritableFS{
				fixtureFS: fixtureFS{
					paths: fixturePaths(paths...),
					modes: fixtureDeviceModes(paths...),
				},
				openReadWriteErrors: openErrors,
			},
			Env:    env,
			GOOS:   goos,
			GOARCH: "amd64",
		})
	}

	t.Run("Linux evdev", func(t *testing.T) {
		path := filepath.FromSlash("/dev/input/event0")
		if !newWritableProber("linux", nil, []string{path}).directEvdevInputAvailable() {
			t.Fatal("read/write-accessible evdev device was rejected")
		}
		if newWritableProber("linux", nil, []string{path}, path).directEvdevInputAvailable() {
			t.Fatal("read-only-only evdev device was accepted")
		}
	})

	t.Run("OpenBSD WSCONS", func(t *testing.T) {
		keyboard := filepath.FromSlash("/dev/wskbd0")
		mouse := filepath.FromSlash("/dev/wsmouse")
		paths := []string{keyboard, mouse}
		if !newWritableProber("openbsd", nil, paths).wsconsInputAvailable() {
			t.Fatal("read/write-accessible WSCONS devices were rejected")
		}
		if newWritableProber("openbsd", nil, paths, keyboard).wsconsInputAvailable() {
			t.Fatal("read-only-only WSCONS keyboard was accepted")
		}
	})

	t.Run("DRM", func(t *testing.T) {
		path := filepath.FromSlash("/dev/dri/card0")
		env := fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}
		if _, ok := newWritableProber("linux", env, []string{path}).directDisplayBackend(); !ok {
			t.Fatal("read/write-accessible DRM device was rejected")
		}
		if _, ok := newWritableProber("linux", env, []string{path}, path).directDisplayBackend(); ok {
			t.Fatal("read-only-only DRM device was accepted")
		}
	})

	t.Run("Qt Linux framebuffer", func(t *testing.T) {
		path := filepath.FromSlash("/dev/fb0")
		env := fixtureEnv{"QT_QPA_PLATFORM": "linuxfb"}
		if _, ok := newWritableProber("linux", env, []string{path}).directQtDisplayBackend("linuxfb"); !ok {
			t.Fatal("read/write-accessible framebuffer device was rejected")
		}
		if _, ok := newWritableProber("linux", env, []string{path}, path).directQtDisplayBackend("linuxfb"); ok {
			t.Fatal("read-only-only framebuffer device was accepted")
		}
		if _, ok := newWritableProber("linux", env, []string{path}).directDisplayBackend(); !ok {
			t.Fatal("read/write-accessible ambient framebuffer device was rejected")
		}
		if _, ok := newWritableProber("linux", env, []string{path}, path).directDisplayBackend(); ok {
			t.Fatal("read-only-only ambient framebuffer device was accepted")
		}
	})
}

func TestInputPathReportsBackendSpecificEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		goos   string
		files  map[string]bool
		modes  map[string]fs.FileMode
		env    fixtureEnv
		want   string
		absent string
	}{
		{
			name:   "linux evdev",
			goos:   "linux",
			files:  fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			modes:  fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")),
			env:    fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"},
			want:   "has an evdev input endpoint",
			absent: "WSCONS",
		},
		{
			name:   "openbsd wscons",
			goos:   "openbsd",
			files:  fixturePaths(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")),
			modes:  fixtureDeviceModes(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")),
			env:    fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"},
			want:   "has a WSCONS input endpoint",
			absent: "evdev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkSummary(t, fixtureProber(tt.goos, "amd64", tt.files, tt.env, nil, tt.modes).Client(context.Background()), "client.input")
			if !strings.Contains(got, tt.want) {
				t.Fatalf("input summary = %q, want substring %q", got, tt.want)
			}
			if strings.Contains(got, tt.absent) {
				t.Fatalf("input summary = %q, unexpectedly contains %q", got, tt.absent)
			}
		})
	}
}

func TestClientReadinessRequiresReachableGraphicalSession(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		goos  string
		files map[string]bool
		modes map[string]fs.FileMode
		env   fixtureEnv
		want  bool
	}{
		{name: "display endpoint", modes: fixtureModes(fs.ModeSocket, targetPathJoin("linux", "/tmp/.X11-unix/X0")), env: fixtureEnv{"DISPLAY": ":0"}, want: true},
		{name: "wayland endpoint", modes: fixtureModes(fs.ModeSocket, targetPathJoin("linux", "/run/user/1000", "wayland-0")), env: fixtureEnv{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, want: true},
		{name: "direct SDL endpoint", files: fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: true},
		{name: "FreeBSD evdev endpoint", goos: "freebsd", files: fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/input/event0")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: true},
		{name: "FreeBSD WSCONS-only endpoint", goos: "freebsd", files: fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: false},
		{name: "OpenBSD WSCONS endpoint", goos: "openbsd", files: fixturePaths(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/drm0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: true},
		{name: "NetBSD unsupported SDL endpoint", goos: "netbsd", files: fixturePaths(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), modes: fixtureDeviceModes(filepath.FromSlash("/dev/dri/card0"), filepath.FromSlash("/dev/wskbd0"), filepath.FromSlash("/dev/wsmouse")), env: fixtureEnv{"SDL_VIDEODRIVER": "kmsdrm"}, want: false},
		{name: "session type without endpoint", env: fixtureEnv{"XDG_SESSION_TYPE": "wayland"}, want: false},
		{name: "headless", env: nil, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{paths: map[string]bool{"moonlight": true}}
			goos := tt.goos
			if goos == "" {
				goos = "linux"
			}
			report := fixtureProber(goos, "amd64", tt.files, tt.env, commands, tt.modes).Client(context.Background())
			if got := report.Ready(); got != tt.want {
				t.Fatalf("client readiness = %v, want %v; report = %+v", got, tt.want, report)
			}
		})
	}
}

func TestClientControlReadinessAllowsHeadlessControlOperations(t *testing.T) {
	t.Parallel()
	report := Report{
		SchemaVersion: SchemaVersion,
		Profile:       ProfileClient,
		OS:            "linux",
		Architecture:  "amd64",
		Status:        StatusFail,
		Checks: []Check{
			{ID: "client.platform", Status: StatusPass},
			{ID: "client.graphical-session", Status: StatusFail},
			{ID: "client.input", Status: StatusWarn},
			{ID: "client.moonlight", Status: StatusPass},
			{ID: "client.audio", Status: StatusWarn},
			{ID: "client.decoder-tools", Status: StatusWarn},
		},
	}
	if !report.ReadyForControl() {
		t.Fatalf("headless control report was rejected: %+v", report)
	}
	if report.Ready() {
		t.Fatalf("headless control report was accepted as stream-ready: %+v", report)
	}
	emptyPass := Report{Profile: ProfileClient, Status: StatusPass}
	if emptyPass.Ready() {
		t.Fatalf("incomplete pass report was accepted as stream-ready: %+v", emptyPass)
	}
	incompletePass := report
	incompletePass.Status = StatusPass
	incompletePass.Checks = append([]Check(nil), report.Checks[:3]...)
	if incompletePass.Ready() {
		t.Fatalf("incomplete pass report was accepted as stream-ready: %+v", incompletePass)
	}
	staleSchema := report
	staleSchema.SchemaVersion = SchemaVersion - 1
	if staleSchema.ReadyForControl() {
		t.Fatalf("stale-schema report was accepted for control readiness: %+v", staleSchema)
	}
	wrongPlatform := report
	wrongPlatform.OS = "windows"
	if wrongPlatform.ReadyForControl() {
		t.Fatalf("wrong-platform report was accepted for control readiness: %+v", wrongPlatform)
	}
	wrongArchitecture := report
	wrongArchitecture.Architecture = "386"
	if wrongArchitecture.ReadyForControl() {
		t.Fatalf("wrong-architecture report was accepted for control readiness: %+v", wrongArchitecture)
	}
	nonClient := report
	nonClient.Profile = ProfileCompatibility
	nonClient.Status = StatusPass
	if nonClient.ReadyForControl() {
		t.Fatalf("non-client report was accepted for control readiness: %+v", nonClient)
	}

	for _, id := range []string{"client.platform", "client.moonlight"} {
		checks := append([]Check(nil), report.Checks...)
		for index := range checks {
			if checks[index].ID == id {
				checks[index].Status = StatusFail
			}
		}
		blocked := report
		blocked.Checks = checks
		if blocked.ReadyForControl() {
			t.Fatalf("control readiness ignored required failure %q: %+v", id, blocked)
		}
	}
	missingGraphical := report
	missingGraphical.Checks = append(append([]Check(nil), report.Checks[:1]...), report.Checks[2:]...)
	if missingGraphical.ReadyForControl() {
		t.Fatalf("control readiness accepted a report without the graphical-session check: %+v", missingGraphical)
	}
	unrelatedFailure := report
	unrelatedFailure.Checks = append([]Check(nil), report.Checks...)
	unrelatedFailure.Checks[3].Status = StatusFail
	if unrelatedFailure.ReadyForControl() {
		t.Fatalf("control readiness ignored an unrelated failure: %+v", unrelatedFailure)
	}
	inconsistent := report
	inconsistent.Status = StatusPass
	if inconsistent.ReadyForControl() {
		t.Fatalf("control readiness accepted an inconsistent aggregate status: %+v", inconsistent)
	}

	missingAdvisory := report
	missingAdvisory.Checks = append([]Check(nil), report.Checks[:3]...)
	if missingAdvisory.ReadyForControl() {
		t.Fatalf("control readiness accepted a report without advisory client checks: %+v", missingAdvisory)
	}
	unknownCheck := report
	unknownCheck.Checks = append([]Check(nil), report.Checks...)
	unknownCheck.Checks[0].ID = "client.unknown"
	if unknownCheck.ReadyForControl() {
		t.Fatalf("control readiness accepted an unknown client check: %+v", unknownCheck)
	}
	duplicateCheck := report
	duplicateCheck.Checks = append([]Check(nil), report.Checks...)
	duplicateCheck.Checks[4].ID = duplicateCheck.Checks[0].ID
	if duplicateCheck.ReadyForControl() {
		t.Fatalf("control readiness accepted duplicate client checks: %+v", duplicateCheck)
	}
}

func TestMalformedDisplayOnlyBlocksLiveStreaming(t *testing.T) {
	t.Parallel()
	commands := &fixtureCommands{paths: map[string]bool{"moonlight": true}}
	report := fixtureProber("linux", "amd64", nil, fixtureEnv{"DISPLAY": ":not-a-display"}, commands).Client(context.Background())
	if !report.ReadyForControl() {
		t.Fatalf("malformed display blocked control readiness: %+v", report)
	}
	if report.Ready() {
		t.Fatalf("malformed display was accepted for live streaming: %+v", report)
	}
}

func TestMoonlightDiscoveryDoesNotExecuteIt(t *testing.T) {
	t.Parallel()
	flatpakSystem := filepath.Join(string(filepath.Separator), "var", "lib", filepath.FromSlash("flatpak/app/com.moonlight_stream.Moonlight"))
	flatpakUser := filepath.Join(filepath.FromSlash("/home/fixture-user"), ".local", "share", filepath.FromSlash("flatpak/app/com.moonlight_stream.Moonlight"))
	flatpakXDG := filepath.Join(filepath.FromSlash("/opt/fixture/share"), "flatpak", filepath.FromSlash("app/com.moonlight_stream.Moonlight"))
	flatpakCustomUser := targetPathJoin("linux", "/opt/fixture/flatpak-user", "app/com.moonlight_stream.Moonlight")
	flatpakCustomSystem := targetPathJoin("linux", "/opt/fixture/flatpak-system", "app/com.moonlight_stream.Moonlight")
	knownExecutable := filepath.Join(filepath.FromSlash("/usr/local/bin"), "moonlight-qt")
	for _, tt := range []struct {
		name    string
		paths   map[string]bool
		files   map[string]bool
		modes   map[string]fs.FileMode
		env     fixtureEnv
		want    Status
		summary string
	}{
		{"binary", map[string]bool{"moonlight": true}, nil, nil, nil, StatusPass, "Moonlight Qt is available."},
		{"qt-binary", map[string]bool{"moonlight-qt": true}, nil, nil, nil, StatusPass, "Moonlight Qt is available."},
		{"known-executable-not-on-path", nil, fixturePaths(knownExecutable), nil, nil, StatusWarn, "cannot resolve"},
		{"system-flatpak", map[string]bool{"flatpak": true}, nil, fixtureModes(fs.ModeDir|0o755, flatpakSystem), nil, StatusPass, "PATH-resolvable Flatpak"},
		{"user-flatpak", map[string]bool{"flatpak": true}, nil, fixtureModes(fs.ModeDir|0o755, flatpakUser), fixtureEnv{"HOME": "/home/fixture-user"}, StatusPass, "PATH-resolvable Flatpak"},
		{"xdg-data-dirs-flatpak", map[string]bool{"flatpak": true}, nil, fixtureModes(fs.ModeDir|0o755, flatpakXDG), fixtureEnv{"XDG_DATA_DIRS": "/opt/fixture/share:/usr/share"}, StatusPass, "PATH-resolvable Flatpak"},
		{"custom-user-flatpak-root", map[string]bool{"flatpak": true}, nil, fixtureModes(fs.ModeDir|0o755, flatpakCustomUser), fixtureEnv{"FLATPAK_USER_DIR": "/opt/fixture/flatpak-user"}, StatusPass, "PATH-resolvable Flatpak"},
		{"custom-system-flatpak-root", map[string]bool{"flatpak": true}, nil, fixtureModes(fs.ModeDir|0o755, flatpakCustomSystem), fixtureEnv{"FLATPAK_SYSTEM_DIR": "/opt/fixture/flatpak-system:/usr/lib/flatpak"}, StatusPass, "PATH-resolvable Flatpak"},
		{"flatpak-app-without-launcher", nil, nil, fixtureModes(fs.ModeDir|0o755, flatpakSystem), nil, StatusWarn, "cannot resolve flatpak"},
		{"missing", nil, nil, nil, nil, StatusFail, "not detected"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{paths: tt.paths}
			report := fixtureProber("linux", "amd64", tt.files, tt.env, commands, tt.modes).Client(context.Background())
			check, _ := report.Check("client.moonlight")
			if check.Status != tt.want || !strings.Contains(check.Summary, tt.summary) {
				t.Fatalf("Moonlight check = %+v", check)
			}
			if check.Status == StatusWarn {
				launcherOnly := Report{Profile: ProfileClient, Status: StatusWarn, Checks: []Check{check}}
				if launcherOnly.Ready() {
					t.Fatalf("non-launchable Moonlight evidence was treated as ready: %+v", check)
				}
			}
			if calls := commands.recordedCalls(); len(calls) != 0 {
				t.Fatalf("discovery executed commands: %+v", calls)
			}
		})
	}
}

func TestMoonlightDiagnosticSelectionMatchesUnixPackageConvention(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		goos     string
		commands map[string]bool
		want     string
	}{
		{name: "linux prefers qt", goos: "linux", commands: map[string]bool{"moonlight": true, "moonlight-qt": true}, want: "Moonlight Qt is available."},
		{name: "freebsd prefers qt when both exist", goos: "freebsd", commands: map[string]bool{"moonlight": true, "moonlight-qt": true}, want: "Moonlight Qt is available."},
		{name: "openbsd prefers qt when both exist", goos: "openbsd", commands: map[string]bool{"moonlight": true, "moonlight-qt": true}, want: "Moonlight Qt is available."},
		{name: "netbsd prefers qt when both exist", goos: "netbsd", commands: map[string]bool{"moonlight": true, "moonlight-qt": true}, want: "Moonlight Qt is available."},
		{name: "dragonfly prefers qt when both exist", goos: "dragonfly", commands: map[string]bool{"moonlight": true, "moonlight-qt": true}, want: "Moonlight Qt is available."},
		{name: "freebsd generic is embedded", goos: "freebsd", commands: map[string]bool{"moonlight": true}, want: "Moonlight Embedded is available."},
		{name: "dragonfly generic is embedded", goos: "dragonfly", commands: map[string]bool{"moonlight": true}, want: "Moonlight Embedded is available."},
		{name: "linux generic follows qt convention", goos: "linux", commands: map[string]bool{"moonlight": true}, want: "Moonlight Qt is available."},
		{name: "explicit embedded executable name", goos: "linux", commands: map[string]bool{"moonlight-embedded": true}, want: "Moonlight Embedded is available."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			check := fixtureProber(tt.goos, "amd64", nil, nil, &fixtureCommands{paths: tt.commands}).moonlightCheck()
			if check.Status != StatusPass || check.Summary != tt.want {
				t.Fatalf("Moonlight check = %+v, want pass/%q", check, tt.want)
			}
		})
	}
}

func TestMoonlightDiagnosticSelectionHonorsRequestedClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		goos       string
		preferred  string
		commands   map[string]bool
		wantStatus Status
		wantText   string
	}{
		{
			name:       "explicit Qt accepts Linux generic executable",
			goos:       "linux",
			preferred:  "moonlight-qt",
			commands:   map[string]bool{"moonlight": true},
			wantStatus: StatusPass,
			wantText:   "selected client setting",
		},
		{
			name:       "explicit Qt rejects FreeBSD generic Embedded executable",
			goos:       "freebsd",
			preferred:  "moonlight-qt",
			commands:   map[string]bool{"moonlight": true},
			wantStatus: StatusFail,
			wantText:   "not detected",
		},
		{
			name:       "explicit Embedded rejects only Qt executable",
			goos:       "linux",
			preferred:  "moonlight-embedded",
			commands:   map[string]bool{"moonlight-qt": true},
			wantStatus: StatusFail,
			wantText:   "not detected",
		},
		{
			name:       "explicit Embedded rejects Linux generic Qt executable",
			goos:       "linux",
			preferred:  "moonlight-embedded",
			commands:   map[string]bool{"moonlight": true},
			wantStatus: StatusFail,
			wantText:   "not detected",
		},
		{
			name:       "explicit Embedded accepts FreeBSD generic executable",
			goos:       "freebsd",
			preferred:  "moonlight-embedded",
			commands:   map[string]bool{"moonlight": true},
			wantStatus: StatusPass,
			wantText:   "selected client setting",
		},
		{
			name:       "explicit Embedded accepts flavor executable",
			goos:       "linux",
			preferred:  "moonlight-embedded",
			commands:   map[string]bool{"moonlight-embedded": true},
			wantStatus: StatusPass,
			wantText:   "selected client setting",
		},
		{
			name:       "explicit generic reports its Embedded execution flavor",
			goos:       "linux",
			preferred:  "moonlight",
			commands:   map[string]bool{"moonlight": true},
			wantStatus: StatusPass,
			wantText:   "Moonlight Embedded",
		},
		{
			name:       "invalid selection",
			goos:       "linux",
			preferred:  "unsupported",
			wantStatus: StatusFail,
			wantText:   "not recognized",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			check := fixtureProber(tt.goos, "amd64", nil, nil, &fixtureCommands{paths: tt.commands}).moonlightCheck(tt.preferred)
			if check.Status != tt.wantStatus || !strings.Contains(check.Summary, tt.wantText) {
				t.Fatalf("Moonlight check = %+v, want %q/%q", check, tt.wantStatus, tt.wantText)
			}
		})
	}
}

func TestAutomaticGenericMoonlightPreflightUsesQtConvention(t *testing.T) {
	t.Parallel()
	commands := &fixtureCommands{paths: map[string]bool{"moonlight": true}}
	prober := fixtureProber("linux", "amd64", nil, fixtureEnv{
		"DISPLAY":         ":0",
		"QT_QPA_PLATFORM": "offscreen",
	}, commands)
	automatic := prober.ClientForAutomatic(context.Background(), "moonlight", "", "")
	if got := checkStatus(t, automatic, "client.graphical-session"); got != StatusFail {
		t.Fatalf("automatic generic Qt graphical-session status = %q, want fail for offscreen", got)
	}
	if summary := checkSummary(t, automatic, "client.moonlight"); !strings.Contains(summary, "Moonlight Qt") {
		t.Fatalf("automatic generic Moonlight summary = %q, want Qt flavor", summary)
	}
	explicit := prober.ClientFor(context.Background(), "moonlight")
	if summary := checkSummary(t, explicit, "client.moonlight"); !strings.Contains(summary, "Moonlight Embedded") {
		t.Fatalf("explicit generic Moonlight summary = %q, want Embedded alias", summary)
	}
}

func TestMoonlightDiagnosticSelectionRequiresInstalledFlatpakApp(t *testing.T) {
	t.Parallel()
	flatpakApp := targetPathJoin("linux", "/var/lib/flatpak/app/com.moonlight_stream.Moonlight")
	tests := []struct {
		name       string
		files      map[string]bool
		modes      map[string]fs.FileMode
		wantStatus Status
		wantText   string
	}{
		{
			name:       "launcher and app",
			modes:      fixtureModes(fs.ModeDir|0o755, flatpakApp),
			wantStatus: StatusPass,
			wantText:   "PATH-resolvable Flatpak",
		},
		{
			name:       "launcher without app",
			wantStatus: StatusFail,
			wantText:   "app is not installed",
		},
		{
			name:       "app without launcher",
			modes:      fixtureModes(fs.ModeDir|0o755, flatpakApp),
			wantStatus: StatusWarn,
			wantText:   "cannot be resolved through PATH",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{}
			if tt.name != "app without launcher" {
				commands.paths = map[string]bool{"flatpak": true}
			}
			check := fixtureProber("linux", "amd64", tt.files, nil, commands, tt.modes).moonlightCheck("flatpak")
			if check.Status != tt.wantStatus || !strings.Contains(check.Summary, tt.wantText) {
				t.Fatalf("Moonlight check = %+v, want %q/%q", check, tt.wantStatus, tt.wantText)
			}
			if calls := commands.recordedCalls(); len(calls) != 0 {
				t.Fatalf("Flatpak selection executed commands: %+v", calls)
			}
		})
	}
}

func TestMoonlightDiagnosticRejectsFlatpakOnBSD(t *testing.T) {
	t.Parallel()
	flatpakApp := filepath.Join(string(filepath.Separator), "var", "lib", filepath.FromSlash("flatpak/app/com.moonlight_stream.Moonlight"))
	for _, goos := range []string{"freebsd", "openbsd", "netbsd", "dragonfly"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{paths: map[string]bool{"flatpak": true}}
			check := fixtureProber(goos, "amd64", nil, nil, commands, fixtureModes(fs.ModeDir|0o755, flatpakApp)).moonlightCheck()
			if check.Status != StatusFail || !strings.Contains(check.Summary, "Linux-only runtime") {
				t.Fatalf("BSD Flatpak check = %+v; want Linux-only failure", check)
			}
			if calls := commands.recordedCalls(); len(calls) != 0 {
				t.Fatalf("BSD Flatpak selection executed commands: %+v", calls)
			}
		})
	}
}

func TestAudioIndicatorsByPlatform(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		goos  string
		env   fixtureEnv
		files map[string]bool
		want  Status
	}{
		{"pipewire-env", "linux", fixtureEnv{"PIPEWIRE_REMOTE": "pipewire-0"}, nil, StatusPass},
		{"runtime-socket", "linux", fixtureEnv{"XDG_RUNTIME_DIR": "/run/user/1000"}, fixturePaths(filepath.Join(filepath.FromSlash("/run/user/1000"), "pulse", "native")), StatusPass},
		{"linux-device", "linux", nil, fixturePaths(filepath.FromSlash("/dev/snd")), StatusPass},
		{"bsd-device", "freebsd", nil, fixturePaths(filepath.FromSlash("/dev/dsp")), StatusPass},
		{"missing", "openbsd", nil, nil, StatusWarn},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkStatus(t, fixtureProber(tt.goos, "amd64", tt.files, tt.env, nil).Client(context.Background()), "client.audio")
			if got != tt.want {
				t.Fatalf("audio status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOptionalDecoderUtilities(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"vainfo", "vdpauinfo", "ffmpeg"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{paths: map[string]bool{name: true}}
			got := checkStatus(t, fixtureProber("linux", "amd64", nil, nil, commands).Client(context.Background()), "client.decoder-tools")
			if got != StatusPass {
				t.Fatalf("decoder status = %q", got)
			}
		})
	}
	got := checkStatus(t, fixtureProber("linux", "amd64", nil, nil, nil).Client(context.Background()), "client.decoder-tools")
	if got != StatusWarn {
		t.Fatalf("missing decoder status = %q", got)
	}
}

func TestReportStatusAndProfileDispatch(t *testing.T) {
	t.Parallel()
	prober := fixtureProber("linux", "amd64", nil, nil, nil)
	report := prober.Client(context.Background())
	if report.SchemaVersion != SchemaVersion || report.Profile != ProfileClient || report.Status != StatusFail || report.Ready() {
		t.Fatalf("unexpected report: %+v", report)
	}
	unknown := prober.Run(context.Background(), Profile("fixture-unknown"))
	if unknown.Status != StatusFail || len(unknown.Checks) != 1 {
		t.Fatalf("unexpected unknown profile report: %+v", unknown)
	}
}

func TestWindowsHostCompleteFixtureStillBlocksOnUnverifiedPrerequisites(t *testing.T) {
	t.Parallel()
	prober, commands := readyWindowsFixture(t)
	report := prober.WindowsHost(context.Background())
	if report.Status != StatusWarn || report.Ready() {
		t.Fatalf("host report status/ready = %q/%v; checks: %+v", report.Status, report.Ready(), report.Checks)
	}
	if got := len(report.Checks); got != 10 {
		t.Fatalf("host check count = %d, want 10", got)
	}
	for _, call := range commands.recordedCalls() {
		if !validCommandArguments(strings.ToLower(call.name), call.args) {
			t.Fatalf("probe requested non-allowlisted command: %+v", call)
		}
	}
}

func TestWindowsVersionEvidence(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		product     string
		installType string
		build       string
		omitBuild   bool
		want        Status
	}{
		{"windows-11", "Windows 11 Pro", "Client", "26100", false, StatusPass},
		{"windows-11-stale-product-name", "Windows 10 Pro", "Client", "26100", false, StatusPass},
		{"windows-11-build-before-release", "Windows 11 Pro", "Client", "19041", false, StatusFail},
		{"windows-10-outside-sunshine-baseline", "Windows 10 Home", "Client", "19041", false, StatusFail},
		{"server", "Windows Server 2025", "Server", "26100", false, StatusFail},
		{"enterprise", "Windows 11 Enterprise", "Client", "26100", false, StatusFail},
		{"old-build", "Windows 10 Pro", "Client", "19040", false, StatusFail},
		{"missing-evidence", "Windows 11 Pro", "Client", "", true, StatusFail},
		{"malformed-build", "Windows 11 Pro", "Client", "secret", false, StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{results: map[string]CommandResult{}}
			addRegistry(commands, windowsVersionKey, "ProductName", tt.product)
			addRegistry(commands, windowsVersionKey, "InstallationType", tt.installType)
			if !tt.omitBuild {
				addRegistry(commands, windowsVersionKey, "CurrentBuildNumber", tt.build)
			}
			prober := fixtureProber("windows", "amd64", nil, nil, commands)
			got := pCheck(t, prober.windowsVersionCheck(context.Background())).Status
			if got != tt.want {
				t.Fatalf("version status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPhysicalHostClassifiesVMIndicatorsByEvidenceStrength(t *testing.T) {
	t.Parallel()
	for _, firmware := range []string{
		"QEMU Standard PC", "VMware Virtual Platform", "VirtualBox", "Microsoft Corporation Virtual Machine",
		"KVM", "Xen HVM domU", "Parallels Virtual Platform", "bhyve",
	} {
		t.Run(firmware, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{results: map[string]CommandResult{}}
			addRegistry(commands, windowsBIOSKey, "SystemManufacturer", firmware)
			got := fixtureProber("windows", "amd64", nil, nil, commands).physicalHostCheck(context.Background())
			if got.Status != StatusFail {
				t.Fatalf("VM firmware %q status = %q", firmware, got.Status)
			}
		})
	}

	commands := &fixtureCommands{results: map[string]CommandResult{}}
	addRegistry(commands, windowsBIOSKey, "SystemManufacturer", "Fixture Hardware Inc")
	driver := filepath.Join(`C:\Windows`, "System32", "drivers", "VBoxGuest.sys")
	prober := fixtureProber("windows", "amd64", fixturePaths(driver), nil, commands)
	if got := prober.physicalHostCheck(context.Background()); got.Status != StatusWarn {
		t.Fatalf("guest driver status = %q", got.Status)
	}
}

func TestPhysicalHostUnverifiedAndBareMetalEvidence(t *testing.T) {
	t.Parallel()
	missing := fixtureProber("windows", "amd64", nil, nil, &fixtureCommands{})
	if got := missing.physicalHostCheck(context.Background()); got.Status != StatusWarn {
		t.Fatalf("missing firmware status = %q", got.Status)
	}
	commands := &fixtureCommands{results: map[string]CommandResult{}}
	addRegistry(commands, windowsBIOSKey, "SystemManufacturer", "Framework")
	addRegistry(commands, windowsBIOSKey, "SystemProductName", "Laptop 16")
	bare := fixtureProber("windows", "amd64", nil, nil, commands)
	if got := bare.physicalHostCheck(context.Background()); got.Status != StatusWarn {
		t.Fatalf("bare-metal evidence status = %q", got.Status)
	}
}

func TestWindowsRequiredComponentsFailIndependently(t *testing.T) {
	t.Parallel()
	prober := fixtureProber("windows", "amd64", nil, fixtureEnv{
		"ProgramFiles":      `C:\Program Files`,
		"ProgramFiles(x86)": `C:\Program Files (x86)`,
		"SystemDrive":       `C:`,
	}, &fixtureCommands{})
	report := prober.WindowsHost(context.Background())
	for _, id := range []string{"host.riot-client", "host.league", "host.vanguard-service", "host.sunshine"} {
		if got := checkStatus(t, report, id); got != StatusFail {
			t.Errorf("%s status = %q, want fail", id, got)
		}
	}
}

func TestServicePresenceUsesReadOnlyServiceState(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		state observedServiceState
		err   error
		want  bool
	}{
		{"registered", serviceRegistered, nil, true},
		{"running", serviceRunning, nil, true},
		{"missing", serviceUnavailable, nil, false},
		{"error", serviceUnavailable, errors.New("fixture secret error"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{
				serviceStates: map[string]observedServiceState{"vgk": tt.state},
				serviceErrors: map[string]error{"vgk": tt.err},
			}
			got := fixtureProber("windows", "amd64", nil, nil, commands).serviceExists(context.Background(), "vgk")
			if got != tt.want {
				t.Fatalf("serviceExists = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVanguardRequiresBothRunningServices(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		vgk  observedServiceState
		vgc  observedServiceState
		want Status
	}{
		{"both running", serviceRunning, serviceRunning, StatusPass},
		{"both registered", serviceRegistered, serviceRegistered, StatusWarn},
		{"kernel-only", serviceRegistered, serviceUnavailable, StatusFail},
		{"user-mode-only", serviceUnavailable, serviceRegistered, StatusFail},
		{"neither", serviceUnavailable, serviceUnavailable, StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{serviceStates: map[string]observedServiceState{}}
			if tt.vgk != serviceUnavailable {
				commands.serviceStates["vgk"] = tt.vgk
			}
			if tt.vgc != serviceUnavailable {
				commands.serviceStates["vgc"] = tt.vgc
			}
			got := fixtureProber("windows", "amd64", nil, nil, commands).vanguardServiceCheck(context.Background()).Status
			if got != tt.want {
				t.Fatalf("Vanguard status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVanguardServiceCheckDistinguishesInstallerOnlyState(t *testing.T) {
	t.Parallel()
	programFiles := `C:\Program Files`
	files := fixturePaths(targetPathJoin("windows", programFiles, "Riot Vanguard", "installer.exe"))
	prober := fixtureProber("windows", "amd64", files, fixtureEnv{
		"ProgramFiles":      programFiles,
		"ProgramFiles(x86)": `C:\Program Files (x86)`,
		"SystemDrive":       `C:`,
	}, &fixtureCommands{})

	check := prober.vanguardServiceCheck(context.Background())
	if check.Status != StatusFail {
		t.Fatalf("Vanguard status = %q, want %q", check.Status, StatusFail)
	}
	if !strings.Contains(check.Summary, "installer executable is present") || !strings.Contains(check.Summary, "does not prove") {
		t.Fatalf("Vanguard summary = %q; want installer-only distinction", check.Summary)
	}
}

func TestSunshineServiceCheckDistinguishesStoppedService(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		state observedServiceState
		want  Status
	}{
		{"running", serviceRunning, StatusPass},
		{"registered but stopped", serviceRegistered, StatusWarn},
		{"missing", serviceUnavailable, StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			commands := &fixtureCommands{serviceStates: map[string]observedServiceState{}}
			if tt.state != serviceUnavailable {
				commands.serviceStates["sunshineservice"] = tt.state
			}
			check := fixtureProber("windows", "amd64", nil, nil, commands).sunshineCheck(context.Background())
			if check.Status != tt.want {
				t.Fatalf("Sunshine status = %q, want %q: %+v", check.Status, tt.want, check)
			}
			if tt.state == serviceRegistered && !strings.Contains(check.Summary, "did not report it as running") {
				t.Fatalf("stopped Sunshine summary = %q", check.Summary)
			}
		})
	}
}

func TestReportsDoNotExposeFixtureSecrets(t *testing.T) {
	t.Parallel()
	secret := "ULTRA-SECRET-user-path-and-command-output"
	commands := &fixtureCommands{
		paths: map[string]bool{"moonlight": true},
		results: map[string]CommandResult{
			commandKey("reg.exe", "query", windowsVersionKey, "/v", "ProductName"): {Output: secret, ExitCode: 0},
		},
		serviceErrors: map[string]error{"vgk": errors.New(secret)},
	}
	prober := fixtureProber("windows", "amd64", nil, fixtureEnv{
		"HOME":         `C:\` + secret,
		"ProgramFiles": `C:\` + secret,
		"DISPLAY":      secret,
	}, commands)
	encoded, err := json.Marshal(prober.WindowsHost(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("report exposed fixture secret: %s", encoded)
	}
}

func TestCommandTimeoutIsApplied(t *testing.T) {
	t.Parallel()
	commands := &fixtureCommands{block: true}
	prober := New(Dependencies{
		FS:             fixtureFS{paths: map[string]bool{}},
		Env:            fixtureEnv{},
		Commands:       commands,
		GOOS:           "windows",
		GOARCH:         "amd64",
		CommandTimeout: 10 * time.Millisecond,
	})
	started := time.Now()
	_, err := prober.run(context.Background(), "reg.exe", "query", windowsVersionKey, "/v", "ProductName")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded command took too long: %s", elapsed)
	}
}

func TestCommandTimeoutHasSafeDefaultsAndCeiling(t *testing.T) {
	t.Parallel()
	defaults := New(Dependencies{FS: fixtureFS{}, Env: fixtureEnv{}, Commands: &fixtureCommands{}})
	if defaults.timeout != defaultCommandTimeout {
		t.Fatalf("default timeout = %s, want %s", defaults.timeout, defaultCommandTimeout)
	}
	capped := New(Dependencies{FS: fixtureFS{}, Env: fixtureEnv{}, Commands: &fixtureCommands{}, CommandTimeout: time.Hour})
	if capped.timeout != maximumCommandTimeout {
		t.Fatalf("capped timeout = %s, want %s", capped.timeout, maximumCommandTimeout)
	}
}

func TestSystemCommandAllowlist(t *testing.T) {
	t.Parallel()
	valid := []struct {
		name string
		args []string
	}{
		{"reg.exe", []string{"query", windowsVersionKey, "/v", "ProductName"}},
		{"reg", []string{"QUERY", windowsBIOSKey, "/V", "SystemManufacturer"}},
		{"reg.exe", []string{"query", windowsDirectXKey, "/v", "Version"}},
		{"reg.exe", []string{"query", windowsSecureBootKey, "/v", "UEFISecureBootEnabled"}},
		{"reg.exe", []string{"query", windowsDeviceGuardKey, "/v", "EnableVirtualizationBasedSecurity"}},
		{"reg.exe", []string{"query", windowsHVCIKey, "/v", "Enabled"}},
	}
	for _, tt := range valid {
		if !validCommandArguments(tt.name, tt.args) {
			t.Errorf("valid command rejected: %s %v", tt.name, tt.args)
		}
	}
	invalid := []struct {
		name string
		args []string
	}{
		{"powershell.exe", []string{"Get-ComputerInfo"}},
		{"cmd.exe", []string{"/c", "whoami"}},
		{"reg.exe", []string{"delete", windowsVersionKey}},
		{"reg.exe", []string{"query", `HKCU\Environment`, "/v", "Path"}},
		{"reg.exe", []string{"query", windowsSecureBootKey, "/v", "AvailableUpdates"}},
		{"reg.exe", []string{"query", windowsDeviceGuardKey, "/v", "Locked"}},
		{"sc.exe", []string{"stop", "vgk"}},
		{"sc.exe", []string{"query", "vgk"}},
		{"sc.exe", []string{"query", "unapproved-service"}},
	}
	for _, tt := range invalid {
		if validCommandArguments(tt.name, tt.args) {
			t.Errorf("unsafe command accepted: %s %v", tt.name, tt.args)
		}
	}
	commands := systemCommands{}
	if _, err := commands.LookPath(filepath.Join("fixture", "moonlight")); err == nil {
		t.Fatal("LookPath accepted a path")
	}
	for _, prohibited := range []string{
		"doas", "su", "sudo",
	} {
		if _, err := commands.LookPath(prohibited); err == nil {
			t.Errorf("LookPath accepted prohibited executable %q", prohibited)
		}
		if _, err := commands.Run(context.Background(), prohibited, "--version"); err == nil {
			t.Errorf("Run accepted prohibited executable %q", prohibited)
		}
	}
	for _, discoverable := range []string{
		"bhyve", "bottles", "cloud-hypervisor", "colima", "containerd", "crossover", "cxoffice", "darling", "docker", "firecracker", "heroic", "incus", "incusd", "kvm", "libvirt", "libvirtd", "lima", "lkvm", "lxc", "lxc-start", "lutris", "moonlight-embedded", "multipass", "nerdctl", "playonlinux", "podman", "proton", "protontricks", "qemu", "qemu-system-i386", "qemu-system-x86_64", "steam", "systemd-nspawn", "umu", "umu-run", "vboxmanage", "vmd", "vmctl", "vmrun", "vmware", "virt-install", "virt-manager", "virtctl", "virsh", "waydroid", "wine", "wine64", "winboat", "wsl", "xen", "xenstored", "xl",
	} {
		if _, ok := discoverableCommands[discoverable]; !ok {
			t.Errorf("alternative executable %q is not allowlisted for passive discovery", discoverable)
		}
		if _, err := commands.Run(context.Background(), discoverable, "--version"); err == nil {
			t.Errorf("Run accepted discoverable executable %q", discoverable)
		}
	}
	if _, ok := discoverableCommands["flatpak"]; !ok {
		t.Fatal("Flatpak is not allowlisted for passive discovery")
	}
	if _, err := commands.Run(context.Background(), "flatpak", "--version"); err == nil {
		t.Fatal("Run accepted Flatpak execution")
	}
	if _, err := commands.Run(context.Background(), "sc.exe", "stop", "vgk"); err == nil {
		t.Fatal("Run accepted a mutating service command")
	}
	for _, name := range []string{"vgk", "vgc", "SunshineService", "sunshine"} {
		if !serviceQueryAllowed(name) {
			t.Errorf("read-only service query rejected %q", name)
		}
	}
	for _, name := range []string{"Spooler", `fixture\vgk`, " vgk", "vgk\x00other"} {
		if serviceQueryAllowed(name) {
			t.Errorf("service query accepted unapproved name %q", name)
		}
		if _, _, err := (systemServices{}).Query(name); err == nil {
			t.Errorf("system service query accepted unapproved name %q", name)
		}
	}
}

func TestLimitedCommandOutput(t *testing.T) {
	t.Parallel()
	var buffer limitedBuffer
	data := strings.Repeat("x", maximumCommandOutput+1024)
	written, err := buffer.Write([]byte(data))
	if err != nil || written != len(data) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", written, err, len(data))
	}
	if len(buffer.String()) != maximumCommandOutput || !buffer.truncated {
		t.Fatalf("buffer length/truncation = %d/%v", len(buffer.String()), buffer.truncated)
	}
}

func TestRegistryParsingIsStrictAndBounded(t *testing.T) {
	t.Parallel()
	value, ok := parseRegistryValue("\r\n ProductName    REG_SZ    Windows 11 Pro\r\n", "ProductName")
	if !ok || value != "Windows 11 Pro" {
		t.Fatalf("parseRegistryValue = (%q, %v)", value, ok)
	}
	for _, output := range []string{
		"ProductName Windows 11 Pro",
		"DifferentName REG_SZ Windows 11 Pro",
		"ProductName REG_SZ",
		strings.Repeat("x", maximumCommandOutput+1),
	} {
		if _, ok := parseRegistryValue(output, "ProductName"); ok {
			t.Errorf("malformed registry output accepted")
		}
	}
	for _, tt := range []struct {
		value string
		want  bool
	}{
		{"26100", true}, {"19045", true}, {"0", false}, {"-1", false}, {"26x", false}, {strings.Repeat("1", 11), false},
	} {
		_, got := parseBuild(tt.value)
		if got != tt.want {
			t.Errorf("parseBuild(%q) validity = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestEveryReportCheckHasStableMetadata(t *testing.T) {
	t.Parallel()
	client := fixtureProber("linux", "amd64", nil, nil, nil).Client(context.Background())
	host := fixtureProber("windows", "amd64", nil, nil, nil).WindowsHost(context.Background())
	seen := map[string]bool{}
	for _, report := range []Report{client, host} {
		for _, check := range report.Checks {
			if check.ID == "" || check.Summary == "" {
				t.Errorf("incomplete check: %+v", check)
			}
			if check.Status != StatusPass && check.Status != StatusWarn && check.Status != StatusFail {
				t.Errorf("invalid status: %+v", check)
			}
			if seen[string(report.Profile)+"/"+check.ID] {
				t.Errorf("duplicate check id %q", check.ID)
			}
			seen[string(report.Profile)+"/"+check.ID] = true
		}
	}
}

func readyWindowsFixture(t *testing.T) (*Prober, *fixtureCommands) {
	t.Helper()
	commands := &fixtureCommands{
		paths:   map[string]bool{},
		results: map[string]CommandResult{},
	}
	addRegistry(commands, windowsVersionKey, "ProductName", "Windows 11 Pro")
	addRegistry(commands, windowsVersionKey, "InstallationType", "Client")
	addRegistry(commands, windowsVersionKey, "CurrentBuildNumber", "26100")
	addRegistry(commands, windowsDirectXKey, "Version", "4.09.00.0904")
	addRegistry(commands, windowsSecureBootKey, "UEFISecureBootEnabled", "0x1")
	addRegistry(commands, windowsDeviceGuardKey, "EnableVirtualizationBasedSecurity", "0x1")
	addRegistry(commands, windowsHVCIKey, "Enabled", "0x1")
	addRegistry(commands, windowsBIOSKey, "SystemManufacturer", "Fixture Hardware Inc")
	addRegistry(commands, windowsBIOSKey, "SystemProductName", "Fixture Workstation")
	addRegistry(commands, windowsBIOSKey, "BaseBoardManufacturer", "Fixture Hardware Inc")
	addRegistry(commands, windowsBIOSKey, "BaseBoardProduct", "Mainboard 1")
	commands.serviceStates = map[string]observedServiceState{
		"vgk":             serviceRunning,
		"vgc":             serviceRunning,
		"sunshineservice": serviceRegistered,
	}

	programFiles := `C:\Program Files`
	systemDrive := `C:`
	files := fixturePaths(
		targetPathJoin("windows", systemDrive+string(filepath.Separator), "Riot Games", "Riot Client", "RiotClientServices.exe"),
		targetPathJoin("windows", systemDrive+string(filepath.Separator), "Riot Games", "League of Legends", "LeagueClient.exe"),
	)
	prober := fixtureProber("windows", "amd64", files, fixtureEnv{
		"ProgramFiles":      programFiles,
		"ProgramFiles(x86)": `C:\Program Files (x86)`,
		"SystemDrive":       systemDrive,
		"SystemRoot":        `C:\Windows`,
	}, commands)
	return prober, commands
}

func addRegistry(commands *fixtureCommands, key, name, value string) {
	if commands.results == nil {
		commands.results = map[string]CommandResult{}
	}
	commands.results[commandKey("reg.exe", "query", key, "/v", name)] = CommandResult{
		Output:   "    " + name + "    REG_SZ    " + value + "\r\n",
		ExitCode: 0,
	}
}

func pCheck(t *testing.T, check Check) Check {
	t.Helper()
	if check.ID == "" || check.Summary == "" {
		t.Fatalf("invalid check: %+v", check)
	}
	return check
}
