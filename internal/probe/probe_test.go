package probe

import (
	"context"
	"encoding/json"
	"errors"
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
		{"linux", "arm64", StatusFail},
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
		name string
		env  fixtureEnv
		want Status
	}{
		{"wayland", fixtureEnv{"WAYLAND_DISPLAY": "wayland-0"}, StatusPass},
		{"x11", fixtureEnv{"DISPLAY": ":0"}, StatusPass},
		{"type-only", fixtureEnv{"XDG_SESSION_TYPE": "wayland"}, StatusWarn},
		{"headless", nil, StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkStatus(t, fixtureProber("linux", "amd64", nil, tt.env, nil).Client(context.Background()), "client.graphical-session")
			if got != tt.want {
				t.Fatalf("session status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMoonlightDiscoveryDoesNotExecuteIt(t *testing.T) {
	t.Parallel()
	flatpakSystem := filepath.Join(string(filepath.Separator), "var", "lib", filepath.FromSlash("flatpak/app/com.moonlight_stream.Moonlight"))
	flatpakUser := filepath.Join(filepath.FromSlash("/home/fixture-user"), ".local", "share", filepath.FromSlash("flatpak/app/com.moonlight_stream.Moonlight"))
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
		{"binary", map[string]bool{"moonlight": true}, nil, nil, nil, StatusPass, "Moonlight is available."},
		{"qt-binary", map[string]bool{"moonlight-qt": true}, nil, nil, nil, StatusPass, "Moonlight Qt is available."},
		{"known-executable-not-on-path", nil, fixturePaths(knownExecutable), nil, nil, StatusWarn, "cannot resolve"},
		{"system-flatpak", map[string]bool{"flatpak": true}, nil, fixtureModes(fs.ModeDir|0o755, flatpakSystem), nil, StatusPass, "PATH-resolvable Flatpak"},
		{"user-flatpak", map[string]bool{"flatpak": true}, nil, fixtureModes(fs.ModeDir|0o755, flatpakUser), fixtureEnv{"HOME": "/home/fixture-user"}, StatusPass, "PATH-resolvable Flatpak"},
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
		"docker", "doas", "podman", "proton", "qemu-system-x86_64", "su", "sudo", "wine", "wine64",
	} {
		if _, err := commands.LookPath(prohibited); err == nil {
			t.Errorf("LookPath accepted prohibited executable %q", prohibited)
		}
		if _, err := commands.Run(context.Background(), prohibited, "--version"); err == nil {
			t.Errorf("Run accepted prohibited executable %q", prohibited)
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
		filepath.Join(systemDrive+string(filepath.Separator), "Riot Games", "Riot Client", "RiotClientServices.exe"),
		filepath.Join(systemDrive+string(filepath.Separator), "Riot Games", "League of Legends", "LeagueClient.exe"),
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
