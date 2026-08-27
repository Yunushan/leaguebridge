package probe

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReadyTreatsWindowsHostWarningsAsBlocking(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		report Report
		want   bool
	}{
		{name: "client pass", report: Report{Profile: ProfileClient, Status: StatusPass}, want: true},
		{name: "client advisory warning", report: Report{Profile: ProfileClient, Status: StatusWarn}, want: true},
		{
			name: "client launcher warning",
			report: Report{
				Profile: ProfileClient,
				Status:  StatusWarn,
				Checks:  []Check{{ID: "client.moonlight", Status: StatusWarn, Summary: "not launchable"}},
			},
			want: false,
		},
		{name: "client failure", report: Report{Profile: ProfileClient, Status: StatusFail}, want: false},
		{name: "host pass", report: Report{Profile: ProfileWindowsHost, Status: StatusPass}, want: true},
		{name: "host unverified warning", report: Report{Profile: ProfileWindowsHost, Status: StatusWarn}, want: false},
		{name: "host failure", report: Report{Profile: ProfileWindowsHost, Status: StatusFail}, want: false},
		{name: "unknown status", report: Report{Profile: ProfileClient, Status: Status("unknown")}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.report.Ready(); got != tt.want {
				t.Fatalf("Ready() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWindowsPlatformRequiresNativeAMD64(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		goos        string
		processArch string
		nativeArch  string
		known       bool
		want        Status
	}{
		{name: "native-amd64", goos: "windows", processArch: "amd64", nativeArch: "amd64", known: true, want: StatusPass},
		{name: "x64-process-on-arm64", goos: "windows", processArch: "amd64", nativeArch: "arm64", known: true, want: StatusFail},
		{name: "native-architecture-unknown", goos: "windows", processArch: "amd64", known: false, want: StatusFail},
		{name: "arm64-process", goos: "windows", processArch: "arm64", nativeArch: "arm64", known: true, want: StatusFail},
		{name: "non-windows", goos: "linux", processArch: "amd64", nativeArch: "amd64", known: true, want: StatusFail},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			prober := fixtureProber(test.goos, test.processArch, nil, nil, nil)
			prober.platform = fixturePlatformInfo{architecture: test.nativeArch, known: test.known}
			check := prober.windowsPlatformCheck()
			if check.Status != test.want {
				t.Fatalf("windowsPlatformCheck() = %+v, want status %q", check, test.want)
			}
		})
	}
}

type unavailableWindowsProcedure struct {
	findError error
	callCount int
}

func (p *unavailableWindowsProcedure) Find() error { return p.findError }

func (p *unavailableWindowsProcedure) Query(uintptr, *uint16, *uint16) bool {
	p.callCount++
	return false
}

func TestMissingNativeArchitectureAPIIsBounded(t *testing.T) {
	t.Parallel()
	procedure := &unavailableWindowsProcedure{findError: errors.New("fixture missing API")}
	if architecture, known := queryNativeWindowsArchitecture(procedure, 1); known || architecture != "" {
		t.Fatalf("missing API result = (%q, %v), want bounded unknown", architecture, known)
	}
	if procedure.callCount != 0 {
		t.Fatalf("missing lazy procedure was called %d times", procedure.callCount)
	}
}

func TestDirectXRuntimeCheckIsStrictAndDoesNotClaimHardware(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"4.09.00.0904", "5.0.0.0"} {
		if !isDirectXRuntimeVersion(version) {
			t.Errorf("isDirectXRuntimeVersion(%q) = false", version)
		}
	}
	for _, version := range []string{"", "4.08.00.0904", "4.9", "4.x.0.0", strings.Repeat("1", 33)} {
		if isDirectXRuntimeVersion(version) {
			t.Errorf("isDirectXRuntimeVersion(%q) = true", version)
		}
	}

	commands := &fixtureCommands{results: map[string]CommandResult{}}
	prober := fixtureProber("windows", "amd64", nil, nil, commands)
	if got := prober.directXCheck(context.Background()); got.Status != StatusFail {
		t.Fatalf("missing DirectX status = %q", got.Status)
	}
	addRegistry(commands, windowsDirectXKey, "Version", "4.09.00.0904")
	got := prober.directXCheck(context.Background())
	if got.Status != StatusPass || !strings.Contains(got.Summary, "does not verify") {
		t.Fatalf("DirectX check = %+v", got)
	}
	if got := prober.hardwareRequirementsCheck(); got.Status != StatusWarn || !strings.Contains(got.Summary, "remain unverified") {
		t.Fatalf("hardware check = %+v", got)
	}
}

func TestWindowsSecurityIndicatorsNeverBecomeAttestation(t *testing.T) {
	t.Parallel()
	enabledCommands := func() *fixtureCommands {
		commands := &fixtureCommands{results: map[string]CommandResult{}}
		addRegistry(commands, windowsVersionKey, "ProductName", "Windows 11 Pro")
		addRegistry(commands, windowsSecureBootKey, "UEFISecureBootEnabled", "0x1")
		addRegistry(commands, windowsDeviceGuardKey, "EnableVirtualizationBasedSecurity", "0x1")
		addRegistry(commands, windowsHVCIKey, "Enabled", "0x1")
		return commands
	}

	configured := fixtureProber("windows", "amd64", nil, nil, enabledCommands()).windowsSecurityCheck(context.Background())
	if configured.Status != StatusWarn || !strings.Contains(configured.Summary, "TPM 2.0") || !strings.Contains(configured.Summary, "IOMMU") {
		t.Fatalf("configured security check = %+v", configured)
	}

	for _, disabled := range []struct {
		key  string
		name string
	}{
		{windowsSecureBootKey, "UEFISecureBootEnabled"},
		{windowsDeviceGuardKey, "EnableVirtualizationBasedSecurity"},
		{windowsHVCIKey, "Enabled"},
	} {
		commands := enabledCommands()
		addRegistry(commands, disabled.key, disabled.name, "0x0")
		if got := fixtureProber("windows", "amd64", nil, nil, commands).windowsSecurityCheck(context.Background()); got.Status != StatusWarn {
			t.Errorf("disabled %s/%s status = %q", disabled.key, disabled.name, got.Status)
		}
	}

	missing := &fixtureCommands{results: map[string]CommandResult{}}
	addRegistry(missing, windowsVersionKey, "ProductName", "Windows 11 Pro")
	if got := fixtureProber("windows", "amd64", nil, nil, missing).windowsSecurityCheck(context.Background()); got.Status != StatusWarn {
		t.Fatalf("missing security evidence status = %q", got.Status)
	}

	windows10 := &fixtureCommands{results: map[string]CommandResult{}}
	addRegistry(windows10, windowsVersionKey, "ProductName", "Windows 10 Pro")
	if got := fixtureProber("windows", "amd64", nil, nil, windows10).windowsSecurityCheck(context.Background()); got.Status != StatusWarn {
		t.Fatalf("conditional Windows 10 security status = %q", got.Status)
	}

	staleProduct := enabledCommands()
	addRegistry(staleProduct, windowsVersionKey, "ProductName", "Windows 10 Pro")
	addRegistry(staleProduct, windowsVersionKey, "CurrentBuildNumber", "26100")
	addRegistry(staleProduct, windowsSecureBootKey, "UEFISecureBootEnabled", "0x0")
	if got := fixtureProber("windows", "amd64", nil, nil, staleProduct).windowsSecurityCheck(context.Background()); got.Status != StatusWarn {
		t.Fatalf("Windows 11 build with stale product name status = %q", got.Status)
	}
}

func TestInstallAndFlatpakPresenceRequireAppropriateTypes(t *testing.T) {
	t.Parallel()
	programFiles := `C:\Program Files`
	env := fixtureEnv{"ProgramFiles": programFiles}
	candidateProber := fixtureProber("windows", "amd64", nil, env, nil)
	candidates := candidateProber.installCandidates(filepath.Join("Riot Games", "Riot Client", "RiotClientServices.exe"))
	if len(candidates) != 1 {
		t.Fatalf("install candidates = %#v", candidates)
	}
	rioClient := candidates[0]

	directoryAtExecutable := fixtureModes(fs.ModeDir|0o755, rioClient)
	prober := fixtureProber("windows", "amd64", nil, env, nil, directoryAtExecutable)
	if got := prober.riotClientCheck(); got.Status != StatusFail {
		t.Fatalf("directory at executable path status = %q", got.Status)
	}
	symlinkAtExecutable := fixtureModes(fs.ModeSymlink|0o777, rioClient)
	prober = fixtureProber("windows", "amd64", nil, env, nil, symlinkAtExecutable)
	if got := prober.riotClientCheck(); got.Status != StatusFail {
		t.Fatalf("symlink at executable path status = %q", got.Status)
	}

	regularAtExecutable := fixtureModes(0o644, rioClient)
	prober = fixtureProber("windows", "amd64", nil, env, nil, regularAtExecutable)
	got := prober.riotClientCheck()
	if got.Status != StatusPass || !strings.Contains(got.Summary, "process environment") {
		t.Fatalf("regular executable check = %+v", got)
	}

	flatpak := filepath.Join(string(filepath.Separator), "var", "lib", filepath.FromSlash("flatpak/app/com.moonlight_stream.Moonlight"))
	flatpakCommands := &fixtureCommands{paths: map[string]bool{"flatpak": true}}
	fileAtDirectory := fixtureModes(0o644, flatpak)
	if got := fixtureProber("linux", "amd64", nil, nil, flatpakCommands, fileAtDirectory).moonlightCheck(); got.Status != StatusFail {
		t.Fatalf("file at Flatpak directory status = %q", got.Status)
	}
	directoryAtDirectory := fixtureModes(fs.ModeDir|0o755, flatpak)
	if got := fixtureProber("linux", "amd64", nil, nil, flatpakCommands, directoryAtDirectory).moonlightCheck(); got.Status != StatusPass {
		t.Fatalf("Flatpak directory status = %q", got.Status)
	}
}

type recordingProbeFS struct {
	mu    sync.Mutex
	calls []string
}

func (f *recordingProbeFS) Stat(name string) (fs.FileInfo, error) {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	f.mu.Unlock()
	return nil, fs.ErrNotExist
}

func (f *recordingProbeFS) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func TestUnsafeEnvironmentRootsNeverReachFileSystem(t *testing.T) {
	t.Parallel()
	const marker = "leaguebridge-unsafe-share"

	windowsFS := &recordingProbeFS{}
	windows := New(Dependencies{
		FS: windowsFS,
		Env: fixtureEnv{
			"ProgramFiles":      `\\` + marker + `\programs`,
			"ProgramFiles(x86)": `\\?\C:\` + marker,
			"SystemDrive":       `\\` + marker,
			"SystemRoot":        `\\.\UNC\` + marker + `\windows`,
		},
		Commands: &fixtureCommands{},
		GOOS:     "windows",
		GOARCH:   "amd64",
	})
	_ = windows.riotClientCheck()
	_ = windows.leagueInstallCheck()
	_ = windows.physicalHostCheck(context.Background())
	assertNoUnsafeStat(t, windowsFS.recorded(), marker)

	clientFS := &recordingProbeFS{}
	client := New(Dependencies{
		FS: clientFS,
		Env: fixtureEnv{
			"HOME":            `//` + marker + `/home`,
			"XDG_DATA_HOME":   `\\` + marker + `\data`,
			"XDG_RUNTIME_DIR": `//?/` + marker + `/runtime`,
		},
		Commands: &fixtureCommands{},
		GOOS:     "linux",
		GOARCH:   "amd64",
	})
	_ = client.moonlightCheck()
	_ = client.audioCheck()
	assertNoUnsafeStat(t, clientFS.recorded(), marker)

	nonWindowsFS := &recordingProbeFS{}
	nonWindowsHostProfile := New(Dependencies{
		FS:       nonWindowsFS,
		Env:      fixtureEnv{"SystemRoot": `C:\Windows`},
		Commands: &fixtureCommands{},
		GOOS:     "linux",
		GOARCH:   "amd64",
	})
	_ = nonWindowsHostProfile.WindowsHost(context.Background())
	if calls := nonWindowsFS.recorded(); len(calls) != 0 {
		t.Fatalf("non-Windows host profile made relative filesystem probes: %#v", calls)
	}
}

func assertNoUnsafeStat(t *testing.T, calls []string, marker string) {
	t.Helper()
	for _, call := range calls {
		if strings.Contains(strings.ToLower(call), strings.ToLower(marker)) {
			t.Fatalf("unsafe environment path reached Stat: %q (all calls: %#v)", call, calls)
		}
	}
}

func TestLocalEnvironmentRootRejectsNetworkDeviceAndRelativePaths(t *testing.T) {
	t.Parallel()
	windows := fixtureProber("windows", "amd64", nil, nil, nil)
	for _, root := range []string{`\\server\share`, `//server/share`, `\\?\C:\Windows`, `\\.\C:\Windows`, `C:relative`, `\relative`, `https://server/share`} {
		if got, ok := windows.localEnvironmentRoot(root); ok {
			t.Errorf("Windows root %q accepted as %q", root, got)
		}
	}
	if got, ok := windows.localEnvironmentRoot(`C:\Program Files`); !ok || !strings.HasPrefix(strings.ToUpper(got), "C:") {
		t.Fatalf("local Windows root = (%q, %v)", got, ok)
	}

	linux := fixtureProber("linux", "amd64", nil, nil, nil)
	for _, root := range []string{`//server/share`, `\\server\share`, `relative`, `file:///tmp`} {
		if got, ok := linux.localEnvironmentRoot(root); ok {
			t.Errorf("Unix root %q accepted as %q", root, got)
		}
	}
	if got, ok := linux.localEnvironmentRoot("/home/user/../user"); !ok || got != "/home/user" {
		t.Fatalf("local Unix root = (%q, %v)", got, ok)
	}
}
