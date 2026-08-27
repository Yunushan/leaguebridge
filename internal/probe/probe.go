// Package probe provides privacy-safe, read-only preflight checks for
// LeagueBridge clients and physical Windows or macOS streaming hosts.
package probe

import (
	"context"
	"io/fs"
	"path"
	"runtime"
	"strings"
	"time"
)

const (
	// SchemaVersion changes only when the serialized report contract changes.
	SchemaVersion = 1

	defaultCommandTimeout = 2 * time.Second
	maximumCommandTimeout = 5 * time.Second
)

// Status is the stable, machine-readable outcome of a Check or Report.
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

// Profile identifies the machine role being inspected.
type Profile string

const (
	ProfileClient      Profile = "client"
	ProfileWindowsHost Profile = "windows-host"
	ProfileMacOSHost   Profile = "macos-host"
)

// Check is one privacy-safe preflight result. Summary and Guidance are written
// from fixed strings; paths, environment values, registry output, and command
// errors are deliberately excluded.
type Check struct {
	ID       string `json:"id"`
	Status   Status `json:"status"`
	Summary  string `json:"summary"`
	Guidance string `json:"guidance,omitempty"`
}

// Report is a deterministic preflight snapshot. It intentionally contains no
// hostname, username, installation path, command output, or timestamp.
type Report struct {
	SchemaVersion int     `json:"schema_version"`
	Profile       Profile `json:"profile"`
	OS            string  `json:"os"`
	// Architecture is the executable's build architecture. The Windows host
	// platform check separately verifies the native machine architecture.
	Architecture string  `json:"architecture"`
	Status       Status  `json:"status"`
	Checks       []Check `json:"checks"`
}

// Ready reports whether the preflight contains enough evidence to continue.
// Most client warnings are advisory, but an unresolved Moonlight launcher is a
// required handoff gate. Every Windows-host warning blocks host readiness.
func (r Report) Ready() bool {
	if r.Status == StatusPass {
		return true
	}
	if r.Profile != ProfileClient || r.Status != StatusWarn {
		return false
	}
	if moonlight, ok := r.Check("client.moonlight"); ok && moonlight.Status != StatusPass {
		return false
	}
	return true
}

// Check returns the check with id, if present.
func (r Report) Check(id string) (Check, bool) {
	for _, check := range r.Checks {
		if check.ID == id {
			return check, true
		}
	}
	return Check{}, false
}

// FileSystem is the read-only filesystem surface used by probes. The system
// implementation does not follow the final symbolic link.
type FileSystem interface {
	Stat(name string) (fs.FileInfo, error)
}

// Environment supplies environment values without requiring probes to depend
// directly on process-global state.
type Environment interface {
	LookupEnv(key string) (string, bool)
}

// CommandResult contains bounded command output. Probes never copy this output
// into a report.
type CommandResult struct {
	Output    string
	ExitCode  int
	Truncated bool
}

// Commands provides command discovery and tightly controlled execution.
// Production execution is allowlisted, shell-free, bounded, and time-limited.
type Commands interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) (CommandResult, error)
}

// Services provides a read-only service registration and running-state query.
// The system implementation uses the Windows Service Control Manager API and
// never starts, stops, or reconfigures a service.
type Services interface {
	Query(name string) (registered, running bool, err error)
}

// PlatformInfo supplies native machine identity without trusting process
// environment variables. Windows uses IsWow64Process2 so an amd64 executable
// running under Windows-on-Arm emulation cannot masquerade as a native amd64
// host.
type PlatformInfo interface {
	NativeArchitecture() (architecture string, known bool)
}

type systemPlatformInfo struct{}

// Dependencies makes every source of host state replaceable by fixtures.
// GOOS and GOARCH default to runtime values when empty.
type Dependencies struct {
	FS             FileSystem
	Env            Environment
	Commands       Commands
	Services       Services
	Platform       PlatformInfo
	GOOS           string
	GOARCH         string
	CommandTimeout time.Duration
}

// Prober performs read-only preflight checks.
type Prober struct {
	fs       FileSystem
	env      Environment
	command  Commands
	services Services
	platform PlatformInfo
	goos     string
	goarch   string
	timeout  time.Duration
}

// New constructs a Prober. Nil dependencies receive safe system defaults.
func New(deps Dependencies) *Prober {
	if deps.FS == nil {
		deps.FS = systemFileSystem{}
	}
	if deps.Env == nil {
		deps.Env = systemEnvironment{}
	}
	if deps.Commands == nil {
		deps.Commands = systemCommands{}
	}
	if deps.Services == nil {
		deps.Services = systemServices{}
	}
	if deps.Platform == nil {
		deps.Platform = systemPlatformInfo{}
	}
	if deps.GOOS == "" {
		deps.GOOS = runtime.GOOS
	}
	if deps.GOARCH == "" {
		deps.GOARCH = runtime.GOARCH
	}
	if deps.CommandTimeout <= 0 {
		deps.CommandTimeout = defaultCommandTimeout
	}
	if deps.CommandTimeout > maximumCommandTimeout {
		deps.CommandTimeout = maximumCommandTimeout
	}
	return &Prober{
		fs:       deps.FS,
		env:      deps.Env,
		command:  deps.Commands,
		services: deps.Services,
		platform: deps.Platform,
		goos:     strings.ToLower(strings.TrimSpace(deps.GOOS)),
		goarch:   strings.ToLower(strings.TrimSpace(deps.GOARCH)),
		timeout:  deps.CommandTimeout,
	}
}

// NewSystem constructs a Prober over the current host.
func NewSystem() *Prober { return New(Dependencies{}) }

// Run selects a preflight profile.
func (p *Prober) Run(ctx context.Context, profile Profile) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	switch profile {
	case ProfileClient:
		return p.Client(ctx)
	case ProfileWindowsHost:
		return p.WindowsHost(ctx)
	case ProfileMacOSHost:
		return p.MacOSHost(ctx)
	default:
		return p.report(profile, []Check{{
			ID:       "profile",
			Status:   StatusFail,
			Summary:  "Unknown preflight profile.",
			Guidance: "Select the client, windows-host, or macos-host profile.",
		}})
	}
}

func (p *Prober) report(profile Profile, checks []Check) Report {
	status := StatusPass
	for _, check := range checks {
		switch check.Status {
		case StatusFail:
			status = StatusFail
		case StatusWarn:
			if status == StatusPass {
				status = StatusWarn
			}
		}
	}
	return Report{
		SchemaVersion: SchemaVersion,
		Profile:       profile,
		OS:            p.goos,
		Architecture:  p.goarch,
		Status:        status,
		Checks:        append([]Check(nil), checks...),
	}
}

func (p *Prober) lookupAny(names ...string) (string, bool) {
	for _, name := range names {
		if _, err := p.command.LookPath(name); err == nil {
			return name, true
		}
	}
	return "", false
}

func (p *Prober) existsAny(paths ...string) bool {
	for _, path := range uniqueNonEmpty(paths) {
		info, err := p.fs.Stat(path)
		if err == nil && info != nil {
			return true
		}
	}
	return false
}

func (p *Prober) regularFileExistsAny(paths ...string) bool {
	for _, candidate := range uniqueNonEmpty(paths) {
		info, err := p.fs.Stat(candidate)
		if err == nil && info != nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func (p *Prober) directoryExistsAny(paths ...string) bool {
	for _, candidate := range uniqueNonEmpty(paths) {
		info, err := p.fs.Stat(candidate)
		if err == nil && info != nil && info.IsDir() {
			return true
		}
	}
	return false
}

func (p *Prober) envValue(key string) string {
	value, ok := p.env.LookupEnv(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// localEnvironmentRoot validates an environment-derived root before any Stat.
// It rejects UNC, device, network-style, drive-relative, and non-absolute paths.
// On Windows only local drive roots are accepted; on Unix only a single-leading-
// slash path is accepted. This is lexical validation, not proof that a Unix
// path is not backed by a user-mounted network filesystem.
func (p *Prober) localEnvironmentRoot(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", false
	}

	if p.goos == "windows" {
		normalized := strings.ReplaceAll(value, `\`, "/")
		if strings.HasPrefix(normalized, "//") || len(normalized) < 3 || normalized[1] != ':' || normalized[2] != '/' ||
			!isASCIILetter(normalized[0]) || strings.Contains(normalized[2:], ":") {
			return "", false
		}
		rest := path.Clean("/" + normalized[3:])
		return strings.ToUpper(normalized[:1]) + ":" + filepathFromSlash(rest), true
	}

	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, `\`) {
		return "", false
	}
	return path.Clean(value), true
}

func isASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

// filepathFromSlash is kept small so target-path validation is deterministic
// under cross-platform unit tests while native Windows still receives its
// preferred separator from filepath.FromSlash.
func filepathFromSlash(value string) string {
	if runtime.GOOS == "windows" {
		return strings.ReplaceAll(value, "/", `\`)
	}
	return value
}

func (p *Prober) run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.command.Run(commandCtx, name, args...)
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
