// Package probe provides privacy-safe, read-only preflight checks for
// LeagueBridge clients and physical Windows or macOS streaming hosts.
package probe

import (
	"context"
	"io"
	"io/fs"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/target"
)

const (
	// SchemaVersion changes only when the serialized report contract changes.
	SchemaVersion = 2

	defaultCommandTimeout = 2 * time.Second
	maximumCommandTimeout = 5 * time.Second
)

var clientReadinessCheckIDs = map[string]struct{}{
	"client.platform":          {},
	"client.graphical-session": {},
	"client.input":             {},
	"client.moonlight":         {},
	"client.audio":             {},
	"client.decoder-tools":     {},
}

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
	ProfileClient        Profile = "client"
	ProfileWindowsHost   Profile = "windows-host"
	ProfileMacOSHost     Profile = "macos-host"
	ProfileCompatibility Profile = "compatibility"
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
// Most client warnings are advisory, but Moonlight, a reachable graphical
// session, and a display-backed input-path indicator are required stream
// gates. Every Windows-host warning blocks host readiness.
func (r Report) Ready() bool {
	if r.Profile != ProfileClient {
		if r.SchemaVersion != SchemaVersion {
			return false
		}
		expectedStatus, ok := aggregateStatus(r.Checks)
		return ok && r.Status == StatusPass && expectedStatus == StatusPass
	}
	if !r.ReadyForControl() {
		return false
	}
	graphicalSession, ok := r.Check("client.graphical-session")
	if !ok || graphicalSession.Status != StatusPass {
		return false
	}
	input, ok := r.Check("client.input")
	return ok && input.Status == StatusPass
}

// ReadyForControl reports whether a client preflight contains enough evidence
// for Moonlight control operations such as pairing or listing applications.
// Those operations do not open a video stream, so missing graphical and input
// endpoints are not control-plane blockers. The target platform and a
// PATH-resolvable Moonlight launcher remain required.
func (r Report) ReadyForControl() bool {
	if r.SchemaVersion != SchemaVersion || r.Profile != ProfileClient || !target.IsSupported(r.OS, r.Architecture) {
		return false
	}
	if _, ok := eligibleClientOS[r.OS]; !ok {
		return false
	}
	seen := make(map[string]struct{}, len(r.Checks))
	for _, check := range r.Checks {
		if _, allowed := clientReadinessCheckIDs[check.ID]; !allowed {
			return false
		}
		if _, duplicate := seen[check.ID]; duplicate {
			return false
		}
		seen[check.ID] = struct{}{}
	}
	if len(seen) != len(clientReadinessCheckIDs) {
		return false
	}
	platform, ok := r.Check("client.platform")
	if !ok || platform.Status != StatusPass {
		return false
	}
	moonlight, ok := r.Check("client.moonlight")
	if !ok || moonlight.Status != StatusPass {
		return false
	}
	// A control report may fail at the graphical-session and input gates;
	// platform and Moonlight failures must remain blocking. Recompute the
	// aggregate status so hand-built or stale reports cannot claim pass while
	// omitting a required check or carrying an unrelated failure.
	expectedStatus, ok := aggregateStatus(r.Checks)
	if !ok {
		return false
	}
	if r.Status != expectedStatus {
		return false
	}
	for _, check := range r.Checks {
		if check.Status == StatusFail && check.ID != "client.graphical-session" && check.ID != "client.input" {
			return false
		}
	}
	return true
}

func aggregateStatus(checks []Check) (Status, bool) {
	if len(checks) == 0 {
		return "", false
	}
	status := StatusPass
	for _, check := range checks {
		switch check.Status {
		case StatusPass:
		case StatusWarn:
			if status == StatusPass {
				status = StatusWarn
			}
		case StatusFail:
			status = StatusFail
		default:
			return "", false
		}
	}
	return status, true
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

// ResolvedFileSystem is an optional read-only filesystem surface for
// environment-selected display endpoints. Unlike FileSystem.Stat, its
// implementation may follow the final symbolic link so a compositor such as
// WSLg can expose a named Wayland socket through a runtime-directory link.
// Callers use it only to confirm the resolved endpoint type; it is not used
// for user-authored files, devices, or executable discovery.
type ResolvedFileSystem interface {
	StatResolved(name string) (fs.FileInfo, error)
}

// DeviceAccess is an optional read-only extension for callers that need to
// check an endpoint with read permission. Fixture file systems may omit it and
// retain existence-only semantics; the system file system implements it with
// a nonblocking read-only open.
type DeviceAccess interface {
	OpenRead(name string) (io.Closer, error)
}

// WritableDeviceAccess is an optional extension used when the native client
// needs read/write permission for a device endpoint. The probe only opens the
// endpoint with O_RDWR|O_NONBLOCK; it never writes to the device. Fixture file
// systems may omit it and retain existence-only semantics.
type WritableDeviceAccess interface {
	OpenReadWrite(name string) (io.Closer, error)
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

// PrivilegeInfo reports the minimum local privilege fact needed by a native
// display-backend probe. It deliberately exposes only the root/non-root bit;
// probes never collect usernames, group memberships, or process credentials.
type PrivilegeInfo interface {
	IsRoot() bool
}

// Dependencies makes every source of host state replaceable by fixtures.
// GOOS and GOARCH default to runtime values when empty.
type Dependencies struct {
	FS             FileSystem
	Env            Environment
	Commands       Commands
	Services       Services
	Platform       PlatformInfo
	Privilege      PrivilegeInfo
	GOOS           string
	GOARCH         string
	CommandTimeout time.Duration
}

// Prober performs read-only preflight checks.
type Prober struct {
	fs        FileSystem
	env       Environment
	command   Commands
	services  Services
	platform  PlatformInfo
	privilege PrivilegeInfo
	goos      string
	goarch    string
	timeout   time.Duration
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
	if deps.Privilege == nil {
		deps.Privilege = systemPrivilegeInfo{}
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
		fs:        deps.FS,
		env:       deps.Env,
		command:   deps.Commands,
		services:  deps.Services,
		platform:  deps.Platform,
		privilege: deps.Privilege,
		goos:      strings.ToLower(strings.TrimSpace(deps.GOOS)),
		goarch:    strings.ToLower(strings.TrimSpace(deps.GOARCH)),
		timeout:   deps.CommandTimeout,
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
	case ProfileCompatibility:
		return p.Compatibility(ctx)
	default:
		return p.report(profile, []Check{{
			ID:       "profile",
			Status:   StatusFail,
			Summary:  "Unknown preflight profile.",
			Guidance: "Select the client, windows-host, macos-host, or compatibility profile.",
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
		return strings.ToUpper(normalized[:1]) + ":" + filepathFromSlash(rest, p.goos), true
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
// under cross-platform unit tests. The target OS, rather than the host running
// a cross-target fixture, determines the preferred separator.
func filepathFromSlash(value, targetGOOS string) string {
	if targetGOOS == "windows" {
		return strings.ReplaceAll(value, "/", `\`)
	}
	return value
}

// targetPathJoin joins a path using the target platform's separators. The
// prober normally runs on the target platform, but tests also exercise a
// Windows target from Unix hosts and must not turn a drive path into a mixed
// separator string.
func targetPathJoin(targetGOOS string, elements ...string) string {
	if targetGOOS != "windows" {
		return path.Join(elements...)
	}
	normalized := make([]string, len(elements))
	for index, element := range elements {
		normalized[index] = strings.ReplaceAll(element, `\`, "/")
	}
	return strings.ReplaceAll(path.Join(normalized...), "/", `\`)
}

func (p *Prober) run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.command.Run(commandCtx, name, args...)
}

// writableCharacterDeviceAny verifies both the device-node type and the
// read/write permission needed by a native client input backend. It
// deliberately returns to existence-only behavior for fixture file systems
// that do not expose the optional WritableDeviceAccess surface.
func (p *Prober) writableCharacterDeviceAny(paths ...string) bool {
	return p.writableDeviceAny(fs.ModeCharDevice, paths...)
}

// writableDeviceNodeAny verifies a device node and the read/write permission
// needed by a direct display backend. It shares the fixture fallback with
// input checks so existing deterministic probe fixtures remain useful without
// pretending to attest permissions they cannot model.
func (p *Prober) writableDeviceNodeAny(paths ...string) bool {
	return p.writableDeviceAny(fs.ModeDevice, paths...)
}

func (p *Prober) writableDeviceAny(requiredMode fs.FileMode, paths ...string) bool {
	access, canCheckAccess := p.fs.(WritableDeviceAccess)
	for _, candidate := range uniqueNonEmpty(paths) {
		info, err := p.fs.Stat(candidate)
		if err != nil || info == nil || info.Mode()&requiredMode == 0 {
			continue
		}
		if !canCheckAccess {
			return true
		}
		device, err := access.OpenReadWrite(candidate)
		if err != nil || device == nil {
			continue
		}
		_ = device.Close()
		return true
	}
	return false
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
