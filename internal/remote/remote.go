// Package remote builds and executes safe Moonlight commands for a separately
// managed physical Windows or macOS streaming host. It never starts Riot
// software locally and never invokes a shell.
package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Yunushan/leaguebridge/internal/config"
)

type Flavor string

const (
	FlavorEmbedded Flavor = "moonlight-embedded"
	FlavorQt       Flavor = "moonlight-qt"
	FlavorFlatpak  Flavor = "moonlight-flatpak"
)

type Operation string

const (
	Pair   Operation = "pair"
	List   Operation = "list"
	Stream Operation = "stream"
)

type Client struct {
	Flavor Flavor   `json:"flavor"`
	Binary string   `json:"binary"`
	Prefix []string `json:"prefix,omitempty"`

	// discovered is deliberately private and non-serialized. Only Discover
	// may mark a client as coming from the passive, real-environment resolver.
	// A hand-built client can still be used for pure argument planning, but its
	// plan must never cross the execution boundary.
	discovered bool
}

// clientBinding is an immutable-in-practice snapshot of the exported Client
// fields that influence process selection. It is kept private and copied into
// a Plan so mutating Plan.Client after discovery cannot redirect execution.
type clientBinding struct {
	flavor Flavor
	binary string
	prefix []string
}

func bindClient(client Client) clientBinding {
	return clientBinding{
		flavor: client.Flavor,
		binary: client.Binary,
		prefix: append([]string(nil), client.Prefix...),
	}
}

func (binding clientBinding) matches(client Client) bool {
	if binding.flavor != client.Flavor || binding.binary != client.Binary || len(binding.prefix) != len(client.Prefix) {
		return false
	}
	for i, value := range binding.prefix {
		if value != client.Prefix[i] {
			return false
		}
	}
	return true
}

type Request struct {
	Route                   config.Route
	Operation               Operation
	Host                    string
	App                     string
	PhysicalHostConfirmed   bool
	AcceptUnverifiedHandoff bool
}

type Plan struct {
	Route     config.Route `json:"route"`
	Client    Client       `json:"client"`
	Arguments []string     `json:"arguments"`
	Warnings  []string     `json:"warnings"`

	// validated is deliberately not serialized. Only BuildDiscoveredPlan can
	// create an executable plan; JSON or a hand-built value must not bypass its
	// route, physical-host confirmation, and acknowledgement checks.
	validated bool

	// clientDiscovered is deliberately not serialized. It binds execution to a
	// Client returned by Discover, so a future caller cannot substitute an
	// arbitrary executable path after passive discovery has completed.
	clientDiscovered bool

	// clientBinding is deliberately not serialized. It snapshots every
	// exported Client field that affects process selection and detects mutation
	// after BuildDiscoveredPlan returns.
	clientBinding clientBinding
}

type Environment interface {
	LookPath(file string) (string, error)
}

type RealEnvironment struct{}

// LookPath resolves a client through the host PATH, then binds the result to
// an absolute regular executable path before it can enter a handoff plan.
// Keeping this check at the real environment boundary prevents a directory,
// device, or non-executable PATH entry from being treated as a launch target.
// Symlinks remain allowed when their final target is a regular executable,
// which preserves normal package-manager layouts while avoiding a bare,
// relative command name whose meaning could change before execution.
func (RealEnvironment) LookPath(file string) (string, error) {
	resolved, err := exec.LookPath(file)
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve Moonlight executable path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect Moonlight executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("resolved Moonlight client is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("resolved Moonlight client is not executable")
	}
	return absolute, nil
}

// Discover locates a known Moonlight client without starting it. It does not
// download software or execute any discovered binary, which keeps discovery
// and --dry-run passive even when an untrusted executable shadows PATH.
func Discover(ctx context.Context, env Environment, preferred string) (Client, error) {
	return discoverForPlatform(ctx, env, preferred, runtime.GOOS)
}

func discoverForPlatform(ctx context.Context, env Environment, preferred, goos string) (Client, error) {
	if env == nil {
		return Client{}, errors.New("Moonlight discovery environment is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lookup := func(name string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("Moonlight discovery canceled: %w", err)
		}
		path, err := env.LookPath(name)
		if contextErr := ctx.Err(); contextErr != nil {
			return "", fmt.Errorf("Moonlight discovery canceled: %w", contextErr)
		}
		return path, err
	}
	lookupCanceled := func(err error) bool {
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	switch preferred {
	case "", "auto":
		if path, err := lookup("moonlight-qt"); err == nil {
			return Client{Flavor: FlavorQt, Binary: path, discovered: true}, nil
		} else if lookupCanceled(err) {
			return Client{}, err
		}
		if path, err := lookup("moonlight"); err == nil {
			flavor := defaultMoonlightFlavorFor(goos)
			return Client{Flavor: flavor, Binary: path, discovered: true}, nil
		} else if lookupCanceled(err) {
			return Client{}, err
		}
		if path, err := lookup("flatpak"); err == nil {
			return Client{Flavor: FlavorFlatpak, Binary: path, Prefix: []string{"run", "com.moonlight_stream.Moonlight"}, discovered: true}, nil
		} else if lookupCanceled(err) {
			return Client{}, err
		}
	case "moonlight-qt":
		path, err := lookup("moonlight-qt")
		if err != nil && !genericMoonlightIsEmbedded(goos) {
			// Some Qt packages, including OpenBSD's port, install the binary as
			// "moonlight". FreeBSD and DragonFly are deliberately excluded because
			// that name identifies Embedded when the distinct Qt binary is absent.
			path, err = lookup("moonlight")
		}
		if lookupCanceled(err) {
			return Client{}, err
		}
		if err == nil {
			return Client{Flavor: FlavorQt, Binary: path, discovered: true}, nil
		}
	case "flatpak":
		path, err := lookup("flatpak")
		if lookupCanceled(err) {
			return Client{}, err
		}
		if err == nil {
			return Client{Flavor: FlavorFlatpak, Binary: path, Prefix: []string{"run", "com.moonlight_stream.Moonlight"}, discovered: true}, nil
		}
	case "moonlight":
		path, err := lookup("moonlight")
		if lookupCanceled(err) {
			return Client{}, err
		}
		if err == nil {
			// The explicit generic selection means Moonlight Embedded. Users of a
			// downstream Qt package named "moonlight" can select moonlight-qt,
			// whose fallback above deliberately accepts that binary name.
			return Client{Flavor: FlavorEmbedded, Binary: path, discovered: true}, nil
		}
	default:
		return Client{}, fmt.Errorf("unsupported Moonlight client selection %q", preferred)
	}
	if err := ctx.Err(); err != nil {
		return Client{}, fmt.Errorf("Moonlight discovery canceled: %w", err)
	}
	return Client{}, errors.New("Moonlight was not found; install Moonlight Qt or Moonlight Embedded from your operating system's trusted package source")
}

func defaultMoonlightFlavor() Flavor {
	return defaultMoonlightFlavorFor(runtime.GOOS)
}

func defaultMoonlightFlavorFor(goos string) Flavor {
	// FreeBSD and DragonFly package Embedded as "moonlight" and Qt separately as
	// "moonlight-qt". Other initial targets conventionally expose Qt under the
	// generic name. Explicit selection is available when a downstream differs.
	if genericMoonlightIsEmbedded(goos) {
		return FlavorEmbedded
	}
	return FlavorQt
}

func genericMoonlightIsEmbedded(goos string) bool {
	return goos == "freebsd" || goos == "dragonfly"
}

func BuildPlan(client Client, req Request) (Plan, error) {
	route := req.Route
	if route == "" {
		// Preserve the original API behavior for callers compiled against the
		// Windows-only request shape.
		route = config.RouteWindows
	}
	if route != config.RouteWindows && route != config.RouteMacOS {
		return Plan{}, fmt.Errorf("unsupported physical-host route %q", route)
	}
	if err := config.ValidateHost(req.Host); err != nil {
		return Plan{}, fmt.Errorf("host: %w", err)
	}
	if req.Operation != Pair && req.Operation != List && req.Operation != Stream {
		return Plan{}, fmt.Errorf("unsupported remote operation %q", req.Operation)
	}
	if client.Binary == "" {
		return Plan{}, errors.New("Moonlight executable path is empty")
	}
	if err := validateClientPrefix(client); err != nil {
		return Plan{}, err
	}
	if !req.PhysicalHostConfirmed {
		hostDescription := "Windows PC"
		if route == config.RouteMacOS {
			hostDescription = "Mac"
		}
		return Plan{}, fmt.Errorf("remote host is not confirmed as a physical %s; LeagueBridge refuses VM handoffs", hostDescription)
	}
	if req.Operation == Stream && !req.AcceptUnverifiedHandoff {
		return Plan{}, errors.New("remote streaming is an unverified handoff, not local Linux/BSD support; pass explicit acknowledgement to continue")
	}
	if req.Operation == Stream {
		if err := config.ValidateAppName(req.App); err != nil {
			return Plan{}, fmt.Errorf("app: %w", err)
		}
	}

	args := append([]string(nil), client.Prefix...)
	switch client.Flavor {
	case FlavorEmbedded:
		switch req.Operation {
		case Stream:
			args = append(args, "stream", "-app", req.App, req.Host)
		default:
			args = append(args, string(req.Operation), req.Host)
		}
	case FlavorQt, FlavorFlatpak:
		args = append(args, string(req.Operation), req.Host)
		if req.Operation == Stream {
			args = append(args, req.App)
		}
	default:
		return Plan{}, fmt.Errorf("unsupported Moonlight flavor %q", client.Flavor)
	}
	warnings := []string{
		"League runs on the physical Windows host, not on Linux or BSD.",
		"Remote-streaming input compatibility is not endorsed or guaranteed by Riot; stop if Vanguard reports an error.",
	}
	if route == config.RouteMacOS {
		warnings = []string{
			"League runs through Riot's native client on the physical Mac, not on Linux or BSD.",
			"Sunshine's macOS host behavior is experimental; gamepad hosting is unavailable, while capture, audio, keyboard/mouse, and gameplay behavior remain unvalidated.",
			"Remote streaming is not endorsed or guaranteed by Riot; stop if Riot software reports an error.",
		}
	}
	return Plan{
		Route:            route,
		Client:           client,
		Arguments:        args,
		Warnings:         warnings,
		validated:        true,
		clientDiscovered: client.discovered,
		clientBinding:    bindClient(client),
	}, nil
}

// BuildDiscoveredPlan is the production handoff entry point. BuildPlan stays
// available as a pure planner for contract tests and dry-run composition, but
// this wrapper refuses a client that did not come from Discover before any
// executable plan is constructed.
func BuildDiscoveredPlan(client Client, req Request) (Plan, error) {
	if !client.discovered {
		return Plan{}, errors.New("Moonlight client was not discovered through the passive resolver")
	}
	return BuildPlan(client, req)
}

func validatePlanRoute(route config.Route) error {
	switch route {
	case config.RouteWindows, config.RouteMacOS:
		return nil
	default:
		return fmt.Errorf("unsupported physical-host route %q", route)
	}
}

func validateClientPrefix(client Client) error {
	switch client.Flavor {
	case FlavorEmbedded, FlavorQt:
		if len(client.Prefix) != 0 {
			return fmt.Errorf("Moonlight %s client cannot have a command prefix", client.Flavor)
		}
	case FlavorFlatpak:
		if len(client.Prefix) != 2 || client.Prefix[0] != "run" || client.Prefix[1] != "com.moonlight_stream.Moonlight" {
			return errors.New("Moonlight Flatpak client requires the fixed run com.moonlight_stream.Moonlight prefix")
		}
	default:
		return fmt.Errorf("unsupported Moonlight flavor %q", client.Flavor)
	}
	return nil
}

// validatePlanArguments re-checks the complete Moonlight argument grammar at
// the execution boundary. Plans are exported values, so a caller can bypass
// BuildPlan and otherwise smuggle arbitrary flags or a different operation to
// the runner. Keeping this grammar fixed makes Execute fail closed even when a
// hand-built Plan is supplied by another package or a future CLI path.
func validatePlanArguments(client Client, args []string) error {
	rest := args
	if client.Flavor == FlavorFlatpak {
		if len(args) < 2 || args[0] != "run" || args[1] != "com.moonlight_stream.Moonlight" {
			return errors.New("Moonlight Flatpak argument vector must begin with the fixed run com.moonlight_stream.Moonlight prefix")
		}
		rest = args[2:]
	}
	if len(rest) == 0 {
		return errors.New("Moonlight argument vector has no operation")
	}

	switch rest[0] {
	case string(Pair), string(List):
		if len(rest) != 2 {
			return fmt.Errorf("%s operation requires exactly one host argument", rest[0])
		}
		if err := config.ValidateHost(rest[1]); err != nil {
			return fmt.Errorf("host: %w", err)
		}
	case string(Stream):
		if client.Flavor == FlavorEmbedded {
			if len(rest) != 4 || rest[1] != "-app" {
				return errors.New("stream operation for Moonlight Embedded requires the fixed stream -app APP HOST argument shape")
			}
			if err := config.ValidateAppName(rest[2]); err != nil {
				return fmt.Errorf("app: %w", err)
			}
			if err := config.ValidateHost(rest[3]); err != nil {
				return fmt.Errorf("host: %w", err)
			}
			return nil
		}
		if len(rest) != 3 {
			return errors.New("stream operation for Moonlight Qt requires the fixed stream HOST APP argument shape")
		}
		if err := config.ValidateHost(rest[1]); err != nil {
			return fmt.Errorf("host: %w", err)
		}
		if err := config.ValidateAppName(rest[2]); err != nil {
			return fmt.Errorf("app: %w", err)
		}
	default:
		return fmt.Errorf("unsupported Moonlight operation %q", rest[0])
	}
	return nil
}

type Runner interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func Execute(ctx context.Context, runner Runner, stdin io.Reader, stdout, stderr io.Writer, plan Plan) error {
	if plan.Client.Binary == "" {
		return errors.New("refusing to execute an empty client path")
	}
	if err := validatePlanRoute(plan.Route); err != nil {
		return fmt.Errorf("refusing to execute an invalid remote plan: %w", err)
	}
	if err := validateClientPrefix(plan.Client); err != nil {
		return fmt.Errorf("refusing to execute an invalid Moonlight client: %w", err)
	}
	if len(plan.Arguments) == 0 {
		return errors.New("refusing to execute an empty argument vector")
	}
	if err := validatePlanArguments(plan.Client, plan.Arguments); err != nil {
		return fmt.Errorf("refusing to execute an invalid Moonlight argument vector: %w", err)
	}
	if !plan.validated {
		return errors.New("refusing to execute an unvalidated remote plan; construct it with BuildDiscoveredPlan")
	}
	if runner == nil {
		return errors.New("refusing to execute with a nil runner")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("refusing to execute a canceled handoff: %w", err)
	}
	if !plan.clientDiscovered {
		return errors.New("refusing to execute a plan whose client was not discovered through the passive resolver")
	}
	if !plan.clientBinding.matches(plan.Client) {
		return errors.New("refusing to execute a plan whose discovered client was changed after planning")
	}
	if err := runner.Run(ctx, stdin, stdout, stderr, plan.Client.Binary, plan.Arguments...); err != nil {
		return fmt.Errorf("Moonlight handoff failed: %w", err)
	}
	return nil
}
