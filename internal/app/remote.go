package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/config"
	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/remote"
)

// Pairing and app-listing are finite control-plane operations. Bound them so
// an unreachable physical host cannot leave a Linux/BSD terminal blocked
// forever. Interactive streaming intentionally keeps the caller's lifetime.
const remoteControlTimeout = 60 * time.Second

// Moonlight application listings are small in normal use. Keep the
// verification capture bounded so a hostile or malfunctioning host cannot
// consume unbounded client memory; output still streams to the caller.
const remoteApplicationListingCaptureLimit = 1 << 20

type remoteListingCapture struct {
	buffer    bytes.Buffer
	remaining int
}

func newRemoteListingCapture() *remoteListingCapture {
	return &remoteListingCapture{remaining: remoteApplicationListingCaptureLimit}
}

func (c *remoteListingCapture) Write(data []byte) (int, error) {
	if c.remaining > 0 {
		keep := len(data)
		if keep > c.remaining {
			keep = c.remaining
		}
		_, _ = c.buffer.Write(data[:keep])
		c.remaining -= keep
	}
	// The capture intentionally accepts discarded bytes so io.MultiWriter
	// does not interrupt the user's live Moonlight output at the cap.
	return len(data), nil
}

func (c *remoteListingCapture) String() string {
	return c.buffer.String()
}

func (a *App) runRemote(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.commandError("remote", false, ExitUsage, "expected pair, list, or stream")
	}
	var operation remote.Operation
	switch args[0] {
	case "pair":
		operation = remote.Pair
	case "list":
		operation = remote.List
	case "stream":
		operation = remote.Stream
	default:
		return a.commandError("remote", false, ExitUsage, "unknown subcommand %q", args[0])
	}

	set := a.flagSet("remote " + args[0])
	configPath := set.String("config", "", "configuration file")
	routeName := set.String("route", "", "physical-host route: windows or macos (default: configuration, then windows)")
	host := set.String("host", "", "physical host DNS name or IP")
	application := set.String("app", "", "Sunshine application name")
	requiredApplication := set.String("require-app", "", "require this application in a live Moonlight list (streams always check their launch app)")
	requireConfiguredApplication := set.Bool("require-configured-app", false, "require the configured application in a live Moonlight list (streams always check it)")
	clientSelection := set.String("client", "", "auto, moonlight, moonlight-embedded, moonlight-qt, or flatpak")
	resolution := set.String("resolution", "", "stream resolution: 720, 1080, 1440, 4k, or WIDTHxHEIGHT (640-7680 x 360-4320)")
	fps := set.Int("fps", 0, "stream frame rate (10-480); zero keeps the client default")
	bitrate := set.Int("bitrate", 0, "stream bitrate in Kbps (500-500000); zero keeps the client default")
	packetSize := set.Int("packet-size", 0, "stream network packet size in bytes (1024-9000, multiple of 16); zero keeps the client default")
	codec := set.String("codec", "", "stream video codec: auto, h264, hevc, or av1; empty keeps the client default")
	audioConfig := set.String("audio-config", "", "stream audio channels: stereo, 5.1-surround, or 7.1-surround")
	preserveHostSettings := set.Bool("preserve-host-settings", false, "ask Moonlight not to apply game or host graphics optimizations")
	networkMode := set.String("network-mode", "", "Moonlight Embedded network mode: auto, lan, or wan")
	platform := set.String("platform", "", "Moonlight Embedded output/input platform: auto, x11, x11_vdpau, or sdl")
	decoder := set.String("decoder", "", "stream video decoder: auto, software, or hardware; Qt/Flatpak only")
	displayMode := set.String("display-mode", "", "stream display mode: fullscreen, windowed, or borderless; Embedded supports windowed, Qt/Flatpak support all three")
	absoluteMouse := set.Bool("absolute-mouse", false, "use Moonlight Qt's remote-desktop optimized absolute mouse mode")
	noAbsoluteMouse := set.Bool("no-absolute-mouse", false, "disable Moonlight Qt's absolute mouse mode")
	confirmed := set.Bool("confirm-physical-host", false, "confirm that the host is not a VM")
	acknowledged := set.Bool("acknowledge-unverified-handoff", false, "acknowledge that streaming is not local Linux/BSD support")
	dryRun := set.Bool("dry-run", false, "validate and print the argument vector without executing")
	asJSON := set.Bool("json", false, "emit JSON (dry-run only)")
	if err := parseFlags(set, args[1:]); err != nil {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
	}
	if *asJSON && !*dryRun {
		return a.commandError("remote "+args[0], true, ExitUsage, "--json requires --dry-run so interactive Moonlight output is not mixed with JSON")
	}
	confirmationOverridden := false
	streamOptionsOverridden := false
	mouseModeOverridden := false
	hostOverridden := false
	applicationOverridden := false
	clientOverridden := false
	requiredApplicationOverridden := false
	requireConfiguredApplicationOverridden := false
	acknowledgementOverridden := false
	set.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "confirm-physical-host":
			confirmationOverridden = true
		case "host":
			hostOverridden = true
		case "resolution", "fps", "bitrate", "packet-size", "codec", "audio-config", "preserve-host-settings", "network-mode", "platform", "decoder", "display-mode":
			streamOptionsOverridden = true
		case "absolute-mouse", "no-absolute-mouse":
			mouseModeOverridden = true
		case "app":
			applicationOverridden = true
		case "require-app":
			requiredApplicationOverridden = true
		case "require-configured-app":
			requireConfiguredApplicationOverridden = true
		case "client":
			clientOverridden = true
		case "acknowledge-unverified-handoff":
			acknowledgementOverridden = true
		}
	})
	if *absoluteMouse && *noAbsoluteMouse {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "cannot combine --absolute-mouse and --no-absolute-mouse")
	}
	if operation != remote.Stream {
		var streamOnly []string
		if streamOptionsOverridden {
			streamOnly = append(streamOnly, "--resolution, --fps, --bitrate, --packet-size, --codec, --audio-config, --preserve-host-settings, --network-mode, --platform, --decoder, and --display-mode")
		}
		if mouseModeOverridden {
			streamOnly = append(streamOnly, "--absolute-mouse and --no-absolute-mouse")
		}
		if applicationOverridden {
			streamOnly = append(streamOnly, "--app")
		}
		if acknowledgementOverridden {
			streamOnly = append(streamOnly, "--acknowledge-unverified-handoff")
		}
		if len(streamOnly) > 0 {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%s require the stream operation", strings.Join(streamOnly, ", "))
		}
	}
	applicationCheckRequested := requiredApplicationOverridden || requireConfiguredApplicationOverridden
	if applicationCheckRequested {
		if operation != remote.List && operation != remote.Stream {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "application presence checks require the list or stream operation")
		}
		if requireConfiguredApplicationOverridden && !*requireConfiguredApplication {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--require-configured-app must be true when supplied")
		}
		if requiredApplicationOverridden {
			if err := config.ValidateAppName(*requiredApplication); err != nil {
				return a.commandError("remote "+args[0], *asJSON, ExitUsage, "invalid required application: %v", err)
			}
		}
		if *dryRun {
			if requiredApplicationOverridden {
				return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--require-app requires a live application-list preflight")
			}
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--require-configured-app requires a live application-list preflight")
		}
	}
	streamOptions := remote.StreamOptions{
		Resolution:           *resolution,
		FPS:                  *fps,
		BitrateKbps:          *bitrate,
		PacketSizeBytes:      *packetSize,
		Codec:                *codec,
		AudioConfig:          *audioConfig,
		PreserveHostSettings: *preserveHostSettings,
		NetworkMode:          *networkMode,
		Platform:             *platform,
		Decoder:              *decoder,
		DisplayMode:          *displayMode,
	}
	if *absoluteMouse {
		streamOptions.MouseMode = "absolute"
	} else if *noAbsoluteMouse {
		streamOptions.MouseMode = "relative"
	}
	if operation == remote.Stream {
		if err := streamOptions.Validate(); err != nil {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
		}
	}
	if !eligibleClientPlatform(a.GOOS, a.GOARCH) {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "remote handoff clients target Linux and BSD on amd64; current host is %s/%s", a.GOOS, a.GOARCH)
	}
	cfg, usedPath, err := loadRemoteConfig(*configPath, *routeName)
	if err != nil {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
	}
	target, route, err := cfg.ActiveRemote()
	if err != nil {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
	}
	if err := a.verifyRemoteHandoffContract(route); err != nil {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "%v", err)
	}
	preflight := a.prober().Run(ctx, probe.ProfileClient)
	ready := preflight.Ready()
	if operation != remote.Stream || *dryRun {
		// A dry-run only composes and prints a fixed argv; it never opens a
		// display, reads input, contacts the host, or starts Moonlight. Keep the
		// graphical/input gates on the live stream path while allowing operators
		// to inspect a plan from a headless SSH session.
		ready = preflight.ReadyForControl()
	}
	if !ready {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "client preflight failed; run `leaguebridge doctor --profile client` for details")
	}
	if hostOverridden {
		target.Host = *host
		// A physical-host confirmation is scoped to the configured destination.
		// Supplying --host creates a new invocation-scoped destination and must
		// never inherit a persisted attestation for another machine.
		target.PhysicalHostConfirmed = false
	}
	if confirmationOverridden {
		// Preserve explicit --confirm-physical-host=false as a revocation rather
		// than silently inheriting a persisted true value.
		target.PhysicalHostConfirmed = false
	}
	if applicationOverridden {
		target.App = *application
	}
	if clientOverridden {
		target.Client = *clientSelection
	}
	if *confirmed {
		target.PhysicalHostConfirmed = true
	}
	if err := cfg.Validate(); err != nil {
		location := "flags/defaults"
		if usedPath != "" {
			location = usedPath
		}
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "invalid remote configuration (%s): %v", location, err)
	}
	applicationCheck := ""
	if requiredApplicationOverridden {
		applicationCheck = *requiredApplication
	}
	if requireConfiguredApplicationOverridden {
		if applicationCheck != "" && applicationCheck != target.App {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--require-app %q must match the configured application %q when --require-configured-app is used", applicationCheck, target.App)
		}
		applicationCheck = target.App
	}
	if operation == remote.Stream && requiredApplicationOverridden && *requiredApplication != target.App {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--require-app %q must match the stream application %q", *requiredApplication, target.App)
	}
	if operation == remote.Stream && !*dryRun {
		// A live stream always checks the final launch target, including when
		// the caller did not spell out one of the optional requirement flags.
		applicationCheck = target.App
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	environment := a.RemoteEnv
	if environment == nil {
		environment = remote.RealEnvironment{}
	}
	client, err := remote.Discover(discoveryCtx, environment, target.Client)
	if err != nil {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "%v", err)
	}
	plan, err := remote.BuildDiscoveredPlan(client, remote.Request{
		Route:                   route,
		Operation:               operation,
		Host:                    target.Host,
		App:                     target.App,
		PhysicalHostConfirmed:   target.PhysicalHostConfirmed,
		AcceptUnverifiedHandoff: *acknowledged,
		Stream:                  streamOptions,
	})
	if err != nil {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "%v", err)
	}
	if *dryRun {
		if *asJSON {
			return a.writeJSON("remote "+args[0], plan)
		}
		fmt.Fprintln(a.Stdout, "Validated argument vector (no process started):")
		fmt.Fprintf(a.Stdout, "  executable: %s\n", strconv.Quote(plan.Client.Binary))
		for i, argument := range plan.Arguments {
			fmt.Fprintf(a.Stdout, "  argv[%d]: %s\n", i+1, strconv.Quote(argument))
		}
		for _, warning := range plan.Warnings {
			fmt.Fprintf(a.Stdout, "  warning: %s\n", warning)
		}
		return ExitOK
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", warning)
	}
	runner := a.RemoteRunner
	if runner == nil {
		runner = remote.ExecRunner{}
	}
	if operation == remote.Stream && !*dryRun {
		// Every live stream gets a host-application preflight. Use the same
		// discovered client and bound executable identity, but build a separate
		// list plan so no stream process starts when Sunshine has not advertised
		// the exact application that will be launched. The explicit application
		// requirement flags remain useful for `remote list` and for documenting
		// intent, but a live stream is never allowed to skip this guard.
		listPlan, err := remote.BuildDiscoveredPlan(client, remote.Request{
			Route:                 route,
			Operation:             remote.List,
			Host:                  target.Host,
			PhysicalHostConfirmed: target.PhysicalHostConfirmed,
		})
		if err != nil {
			return a.commandError("remote "+args[0], false, ExitBlocked, "cannot build the application-list preflight: %v", err)
		}
		fmt.Fprintln(a.Stderr, "preflight: checking that the physical host advertises the requested application before streaming")
		preflightCtx, cancelPreflight := context.WithTimeout(ctx, remoteControlTimeout)
		observedListing := newRemoteListingCapture()
		preflightStdout := io.MultiWriter(a.Stdout, observedListing)
		preflightErr := remote.Execute(preflightCtx, runner, a.Stdin, preflightStdout, a.Stderr, listPlan)
		preflightTimedOut := ctx.Err() == nil &&
			(errors.Is(preflightCtx.Err(), context.DeadlineExceeded) || errors.Is(preflightErr, context.DeadlineExceeded))
		cancelPreflight()
		if preflightErr != nil {
			if preflightTimedOut {
				return a.commandError("remote "+args[0], false, ExitInternal, "Moonlight application-list preflight timed out after %s; verify that the physical host is reachable and try again", remoteControlTimeout)
			}
			return a.commandError("remote "+args[0], false, ExitInternal, "Moonlight application-list preflight failed: %v", preflightErr)
		}
		if !remote.ApplicationListed(observedListing.String(), applicationCheck) {
			return a.commandError("remote "+args[0], false, ExitBlocked, "Moonlight listed the host successfully, but required application %q was not advertised; no stream was started", applicationCheck)
		}
	}
	executionCtx := ctx
	cancelExecution := func() {}
	controllerDeadline := false
	if operation != remote.Stream {
		executionCtx, cancelExecution = context.WithTimeout(ctx, remoteControlTimeout)
		controllerDeadline = true
	}
	defer cancelExecution()
	remoteStdout := io.Writer(a.Stdout)
	remoteStderr := io.Writer(a.Stderr)
	observedListing := newRemoteListingCapture()
	if operation == remote.List && applicationCheckRequested {
		// Preserve the normal interactive output while retaining a bounded copy
		// of stdout for the optional application-presence check. Moonlight sends
		// its application list as informational stdout; stderr is diagnostics and
		// must never satisfy the requirement.
		remoteStdout = io.MultiWriter(a.Stdout, observedListing)
	}
	if err := remote.Execute(executionCtx, runner, a.Stdin, remoteStdout, remoteStderr, plan); err != nil {
		if controllerDeadline && ctx.Err() == nil && errors.Is(executionCtx.Err(), context.DeadlineExceeded) {
			return a.commandError("remote "+args[0], false, ExitInternal, "Moonlight %s timed out after %s; verify that the physical host is reachable and try again", args[0], remoteControlTimeout)
		}
		return a.commandError("remote "+args[0], false, ExitInternal, "%v", err)
	}
	if operation == remote.List && applicationCheckRequested && !remote.ApplicationListed(observedListing.String(), applicationCheck) {
		return a.commandError("remote "+args[0], false, ExitBlocked, "Moonlight listed the host successfully, but required application %q was not advertised; configure that application on the physical host", applicationCheck)
	}
	return ExitOK
}

func loadRemoteConfig(explicitPath string, requestedRoute ...string) (config.Config, string, error) {
	if len(requestedRoute) > 1 {
		return config.Config{}, "", errors.New("only one remote route may be requested")
	}
	var selected config.Route
	if len(requestedRoute) == 1 && strings.TrimSpace(requestedRoute[0]) != "" {
		var err error
		selected, err = config.ParseRoute(requestedRoute[0])
		if err != nil {
			return config.Config{}, "", err
		}
	}
	validateSelection := func(cfg config.Config, path string) (config.Config, string, error) {
		if selected == "" {
			return cfg, path, nil
		}
		actual, err := cfg.Route()
		if err != nil {
			return config.Config{}, path, err
		}
		if actual != selected {
			return config.Config{}, path, fmt.Errorf("requested route %q conflicts with configuration route %q", selected, actual)
		}
		return cfg, path, nil
	}
	if strings.TrimSpace(explicitPath) != "" {
		cfg, err := config.Load(explicitPath)
		if err != nil {
			return config.Config{}, explicitPath, fmt.Errorf("load configuration %s: %w", explicitPath, err)
		}
		return validateSelection(cfg, explicitPath)
	}
	path, err := config.DefaultPath()
	if err != nil {
		return config.Config{}, "", err
	}
	cfg, err := config.Load(path)
	if err == nil {
		return validateSelection(cfg, path)
	}
	if errors.Is(err, config.ErrNotFound) {
		if selected == "" {
			selected = config.RouteWindows
		}
		cfg, defaultErr := config.DefaultForRoute(selected)
		return cfg, "", defaultErr
	}
	return config.Config{}, path, fmt.Errorf("load default configuration: %w", err)
}

func (a *App) verifyRemoteHandoffContract(routes ...config.Route) error {
	if len(routes) > 1 {
		return errors.New("only one remote route may be verified")
	}
	route := config.RouteWindows
	if len(routes) == 1 {
		route = routes[0]
	}
	var backendID compat.BackendID
	var backendKind compat.BackendKind
	switch route {
	case config.RouteWindows:
		backendID = compat.BackendPhysicalWindowsRemote
		backendKind = compat.KindRemotePhysicalWindows
	case config.RouteMacOS:
		backendID = compat.BackendPhysicalMacOSRemote
		backendKind = compat.KindRemotePhysicalMacOS
	default:
		return fmt.Errorf("unsupported physical-host route %q", route)
	}
	manifest, err := compat.Embedded()
	if err != nil {
		return fmt.Errorf("embedded compatibility authority is invalid: %w", err)
	}
	freshness, err := manifest.FreshnessAt(a.now())
	if err != nil {
		return fmt.Errorf("compatibility evidence cannot be evaluated: %w", err)
	}
	if freshness.State != compat.FreshnessFresh {
		return fmt.Errorf("compatibility evidence is %s; install a current LeagueBridge release before remote handoff", freshness.State)
	}
	for _, backend := range manifest.Backends {
		if backend.ID != backendID {
			continue
		}
		if backend.State != compat.StateHandoffOnly || backend.LaunchMode != compat.LaunchRemote || backend.Kind != backendKind || backend.LaunchVerdict != compat.DecisionDeny || backend.Authorization != compat.AuthorizationUnverified {
			return errors.New("embedded remote-handoff safety contract is not satisfied")
		}
		return nil
	}
	return errors.New("embedded remote-handoff backend is missing")
}

func eligibleClientPlatform(goos, goarch string) bool {
	if !strings.EqualFold(goarch, "amd64") {
		return false
	}
	switch strings.ToLower(goos) {
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		return true
	default:
		return false
	}
}
