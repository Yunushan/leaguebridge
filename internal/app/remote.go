package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/config"
	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/remote"
)

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
	clientSelection := set.String("client", "", "auto, moonlight, moonlight-qt, or flatpak")
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
	set.Visit(func(option *flag.Flag) {
		if option.Name == "confirm-physical-host" {
			confirmationOverridden = true
		}
	})
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
	if !preflight.Ready() {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "client preflight failed; run `leaguebridge doctor --profile client` for details")
	}
	if *host != "" {
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
	if *application != "" {
		target.App = *application
	}
	if *clientSelection != "" {
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
	if err := remote.Execute(ctx, runner, a.Stdin, a.Stdout, a.Stderr, plan); err != nil {
		return a.commandError("remote "+args[0], false, ExitInternal, "%v", err)
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
