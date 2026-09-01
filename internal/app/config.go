package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/config"
)

func (a *App) runConfig(args []string) int {
	if len(args) == 0 {
		return a.commandError("config", false, ExitUsage, "expected example, init, validate, or path")
	}
	switch args[0] {
	case "example":
		set := a.flagSet("config example")
		routeName := set.String("route", "windows", "physical-host route: windows or macos")
		if err := parseFlags(set, args[1:]); err != nil {
			return a.commandError("config example", false, ExitUsage, "%v", err)
		}
		route, err := config.ParseRoute(*routeName)
		if err != nil {
			return a.commandError("config example", false, ExitUsage, "%v", err)
		}
		data, err := config.MarshalExampleForRoute(route)
		if err != nil {
			return a.commandError("config example", false, ExitInternal, "encode example: %v", err)
		}
		if _, err := a.Stdout.Write(data); err != nil {
			return a.commandError("config example", false, ExitInternal, "write example: %v", err)
		}
		return ExitOK
	case "path":
		set := a.flagSet("config path")
		if err := parseFlags(set, args[1:]); err != nil {
			return a.commandError("config path", false, ExitUsage, "%v", err)
		}
		path, err := config.DefaultPath()
		if err != nil {
			return a.commandError("config path", false, ExitInternal, "%v", err)
		}
		fmt.Fprintln(a.Stdout, path)
		return ExitOK
	case "validate":
		return a.runConfigValidate(args[1:])
	case "init":
		return a.runConfigInit(args[1:])
	default:
		return a.commandError("config", false, ExitUsage, "unknown subcommand %q", args[0])
	}
}

func (a *App) runConfigValidate(args []string) int {
	set := a.flagSet("config validate")
	file := set.String("file", "", "configuration file (default: per-user path)")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("config validate", false, ExitUsage, "%v", err)
	}
	path := strings.TrimSpace(*file)
	if path == "" {
		var err error
		path, err = config.DefaultPath()
		if err != nil {
			return a.commandError("config validate", false, ExitInternal, "%v", err)
		}
	}
	if _, err := config.Load(path); err != nil {
		return a.commandError("config validate", false, ExitBlocked, "invalid configuration: %v", err)
	}
	fmt.Fprintf(a.Stdout, "Configuration is valid and contains no LeagueBridge-managed credentials: %s\n", path)
	return ExitOK
}

func (a *App) runConfigInit(args []string) int {
	set := a.flagSet("config init")
	file := set.String("file", "", "destination (default: per-user path)")
	routeName := set.String("route", "windows", "physical-host route: windows or macos")
	host := set.String("host", "", "physical host DNS name or IP; use HOST:PORT or [IPv6]:PORT for an explicit Moonlight port")
	application := set.String("app", config.DefaultRemoteApplication, "Sunshine application name (default: League of Legends)")
	client := set.String("client", "auto", "auto, moonlight, moonlight-embedded, moonlight-qt, or flatpak")
	confirmed := set.Bool("confirm-physical-host", false, "confirm that the host is not a VM")
	kvmURL := set.String("kvm-url", "", "optional clean hardware-KVM web-interface URL to store in the credential-free config")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("config init", false, ExitUsage, "%v", err)
	}
	route, err := config.ParseRoute(*routeName)
	if err != nil {
		return a.commandError("config init", false, ExitUsage, "%v", err)
	}
	path := strings.TrimSpace(*file)
	if path == "" {
		var err error
		path, err = config.DefaultPath()
		if err != nil {
			return a.commandError("config init", false, ExitInternal, "%v", err)
		}
	}
	cfg, err := config.DefaultForRoute(route)
	if err != nil {
		return a.commandError("config init", false, ExitUsage, "%v", err)
	}
	target, _, err := cfg.ActiveRemote()
	if err != nil {
		return a.commandError("config init", false, ExitInternal, "%v", err)
	}
	target.Host = *host
	target.App = *application
	target.Client = *client
	target.PhysicalHostConfirmed = *confirmed
	if *kvmURL != "" {
		cfg.KVM = &config.KVMConfig{Endpoint: *kvmURL}
	}
	if err := config.WriteNew(path, cfg); err != nil {
		if errors.Is(err, config.ErrExists) {
			return a.commandError("config init", false, ExitUsage, "refusing to overwrite existing configuration: %s", path)
		}
		return a.commandError("config init", false, ExitUsage, "create configuration: %v", err)
	}
	fmt.Fprintf(a.Stdout, "Created credential-free configuration: %s\n", path)
	if a.GOOS == "windows" {
		fmt.Fprintln(a.Stdout, "Windows inherits the parent directory ACL; verify that only intended accounts can read this file.")
	} else {
		fmt.Fprintln(a.Stdout, "Requested owner-only file mode 0600.")
	}
	if !*confirmed {
		fmt.Fprintln(a.Stdout, "Remote operations remain blocked until physical_host_confirmed is true or --confirm-physical-host is supplied.")
	}
	return ExitOK
}
