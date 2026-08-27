package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/probe"
)

func (a *App) runDoctor(ctx context.Context, args []string) int {
	set := a.flagSet("doctor")
	profileName := set.String("profile", defaultProfileName(a.GOOS), "client, windows-host, or macos-host")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("doctor", *asJSON, ExitUsage, "%v", err)
	}
	profile, err := parseProfile(*profileName)
	if err != nil {
		return a.commandError("doctor", *asJSON, ExitUsage, "%v", err)
	}
	report := a.prober().Run(ctx, profile)
	if *asJSON {
		if code := a.writeJSON("doctor", report); code != ExitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.Stdout, "Preflight %s on %s/%s: %s\n\n", report.Profile, report.OS, report.Architecture, strings.ToUpper(string(report.Status)))
		for _, check := range report.Checks {
			fmt.Fprintf(a.Stdout, "[%s] %s — %s\n", strings.ToUpper(string(check.Status)), check.ID, check.Summary)
			if check.Guidance != "" {
				fmt.Fprintf(a.Stdout, "       %s\n", check.Guidance)
			}
		}
	}
	if !report.Ready() {
		return ExitBlocked
	}
	return ExitOK
}

func defaultProfileName(goos string) string {
	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "windows":
		return string(probe.ProfileWindowsHost)
	case "darwin":
		return string(probe.ProfileMacOSHost)
	default:
		return string(probe.ProfileClient)
	}
}

func parseProfile(value string) (probe.Profile, error) {
	switch probe.Profile(strings.ToLower(strings.TrimSpace(value))) {
	case probe.ProfileClient:
		return probe.ProfileClient, nil
	case probe.ProfileWindowsHost:
		return probe.ProfileWindowsHost, nil
	case probe.ProfileMacOSHost:
		return probe.ProfileMacOSHost, nil
	default:
		return "", fmt.Errorf("profile must be client, windows-host, or macos-host, got %q", value)
	}
}
