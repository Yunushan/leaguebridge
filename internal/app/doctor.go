package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/remote"
)

func (a *App) runDoctor(ctx context.Context, args []string) int {
	set := a.flagSet("doctor")
	profileName := set.String("profile", defaultProfileName(a.GOOS), "client, windows-host, macos-host, or compatibility")
	clientSelection := set.String("client", "", "client profile selection: auto, moonlight, moonlight-embedded, moonlight-qt, or flatpak")
	outputPlatform := set.String("platform", "", "Embedded output backend: auto, x11, x11_vdpau, x11_vaapi, or sdl")
	qtPlatform := set.String("qt-platform", "", "Qt output backend: auto, xcb, wayland, eglfs, or linuxfb")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("doctor", *asJSON, ExitUsage, "%v", err)
	}
	profile, err := parseProfile(*profileName)
	if err != nil {
		return a.commandError("doctor", *asJSON, ExitUsage, "%v", err)
	}
	if profile != probe.ProfileClient && (strings.TrimSpace(*clientSelection) != "" || strings.TrimSpace(*outputPlatform) != "" || strings.TrimSpace(*qtPlatform) != "") {
		return a.commandError("doctor", *asJSON, ExitUsage, "--client, --platform, and --qt-platform require the client profile")
	}
	preferred, err := validateDoctorClientSelection(*clientSelection)
	if err != nil {
		return a.commandError("doctor", *asJSON, ExitUsage, "%v", err)
	}
	selectedOutputPlatform := strings.ToLower(strings.TrimSpace(*outputPlatform))
	selectedQtPlatform := strings.ToLower(strings.TrimSpace(*qtPlatform))
	if selectedOutputPlatform != "" {
		if err := validateDoctorOutputPlatform(selectedOutputPlatform); err != nil {
			return a.commandError("doctor", *asJSON, ExitUsage, "%v", err)
		}
		if selectedQtPlatform != "" {
			return a.commandError("doctor", *asJSON, ExitUsage, "--platform and --qt-platform cannot be combined")
		}
		if preferred == "" || preferred == "auto" {
			preferred = "moonlight-embedded"
		}
		if preferred == "moonlight-qt" || preferred == "flatpak" {
			return a.commandError("doctor", *asJSON, ExitUsage, "--platform selects an Embedded backend; it cannot be combined with --client %s", preferred)
		}
	}
	if selectedQtPlatform != "" {
		if err := remote.ValidateQtPlatform(selectedQtPlatform); err != nil {
			return a.commandError("doctor", *asJSON, ExitUsage, "%v", err)
		}
		if preferred == "" || preferred == "auto" {
			preferred = "moonlight-qt"
		}
		if preferred != "moonlight-qt" && preferred != "flatpak" {
			return a.commandError("doctor", *asJSON, ExitUsage, "--qt-platform selects a Qt backend; it requires --client moonlight-qt or flatpak")
		}
	}
	prober := a.prober()
	report := doctorReport(ctx, prober, profile, preferred, selectedOutputPlatform, selectedQtPlatform)
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

func validateDoctorClientSelection(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "", "auto", "moonlight", "moonlight-embedded", "moonlight-qt", "flatpak":
		return normalized, nil
	default:
		return "", fmt.Errorf("client must be auto, moonlight, moonlight-embedded, moonlight-qt, or flatpak, got %q", value)
	}
}

func validateDoctorOutputPlatform(value string) error {
	switch value {
	case "auto", "x11", "x11_vdpau", "x11_vaapi", "sdl":
		return nil
	default:
		return fmt.Errorf("Embedded platform must be auto, x11, x11_vdpau, x11_vaapi, or sdl, got %q", value)
	}
}

// doctorReport selects the same probe extension used by a live remote stream.
// The generic ProbeRunner remains sufficient for the unqualified profiles and
// for custom callers that do not expose the optional stream-aware methods.
func doctorReport(ctx context.Context, prober ProbeRunner, profile probe.Profile, preferred, outputPlatform, qtPlatform string) probe.Report {
	if profile != probe.ProfileClient {
		return prober.Run(ctx, profile)
	}
	if qtPlatform != "" {
		if streamAware, ok := prober.(interface {
			ClientForStreamWithQtPlatform(context.Context, string, string, string) probe.Report
		}); ok {
			return streamAware.ClientForStreamWithQtPlatform(ctx, preferred, outputPlatform, qtPlatform)
		}
	}
	if outputPlatform != "" {
		if streamAware, ok := prober.(interface {
			ClientForStream(context.Context, string, string) probe.Report
		}); ok {
			return streamAware.ClientForStream(ctx, preferred, outputPlatform)
		}
	}
	if preferred != "" {
		if selectionAware, ok := prober.(interface {
			ClientFor(context.Context, string) probe.Report
		}); ok {
			return selectionAware.ClientFor(ctx, preferred)
		}
	}
	return prober.Run(ctx, profile)
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
	case probe.ProfileCompatibility:
		return probe.ProfileCompatibility, nil
	default:
		return "", fmt.Errorf("profile must be client, windows-host, macos-host, or compatibility, got %q", value)
	}
}
