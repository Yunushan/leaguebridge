package probe

import (
	"context"
	"path/filepath"
)

var eligibleClientOS = map[string]string{
	"dragonfly": "DragonFly BSD",
	"freebsd":   "FreeBSD",
	"linux":     "Linux",
	"netbsd":    "NetBSD",
	"openbsd":   "OpenBSD",
}

// Client inspects whether this Linux or BSD machine can act as a Moonlight
// streaming client. It never starts Moonlight or any compatibility runtime.
func (p *Prober) Client(_ context.Context) Report {
	checks := []Check{
		p.clientPlatformCheck(),
		p.graphicalSessionCheck(),
		p.moonlightCheck(),
		p.audioCheck(),
		p.decoderCheck(),
	}
	return p.report(ProfileClient, checks)
}

func (p *Prober) clientPlatformCheck() Check {
	name, osEligible := eligibleClientOS[p.goos]
	if !osEligible || p.goarch != "amd64" {
		return Check{
			ID:       "client.platform",
			Status:   StatusFail,
			Summary:  "This operating system or architecture is outside the initial client target.",
			Guidance: "Use Linux, FreeBSD, OpenBSD, NetBSD, or DragonFly BSD on amd64.",
		}
	}
	return Check{
		ID:      "client.platform",
		Status:  StatusPass,
		Summary: name + " on amd64 is eligible for client preflight.",
	}
}

func (p *Prober) graphicalSessionCheck() Check {
	wayland := p.envValue("WAYLAND_DISPLAY") != ""
	x11 := p.envValue("DISPLAY") != ""
	sessionType := p.envValue("XDG_SESSION_TYPE")
	if wayland || x11 {
		return Check{
			ID:      "client.graphical-session",
			Status:  StatusPass,
			Summary: "A graphical desktop session is available.",
		}
	}
	if sessionType == "wayland" || sessionType == "x11" {
		return Check{
			ID:       "client.graphical-session",
			Status:   StatusWarn,
			Summary:  "A desktop session is indicated, but its display endpoint is unavailable.",
			Guidance: "Run LeagueBridge from a terminal inside the graphical desktop session.",
		}
	}
	return Check{
		ID:       "client.graphical-session",
		Status:   StatusFail,
		Summary:  "No Wayland or X11 graphical session was detected.",
		Guidance: "Start a supported graphical desktop session before streaming.",
	}
}

func (p *Prober) moonlightCheck() Check {
	if command, ok := p.lookupAny("moonlight", "moonlight-qt"); ok {
		label := "Moonlight"
		if command == "moonlight-qt" {
			label = "Moonlight Qt"
		}
		return Check{ID: "client.moonlight", Status: StatusPass, Summary: label + " is available."}
	}
	flatpakID := filepath.FromSlash("flatpak/app/com.moonlight_stream.Moonlight")
	paths := []string{
		filepath.Join(string(filepath.Separator), "var", "lib", flatpakID),
		filepath.Join(string(filepath.Separator), "usr", "local", "share", flatpakID),
	}
	if dataHome, ok := p.localEnvironmentRoot(p.envValue("XDG_DATA_HOME")); ok {
		paths = append(paths, filepath.Join(dataHome, flatpakID))
	}
	if home, ok := p.localEnvironmentRoot(p.envValue("HOME")); ok {
		paths = append(paths, filepath.Join(home, ".local", "share", flatpakID))
	}
	flatpakInstalled := p.directoryExistsAny(paths...)
	if _, flatpakAvailable := p.lookupAny("flatpak"); flatpakInstalled && flatpakAvailable {
		return Check{ID: "client.moonlight", Status: StatusPass, Summary: "Moonlight Flatpak app evidence and a PATH-resolvable Flatpak launcher are present; user roots, when used, remain process-environment indicators."}
	}

	knownExecutables := make([]string, 0, 8)
	for _, directory := range []string{"/usr/bin", "/usr/local/bin", "/usr/pkg/bin", "/opt/local/bin"} {
		for _, name := range []string{"moonlight", "moonlight-qt"} {
			knownExecutables = append(knownExecutables, filepath.Join(filepath.FromSlash(directory), name))
		}
	}
	if p.regularFileExistsAny(knownExecutables...) {
		return Check{
			ID:       "client.moonlight",
			Status:   StatusWarn,
			Summary:  "A Moonlight file exists at a fixed local path, but the remote launcher cannot resolve it through PATH.",
			Guidance: "Add the trusted packaged Moonlight executable to PATH or select an installation that exposes moonlight or moonlight-qt.",
		}
	}
	if flatpakInstalled {
		return Check{
			ID:       "client.moonlight",
			Status:   StatusWarn,
			Summary:  "A Moonlight Flatpak directory is present, but the remote launcher cannot resolve flatpak through PATH.",
			Guidance: "Install Flatpak from the operating system's trusted source and make its launcher available through PATH.",
		}
	}
	return Check{
		ID:       "client.moonlight",
		Status:   StatusFail,
		Summary:  "Moonlight was not detected.",
		Guidance: "Install Moonlight from a trusted operating-system or Flatpak source.",
	}
}

func (p *Prober) audioCheck() Check {
	if p.envValue("PULSE_SERVER") != "" || p.envValue("PIPEWIRE_REMOTE") != "" {
		return Check{ID: "client.audio", Status: StatusPass, Summary: "Process environment indicates a desktop audio endpoint; connectivity is not verified."}
	}

	if runtimeDir, ok := p.localEnvironmentRoot(p.envValue("XDG_RUNTIME_DIR")); ok {
		if p.existsAny(
			filepath.Join(runtimeDir, "pipewire-0"),
			filepath.Join(runtimeDir, "pulse", "native"),
		) {
			return Check{ID: "client.audio", Status: StatusPass, Summary: "A local audio endpoint exists under an environment-derived runtime root; usability is not verified."}
		}
	}

	paths := make([]string, 0, 6)
	switch p.goos {
	case "linux":
		paths = append(paths, filepath.FromSlash("/dev/snd"))
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		paths = append(paths,
			filepath.FromSlash("/dev/audio"),
			filepath.FromSlash("/dev/dsp"),
			filepath.FromSlash("/dev/mixer"),
			filepath.FromSlash("/dev/sndstat"),
		)
	}
	if p.existsAny(paths...) {
		return Check{ID: "client.audio", Status: StatusPass, Summary: "An audio subsystem is available."}
	}
	return Check{
		ID:       "client.audio",
		Status:   StatusWarn,
		Summary:  "No desktop or kernel audio indicator was detected.",
		Guidance: "Confirm that audio works in the current desktop session before streaming.",
	}
}

func (p *Prober) decoderCheck() Check {
	if command, ok := p.lookupAny("vainfo", "vdpauinfo", "ffmpeg"); ok {
		labels := map[string]string{"ffmpeg": "FFmpeg", "vainfo": "VA-API diagnostics", "vdpauinfo": "VDPAU diagnostics"}
		return Check{ID: "client.decoder-tools", Status: StatusPass, Summary: labels[command] + " is available for optional decoder diagnostics."}
	}
	return Check{
		ID:       "client.decoder-tools",
		Status:   StatusWarn,
		Summary:  "Optional video-decoder diagnostic utilities were not detected.",
		Guidance: "Install vainfo, vdpauinfo, or FFmpeg when hardware-decoder troubleshooting is needed.",
	}
}
