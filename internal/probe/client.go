package probe

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
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
		p.inputPathCheck(),
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
	if reason, guidance := p.unsupportedDirectDisplay(); reason != "" {
		return Check{
			ID:       "client.graphical-session",
			Status:   StatusFail,
			Summary:  reason,
			Guidance: guidance,
		}
	}
	if wayland || x11 {
		return Check{
			ID:      "client.graphical-session",
			Status:  StatusPass,
			Summary: "A graphical desktop session is available.",
		}
	}
	if backend, ok := p.directDisplayBackend(); ok {
		return Check{
			ID:      "client.graphical-session",
			Status:  StatusPass,
			Summary: "A direct " + backend + " display backend and device endpoint are available; display usability is not verified.",
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

func (p *Prober) inputPathCheck() Check {
	if p.envValue("WAYLAND_DISPLAY") != "" || p.envValue("DISPLAY") != "" {
		return Check{
			ID:      "client.input",
			Status:  StatusPass,
			Summary: "A display-backed desktop input path is indicated; keyboard and mouse delivery is not verified.",
		}
	}
	if backend, ok := p.directDisplayBackend(); ok {
		if inputBackend, ok := p.directInputBackend(backend); ok {
			article := "a"
			if inputBackend == "evdev" {
				article = "an"
			}
			return Check{
				ID:      "client.input",
				Status:  StatusPass,
				Summary: "The direct " + backend + " path has " + article + " " + inputBackend + " input endpoint; input delivery is not verified.",
			}
		}
		guidance := "Grant the session access to a supported /dev/input/event* device before streaming."
		inputSummary := "no evdev input endpoint"
		if backend == "SDL KMS/DRM" && p.goos != "linux" {
			inputSummary = "no evdev or WSCONS input endpoint"
			guidance = "Grant the session access to a supported /dev/input/event* device, or WSCONS /dev/wskbd* and /dev/wsmouse* devices, before streaming."
		}
		return Check{
			ID:       "client.input",
			Status:   StatusWarn,
			Summary:  "A direct " + backend + " display path is available, but " + inputSummary + " was detected.",
			Guidance: guidance,
		}
	}
	if sessionType := p.envValue("XDG_SESSION_TYPE"); sessionType == "wayland" || sessionType == "x11" {
		return Check{
			ID:       "client.input",
			Status:   StatusWarn,
			Summary:  "A desktop session is indicated, but no display-backed input path was detected.",
			Guidance: "Run LeagueBridge from a terminal inside the graphical desktop session before streaming.",
		}
	}
	return Check{
		ID:       "client.input",
		Status:   StatusWarn,
		Summary:  "No display-backed desktop input path was detected; headless control may still work, but streaming input cannot be preflighted.",
		Guidance: "Start a supported graphical desktop session before streaming.",
	}
}

// directDisplayBackend recognizes only explicitly selected direct-display
// backends. A DRM device by itself is not enough: without an explicit SDL or
// Qt backend selection, a desktop may still be headless or owned by another
// session. The check remains an indicator, not proof that the client can open
// the device or render a usable stream.
func (p *Prober) directDisplayBackend() (string, bool) {
	if _, ok := eligibleClientOS[p.goos]; !ok {
		return "", false
	}
	if driver := strings.ToLower(strings.TrimSpace(p.envValue("SDL_VIDEODRIVER"))); driver == "kmsdrm" {
		if p.goos == "netbsd" {
			return "", false
		}
		if p.existsAny(p.directDRMDevicePaths()...) {
			return "SDL KMS/DRM", true
		}
	}
	switch platform := strings.ToLower(strings.TrimSpace(p.envValue("QT_QPA_PLATFORM"))); platform {
	case "eglfs", "kms", "kmsdrm":
		if p.existsAny(p.directDRMDevicePaths()...) {
			return "Qt EGLFS/KMS", true
		}
	case "linuxfb":
		if p.existsAny(filepath.FromSlash("/dev/fb0")) {
			return "Qt Linux framebuffer", true
		}
	}
	return "", false
}

func (p *Prober) unsupportedDirectDisplay() (string, string) {
	if p.goos == "netbsd" && strings.EqualFold(strings.TrimSpace(p.envValue("SDL_VIDEODRIVER")), "kmsdrm") {
		return "SDL KMS/DRM direct display is not supported on NetBSD by the current SDL *BSD backend.", "Use an X11 or Wayland session on NetBSD instead of SDL KMS/DRM."
	}
	return "", ""
}

func (p *Prober) directDRMDevicePaths() []string {
	paths := make([]string, 0, 8)
	for index := 0; index < 8; index++ {
		paths = append(paths, filepath.FromSlash("/dev/dri/card"+strconv.Itoa(index)))
	}
	if p.goos == "openbsd" {
		for index := 0; index < 8; index++ {
			paths = append(paths, filepath.FromSlash("/dev/drm"+strconv.Itoa(index)))
		}
	}
	return paths
}

func (p *Prober) directEvdevInputAvailable() bool {
	paths := make([]string, 0, 64)
	for index := 0; index < 64; index++ {
		paths = append(paths, filepath.FromSlash("/dev/input/event"+strconv.Itoa(index)))
	}
	return p.existsAny(paths...)
}

func (p *Prober) directInputBackend(backend string) (string, bool) {
	if p.goos != "openbsd" && p.goos != "netbsd" && p.directEvdevInputAvailable() {
		return "evdev", true
	}
	if backend != "SDL KMS/DRM" {
		return "", false
	}
	if p.wsconsInputAvailable() {
		return "WSCONS", true
	}
	return "", false
}

func (p *Prober) wsconsInputAvailable() bool {
	// SDL documents WSCONS as the OpenBSD input backend for KMS/DRM.
	// FreeBSD and DragonFly use their packaged SDL evdev path here, while
	// NetBSD's SDL KMS/DRM video backend is unsupported and is rejected before
	// this fallback can be considered.
	if p.goos != "openbsd" {
		return false
	}
	return p.existsAny(wsconsKeyboardDevicePaths()...) && p.existsAny(wsconsMouseDevicePaths()...)
}

func wsconsKeyboardDevicePaths() []string {
	paths := []string{filepath.FromSlash("/dev/wskbd")}
	for index := 0; index < 8; index++ {
		paths = append(paths, filepath.FromSlash("/dev/wskbd"+strconv.Itoa(index)))
	}
	return paths
}

func wsconsMouseDevicePaths() []string {
	paths := []string{filepath.FromSlash("/dev/wsmouse")}
	for index := 0; index < 8; index++ {
		paths = append(paths, filepath.FromSlash("/dev/wsmouse"+strconv.Itoa(index)))
	}
	return paths
}

func (p *Prober) moonlightCheck() Check {
	if command, ok := p.lookupMoonlight(); ok {
		label := moonlightCommandLabel(p.goos, command)
		return Check{ID: "client.moonlight", Status: StatusPass, Summary: label + " is available."}
	}
	flatpakID := filepath.FromSlash("app/com.moonlight_stream.Moonlight")
	paths := p.flatpakInstallPaths(flatpakID)
	flatpakInstalled := p.directoryExistsAny(paths...)
	if _, flatpakAvailable := p.lookupAny("flatpak"); flatpakInstalled && flatpakAvailable {
		return Check{ID: "client.moonlight", Status: StatusPass, Summary: "Moonlight Flatpak app evidence and a PATH-resolvable Flatpak launcher are present; user roots, when used, remain process-environment indicators."}
	}

	knownExecutables := make([]string, 0, 12)
	for _, directory := range []string{"/usr/bin", "/usr/local/bin", "/usr/pkg/bin", "/opt/local/bin"} {
		for _, name := range []string{"moonlight", "moonlight-embedded", "moonlight-qt"} {
			knownExecutables = append(knownExecutables, filepath.Join(filepath.FromSlash(directory), name))
		}
	}
	if p.regularFileExistsAny(knownExecutables...) {
		return Check{
			ID:       "client.moonlight",
			Status:   StatusWarn,
			Summary:  "A Moonlight file exists at a fixed local path, but the remote launcher cannot resolve it through PATH.",
			Guidance: "Add the trusted packaged Moonlight executable to PATH or select an installation that exposes moonlight, moonlight-embedded, or moonlight-qt. " + moonlightInstallGuidance(p.goos),
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
		Guidance: moonlightInstallGuidance(p.goos),
	}
}

// flatpakInstallPaths covers the standard system locations plus XDG-selected
// data roots. It only constructs paths and calls the read-only FileSystem
// surface; it never executes Flatpak or trusts arbitrary command output.
func (p *Prober) flatpakInstallPaths(flatpakID string) []string {
	roots := []string{
		filepath.FromSlash("/var/lib/flatpak"),
		filepath.FromSlash("/usr/local/share/flatpak"),
		filepath.FromSlash("/usr/share/flatpak"),
	}
	if dataHome, ok := p.localEnvironmentRoot(p.envValue("XDG_DATA_HOME")); ok {
		roots = append(roots, filepath.Join(dataHome, "flatpak"))
	}
	if home, ok := p.localEnvironmentRoot(p.envValue("HOME")); ok {
		roots = append(roots, filepath.Join(home, ".local", "share", "flatpak"))
	}
	if dataDirs := p.envValue("XDG_DATA_DIRS"); dataDirs != "" {
		for _, dataDir := range strings.Split(dataDirs, ":") {
			if root, ok := p.localEnvironmentRoot(dataDir); ok {
				roots = append(roots, filepath.Join(root, "flatpak"))
			}
		}
	}
	paths := make([]string, 0, len(roots))
	for _, root := range uniqueNonEmpty(roots) {
		paths = append(paths, filepath.Join(root, flatpakID))
	}
	return paths
}

// lookupMoonlight mirrors the remote resolver's automatic preference: choose
// the explicitly named Qt executable first, then interpret the generic
// executable according to the package convention of the current Unix target.
// Keeping the diagnostic and execution paths aligned prevents doctor output
// from describing a different client flavor than the handoff will use.
func (p *Prober) lookupMoonlight() (string, bool) {
	if command, ok := p.lookupAny("moonlight-qt"); ok {
		return command, true
	}
	if command, ok := p.lookupAny("moonlight-embedded"); ok {
		return command, true
	}
	return p.lookupAny("moonlight")
}

func moonlightCommandLabel(goos, command string) string {
	if command == "moonlight-qt" || (command == "moonlight" && !genericMoonlightIsEmbeddedOnTarget(goos)) {
		return "Moonlight Qt"
	}
	return "Moonlight Embedded"
}

func genericMoonlightIsEmbeddedOnTarget(goos string) bool {
	return goos == "freebsd" || goos == "dragonfly"
}

func moonlightInstallGuidance(goos string) string {
	switch goos {
	case "freebsd":
		return "Install Moonlight Qt with `pkg install moonlight-qt` (or Moonlight Embedded with `pkg install moonlight-embedded`) from a configured signed repository, or build games/moonlight-qt or games/moonlight-embedded from FreeBSD's official ports tree; expose moonlight-qt, moonlight-embedded, or moonlight on PATH."
	case "openbsd":
		return "Install Moonlight Qt with `pkg_add moonlight-qt` from a configured signed repository, or build games/moonlight-qt from OpenBSD's official ports tree; expose moonlight-qt, moonlight-embedded, or moonlight on PATH."
	case "netbsd":
		return "Install Moonlight Qt with `pkgin install moonlight-qt` from a configured signed pkgsrc binary repository, or build games/moonlight-qt from NetBSD's official pkgsrc tree; expose moonlight-qt, moonlight-embedded, or moonlight on PATH."
	case "dragonfly":
		return "Install Moonlight Qt with `pkg install moonlight-qt` (or Moonlight Embedded with `pkg install moonlight-embedded`) from a configured signed repository, or build games/moonlight-qt or games/moonlight-embedded from DragonFly's DPorts tree; expose moonlight-qt, moonlight-embedded, or moonlight on PATH."
	case "linux":
		return "Install Moonlight Qt or Embedded from the distribution's signed package repository, or install the official Flatpak with `flatpak install flathub com.moonlight_stream.Moonlight` after configuring a trusted Flathub remote; expose moonlight, moonlight-embedded, moonlight-qt, or the Flatpak launcher on PATH."
	default:
		return "This client profile supports only Linux and the supported BSD targets on amd64; Windows and macOS are external physical-host destinations, not LeagueBridge installation targets."
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
