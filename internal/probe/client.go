package probe

import (
	"context"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/target"
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
// With no requested client, the check preserves the normal automatic
// Moonlight preference used by the diagnostic command.
func (p *Prober) Client(ctx context.Context) Report {
	return p.client(ctx, "", "", "")
}

// ClientFor performs the same read-only client preflight while honoring an
// invocation's explicit Moonlight selection. This keeps the remote handoff
// gate aligned with the launcher that will actually be discovered and run;
// an unrelated installed client must not make an explicit selection appear
// ready.
func (p *Prober) ClientFor(ctx context.Context, preferred string) Report {
	return p.client(ctx, preferred, "", "")
}

// ClientForStream performs client preflight for the exact Moonlight flavor and
// Embedded output backend that a live stream will use. An explicit output
// selection must not inherit a pass from a different graphical endpoint.
func (p *Prober) ClientForStream(ctx context.Context, preferred, outputPlatform string) Report {
	return p.client(ctx, preferred, outputPlatform, "")
}

// ClientForStreamWithQtPlatform performs the same stream preflight while
// applying one bounded Qt QPA platform selection to the display and input
// checks. It is used by the remote handoff path so a stale ambient
// WAYLAND_DISPLAY cannot override an explicit xcb selection, and so direct
// eglfs/linuxfb setups can be checked before Moonlight starts.
func (p *Prober) ClientForStreamWithQtPlatform(ctx context.Context, preferred, outputPlatform, qtPlatform string) Report {
	return p.client(ctx, preferred, outputPlatform, normalizeQtPlatform(qtPlatform))
}

func (p *Prober) client(_ context.Context, preferred, outputPlatform, qtPlatform string) Report {
	selectedQtPlatform := normalizeQtPlatform(qtPlatform)
	if p.qtClientSelected(preferred) && (selectedQtPlatform == "" || selectedQtPlatform == "auto") {
		// Qt consumes QT_QPA_PLATFORM from the child environment when no
		// invocation-scoped override was supplied. Mirror that choice during
		// preflight so a stale offscreen/minimal/invalid backend cannot make a
		// valid DISPLAY look stream-ready, and so a stale Wayland endpoint cannot
		// win over an ambient xcb selection.
		selectedQtPlatform = normalizeQtPlatform(p.envValue("QT_QPA_PLATFORM"))
	}
	graphicalSession := p.graphicalSessionCheckForQt(outputPlatform, selectedQtPlatform)
	inputPath := p.inputPathCheckForQt(outputPlatform, selectedQtPlatform, graphicalSession)
	checks := []Check{
		p.clientPlatformCheck(),
		graphicalSession,
		inputPath,
		p.moonlightCheck(preferred),
		p.audioCheck(),
		p.decoderCheck(),
	}
	return p.report(ProfileClient, checks)
}

// qtClientSelected reports whether the launcher that the remote resolver will
// choose is a Qt client. It intentionally uses only the same PATH lookup and
// package-name convention as moonlightCheck; it never starts a client. This is
// needed because QT_QPA_PLATFORM affects Qt only and must not block an
// Embedded stream that happens to inherit the same process environment.
func (p *Prober) qtClientSelected(preferred string) bool {
	selection := strings.ToLower(strings.TrimSpace(preferred))
	switch selection {
	case "moonlight-qt", "flatpak":
		return true
	case "moonlight", "moonlight-embedded":
		return false
	case "", "auto":
		if command, ok := p.lookupMoonlight(); ok {
			return moonlightCommandUsesQt(p.goos, command, selection)
		}
		return p.flatpakClientSelected()
	default:
		return false
	}
}

func (p *Prober) flatpakClientSelected() bool {
	if p.goos != "linux" {
		return false
	}
	if _, ok := p.lookupAny("flatpak"); !ok {
		return false
	}
	return p.directoryExistsAny(p.flatpakInstallPaths(filepath.FromSlash("app/com.moonlight_stream.Moonlight"))...)
}

func (p *Prober) clientPlatformCheck() Check {
	name, osEligible := eligibleClientOS[p.goos]
	if !osEligible || !target.IsSupported(p.goos, p.goarch) {
		return Check{
			ID:       "client.platform",
			Status:   StatusFail,
			Summary:  "This operating system or architecture is outside the supported client target.",
			Guidance: "Use Linux, FreeBSD, OpenBSD, or NetBSD on amd64/arm64, or DragonFly BSD on amd64.",
		}
	}
	return Check{
		ID:      "client.platform",
		Status:  StatusPass,
		Summary: name + " on " + target.NormalizeArchitecture(p.goarch) + " is eligible for client preflight.",
	}
}

func (p *Prober) graphicalSessionCheck() Check {
	return p.graphicalSessionCheckForQt("", "")
}

func (p *Prober) graphicalSessionCheckFor(outputPlatform string) Check {
	return p.graphicalSessionCheckForQt(outputPlatform, "")
}

func (p *Prober) graphicalSessionCheckForQt(outputPlatform, qtPlatform string) Check {
	if selected := normalizeOutputPlatform(outputPlatform); selected != "" && selected != "auto" {
		display := p.selectedDisplayEnvironmentCheck(selected)
		return Check{
			ID:       "client.graphical-session",
			Status:   display.status,
			Summary:  display.summary,
			Guidance: display.guidance,
		}
	}
	if selected := normalizeQtPlatform(qtPlatform); selected != "" && selected != "auto" {
		display := p.selectedQtDisplayEnvironmentCheck(selected)
		return Check{
			ID:       "client.graphical-session",
			Status:   display.status,
			Summary:  display.summary,
			Guidance: display.guidance,
		}
	}
	sessionType := p.envValue("XDG_SESSION_TYPE")
	if reason, guidance := p.unsupportedDirectDisplay(); reason != "" {
		return Check{
			ID:       "client.graphical-session",
			Status:   StatusFail,
			Summary:  reason,
			Guidance: guidance,
		}
	}
	if display := p.displayEnvironmentCheck(); display.configured {
		return Check{
			ID:       "client.graphical-session",
			Status:   display.status,
			Summary:  display.summary,
			Guidance: display.guidance,
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
	return p.inputPathCheckForQt("", "", Check{})
}

func (p *Prober) inputPathCheckFor(outputPlatform string, graphicalSession Check) Check {
	return p.inputPathCheckForQt(outputPlatform, "", graphicalSession)
}

func (p *Prober) inputPathCheckForQt(outputPlatform, qtPlatform string, graphicalSession Check) Check {
	if selected := normalizeOutputPlatform(outputPlatform); selected != "" && selected != "auto" {
		if graphicalSession.Status != StatusPass {
			status := graphicalSession.Status
			if status == "" {
				status = StatusFail
			}
			return Check{
				ID:       "client.input",
				Status:   status,
				Summary:  "The selected " + selected + " output backend has no confirmed display endpoint, so a display-backed input path cannot be preflighted.",
				Guidance: graphicalSession.Guidance,
			}
		}
		if selected == "sdl" && strings.EqualFold(strings.TrimSpace(p.envValue("SDL_VIDEODRIVER")), "kmsdrm") {
			if backend, ok := p.directDisplayBackend(); ok {
				if inputBackend, ok := p.directInputBackend(backend); ok {
					article := "a"
					if inputBackend == "evdev" {
						article = "an"
					}
					return Check{
						ID:      "client.input",
						Status:  StatusPass,
						Summary: "The selected SDL KMS/DRM path has " + article + " " + inputBackend + " input endpoint; input delivery is not verified.",
					}
				}
			}
			return Check{
				ID:       "client.input",
				Status:   StatusWarn,
				Summary:  "The selected SDL KMS/DRM display is available, but no supported input endpoint was detected.",
				Guidance: "Grant the session access to a supported /dev/input/event* device, or WSCONS /dev/wskbd* and /dev/wsmouse* devices, before streaming.",
			}
		}
		return Check{
			ID:      "client.input",
			Status:  StatusPass,
			Summary: "The selected " + selected + " display endpoint indicates a display-backed desktop input path; keyboard and mouse delivery is not verified.",
		}
	}

	if selected := normalizeQtPlatform(qtPlatform); selected != "" && selected != "auto" {
		if graphicalSession.Status != StatusPass {
			status := graphicalSession.Status
			if status == "" {
				status = StatusFail
			}
			return Check{
				ID:       "client.input",
				Status:   status,
				Summary:  "The selected Qt " + selected + " output backend has no confirmed display endpoint, so a display-backed input path cannot be preflighted.",
				Guidance: graphicalSession.Guidance,
			}
		}
		if selected == "xcb" || selected == "wayland" {
			return Check{
				ID:      "client.input",
				Status:  StatusPass,
				Summary: "The selected Qt " + selected + " display endpoint indicates a display-backed desktop input path; keyboard and mouse delivery is not verified.",
			}
		}
		if backend, ok := p.directQtDisplayBackend(selected); ok {
			if inputBackend, ok := p.directInputBackend(backend); ok {
				article := "a"
				if inputBackend == "evdev" {
					article = "an"
				}
				return Check{
					ID:      "client.input",
					Status:  StatusPass,
					Summary: "The selected Qt " + selected + " path has " + article + " " + inputBackend + " input endpoint; input delivery is not verified.",
				}
			}
			return Check{
				ID:       "client.input",
				Status:   StatusWarn,
				Summary:  "The selected Qt " + selected + " display is available, but no supported evdev input endpoint was detected.",
				Guidance: "Grant the session access to a supported /dev/input/event* device before streaming.",
			}
		}
	}

	if display := p.displayEnvironmentCheck(); display.configured {
		if display.status != StatusPass {
			return Check{
				ID:       "client.input",
				Status:   display.status,
				Summary:  "The configured graphical display endpoint is not usable, so a display-backed input path cannot be confirmed.",
				Guidance: display.guidance,
			}
		}
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

func normalizeOutputPlatform(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeQtPlatform(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (p *Prober) selectedDisplayEnvironmentCheck(outputPlatform string) displayEnvironmentResult {
	switch outputPlatform {
	case "x11", "x11_vdpau", "x11_vaapi":
		return p.x11DisplayEnvironmentCheck(outputPlatform)
	case "sdl":
		return p.sdlDisplayEnvironmentCheck()
	default:
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "The selected Moonlight output backend is not recognized by the client preflight.",
			guidance:   "Select auto, x11, x11_vdpau, x11_vaapi, or sdl for the Embedded output backend.",
		}
	}
}

func (p *Prober) selectedQtDisplayEnvironmentCheck(qtPlatform string) displayEnvironmentResult {
	switch qtPlatform {
	case "xcb":
		return p.x11DisplayEnvironmentCheck("x11")
	case "wayland":
		return p.waylandDisplayEnvironmentCheck()
	case "eglfs", "linuxfb":
		_, ok := p.directQtDisplayBackend(qtPlatform)
		if !ok {
			return displayEnvironmentResult{
				configured: true,
				status:     StatusFail,
				summary:    "The selected Qt " + qtPlatform + " output backend has no accessible display device endpoint.",
				guidance:   "Grant the session access to the target display device, then run the client preflight again.",
			}
		}
		return displayEnvironmentResult{
			configured: true,
			status:     StatusPass,
			summary:    "The selected Qt " + qtPlatform + " output backend and device endpoint are available; display usability is not verified.",
		}
	default:
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "The selected Qt output backend is not recognized by the client preflight.",
			guidance:   "Select auto, xcb, wayland, eglfs, or linuxfb for a Qt stream.",
		}
	}
}

func (p *Prober) x11DisplayEnvironmentCheck(outputPlatform string) displayEnvironmentResult {
	x11 := p.envValue("DISPLAY")
	label := "X11"
	switch outputPlatform {
	case "x11_vdpau":
		label = "X11/VDPAU"
	case "x11_vaapi":
		label = "X11/VA-API"
	}
	if x11 == "" {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "The selected " + label + " output backend requires DISPLAY, but no X11 display endpoint is configured.",
			guidance:   "Set DISPLAY to a valid endpoint such as :0 before streaming, or select the graphical backend that is actually available.",
		}
	}
	if !validX11Display(x11) {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "The selected " + label + " output backend has an invalid X11 display endpoint.",
			guidance:   "Set DISPLAY to a value such as :0 or host:0 before streaming.",
		}
	}
	if socketPath := x11LocalSocketPath(x11, p.goos); socketPath != "" {
		if info, err := p.fs.Stat(socketPath); err == nil && info != nil && info.Mode()&fs.ModeSocket != 0 {
			return displayEnvironmentResult{
				configured: true,
				status:     StatusPass,
				summary:    "The selected " + label + " output backend has a local X11 display socket; authentication and input delivery are not verified.",
			}
		}
	}
	return displayEnvironmentResult{
		configured: true,
		status:     StatusPass,
		summary:    "The selected " + label + " output backend has a valid X11 display endpoint; socket ownership and authentication are not verified.",
	}
}

func (p *Prober) sdlDisplayEnvironmentCheck() displayEnvironmentResult {
	driver := strings.ToLower(strings.TrimSpace(p.envValue("SDL_VIDEODRIVER")))
	switch driver {
	case "":
		display := p.displayEnvironmentCheck()
		if display.configured {
			return display
		}
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "The selected SDL output backend has no X11, Wayland, or explicitly configured direct-display endpoint.",
			guidance:   "Run inside X11/Wayland, or set SDL_VIDEODRIVER=kmsdrm with an accessible DRM device before streaming.",
		}
	case "x11":
		return p.x11DisplayEnvironmentCheck("x11")
	case "wayland":
		return p.waylandDisplayEnvironmentCheck()
	case "kmsdrm":
		if reason, guidance := p.unsupportedDirectDisplay(); reason != "" {
			return displayEnvironmentResult{configured: true, status: StatusFail, summary: reason, guidance: guidance}
		}
		if _, ok := p.directDisplayBackend(); ok {
			return displayEnvironmentResult{
				configured: true,
				status:     StatusPass,
				summary:    "The selected SDL KMS/DRM output backend and device endpoint are available; display usability is not verified.",
			}
		} else {
			return displayEnvironmentResult{
				configured: true,
				status:     StatusFail,
				summary:    "The selected SDL KMS/DRM output backend has no accessible DRM device endpoint.",
				guidance:   "Grant the session access to the target's DRM device, then run the client preflight again.",
			}
		}
	default:
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "SDL_VIDEODRIVER selects an unsupported or non-display SDL backend for streaming.",
			guidance:   "Use SDL_VIDEODRIVER=x11, wayland, or kmsdrm with a usable local endpoint.",
		}
	}
}

func (p *Prober) waylandDisplayEnvironmentCheck() displayEnvironmentResult {
	wayland := p.envValue("WAYLAND_DISPLAY")
	if wayland == "" {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "The selected Wayland output backend requires WAYLAND_DISPLAY, but no endpoint is configured.",
			guidance:   "Set WAYLAND_DISPLAY to a socket name such as wayland-0 with XDG_RUNTIME_DIR before streaming.",
		}
	}
	if !validWaylandDisplay(wayland, p) {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusFail,
			summary:    "The selected Wayland output backend has an invalid display endpoint.",
			guidance:   "Use a Wayland socket name such as wayland-0 with a safe XDG_RUNTIME_DIR.",
		}
	}
	endpoint, resolvable := p.waylandDisplayEndpoint(wayland)
	if !resolvable && p.envValue("XDG_RUNTIME_DIR") == "" {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusPass,
			summary:    "The selected Wayland output backend is indicated; its socket cannot be resolved without XDG_RUNTIME_DIR, so connectivity is not verified.",
			guidance:   "Run LeagueBridge from the graphical session with XDG_RUNTIME_DIR set when possible.",
		}
	}
	if !resolvable {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusWarn,
			summary:    "The selected Wayland output backend cannot resolve its configured runtime root.",
			guidance:   "Run LeagueBridge inside the graphical session and ensure XDG_RUNTIME_DIR is accessible.",
		}
	}
	info, err := p.fs.Stat(endpoint)
	if err == nil && info != nil && info.Mode()&fs.ModeSocket != 0 {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusPass,
			summary:    "The selected Wayland output backend has an available display socket; compositor permissions and input delivery are not verified.",
		}
	}
	if err == nil && info != nil {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusWarn,
			summary:    "The selected Wayland output backend points to a non-socket endpoint.",
			guidance:   "Fix WAYLAND_DISPLAY or select the graphical backend that is actually available.",
		}
	}
	return displayEnvironmentResult{
		configured: true,
		status:     StatusWarn,
		summary:    "The selected Wayland output backend's display socket is unavailable.",
		guidance:   "Run LeagueBridge inside the graphical session and ensure the Wayland socket is accessible before streaming.",
	}
}

type displayEnvironmentResult struct {
	configured bool
	status     Status
	summary    string
	guidance   string
}

// displayEnvironmentCheck validates the environment-backed desktop endpoint
// without opening a socket or starting a client. Wayland names can be checked
// against XDG_RUNTIME_DIR when that root is available. X11 also supports an
// abstract local socket and remote display forms, so a syntactically valid
// DISPLAY remains an indicator when its filesystem socket cannot be observed.
// The result deliberately contains fixed text only; environment values and
// paths never enter a report.
func (p *Prober) displayEnvironmentCheck() displayEnvironmentResult {
	wayland := p.envValue("WAYLAND_DISPLAY")
	x11 := p.envValue("DISPLAY")
	if wayland == "" && x11 == "" {
		return displayEnvironmentResult{}
	}
	if wayland != "" && !validWaylandDisplay(wayland, p) {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusWarn,
			summary:    "WAYLAND_DISPLAY is not a safe local display name or path.",
			guidance:   "Use a Wayland socket name such as wayland-0 with a safe XDG_RUNTIME_DIR, or use a valid local X11 DISPLAY.",
		}
	}
	if x11 != "" && !validX11Display(x11) {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusWarn,
			summary:    "DISPLAY is not a valid X11 display endpoint.",
			guidance:   "Set DISPLAY to a value such as :0 or host:0 before streaming.",
		}
	}

	waylandProblem := ""
	if wayland != "" {
		endpoint, resolvable := p.waylandDisplayEndpoint(wayland)
		switch {
		case !resolvable && p.envValue("XDG_RUNTIME_DIR") == "":
			// A relative Wayland name normally uses XDG_RUNTIME_DIR. Keep this
			// compatible with session managers that provide the socket through a
			// custom environment, while making the missing verification explicit.
			return displayEnvironmentResult{
				configured: true,
				status:     StatusPass,
				summary:    "A Wayland display session is indicated; its socket path cannot be resolved without XDG_RUNTIME_DIR, so connectivity is not verified.",
				guidance:   "Run LeagueBridge from the graphical session with XDG_RUNTIME_DIR set when possible.",
			}
		case !resolvable:
			waylandProblem = "the configured Wayland runtime root is unavailable"
		default:
			info, err := p.fs.Stat(endpoint)
			if err == nil && info != nil && info.Mode()&fs.ModeSocket != 0 {
				return displayEnvironmentResult{
					configured: true,
					status:     StatusPass,
					summary:    "A Wayland display socket is available; connectivity and compositor permissions are not verified.",
				}
			}
			if err == nil && info != nil {
				waylandProblem = "WAYLAND_DISPLAY points to a non-socket endpoint"
			} else {
				waylandProblem = "the configured Wayland display socket is unavailable"
			}
		}
	}

	if x11 != "" {
		if waylandProblem != "" {
			return displayEnvironmentResult{
				configured: true,
				status:     StatusWarn,
				summary:    "An X11 display is indicated, but the configured Wayland endpoint could not be verified; Moonlight may select the unusable endpoint first.",
				guidance:   "Fix or unset the stale WAYLAND_DISPLAY, or explicitly select the working X11 backend before streaming.",
			}
		}
		if socketPath := x11LocalSocketPath(x11, p.goos); socketPath != "" {
			if info, err := p.fs.Stat(socketPath); err == nil && info != nil && info.Mode()&fs.ModeSocket != 0 {
				return displayEnvironmentResult{
					configured: true,
					status:     StatusPass,
					summary:    "An X11 display socket is present; authentication and input delivery are not verified.",
				}
			}
		}
		return displayEnvironmentResult{
			configured: true,
			status:     StatusPass,
			summary:    "A valid X11 display endpoint is indicated; abstract-socket, remote-display, and authentication state are not verified.",
		}
	}
	if waylandProblem != "" {
		return displayEnvironmentResult{
			configured: true,
			status:     StatusWarn,
			summary:    "A Wayland session is indicated, but " + waylandProblem + ".",
			guidance:   "Run LeagueBridge inside the graphical session and ensure the Wayland socket is accessible before streaming.",
		}
	}
	return displayEnvironmentResult{}
}

func validWaylandDisplay(value string, p *Prober) bool {
	if value == "" || len(value) > 256 || strings.ContainsRune(value, '\x00') {
		return false
	}
	if strings.HasPrefix(value, "/") {
		_, ok := p.localEnvironmentRoot(value)
		return ok
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\\`) {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func validX11Display(value string) bool {
	if value == "" || len(value) > 256 || strings.ContainsRune(value, '\x00') {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f || value[index] == '\\' {
			return false
		}
	}
	colon := strings.LastIndexByte(value, ':')
	if colon < 0 || colon == len(value)-1 {
		return false
	}
	parts := strings.Split(value[colon+1:], ".")
	if len(parts) > 2 || !decimalDisplayPart(parts[0]) {
		return false
	}
	return len(parts) == 1 || decimalDisplayPart(parts[1])
}

func decimalDisplayPart(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func (p *Prober) waylandDisplayEndpoint(value string) (string, bool) {
	if strings.HasPrefix(value, "/") {
		return p.localEnvironmentRoot(value)
	}
	runtimeRoot, ok := p.localEnvironmentRoot(p.envValue("XDG_RUNTIME_DIR"))
	if !ok {
		return "", false
	}
	return targetPathJoin(p.goos, runtimeRoot, value), true
}

func x11LocalSocketPath(value, targetGOOS string) string {
	colon := strings.LastIndexByte(value, ':')
	if colon < 0 {
		return ""
	}
	prefix := value[:colon]
	if prefix != "" && prefix != "unix/" {
		return ""
	}
	display := strings.Split(value[colon+1:], ".")[0]
	return targetPathJoin(targetGOOS, "/tmp/.X11-unix/X"+display)
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
		if p.deviceNodeExistsAny(p.directDRMDevicePaths()...) {
			return "SDL KMS/DRM", true
		}
	}
	switch platform := strings.ToLower(strings.TrimSpace(p.envValue("QT_QPA_PLATFORM"))); platform {
	case "eglfs", "kms", "kmsdrm":
		if p.deviceNodeExistsAny(p.directDRMDevicePaths()...) {
			return "Qt EGLFS/KMS", true
		}
	case "linuxfb":
		if p.deviceNodeExistsAny(filepath.FromSlash("/dev/fb0")) {
			return "Qt Linux framebuffer", true
		}
	}
	return "", false
}

func (p *Prober) directQtDisplayBackend(qtPlatform string) (string, bool) {
	if _, ok := eligibleClientOS[p.goos]; !ok {
		return "", false
	}
	switch qtPlatform {
	case "eglfs":
		if p.deviceNodeExistsAny(p.directDRMDevicePaths()...) {
			return "Qt EGLFS", true
		}
	case "linuxfb":
		if p.deviceNodeExistsAny(filepath.FromSlash("/dev/fb0")) {
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
	return p.readableCharacterDeviceAny(paths...)
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
	return p.readableCharacterDeviceAny(wsconsKeyboardDevicePaths()...) && p.readableCharacterDeviceAny(wsconsMouseDevicePaths()...)
}

// deviceNodeExistsAny rejects regular files and directories at device paths.
// This keeps direct-display and direct-input preflight from treating a
// placeholder, bind-mount artifact, or stale path as a usable kernel endpoint.
func (p *Prober) deviceNodeExistsAny(paths ...string) bool {
	for _, candidate := range uniqueNonEmpty(paths) {
		info, err := p.fs.Stat(candidate)
		if err == nil && info != nil && info.Mode()&fs.ModeDevice != 0 {
			return true
		}
	}
	return false
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

func (p *Prober) moonlightCheck(preferred ...string) Check {
	selection := ""
	if len(preferred) > 0 {
		selection = strings.ToLower(strings.TrimSpace(preferred[0]))
	}
	switch selection {
	case "", "auto", "moonlight", "moonlight-embedded", "moonlight-qt", "flatpak":
	default:
		return Check{
			ID:       "client.moonlight",
			Status:   StatusFail,
			Summary:  "The configured Moonlight client selection is not recognized.",
			Guidance: "Select auto, moonlight, moonlight-embedded, moonlight-qt, or flatpak.",
		}
	}
	if selection == "flatpak" && p.goos != "linux" {
		return Check{
			ID:       "client.moonlight",
			Status:   StatusFail,
			Summary:  "The Flatpak Moonlight client is a Linux-only runtime and cannot satisfy a BSD client selection.",
			Guidance: moonlightInstallGuidance(p.goos),
		}
	}

	if selection != "flatpak" {
		if command, ok := p.lookupMoonlightFor(selection); ok {
			label := moonlightCommandLabel(p.goos, command, selection)
			summary := label + " is available."
			if selection != "" && selection != "auto" {
				summary = label + " is available for the selected client setting."
			}
			return Check{ID: "client.moonlight", Status: StatusPass, Summary: summary}
		}
	}

	flatpakID := filepath.FromSlash("app/com.moonlight_stream.Moonlight")
	paths := p.flatpakInstallPaths(flatpakID)
	flatpakInstalled := p.directoryExistsAny(paths...)
	_, flatpakAvailable := p.lookupAny("flatpak")
	flatpakEligible := p.goos == "linux" && (selection == "" || selection == "auto" || selection == "flatpak")
	if flatpakEligible && flatpakInstalled && flatpakAvailable {
		return Check{ID: "client.moonlight", Status: StatusPass, Summary: "Moonlight Flatpak app evidence and a PATH-resolvable Flatpak launcher are present for the selected client setting; user roots, when used, remain process-environment indicators."}
	}
	if flatpakEligible && flatpakAvailable && !flatpakInstalled {
		if selection == "flatpak" {
			return Check{
				ID:       "client.moonlight",
				Status:   StatusFail,
				Summary:  "The selected Flatpak launcher is available, but the Moonlight Flatpak app is not installed.",
				Guidance: "Install the official Moonlight Flatpak app from a trusted Flathub remote, then run the client preflight again.",
			}
		}
		// Automatic selection should explain why its last fallback cannot be
		// used, rather than making a present-but-incomplete Flatpak install
		// look identical to a host with no Flatpak support.
		return Check{
			ID:       "client.moonlight",
			Status:   StatusFail,
			Summary:  "A Flatpak launcher is available, but its Moonlight app is not installed; no automatic Moonlight client is ready.",
			Guidance: "Install the official Moonlight Flatpak app from a trusted Flathub remote, or expose a packaged Moonlight executable on PATH.",
		}
	}
	if selection == "flatpak" {
		if flatpakInstalled {
			return Check{
				ID:       "client.moonlight",
				Status:   StatusWarn,
				Summary:  "The selected Moonlight Flatpak app is present, but the Flatpak launcher cannot be resolved through PATH.",
				Guidance: "Install Flatpak from the operating system's trusted source and make its launcher available through PATH.",
			}
		}
		return Check{
			ID:       "client.moonlight",
			Status:   StatusFail,
			Summary:  "The selected Moonlight Flatpak launcher was not detected.",
			Guidance: "Install Flatpak from the operating system's trusted source and expose its launcher through PATH.",
		}
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
		if p.goos != "linux" {
			return Check{
				ID:       "client.moonlight",
				Status:   StatusFail,
				Summary:  "A Moonlight Flatpak directory is present, but Flatpak is a Linux-only runtime and no native Moonlight client was detected.",
				Guidance: moonlightInstallGuidance(p.goos),
			}
		}
		return Check{
			ID:       "client.moonlight",
			Status:   StatusWarn,
			Summary:  "A Moonlight Flatpak directory is present, but the remote launcher cannot resolve flatpak through PATH or the target operating system cannot use the Linux Flatpak runtime.",
			Guidance: "On Linux, install Flatpak from the operating system's trusted source and make its launcher available through PATH. On BSD, install native Moonlight Qt or Embedded from a signed package source instead.",
		}
	}
	return Check{
		ID:       "client.moonlight",
		Status:   StatusFail,
		Summary:  "Moonlight was not detected.",
		Guidance: moonlightInstallGuidance(p.goos),
	}
}

// lookupMoonlightFor mirrors the remote resolver's explicit-selection rules.
// The generic executable is a Qt convention on Linux/OpenBSD/NetBSD and an
// Embedded convention on FreeBSD/DragonFly, so an explicit Qt selection only
// falls back to the generic name where that target does not reserve it for
// Embedded.
func (p *Prober) lookupMoonlightFor(selection string) (string, bool) {
	switch selection {
	case "", "auto":
		return p.lookupMoonlight()
	case "moonlight-qt":
		if command, ok := p.lookupAny("moonlight-qt"); ok {
			return command, true
		}
		if !genericMoonlightIsEmbeddedOnTarget(p.goos) {
			return p.lookupAny("moonlight")
		}
	case "moonlight":
		return p.lookupAny("moonlight")
	case "moonlight-embedded":
		if command, ok := p.lookupAny("moonlight-embedded"); ok {
			return command, true
		}
		if genericMoonlightIsEmbeddedOnTarget(p.goos) {
			return p.lookupAny("moonlight")
		}
		return "", false
	}
	return "", false
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
	if userRoot, ok := p.localEnvironmentRoot(p.envValue("FLATPAK_USER_DIR")); ok {
		// Flatpak allows the user installation root to be overridden. It is
		// already the repository root, unlike XDG_DATA_HOME which needs the
		// conventional /flatpak suffix below.
		roots = append(roots, userRoot)
	}
	if systemRoots := p.envValue("FLATPAK_SYSTEM_DIR"); systemRoots != "" {
		for _, systemRoot := range strings.Split(systemRoots, ":") {
			if root, ok := p.localEnvironmentRoot(systemRoot); ok {
				roots = append(roots, root)
			}
		}
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

func moonlightCommandLabel(goos, command, selection string) string {
	// The explicit legacy "moonlight" setting is intentionally resolved by
	// remote.Discover as Embedded. Keep diagnostics honest even on targets
	// where the same generic executable name is conventionally Qt under auto
	// selection; an explicit setting must describe the flavor it requests.
	if selection == "moonlight" || selection == "moonlight-embedded" {
		return "Moonlight Embedded"
	}
	if selection == "moonlight-qt" {
		return "Moonlight Qt"
	}
	if moonlightCommandUsesQt(goos, command, selection) {
		return "Moonlight Qt"
	}
	return "Moonlight Embedded"
}

func moonlightCommandUsesQt(goos, command, selection string) bool {
	if selection == "moonlight" || selection == "moonlight-embedded" {
		return false
	}
	return command == "moonlight-qt" || (command == "moonlight" && !genericMoonlightIsEmbeddedOnTarget(goos))
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
		return "This client profile supports only Linux, FreeBSD, OpenBSD, and NetBSD on amd64/arm64, or DragonFly BSD on amd64; Windows and macOS are external physical-host destinations, not LeagueBridge installation targets."
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
