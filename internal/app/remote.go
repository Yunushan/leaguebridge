package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/config"
	"github.com/Yunushan/leaguebridge/internal/kvm"
	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/remote"
	"github.com/Yunushan/leaguebridge/internal/target"
	"github.com/Yunushan/leaguebridge/internal/wol"
)

// Pairing, app-listing, and remote-session termination are finite control-plane
// operations. Bound them so an unreachable physical host cannot leave a
// Linux/BSD terminal blocked forever. Interactive streaming intentionally
// keeps the caller's lifetime.
const (
	remoteControlTimeout        = 60 * time.Second
	remoteMaxReconnectAttempts  = 5
	remoteMaxReconnectDelay     = 60
	remoteDefaultWakeWait       = 15
	remoteMaxWakeWait           = 300
	remoteDefaultWakeRetries    = 3
	remoteMaxWakeRetries        = 5
	remoteDefaultWakeRetryDelay = 5
	remoteMaxWakeRetryDelay     = 60
)

// Moonlight application listings are small in normal use. Keep the
// verification capture bounded so a hostile or malfunctioning host cannot
// consume unbounded client memory; output still streams to the caller.
const remoteApplicationListingCaptureLimit = 1 << 20

// SDL gamecontroller database files are small text files. Bound the local
// preflight so a mistaken path cannot make a remote invocation inspect an
// unexpectedly large file; Moonlight still owns parsing the file.
const remoteInputMappingFileLimit = 8 << 20

type remoteListingCapture struct {
	buffer    bytes.Buffer
	remaining int
}

type remoteWakeRetryPlan struct {
	AdditionalAttempts int `json:"additional_attempts"`
	DelaySeconds       int `json:"delay_seconds"`
}

// repeatedStringFlag preserves every occurrence of an option such as
// Embedded's repeatable --input-device instead of silently keeping only the
// last value, which is the default behavior of flag.String.
type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *repeatedStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
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
		return a.commandError("remote", false, ExitUsage, "expected map, kvm, wake, pair, unpair, list, play, stream, or quit")
	}
	if args[0] == "map" {
		return a.runRemoteMap(ctx, args[1:])
	}
	if args[0] == "kvm" {
		return a.runRemoteKVM(ctx, args[1:])
	}
	if args[0] == "wake" {
		return a.runRemoteWake(ctx, args[1:])
	}
	var operation remote.Operation
	switch args[0] {
	case "pair":
		operation = remote.Pair
	case "unpair":
		operation = remote.Unpair
	case "list":
		operation = remote.List
	case "play":
		// `play` is a League-oriented stream alias. It deliberately reuses the
		// guarded stream path below so physical-host confirmation, explicit
		// handoff acknowledgement, application presence, and client discovery
		// cannot be bypassed by the convenience command.
		operation = remote.Stream
	case "quit":
		operation = remote.Quit
	case "stream":
		operation = remote.Stream
	default:
		return a.commandError("remote", false, ExitUsage, "unknown subcommand %q", args[0])
	}

	set := a.flagSet("remote " + args[0])
	configPath := set.String("config", "", "configuration file")
	routeName := set.String("route", "", "physical-host route: windows or macos (default: configuration, then windows)")
	host := set.String("host", "", "physical host DNS name or IP; use HOST:PORT or [IPv6]:PORT for an explicit Moonlight port")
	application := set.String("app", "", "Sunshine application name")
	pairingPIN := set.String("pin", "", "Moonlight Qt or Embedded pairing PIN (exactly four ASCII digits; live pair only)")
	requiredApplication := set.String("require-app", "", "require this application in a live Moonlight list (streams always check their launch app)")
	requireConfiguredApplication := set.Bool("require-configured-app", false, "require the configured application in a live Moonlight list (streams always check it)")
	clientSelection := set.String("client", "", "auto, moonlight, moonlight-embedded, moonlight-qt, or flatpak")
	resolution := set.String("resolution", "", "stream resolution: 720, 1080, 1440, 4k, or WIDTHxHEIGHT (640-7680 x 360-4320)")
	fps := set.Int("fps", 0, "stream frame rate (10-480); zero keeps the client default")
	bitrate := set.Int("bitrate", 0, "stream bitrate in Kbps (500-500000); zero keeps the client default")
	packetSize := set.Int("packet-size", 0, "stream network packet size in bytes (1024-9000, multiple of 16); zero keeps the client default")
	codec := set.String("codec", "", "stream video codec: auto, h264, h265, hevc, or av1; empty keeps the client default")
	audioConfig := set.String("audio-config", "", "stream audio channels: stereo, 5.1-surround, or 7.1-surround")
	audioOnHost := set.Bool("audio-on-host", false, "play stream audio on the physical host")
	audioDevice := set.String("audio-device", "", "Moonlight Embedded audio output device (for example sysdefault or hw:0,0)")
	preserveHostSettings := set.Bool("preserve-host-settings", false, "ask Moonlight not to apply game or host graphics optimizations")
	disableGamepadMouseEmulation := set.Bool("disable-gamepad-mouse-emulation", false, "disable Moonlight Embedded gamepad-to-mouse emulation")
	var inputDevices repeatedStringFlag
	set.Var(&inputDevices, "input-device", "Moonlight Embedded evdev input device (repeat for multiple /dev/input/eventN devices)")
	inputMapping := set.String("input-mapping", "", "Moonlight Embedded SDL controller mapping file (absolute Linux/BSD path)")
	networkMode := set.String("network-mode", "", "Moonlight Embedded network mode: auto, lan, or wan")
	qtPlatform := set.String("qt-platform", "", "Moonlight Qt display backend: auto, xcb, wayland, eglfs, or linuxfb (live stream only)")
	framePacing := set.String("frame-pacing", "", "Moonlight Qt frame pacing: auto, on, or off")
	vsync := set.String("vsync", "", "Moonlight Qt VSync: auto, on, or off")
	keepAwake := set.Bool("keep-awake", false, "ask Moonlight Qt to prevent display sleep while streaming")
	quitAfter := set.Bool("quit-after", false, "ask Moonlight to stop the host application when the stream ends")
	captureSystemKeys := set.String("capture-system-keys", "", "Moonlight Qt system-key capture: auto, never, fullscreen, or always")
	reconnectAttempts := set.Int("reconnect-attempts", 0, "additional stream attempts after a failed Moonlight session (0-5)")
	reconnectDelay := set.Int("reconnect-delay", 2, "seconds to wait between reconnect attempts (0-60)")
	platform := set.String("platform", "", "Moonlight Embedded output/input platform: auto, x11, x11_vdpau, x11_vaapi, or sdl")
	decoder := set.String("decoder", "", "stream video decoder: auto, software, or hardware; Qt/Flatpak only")
	displayMode := set.String("display-mode", "", "stream display mode: fullscreen, windowed, or borderless; Embedded supports windowed, Qt/Flatpak support all three")
	absoluteMouse := set.Bool("absolute-mouse", false, "use Moonlight Qt's remote-desktop optimized absolute mouse mode")
	noAbsoluteMouse := set.Bool("no-absolute-mouse", false, "disable Moonlight Qt's absolute mouse mode")
	multiController := set.Bool("multi-controller", false, "enable multiple controller input in Moonlight Qt")
	mouseButtonsSwap := set.Bool("mouse-buttons-swap", false, "swap left and right mouse buttons in Moonlight Qt")
	touchscreenTrackpad := set.Bool("touchscreen-trackpad", false, "use touchscreen input as a trackpad in Moonlight Qt")
	muteOnFocusLoss := set.Bool("mute-on-focus-loss", false, "mute stream audio when the Moonlight Qt window loses focus")
	backgroundGamepad := set.Bool("background-gamepad", false, "accept gamepad input when the Moonlight Qt window is not focused")
	reverseScrollDirection := set.Bool("reverse-scroll-direction", false, "reverse scroll direction in Moonlight Qt")
	swapGamepadButtons := set.Bool("swap-gamepad-buttons", false, "swap A/B and X/Y gamepad buttons in Moonlight Qt")
	performanceOverlay := set.Bool("performance-overlay", false, "show Moonlight Qt's performance overlay")
	hdr := set.Bool("hdr", false, "request HDR streaming in Moonlight Qt or Embedded")
	yuv444 := set.Bool("yuv444", false, "request YUV 4:4:4 streaming in Moonlight Qt")
	confirmed := set.Bool("confirm-physical-host", false, "confirm that the host is not a VM")
	acknowledged := set.Bool("acknowledge-unverified-handoff", false, "acknowledge that the physical-host handoff is not local Linux/BSD support")
	wakeMAC := set.String("wake-mac", "", "Wake-on-LAN MAC address to wake the physical host before pairing, listing, or streaming")
	wakeDestination := set.String("wake-broadcast", wol.DefaultDestination, "Wake-on-LAN IPv4 broadcast or unicast destination")
	wakePort := set.Int("wake-port", wol.DefaultPort, "Wake-on-LAN UDP destination port")
	wakeWait := set.Int("wake-wait", remoteDefaultWakeWait, "seconds to wait after Wake-on-LAN before host application preflight (0-300)")
	wakeRetries := set.Int("wake-retries", remoteDefaultWakeRetries, "additional application-list attempts after Wake-on-LAN (0-5; list/stream only)")
	wakeRetryDelay := set.Int("wake-retry-delay", remoteDefaultWakeRetryDelay, "seconds between Wake-on-LAN application-list retries (0-60)")
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
	qtPlatformOverridden := false
	mouseModeOverridden := false
	hostOverridden := false
	applicationOverridden := false
	pairingPINOverridden := false
	clientOverridden := false
	requiredApplicationOverridden := false
	requireConfiguredApplicationOverridden := false
	acknowledgementOverridden := false
	reconnectDelayOverridden := false
	wakeMACOverridden := false
	wakeDestinationOverridden := false
	wakePortOverridden := false
	wakeWaitOverridden := false
	wakeRetriesOverridden := false
	wakeRetryDelayOverridden := false
	optionProvided := make(map[string]bool)
	set.Visit(func(option *flag.Flag) {
		optionProvided[option.Name] = true
		switch option.Name {
		case "confirm-physical-host":
			confirmationOverridden = true
		case "host":
			hostOverridden = true
		case "resolution", "fps", "bitrate", "packet-size", "codec", "audio-config", "audio-on-host", "audio-device", "preserve-host-settings", "disable-gamepad-mouse-emulation", "input-device", "input-mapping", "network-mode", "frame-pacing", "vsync", "keep-awake", "quit-after", "capture-system-keys", "reconnect-attempts", "reconnect-delay", "platform", "decoder", "display-mode", "multi-controller", "mouse-buttons-swap", "touchscreen-trackpad", "mute-on-focus-loss", "background-gamepad", "reverse-scroll-direction", "swap-gamepad-buttons", "performance-overlay", "hdr", "yuv444":
			streamOptionsOverridden = true
			if option.Name == "reconnect-delay" {
				reconnectDelayOverridden = true
			}
		case "absolute-mouse", "no-absolute-mouse":
			mouseModeOverridden = true
		case "app":
			applicationOverridden = true
		case "pin":
			pairingPINOverridden = true
		case "qt-platform":
			qtPlatformOverridden = true
		case "require-app":
			requiredApplicationOverridden = true
		case "require-configured-app":
			requireConfiguredApplicationOverridden = true
		case "client":
			clientOverridden = true
		case "acknowledge-unverified-handoff":
			acknowledgementOverridden = true
		case "wake-mac":
			wakeMACOverridden = true
		case "wake-broadcast":
			wakeDestinationOverridden = true
		case "wake-port":
			wakePortOverridden = true
		case "wake-wait":
			wakeWaitOverridden = true
		case "wake-retries":
			wakeRetriesOverridden = true
		case "wake-retry-delay":
			wakeRetryDelayOverridden = true
		}
	})
	if args[0] == "play" {
		// Keep the convenience path predictable for a League session while
		// allowing operators to override any quality value explicitly. These
		// values match the packaged Linux/BSD live-session helper.
		if !optionProvided["resolution"] {
			*resolution = "1080"
		}
		if !optionProvided["fps"] {
			*fps = 60
		}
		if !optionProvided["bitrate"] {
			*bitrate = 20000
		}
		if !optionProvided["packet-size"] {
			*packetSize = 1392
		}
		if !optionProvided["codec"] {
			*codec = "h264"
		}
	}
	if *absoluteMouse && *noAbsoluteMouse {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "cannot combine --absolute-mouse and --no-absolute-mouse")
	}
	if pairingPINOverridden {
		if operation != remote.Pair {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--pin requires the pair operation")
		}
		if *dryRun {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--pin cannot be used with --dry-run because the pairing PIN would be included in the planned process arguments")
		}
		if err := remote.ValidatePairingPIN(*pairingPIN); err != nil {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
		}
	}
	if qtPlatformOverridden {
		if operation != remote.Stream {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--qt-platform requires the stream operation")
		}
		if err := remote.ValidateQtPlatform(*qtPlatform); err != nil {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
		}
	}
	wakeRequested := strings.TrimSpace(*wakeMAC) != ""
	if operation != remote.Stream {
		var streamOnly []string
		if streamOptionsOverridden {
			streamOnly = append(streamOnly, "--resolution, --fps, --bitrate, --packet-size, --codec, --audio-config, --audio-on-host, --audio-device, --preserve-host-settings, --disable-gamepad-mouse-emulation, --input-device, --input-mapping, --network-mode, --frame-pacing, --vsync, --keep-awake, --quit-after, --capture-system-keys, --reconnect-attempts, --reconnect-delay, --platform, --decoder, --display-mode, --multi-controller, --mouse-buttons-swap, --touchscreen-trackpad, --mute-on-focus-loss, --background-gamepad, --reverse-scroll-direction, --swap-gamepad-buttons, --performance-overlay, --hdr, and --yuv444")
		}
		if mouseModeOverridden {
			streamOnly = append(streamOnly, "--absolute-mouse and --no-absolute-mouse")
		}
		if applicationOverridden {
			streamOnly = append(streamOnly, "--app")
		}
		if acknowledgementOverridden && !((operation == remote.Pair || operation == remote.List) && wakeRequested) {
			streamOnly = append(streamOnly, "--acknowledge-unverified-handoff")
		}
		if operation != remote.Pair && operation != remote.List && (wakeMACOverridden || wakeDestinationOverridden || wakePortOverridden || wakeWaitOverridden) {
			streamOnly = append(streamOnly, "--wake-mac, --wake-broadcast, --wake-port, and --wake-wait")
		}
		if operation != remote.List && operation != remote.Stream && (wakeRetriesOverridden || wakeRetryDelayOverridden) {
			streamOnly = append(streamOnly, "--wake-retries and --wake-retry-delay")
		}
		if len(streamOnly) > 0 {
			if wakeRetriesOverridden || wakeRetryDelayOverridden {
				return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%s require the list or stream operation", strings.Join(streamOnly, ", "))
			}
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%s require the stream operation", strings.Join(streamOnly, ", "))
		}
	}
	if wakeMACOverridden && !wakeRequested {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--wake-mac must not be empty")
	}
	if (wakeDestinationOverridden || wakePortOverridden || wakeWaitOverridden) && !wakeRequested {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--wake-broadcast, --wake-port, and --wake-wait require --wake-mac")
	}
	if (wakeRetriesOverridden || wakeRetryDelayOverridden) && !wakeRequested {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--wake-retries and --wake-retry-delay require --wake-mac")
	}
	if wakeRequested && (*wakeWait < 0 || *wakeWait > remoteMaxWakeWait) {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--wake-wait must be between 0 and %d seconds, got %d", remoteMaxWakeWait, *wakeWait)
	}
	if wakeRequested && (*wakeRetries < 0 || *wakeRetries > remoteMaxWakeRetries) {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--wake-retries must be between 0 and %d, got %d", remoteMaxWakeRetries, *wakeRetries)
	}
	if wakeRequested && (*wakeRetryDelay < 0 || *wakeRetryDelay > remoteMaxWakeRetryDelay) {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--wake-retry-delay must be between 0 and %d seconds, got %d", remoteMaxWakeRetryDelay, *wakeRetryDelay)
	}
	if wakeRetryDelayOverridden && *wakeRetries == 0 {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--wake-retry-delay requires --wake-retries greater than zero")
	}
	if *reconnectAttempts < 0 || *reconnectAttempts > remoteMaxReconnectAttempts {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--reconnect-attempts must be between 0 and %d, got %d", remoteMaxReconnectAttempts, *reconnectAttempts)
	}
	if *reconnectDelay < 0 || *reconnectDelay > remoteMaxReconnectDelay {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--reconnect-delay must be between 0 and %d seconds, got %d", remoteMaxReconnectDelay, *reconnectDelay)
	}
	if reconnectDelayOverridden && *reconnectAttempts == 0 {
		return a.commandError("remote "+args[0], *asJSON, ExitUsage, "--reconnect-delay requires --reconnect-attempts greater than zero")
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
		Resolution:                   *resolution,
		FPS:                          *fps,
		BitrateKbps:                  *bitrate,
		PacketSizeBytes:              *packetSize,
		Codec:                        *codec,
		AudioConfig:                  *audioConfig,
		AudioOnHost:                  *audioOnHost,
		AudioDevice:                  *audioDevice,
		PreserveHostSettings:         *preserveHostSettings,
		DisableGamepadMouseEmulation: *disableGamepadMouseEmulation,
		InputDevices:                 append([]string(nil), inputDevices...),
		InputMapping:                 *inputMapping,
		NetworkMode:                  *networkMode,
		FramePacing:                  *framePacing,
		VSync:                        *vsync,
		KeepAwake:                    *keepAwake,
		QuitAfter:                    *quitAfter,
		CaptureSystemKeys:            *captureSystemKeys,
		Platform:                     *platform,
		Decoder:                      *decoder,
		DisplayMode:                  *displayMode,
		MultiController:              *multiController,
		MouseButtonsSwap:             *mouseButtonsSwap,
		TouchscreenTrackpad:          *touchscreenTrackpad,
		MuteOnFocusLoss:              *muteOnFocusLoss,
		BackgroundGamepad:            *backgroundGamepad,
		ReverseScrollDirection:       *reverseScrollDirection,
		SwapGamepadButtons:           *swapGamepadButtons,
		PerformanceOverlay:           *performanceOverlay,
		HDR:                          *hdr,
		YUV444:                       *yuv444,
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
		if *inputMapping != "" && !*dryRun {
			if err := validateRemoteInputMappingFile(*inputMapping); err != nil {
				return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
			}
		}
		if len(inputDevices) > 0 && !*dryRun {
			if err := validateRemoteInputDevices(inputDevices); err != nil {
				return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
			}
		}
	}
	if !eligibleClientPlatform(a.GOOS, a.GOARCH) {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "remote handoff clients target Linux, FreeBSD, OpenBSD, or NetBSD on amd64/arm64, or DragonFly BSD on amd64; current host is %s/%s", a.GOOS, a.GOARCH)
	}
	var cfg config.Config
	var usedPath string
	var err error
	if fullyExplicitRemoteInvocation(operation, *configPath, *routeName, hostOverridden, applicationOverridden, clientOverridden, confirmationOverridden, *confirmed) {
		// A route, host, client, application (for streams), and positive physical
		// confirmation supplied on the command line form a complete invocation.
		// Use a route-shaped empty config as the mutable target container so an
		// unrelated default config cannot block an explicitly selected physical
		// host. A named --config remains authoritative and is never bypassed.
		selectedRoute, parseErr := config.ParseRoute(*routeName)
		if parseErr != nil {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", parseErr)
		}
		cfg, err = config.DefaultForRoute(selectedRoute)
	} else {
		cfg, usedPath, err = loadRemoteConfig(*configPath, *routeName)
	}
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
		target.Client = strings.ToLower(strings.TrimSpace(*clientSelection))
	}
	if *confirmed {
		target.PhysicalHostConfirmed = true
	}
	automaticClientSelectionRequested := strings.EqualFold(strings.TrimSpace(target.Client), "auto") || strings.TrimSpace(target.Client) == ""
	if operation == remote.Unpair && (strings.EqualFold(strings.TrimSpace(target.Client), "auto") || strings.TrimSpace(target.Client) == "") {
		// Unpair is an Embedded-only control operation. Resolve an automatic
		// selection to that flavor before preflight and discovery instead of
		// allowing the normal Qt-first preference to produce an unusable plan.
		target.Client = "moonlight-embedded"
	}
	if operation == remote.Stream {
		effectiveClient, err := effectiveRemoteStreamClientSelection(target.Client, *platform, *qtPlatform, streamOptions)
		if err != nil {
			return a.commandError("remote "+args[0], *asJSON, ExitUsage, "%v", err)
		}
		// Backend selectors are invocation-scoped. When the configuration leaves
		// the client on auto, bind discovery to the flavor whose command surface
		// owns the selector; otherwise preflight and discovery can choose different
		// Moonlight clients when both are installed.
		target.Client = effectiveClient
	}
	automaticClientSelection := automaticClientSelectionRequested
	var automaticStreamFlavor remote.Flavor
	if operation == remote.Stream && automaticClientSelectionRequested {
		requiresEmbedded, requiresQt := streamOptionBackendRequirements(streamOptions)
		if strings.TrimSpace(*qtPlatform) != "" {
			requiresQt = true
		}
		if requiresQt && !requiresEmbedded {
			automaticStreamFlavor = remote.FlavorQt
		} else if requiresEmbedded && !requiresQt {
			automaticStreamFlavor = remote.FlavorEmbedded
		}
	}
	prober := a.prober()
	environment := a.RemoteEnv
	if environment == nil {
		environment = remote.RealEnvironment{}
	}
	preflight := remoteClientPreflight(ctx, prober, operation, target.Client, *platform, *qtPlatform)
	ready := preflight.Ready()
	if operation != remote.Stream || *dryRun {
		// A dry-run only composes and prints a fixed argv; it never opens a
		// display, reads input, contacts the host, or starts Moonlight. Keep the
		// graphical/input gates on the live stream path while allowing operators
		// to inspect a plan from a headless SSH session.
		ready = preflight.ReadyForControl()
	}
	var client remote.Client
	automaticFallbackSelection := ""
	var discoveryCtx context.Context
	var cancelDiscovery context.CancelFunc
	if !ready && operation == remote.Stream && automaticClientSelectionRequested && automaticStreamFlavor != "" {
		// A flavor-specific stream selector narrows automatic discovery to
		// compatible surfaces. Keep the official Linux Flatpak eligible when no
		// native Qt executable is installed, while filtering incompatible clients
		// before any process can start.
		discoveryCtx, cancelDiscovery = context.WithTimeout(ctx, 3*time.Second)
		defer cancelDiscovery()
		candidate, candidatePreflight, selection, found := discoverAutomaticStreamClientForFlavor(
			discoveryCtx, prober, environment, a.GOOS, *platform, *qtPlatform, automaticStreamFlavor,
		)
		if found {
			preflight = candidatePreflight
			ready = true
			target.Client = selection
			client = candidate
			automaticFallbackSelection = selection
		}
	}
	if !ready && !*dryRun && operation == remote.Stream && target.Client == "auto" &&
		strings.TrimSpace(*platform) == "" && strings.TrimSpace(*qtPlatform) == "" {
		// Automatic selection normally stops at the first discovered client. A
		// live stream has a stricter local display/input gate, so give the other
		// installed native Moonlight clients a chance when that first choice is
		// unusable. Each candidate is still preflighted and passively discovered;
		// no candidate is started until one complete selection succeeds.
		discoveryCtx, cancelDiscovery = context.WithTimeout(ctx, 3*time.Second)
		defer cancelDiscovery()
		candidate, candidatePreflight, selection, found := discoverAutomaticStreamClient(
			discoveryCtx, prober, environment, a.GOOS, *platform, *qtPlatform,
		)
		if found {
			preflight = candidatePreflight
			ready = true
			target.Client = selection
			client = candidate
			automaticFallbackSelection = selection
		}
	}
	if !ready && !*dryRun && automaticClientSelection &&
		(operation == remote.Pair || operation == remote.List || operation == remote.Quit) {
		// These are control-plane operations, so a headless client may still be
		// usable even when the preferred automatic client report is not
		// stream-ready. Try the other supported clients with the weaker control
		// readiness gate before declaring the handoff blocked.
		discoveryCtx, cancelDiscovery = context.WithTimeout(ctx, 3*time.Second)
		defer cancelDiscovery()
		candidate, candidatePreflight, selection, found := discoverAutomaticControlClient(
			discoveryCtx, prober, environment, a.GOOS,
		)
		if found {
			preflight = candidatePreflight
			ready = true
			target.Client = selection
			client = candidate
			automaticFallbackSelection = selection
		}
	}
	if !ready {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "client preflight failed; run `leaguebridge doctor --profile client` for details")
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
	if discoveryCtx == nil {
		discoveryCtx, cancelDiscovery = context.WithTimeout(ctx, 3*time.Second)
		defer cancelDiscovery()
	}
	if client.Binary == "" {
		client, err = remote.DiscoverForPlatform(discoveryCtx, environment, target.Client, a.GOOS)
		if err != nil && operation == remote.Stream && !*dryRun && automaticClientSelectionRequested && automaticStreamFlavor != "" {
			// A PATH/package change can occur after the flavor-specific preflight.
			// Retry the constrained passive search so an automatic request can still
			// recover to a compatible client without accepting the wrong flavor.
			retryCtx, cancelRetry := context.WithTimeout(ctx, 3*time.Second)
			candidate, candidatePreflight, selection, found := discoverAutomaticStreamClientForFlavor(
				retryCtx, prober, environment, a.GOOS, *platform, *qtPlatform, automaticStreamFlavor,
			)
			cancelRetry()
			if found {
				client = candidate
				preflight = candidatePreflight
				target.Client = selection
				automaticFallbackSelection = selection
				err = nil
			}
		}
		if err != nil && operation == remote.Stream && !*dryRun && target.Client == "auto" &&
			strings.TrimSpace(*platform) == "" && strings.TrimSpace(*qtPlatform) == "" {
			// The initial automatic preflight may have raced with a PATH or package
			// change between the check and discovery. Give the remaining native
			// clients the same bounded preflight/discovery opportunity used when the
			// first client fails the graphical or input gate.
			retryCtx, cancelRetry := context.WithTimeout(ctx, 3*time.Second)
			candidate, candidatePreflight, selection, found := discoverAutomaticStreamClient(
				retryCtx, prober, environment, a.GOOS, *platform, *qtPlatform,
			)
			cancelRetry()
			if found {
				client = candidate
				preflight = candidatePreflight
				target.Client = selection
				automaticFallbackSelection = selection
				err = nil
			}
		}
		if err != nil && operation == remote.List && !*dryRun && automaticClientSelection {
			// Automatic control discovery can race with package installation or a
			// PATH update. Give the remaining supported clients one bounded chance
			// before returning the resolver error.
			retryCtx, cancelRetry := context.WithTimeout(ctx, 3*time.Second)
			candidate, candidatePreflight, selection, found := discoverAutomaticControlClient(
				retryCtx, prober, environment, a.GOOS,
			)
			cancelRetry()
			if found {
				client = candidate
				preflight = candidatePreflight
				target.Client = selection
				automaticFallbackSelection = selection
				err = nil
			}
		}
		if err != nil {
			return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "%v", err)
		}
	}
	streamMouseModeExplicit := streamOptions.MouseMode != ""
	buildStreamPlan := func() (remote.Plan, error) {
		if operation == remote.Stream && !*dryRun && client.Flavor == remote.FlavorEmbedded {
			// Current Moonlight Embedded requires a controller database for its
			// non-SDL input path. Check the same local search boundary before the
			// process starts so a missing package data file cannot surface as a
			// late, opaque client failure. This is intentionally live-only: dry
			// runs must remain usable from a headless validation environment.
			if err := validateEmbeddedStreamMappingAvailability(streamOptions.InputMapping, *platform); err != nil {
				return remote.Plan{}, err
			}
		}
		if operation == remote.Stream && !streamMouseModeExplicit {
			// League's remote-input experiment needs relative pointer capture so a
			// physical Windows host can expose mouse events through its documented
			// Raw Input path. Make Moonlight Qt's documented relative default
			// explicit in generated plans while preserving an explicit absolute
			// override and Embedded's separate evdev input path. Reset the derived
			// value first because automatic client recovery may switch from Qt to
			// Embedded, where the Qt-only flag is invalid.
			streamOptions.MouseMode = ""
			switch client.Flavor {
			case remote.FlavorQt, remote.FlavorFlatpak:
				streamOptions.MouseMode = "relative"
			}
		}
		return remote.BuildDiscoveredPlan(client, remote.Request{
			Route:                   route,
			Operation:               operation,
			Host:                    target.Host,
			App:                     target.App,
			PairingPIN:              *pairingPIN,
			QtPlatform:              *qtPlatform,
			PhysicalHostConfirmed:   target.PhysicalHostConfirmed,
			AcceptUnverifiedHandoff: *acknowledged,
			Stream:                  streamOptions,
		})
	}
	plan, err := buildStreamPlan()
	if err != nil {
		return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "%v", err)
	}
	if automaticFallbackSelection != "" {
		operationDescription := "the live stream"
		switch operation {
		case remote.List:
			operationDescription = "application listing"
		case remote.Pair, remote.Quit:
			operationDescription = args[0] + " operation"
		}
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("automatic Moonlight selection used %s after the preferred automatic client could not be used for %s", automaticFallbackSelection, operationDescription))
	}
	rebuildPlan := func() error {
		rebuilt, buildErr := buildStreamPlan()
		if buildErr != nil {
			return fmt.Errorf("cannot rebuild the remote plan after automatic client recovery: %w", buildErr)
		}
		plan = rebuilt
		return nil
	}
	var wakePlan *wol.Plan
	if wakeRequested {
		builtWakePlan, err := wol.BuildPlan(wol.Request{
			MAC:                     *wakeMAC,
			Destination:             *wakeDestination,
			Port:                    *wakePort,
			PhysicalHostConfirmed:   target.PhysicalHostConfirmed,
			AcceptUnverifiedHandoff: *acknowledged,
		})
		if err != nil {
			return a.commandError("remote "+args[0], *asJSON, ExitBlocked, "%v", err)
		}
		wakePlan = &builtWakePlan
	}
	if operation == remote.Stream && *reconnectAttempts > 0 {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("controller will make up to %d additional Moonlight stream attempt(s), waiting %d second(s) between attempts; cancellation never retries", *reconnectAttempts, *reconnectDelay))
	}
	var wakeRetryPlan *remoteWakeRetryPlan
	if wakePlan != nil && (operation == remote.List || operation == remote.Stream) {
		wakeRetryPlan = &remoteWakeRetryPlan{
			AdditionalAttempts: *wakeRetries,
			DelaySeconds:       *wakeRetryDelay,
		}
		if *wakeRetries > 0 {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("controller will make up to %d additional application-list attempt(s) after Wake-on-LAN, waiting %d second(s) between attempts; a missing advertised application is not retried", *wakeRetries, *wakeRetryDelay))
		}
	}
	if *dryRun {
		if *asJSON {
			if wakePlan != nil {
				return a.writeJSON("remote "+args[0], struct {
					remote.Plan
					Wake      *wol.Plan            `json:"wake,omitempty"`
					WakeRetry *remoteWakeRetryPlan `json:"wake_retry,omitempty"`
				}{Plan: plan, Wake: wakePlan, WakeRetry: wakeRetryPlan})
			}
			return a.writeJSON("remote "+args[0], plan)
		}
		fmt.Fprintln(a.Stdout, "Validated argument vector (no process started):")
		fmt.Fprintf(a.Stdout, "  executable: %s\n", strconv.Quote(plan.Client.Binary))
		for i, argument := range plan.Arguments {
			fmt.Fprintf(a.Stdout, "  argv[%d]: %s\n", i+1, strconv.Quote(argument))
		}
		if plan.QtPlatform != "" && plan.QtPlatform != "auto" {
			fmt.Fprintf(a.Stdout, "  environment: QT_QPA_PLATFORM=%s\n", plan.QtPlatform)
		}
		for _, warning := range plan.Warnings {
			fmt.Fprintf(a.Stdout, "  warning: %s\n", warning)
		}
		if wakePlan != nil {
			fmt.Fprintf(a.Stdout, "  wake: %s:%d for %s; wait %d second(s) before host preflight\n", wakePlan.Destination, wakePlan.Port, wakePlan.MAC, *wakeWait)
			if wakeRetryPlan != nil {
				fmt.Fprintf(a.Stdout, "  wake retry: up to %d additional application-list attempt(s), %d second(s) apart\n", wakeRetryPlan.AdditionalAttempts, wakeRetryPlan.DelaySeconds)
			}
			for _, warning := range wakePlan.Warnings {
				fmt.Fprintf(a.Stdout, "  wake warning: %s\n", warning)
			}
		}
		return ExitOK
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", warning)
	}
	if wakePlan != nil {
		for _, warning := range wakePlan.Warnings {
			fmt.Fprintf(a.Stderr, "warning: %s\n", warning)
		}
		wakeCtx, cancelWake := context.WithTimeout(ctx, remoteControlTimeout)
		err := wol.Execute(wakeCtx, *wakePlan)
		wakeTimedOut := ctx.Err() == nil && errors.Is(wakeCtx.Err(), context.DeadlineExceeded)
		cancelWake()
		if err != nil {
			if wakeTimedOut {
				return a.commandError("remote "+args[0], false, ExitInternal, "Wake-on-LAN send timed out after %s; verify the local network and destination", remoteControlTimeout)
			}
			return a.commandError("remote "+args[0], false, ExitInternal, "%v", err)
		}
		fmt.Fprintf(a.Stdout, "Wake-on-LAN packet sent to %s:%d for %s.\n", wakePlan.Destination, wakePlan.Port, wakePlan.MAC)
		if *wakeWait > 0 {
			fmt.Fprintf(a.Stderr, "waiting %d second(s) for the physical host before application preflight\n", *wakeWait)
			if err := waitForRemoteReconnect(ctx, time.Duration(*wakeWait)*time.Second); err != nil {
				return a.commandError("remote "+args[0], false, ExitInternal, "Wake-on-LAN wait canceled: %v", err)
			}
		}
	}
	runner := a.RemoteRunner
	if runner == nil {
		runner = remote.ExecRunner{}
	}
	var checkStreamApplication func() (int, error)
	if operation == remote.Stream && !*dryRun {
		// Every live stream gets a host-application preflight. Use the same
		// discovered client and bound executable identity, but build a separate
		// list plan so no stream process starts when Sunshine has not advertised
		// the exact application that will be launched. The explicit application
		// requirement flags remain useful for `remote list` and for documenting
		// intent, but a live stream is never allowed to skip this guard. Reconnect
		// attempts call this closure again so a stale application listing cannot
		// authorize a later launch after a dropped session.
		var listPlan remote.Plan
		rebuildStreamPlans := func() error {
			streamPlan, streamErr := buildStreamPlan()
			if streamErr != nil {
				return fmt.Errorf("cannot rebuild the stream plan after automatic client recovery: %w", streamErr)
			}
			applicationPlan, applicationErr := remote.BuildDiscoveredPlan(client, remote.Request{
				Route:                 route,
				Operation:             remote.List,
				Host:                  target.Host,
				PhysicalHostConfirmed: target.PhysicalHostConfirmed,
			})
			if applicationErr != nil {
				return fmt.Errorf("cannot build the application-list preflight after automatic client recovery: %w", applicationErr)
			}
			plan = streamPlan
			listPlan = applicationPlan
			return nil
		}
		if err := rebuildStreamPlans(); err != nil {
			return a.commandError("remote "+args[0], false, ExitBlocked, "%v", err)
		}
		automaticClientFallbackTried := false
		checkStreamApplication = func() (int, error) {
			for {
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
						return ExitInternal, fmt.Errorf("Moonlight application-list preflight timed out after %s; verify that the physical host is reachable and try again", remoteControlTimeout)
					}
					if automaticClientSelection && !automaticClientFallbackTried && !remoteReconnectStopped(ctx, preflightErr) {
						automaticClientFallbackTried = true
						retryCtx, cancelRetry := context.WithTimeout(ctx, 3*time.Second)
						var candidate remote.Client
						var candidatePreflight probe.Report
						var selection string
						var found bool
						if automaticStreamFlavor != "" {
							candidate, candidatePreflight, selection, found = discoverAutomaticStreamClientForFlavorExcluding(
								retryCtx, prober, environment, a.GOOS, *platform, *qtPlatform, automaticStreamFlavor, client.Binary,
							)
						} else {
							candidate, candidatePreflight, selection, found = discoverAutomaticStreamClientExcluding(
								retryCtx, prober, environment, a.GOOS, *platform, *qtPlatform, client.Binary,
							)
						}
						cancelRetry()
						if found {
							client = candidate
							preflight = candidatePreflight
							target.Client = selection
							automaticFallbackSelection = selection
							if err := rebuildStreamPlans(); err != nil {
								return ExitBlocked, err
							}
							fmt.Fprintf(a.Stderr, "warning: automatic Moonlight selection used %s after the preferred client failed the host application-list preflight; retrying with the selected native client\n", selection)
							continue
						}
					}
					return ExitInternal, fmt.Errorf("Moonlight application-list preflight failed: %w", preflightErr)
				}
				if !remote.ApplicationListedForFlavor(observedListing.String(), applicationCheck, client.Flavor) {
					return ExitBlocked, fmt.Errorf("Moonlight listed the host successfully, but required application %q was not advertised; no stream was started", applicationCheck)
				}
				return ExitOK, nil
			}
		}
		for attempt := 0; ; attempt++ {
			preflightCode, preflightErr := checkStreamApplication()
			if preflightErr == nil {
				break
			}
			if wakeRetryPlan == nil || attempt >= wakeRetryPlan.AdditionalAttempts || remoteReconnectStopped(ctx, preflightErr) || preflightCode != ExitInternal {
				return a.commandError("remote "+args[0], false, preflightCode, "%v", preflightErr)
			}
			remaining := wakeRetryPlan.AdditionalAttempts - attempt
			fmt.Fprintf(a.Stderr, "warning: initial Moonlight application-list attempt %d failed: %v; retrying in %d second(s) (%d Wake-on-LAN retry attempt(s) remaining)\n", attempt+1, preflightErr, wakeRetryPlan.DelaySeconds, remaining)
			if err := waitForRemoteReconnect(ctx, time.Duration(wakeRetryPlan.DelaySeconds)*time.Second); err != nil {
				return a.commandError("remote "+args[0], false, ExitInternal, "Wake-on-LAN application-list retry canceled: %v", err)
			}
		}
	}
	remoteStderr := io.Writer(a.Stderr)
	if operation == remote.Stream {
		for attempt := 0; ; attempt++ {
			err := remote.Execute(ctx, runner, a.Stdin, a.Stdout, remoteStderr, plan)
			if err == nil {
				return ExitOK
			}
			if attempt >= *reconnectAttempts || remoteReconnectStopped(ctx, err) {
				return a.commandError("remote "+args[0], false, ExitInternal, "%v", err)
			}
			remaining := *reconnectAttempts - attempt
			fmt.Fprintf(a.Stderr, "warning: Moonlight stream attempt %d failed: %v; retrying in %d second(s) (%d reconnect attempt(s) remaining)\n", attempt+1, err, *reconnectDelay, remaining)
			if err := waitForRemoteReconnect(ctx, time.Duration(*reconnectDelay)*time.Second); err != nil {
				return a.commandError("remote "+args[0], false, ExitInternal, "stream reconnect canceled: %v", err)
			}
			if checkStreamApplication != nil {
				preflightCode, preflightErr := checkStreamApplication()
				if preflightErr != nil {
					return a.commandError("remote "+args[0], false, preflightCode, "%v", preflightErr)
				}
			}
		}
	}
	if operation == remote.List {
		automaticClientFallbackTried := false
		for attempt := 0; ; attempt++ {
			observedListing := newRemoteListingCapture()
			remoteStdout := io.Writer(a.Stdout)
			if applicationCheckRequested {
				// Preserve the normal interactive output while retaining a bounded
				// copy for the optional application-presence check. Stderr is
				// diagnostics and must never satisfy the requirement.
				remoteStdout = io.MultiWriter(a.Stdout, observedListing)
			}
			executionCtx, cancelExecution := context.WithTimeout(ctx, remoteControlTimeout)
			err := remote.Execute(executionCtx, runner, a.Stdin, remoteStdout, remoteStderr, plan)
			timedOut := ctx.Err() == nil && (errors.Is(executionCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded))
			cancelExecution()
			if err == nil {
				if applicationCheckRequested && !remote.ApplicationListedForFlavor(observedListing.String(), applicationCheck, client.Flavor) {
					return a.commandError("remote "+args[0], false, ExitBlocked, "Moonlight listed the host successfully, but required application %q was not advertised; configure that application on the physical host", applicationCheck)
				}
				return ExitOK
			}
			if automaticClientSelection && !automaticClientFallbackTried && attempt == 0 && !remoteReconnectStopped(ctx, err) {
				automaticClientFallbackTried = true
				retryCtx, cancelRetry := context.WithTimeout(ctx, 3*time.Second)
				candidate, candidatePreflight, selection, found := discoverAutomaticControlClientExcluding(
					retryCtx, prober, environment, a.GOOS, client.Binary,
				)
				cancelRetry()
				if found {
					client = candidate
					preflight = candidatePreflight
					target.Client = selection
					automaticFallbackSelection = selection
					if err := rebuildPlan(); err != nil {
						return a.commandError("remote "+args[0], false, ExitBlocked, "%v", err)
					}
					fmt.Fprintf(a.Stderr, "warning: automatic Moonlight selection used %s after the preferred client failed the application-list operation; retrying with the selected client\n", selection)
					continue
				}
			}
			if wakeRetryPlan == nil || attempt >= wakeRetryPlan.AdditionalAttempts || remoteReconnectStopped(ctx, err) {
				if timedOut {
					return a.commandError("remote "+args[0], false, ExitInternal, "Moonlight %s timed out after %s; verify that the physical host is reachable and try again", args[0], remoteControlTimeout)
				}
				return a.commandError("remote "+args[0], false, ExitInternal, "%v", err)
			}
			remaining := wakeRetryPlan.AdditionalAttempts - attempt
			fmt.Fprintf(a.Stderr, "warning: Moonlight application-list attempt %d failed: %v; retrying in %d second(s) (%d Wake-on-LAN retry attempt(s) remaining)\n", attempt+1, err, wakeRetryPlan.DelaySeconds, remaining)
			if err := waitForRemoteReconnect(ctx, time.Duration(wakeRetryPlan.DelaySeconds)*time.Second); err != nil {
				return a.commandError("remote "+args[0], false, ExitInternal, "Wake-on-LAN application-list retry canceled: %v", err)
			}
		}
	}
	if operation == remote.Pair || operation == remote.Quit {
		// Pairing and remote-session termination are both supported by the
		// native Qt and Embedded surfaces. When automatic discovery picked one
		// launcher but its control operation failed, give one other installed
		// native launcher a bounded chance before returning the error. Keep the
		// failed executable excluded so a generic package alias cannot resolve
		// straight back to the same process, and never replace an explicit
		// --client choice.
		automaticClientFallbackTried := false
		for attempt := 0; ; attempt++ {
			executionCtx, cancelExecution := context.WithTimeout(ctx, remoteControlTimeout)
			err := remote.Execute(executionCtx, runner, a.Stdin, a.Stdout, remoteStderr, plan)
			timedOut := ctx.Err() == nil && (errors.Is(executionCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded))
			cancelExecution()
			if err == nil {
				return ExitOK
			}
			if automaticClientSelection && !automaticClientFallbackTried && attempt == 0 && !remoteReconnectStopped(ctx, err) {
				automaticClientFallbackTried = true
				retryCtx, cancelRetry := context.WithTimeout(ctx, 3*time.Second)
				candidate, candidatePreflight, selection, found := discoverAutomaticControlClientExcluding(
					retryCtx, prober, environment, a.GOOS, client.Binary,
				)
				cancelRetry()
				if found {
					client = candidate
					preflight = candidatePreflight
					target.Client = selection
					automaticFallbackSelection = selection
					if err := rebuildPlan(); err != nil {
						return a.commandError("remote "+args[0], false, ExitBlocked, "%v", err)
					}
					fmt.Fprintf(a.Stderr, "warning: automatic Moonlight selection used %s after the preferred client failed the %s operation; retrying with the selected client\n", selection, args[0])
					continue
				}
			}
			if timedOut {
				return a.commandError("remote "+args[0], false, ExitInternal, "Moonlight %s timed out after %s; verify that the physical host is reachable and try again", args[0], remoteControlTimeout)
			}
			return a.commandError("remote "+args[0], false, ExitInternal, "%v", err)
		}
	}
	executionCtx, cancelExecution := context.WithTimeout(ctx, remoteControlTimeout)
	defer cancelExecution()
	if err := remote.Execute(executionCtx, runner, a.Stdin, a.Stdout, remoteStderr, plan); err != nil {
		if ctx.Err() == nil && (errors.Is(executionCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)) {
			return a.commandError("remote "+args[0], false, ExitInternal, "Moonlight %s timed out after %s; verify that the physical host is reachable and try again", args[0], remoteControlTimeout)
		}
		return a.commandError("remote "+args[0], false, ExitInternal, "%v", err)
	}
	return ExitOK
}

// fullyExplicitRemoteInvocation reports whether the command line contains all
// values that can otherwise come from a default remote configuration. It is
// intentionally narrower than the KVM shortcut: a Moonlight operation must
// bind its route, host, client, and physical-host confirmation explicitly, and
// a stream must also bind its application. An explicit --config always remains
// authoritative and therefore disables this shortcut.
func fullyExplicitRemoteInvocation(operation remote.Operation, configPath, routeName string, hostOverridden, applicationOverridden, clientOverridden, confirmationOverridden, confirmed bool) bool {
	if strings.TrimSpace(configPath) != "" || strings.TrimSpace(routeName) == "" || !hostOverridden || !clientOverridden || !confirmationOverridden || !confirmed {
		return false
	}
	return operation != remote.Stream || applicationOverridden
}

// remoteClientPreflight keeps the remote command's diagnostic call aligned
// with the launcher it will discover. The optional stream-aware interfaces are
// used by the real prober and by richer callers; the base interface remains a
// safe compatibility fallback for small embedders.
func remoteClientPreflight(ctx context.Context, prober ProbeRunner, operation remote.Operation, preferred, outputPlatform, qtPlatform string) probe.Report {
	if qtStreamAware, ok := prober.(interface {
		ClientForStreamWithQtPlatform(context.Context, string, string, string) probe.Report
	}); operation == remote.Stream && ok {
		// A Qt platform override changes which local display and input endpoint
		// the child process will use. Preflight the effective selection rather
		// than allowing a stale ambient Wayland endpoint to block explicit X11.
		return qtStreamAware.ClientForStreamWithQtPlatform(ctx, preferred, outputPlatform, qtPlatform)
	}
	if streamAware, ok := prober.(interface {
		ClientForStream(context.Context, string, string) probe.Report
	}); operation == remote.Stream && ok {
		// A live stream must preflight the exact output backend selected by the
		// invocation. The generic client report cannot distinguish an available
		// X11 endpoint from an explicitly requested SDL or X11 backend.
		return streamAware.ClientForStream(ctx, preferred, outputPlatform)
	}
	if selectionAware, ok := prober.(interface {
		ClientFor(context.Context, string) probe.Report
	}); ok {
		// The generic client profile remains useful for `doctor`, but a remote
		// invocation must gate on the exact launcher selected by its config or
		// flags. Otherwise an unrelated installed client can make a later
		// discovery failure look like a ready handoff.
		return selectionAware.ClientFor(ctx, preferred)
	}
	return prober.Run(ctx, probe.ProfileClient)
}

func remoteAutomaticClientPreflight(ctx context.Context, prober ProbeRunner, operation remote.Operation, preferred, outputPlatform, qtPlatform string) probe.Report {
	if automaticAware, ok := prober.(interface {
		ClientForAutomatic(context.Context, string, string, string) probe.Report
	}); ok {
		return automaticAware.ClientForAutomatic(ctx, preferred, outputPlatform, qtPlatform)
	}
	return remoteClientPreflight(ctx, prober, operation, preferred, outputPlatform, qtPlatform)
}

// discoverAutomaticStreamClient tries each native Moonlight selection in the
// same order as the passive resolver. Every candidate must pass the exact live
// stream preflight and then be discovered from the real environment before it
// can be returned. The helper never starts a client and deliberately leaves
// explicit selections outside this retry path.
func discoverAutomaticStreamClient(ctx context.Context, prober ProbeRunner, environment remote.Environment, goos, outputPlatform, qtPlatform string) (remote.Client, probe.Report, string, bool) {
	return discoverAutomaticStreamClientForFlavorExcluding(ctx, prober, environment, goos, outputPlatform, qtPlatform, "", "")
}

// discoverAutomaticStreamClientExcluding is the recovery form used after a
// discovered client has failed the host application-list handshake. The
// failed executable is excluded so automatic recovery actually gives another
// installed native client a chance instead of immediately repeating the same
// launcher. No process is started during this search.
func discoverAutomaticStreamClientExcluding(ctx context.Context, prober ProbeRunner, environment remote.Environment, goos, outputPlatform, qtPlatform, excludedBinary string) (remote.Client, probe.Report, string, bool) {
	return discoverAutomaticStreamClientForFlavorExcluding(ctx, prober, environment, goos, outputPlatform, qtPlatform, "", excludedBinary)
}

// discoverAutomaticStreamClientForFlavor tries the automatic native-client
// order while requiring a particular Moonlight flavor. This is used when an
// invocation-scoped option narrows the command surface, such as a Qt-only
// decoder or display mode. Discovery remains passive and the flavor is
// checked after resolution so generic package names and Linux Flatpak are
// handled according to the actual discovered client.
func discoverAutomaticStreamClientForFlavor(ctx context.Context, prober ProbeRunner, environment remote.Environment, goos, outputPlatform, qtPlatform string, requiredFlavor remote.Flavor) (remote.Client, probe.Report, string, bool) {
	return discoverAutomaticStreamClientForFlavorExcluding(ctx, prober, environment, goos, outputPlatform, qtPlatform, requiredFlavor, "")
}

func discoverAutomaticStreamClientForFlavorExcluding(ctx context.Context, prober ProbeRunner, environment remote.Environment, goos, outputPlatform, qtPlatform string, requiredFlavor remote.Flavor, excludedBinary string) (remote.Client, probe.Report, string, bool) {
	excludedBinary = strings.TrimSpace(excludedBinary)
	for _, selection := range remote.AutomaticClientSelections(goos) {
		candidatePreflight := remoteAutomaticClientPreflight(ctx, prober, remote.Stream, selection, outputPlatform, qtPlatform)
		if !candidatePreflight.Ready() {
			continue
		}
		candidate, err := remote.DiscoverAutomaticClientForPlatform(ctx, environment, selection, goos)
		if err != nil {
			continue
		}
		if requiredFlavor != "" && !streamClientFlavorMatches(requiredFlavor, candidate.Flavor) {
			continue
		}
		if excludedBinary != "" && candidate.Binary == excludedBinary {
			continue
		}
		return candidate, candidatePreflight, selection, true
	}
	return remote.Client{}, probe.Report{}, "", false
}

func streamClientFlavorMatches(required, actual remote.Flavor) bool {
	if required == remote.FlavorQt {
		return actual == remote.FlavorQt || actual == remote.FlavorFlatpak
	}
	return actual == required
}

// discoverAutomaticControlClient tries the supported Moonlight selections
// for a control-plane operation such as application listing. It deliberately
// uses ReadyForControl rather than the graphical/input gates required by a
// live stream, then passively binds the executable before returning it.
func discoverAutomaticControlClient(ctx context.Context, prober ProbeRunner, environment remote.Environment, goos string) (remote.Client, probe.Report, string, bool) {
	return discoverAutomaticControlClientExcluding(ctx, prober, environment, goos, "")
}

// discoverAutomaticControlClientExcluding is used after an automatic client
// has failed a list operation. Excluding the failed executable prevents a
// generic package alias from immediately resolving back to the same launcher.
func discoverAutomaticControlClientExcluding(ctx context.Context, prober ProbeRunner, environment remote.Environment, goos, excludedBinary string) (remote.Client, probe.Report, string, bool) {
	excludedBinary = strings.TrimSpace(excludedBinary)
	for _, selection := range remote.AutomaticClientSelections(goos) {
		candidatePreflight := remoteAutomaticClientPreflight(ctx, prober, remote.List, selection, "", "")
		if !candidatePreflight.ReadyForControl() {
			continue
		}
		candidate, err := remote.DiscoverAutomaticClientForPlatform(ctx, environment, selection, goos)
		if err != nil {
			continue
		}
		if excludedBinary != "" && candidate.Binary == excludedBinary {
			continue
		}
		return candidate, candidatePreflight, selection, true
	}
	return remote.Client{}, probe.Report{}, "", false
}

// effectiveRemoteStreamClientSelection keeps the launcher's discovered flavor
// aligned with a stream backend selector and with every flavor-specific stream
// option. The doctor command applies the same backend policy for its targeted
// client report; the remote command must apply it before both preflight and
// discovery so an auto selection cannot drift between those stages.
func effectiveRemoteStreamClientSelection(preferred, outputPlatform, qtPlatform string, options remote.StreamOptions) (string, error) {
	preferred = strings.ToLower(strings.TrimSpace(preferred))
	selectedOutputPlatform := strings.ToLower(strings.TrimSpace(outputPlatform))
	selectedQtPlatform := strings.ToLower(strings.TrimSpace(qtPlatform))
	if selectedOutputPlatform != "" && selectedQtPlatform != "" {
		return preferred, errors.New("--platform and --qt-platform cannot be combined")
	}
	requiresEmbedded, requiresQt := streamOptionBackendRequirements(options)
	if selectedOutputPlatform != "" {
		requiresEmbedded = true
	}
	if selectedQtPlatform != "" {
		requiresQt = true
	}
	if requiresEmbedded && requiresQt {
		return preferred, errors.New("the selected stream options require both Embedded and Qt backends; choose one compatible client surface")
	}
	if requiresEmbedded {
		if selectedQtPlatform != "" {
			return preferred, errors.New("Embedded-only stream options cannot be combined with --qt-platform")
		}
		if preferred == "" || preferred == "auto" {
			return "moonlight-embedded", nil
		}
		if preferred == "moonlight-qt" || preferred == "flatpak" {
			return preferred, fmt.Errorf("the selected stream options require Moonlight Embedded; they cannot be combined with --client %s", preferred)
		}
	}
	if requiresQt {
		if selectedOutputPlatform != "" {
			return preferred, errors.New("Qt-only stream options cannot be combined with --platform")
		}
		if preferred == "" || preferred == "auto" {
			return "moonlight-qt", nil
		}
		if preferred != "moonlight-qt" && preferred != "flatpak" {
			return preferred, fmt.Errorf("the selected stream options require Moonlight Qt; they cannot be combined with --client %s", preferred)
		}
	}
	if selectedOutputPlatform != "" {
		if preferred == "" || preferred == "auto" {
			return "moonlight-embedded", nil
		}
		if preferred == "moonlight-qt" || preferred == "flatpak" {
			return preferred, fmt.Errorf("--platform selects an Embedded backend; it cannot be combined with --client %s", preferred)
		}
	}
	if selectedQtPlatform != "" {
		if preferred == "" || preferred == "auto" {
			return "moonlight-qt", nil
		}
		if preferred != "moonlight-qt" && preferred != "flatpak" {
			return preferred, errors.New("--qt-platform selects a Qt backend; it requires --client moonlight-qt or flatpak")
		}
	}
	return preferred, nil
}

func streamOptionBackendRequirements(options remote.StreamOptions) (requiresEmbedded, requiresQt bool) {
	requiresEmbedded = options.AudioDevice != "" || options.DisableGamepadMouseEmulation ||
		options.InputDevice != "" || len(options.InputDevices) > 0 || options.InputMapping != "" ||
		options.NetworkMode != "" || options.Platform != ""
	requiresQt = options.FramePacing != "" || options.VSync != "" || options.KeepAwake ||
		options.CaptureSystemKeys != "" || options.Decoder != "" || options.MouseMode != "" ||
		options.MultiController || options.MouseButtonsSwap || options.TouchscreenTrackpad ||
		options.MuteOnFocusLoss || options.BackgroundGamepad || options.ReverseScrollDirection ||
		options.SwapGamepadButtons || options.PerformanceOverlay || options.YUV444 ||
		strings.EqualFold(strings.TrimSpace(options.DisplayMode), "borderless")
	return requiresEmbedded, requiresQt
}

func (a *App) runRemoteMap(ctx context.Context, args []string) int {
	set := a.flagSet("remote map")
	clientSelection := set.String("client", "moonlight-embedded", "moonlight-embedded or moonlight (BSD alias)")
	var inputDevices repeatedStringFlag
	set.Var(&inputDevices, "input-device", "Moonlight Embedded evdev input device (exactly one /dev/input/eventN device)")
	dryRun := set.Bool("dry-run", false, "validate and print the argument vector without executing")
	asJSON := set.Bool("json", false, "emit JSON (dry-run only)")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("remote map", *asJSON, ExitUsage, "%v", err)
	}
	if *asJSON && !*dryRun {
		return a.commandError("remote map", true, ExitUsage, "--json requires --dry-run so interactive Moonlight output is not mixed with JSON")
	}
	if len(inputDevices) == 0 || strings.TrimSpace(inputDevices[0]) == "" {
		return a.commandError("remote map", *asJSON, ExitUsage, "--input-device is required; provide one /dev/input/eventN device")
	}
	if len(inputDevices) != 1 {
		return a.commandError("remote map", *asJSON, ExitUsage, "remote map accepts exactly one --input-device; repeat it only for remote stream")
	}
	inputDevice := inputDevices[0]
	effectiveClientSelection := strings.ToLower(strings.TrimSpace(*clientSelection))
	if effectiveClientSelection == "" || effectiveClientSelection == "auto" {
		// Mapping is an Embedded-only local action. Resolve an automatic choice to
		// Embedded before preflight and discovery instead of letting the normal
		// Qt-first resolver produce a plan that cannot support `map`.
		effectiveClientSelection = "moonlight-embedded"
	}
	if !eligibleClientPlatform(a.GOOS, a.GOARCH) {
		return a.commandError("remote map", *asJSON, ExitBlocked, "local controller mapping targets Linux, FreeBSD, OpenBSD, or NetBSD on amd64/arm64, or DragonFly BSD on amd64; current host is %s/%s", a.GOOS, a.GOARCH)
	}
	if !*dryRun {
		if err := validateRemoteInputDevice(inputDevice); err != nil {
			return a.commandError("remote map", *asJSON, ExitUsage, "%v", err)
		}
	}
	prober := a.prober()
	var preflight probe.Report
	if selectionAware, ok := prober.(interface {
		ClientFor(context.Context, string) probe.Report
	}); ok {
		preflight = selectionAware.ClientFor(ctx, effectiveClientSelection)
	} else {
		preflight = prober.Run(ctx, probe.ProfileClient)
	}
	if !preflight.ReadyForControl() {
		return a.commandError("remote map", *asJSON, ExitBlocked, "client preflight failed; install the selected Moonlight Embedded client and run `leaguebridge doctor --profile client` for details")
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	environment := a.RemoteEnv
	if environment == nil {
		environment = remote.RealEnvironment{}
	}
	client, err := remote.DiscoverForPlatform(discoveryCtx, environment, effectiveClientSelection, a.GOOS)
	if err != nil {
		return a.commandError("remote map", *asJSON, ExitBlocked, "%v", err)
	}
	if client.Flavor != remote.FlavorEmbedded {
		return a.commandError("remote map", *asJSON, ExitUsage, "local controller mapping requires Moonlight Embedded; select --client moonlight-embedded or --client moonlight (got %q)", client.Flavor)
	}
	plan, err := remote.BuildDiscoveredInputMappingPlan(client, inputDevice)
	if err != nil {
		return a.commandError("remote map", *asJSON, ExitBlocked, "%v", err)
	}
	if *dryRun {
		if *asJSON {
			return a.writeJSON("remote map", plan)
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
		return a.commandError("remote map", false, ExitInternal, "%v", err)
	}
	return ExitOK
}

func (a *App) runRemoteKVM(ctx context.Context, args []string) int {
	set := a.flagSet("remote kvm")
	configPath := set.String("config", "", "configuration file (uses its credential-free KVM endpoint when --url is omitted)")
	routeName := set.String("route", "", "physical-host route: windows or macos (default: configuration, then windows)")
	endpoint := set.String("url", "", "hardware KVM web-interface URL (https://...; clean endpoint only)")
	browser := set.String("browser", "auto", "KVM launcher: auto, xdg-open, gio, sensible-browser, or an allowlisted browser (firefox/chromium/etc.)")
	allowHTTP := set.Bool("allow-http", false, "allow an unencrypted HTTP KVM URL for a trusted LAN bootstrap")
	confirmed := set.Bool("confirm-physical-host", false, "confirm that the KVM is attached to a physical Windows PC or Mac")
	acknowledged := set.Bool("acknowledge-unverified-handoff", false, "acknowledge that hardware-KVM control is an unverified manual handoff")
	wakeMAC := set.String("wake-mac", "", "Wake-on-LAN MAC address to wake the physical host before opening the KVM UI")
	wakeDestination := set.String("wake-broadcast", wol.DefaultDestination, "Wake-on-LAN IPv4 broadcast or unicast destination")
	wakePort := set.Int("wake-port", wol.DefaultPort, "Wake-on-LAN UDP destination port")
	wakeWait := set.Int("wake-wait", remoteDefaultWakeWait, "seconds to wait after Wake-on-LAN before opening the KVM UI (0-300)")
	dryRun := set.Bool("dry-run", false, "validate and print the browser argument vector without executing")
	asJSON := set.Bool("json", false, "emit JSON (dry-run only)")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("remote kvm", *asJSON, ExitUsage, "%v", err)
	}
	if *asJSON && !*dryRun {
		return a.commandError("remote kvm", true, ExitUsage, "--json requires --dry-run so browser launch output is not mixed with JSON")
	}
	urlOverridden := false
	confirmedOverridden := false
	wakeMACOverridden := false
	wakeDestinationOverridden := false
	wakePortOverridden := false
	wakeWaitOverridden := false
	set.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "url":
			urlOverridden = true
		case "confirm-physical-host":
			confirmedOverridden = true
		case "wake-mac":
			wakeMACOverridden = true
		case "wake-broadcast":
			wakeDestinationOverridden = true
		case "wake-port":
			wakePortOverridden = true
		case "wake-wait":
			wakeWaitOverridden = true
		}
	})
	wakeRequested := strings.TrimSpace(*wakeMAC) != ""
	if wakeMACOverridden && !wakeRequested {
		return a.commandError("remote kvm", *asJSON, ExitUsage, "--wake-mac must not be empty")
	}
	if (wakeDestinationOverridden || wakePortOverridden || wakeWaitOverridden) && !wakeRequested {
		return a.commandError("remote kvm", *asJSON, ExitUsage, "--wake-broadcast, --wake-port, and --wake-wait require --wake-mac")
	}
	if wakeRequested && (*wakeWait < 0 || *wakeWait > remoteMaxWakeWait) {
		return a.commandError("remote kvm", *asJSON, ExitUsage, "--wake-wait must be between 0 and %d seconds, got %d", remoteMaxWakeWait, *wakeWait)
	}
	if !eligibleClientPlatform(a.GOOS, a.GOARCH) {
		return a.commandError("remote kvm", *asJSON, ExitBlocked, "hardware-KVM control targets Linux, FreeBSD, OpenBSD, or NetBSD on amd64/arm64, or DragonFly BSD on amd64; current host is %s/%s", a.GOOS, a.GOARCH)
	}
	selectedRoute := config.RouteWindows
	if strings.TrimSpace(*routeName) != "" {
		parsedRoute, err := config.ParseRoute(*routeName)
		if err != nil {
			return a.commandError("remote kvm", *asJSON, ExitUsage, "%v", err)
		}
		selectedRoute = parsedRoute
	}
	// A configured KVM endpoint is deliberately limited to a clean URL and is
	// never a credential store. Explicit flags override the optional config
	// values; the per-operation acknowledgement is never persisted. The same
	// configuration route also selects which physical-host contract governs the
	// KVM operation. An explicit route must agree with a configuration when one
	// is actually used. A fully explicit URL, route, and physical-host
	// confirmation is intentionally self-contained: an unrelated default
	// configuration for the other host route must not block an ad-hoc KVM
	// operation. If the endpoint or confirmation still needs to come from a
	// configuration, load it and retain the route-conflict check.
	needsConfiguredValues := !urlOverridden || strings.TrimSpace(*configPath) != "" || wakeRequested && !confirmedOverridden
	if needsConfiguredValues {
		configured, _, err := loadRemoteConfig(*configPath, *routeName)
		if err != nil {
			return a.commandError("remote kvm", *asJSON, ExitUsage, "load KVM configuration: %v", err)
		}
		configuredRoute, err := configured.Route()
		if err != nil {
			return a.commandError("remote kvm", *asJSON, ExitUsage, "resolve KVM physical-host route: %v", err)
		}
		selectedRoute = configuredRoute
		if !confirmedOverridden {
			*confirmed = configured.RemoteHost.PhysicalHostConfirmed
		}
		if configured.KVM != nil {
			if !urlOverridden {
				*endpoint = configured.KVM.Endpoint
			}
		} else if !urlOverridden {
			return a.commandError("remote kvm", *asJSON, ExitUsage, "hardware KVM endpoint is not configured; pass --url or configure kvm.endpoint")
		}
	}
	// A KVM operation is governed by the one selected physical-host route. Do
	// not let an unrelated route's stale evidence block this handoff, and do
	// not allow the selected route to bypass its own fresh handoff contract.
	if err := a.verifyRemoteHandoffContract(selectedRoute); err != nil {
		return a.commandError("remote kvm", *asJSON, ExitBlocked, "%s physical-host handoff contract: %v", selectedRoute, err)
	}
	if err := a.verifyHardwareKVMContract(); err != nil {
		return a.commandError("remote kvm", *asJSON, ExitBlocked, "hardware-KVM handoff contract: %v", err)
	}
	request := kvm.Request{
		Endpoint:                *endpoint,
		AllowHTTP:               *allowHTTP,
		PhysicalHostConfirmed:   *confirmed,
		AcceptUnverifiedHandoff: *acknowledged,
	}
	if err := kvm.ValidateEndpoint(request.Endpoint, request.AllowHTTP); err != nil {
		return a.commandError("remote kvm", *asJSON, ExitUsage, "%v", err)
	}
	environment := a.RemoteEnv
	if environment == nil {
		environment = remote.RealEnvironment{}
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	launcher, err := kvm.Discover(discoveryCtx, environment, *browser)
	if err != nil {
		return a.commandError("remote kvm", *asJSON, ExitBlocked, "%v", err)
	}
	plan, err := kvm.BuildDiscoveredPlan(launcher, request)
	if err != nil {
		return a.commandError("remote kvm", *asJSON, ExitBlocked, "%v", err)
	}
	var wakePlan *wol.Plan
	if wakeRequested {
		builtWakePlan, err := wol.BuildPlan(wol.Request{
			MAC:                     *wakeMAC,
			Destination:             *wakeDestination,
			Port:                    *wakePort,
			PhysicalHostConfirmed:   *confirmed,
			AcceptUnverifiedHandoff: *acknowledged,
		})
		if err != nil {
			return a.commandError("remote kvm", *asJSON, ExitBlocked, "%v", err)
		}
		wakePlan = &builtWakePlan
	}
	if *dryRun {
		if *asJSON {
			if wakePlan != nil {
				return a.writeJSON("remote kvm", struct {
					kvm.Plan
					Wake *wol.Plan `json:"wake,omitempty"`
				}{Plan: plan, Wake: wakePlan})
			}
			return a.writeJSON("remote kvm", plan)
		}
		fmt.Fprintln(a.Stdout, "Validated KVM browser argument vector (no process started):")
		fmt.Fprintf(a.Stdout, "  executable: %s\n", strconv.Quote(plan.Launcher.Binary))
		for i, argument := range plan.Arguments {
			fmt.Fprintf(a.Stdout, "  argv[%d]: %s\n", i+1, strconv.Quote(argument))
		}
		for _, warning := range plan.Warnings {
			fmt.Fprintf(a.Stdout, "  warning: %s\n", warning)
		}
		if wakePlan != nil {
			fmt.Fprintf(a.Stdout, "  wake: %s:%d for %s; wait %d second(s) before opening the KVM UI\n", wakePlan.Destination, wakePlan.Port, wakePlan.MAC, *wakeWait)
			for _, warning := range wakePlan.Warnings {
				fmt.Fprintf(a.Stdout, "  wake warning: %s\n", warning)
			}
		}
		return ExitOK
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", warning)
	}
	if wakePlan != nil {
		for _, warning := range wakePlan.Warnings {
			fmt.Fprintf(a.Stderr, "warning: %s\n", warning)
		}
		wakeCtx, cancelWake := context.WithTimeout(ctx, remoteControlTimeout)
		err := wol.Execute(wakeCtx, *wakePlan)
		wakeTimedOut := ctx.Err() == nil && errors.Is(wakeCtx.Err(), context.DeadlineExceeded)
		cancelWake()
		if err != nil {
			if wakeTimedOut {
				return a.commandError("remote kvm", false, ExitInternal, "Wake-on-LAN send timed out after %s; verify the local network and destination", remoteControlTimeout)
			}
			return a.commandError("remote kvm", false, ExitInternal, "%v", err)
		}
		fmt.Fprintf(a.Stdout, "Wake-on-LAN packet sent to %s:%d for %s.\n", wakePlan.Destination, wakePlan.Port, wakePlan.MAC)
		if *wakeWait > 0 {
			fmt.Fprintf(a.Stderr, "waiting %d second(s) for the physical host before opening the KVM UI\n", *wakeWait)
			if err := waitForRemoteReconnect(ctx, time.Duration(*wakeWait)*time.Second); err != nil {
				return a.commandError("remote kvm", false, ExitInternal, "Wake-on-LAN wait canceled: %v", err)
			}
		}
	}
	runner := a.RemoteRunner
	if runner == nil {
		runner = remote.ExecRunner{}
	}
	executionCtx, cancelExecution := context.WithTimeout(ctx, remoteControlTimeout)
	defer cancelExecution()
	if err := kvm.Execute(executionCtx, runner, a.Stdin, a.Stdout, a.Stderr, plan); err != nil {
		if ctx.Err() == nil && errors.Is(executionCtx.Err(), context.DeadlineExceeded) {
			return a.commandError("remote kvm", false, ExitInternal, "KVM browser launch timed out after %s; verify the desktop session and selected launcher", remoteControlTimeout)
		}
		return a.commandError("remote kvm", false, ExitInternal, "%v", err)
	}
	return ExitOK
}

func (a *App) runRemoteWake(ctx context.Context, args []string) int {
	set := a.flagSet("remote wake")
	configPath := set.String("config", "", "configuration file (used to verify the selected physical-host route)")
	mac := set.String("mac", "", "physical host network-interface MAC address (for example 00:11:22:33:44:55)")
	destination := set.String("broadcast", wol.DefaultDestination, "IPv4 broadcast or unicast destination for the magic packet")
	port := set.Int("port", wol.DefaultPort, "UDP destination port for the magic packet")
	confirmed := set.Bool("confirm-physical-host", false, "confirm that the target host is not a VM")
	acknowledged := set.Bool("acknowledge-unverified-handoff", false, "acknowledge that waking the physical host is an unverified handoff")
	dryRun := set.Bool("dry-run", false, "validate and print the Wake-on-LAN plan without sending a packet")
	asJSON := set.Bool("json", false, "emit JSON (dry-run only)")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("remote wake", *asJSON, ExitUsage, "%v", err)
	}
	if *asJSON && !*dryRun {
		return a.commandError("remote wake", true, ExitUsage, "--json requires --dry-run so packet output is not mixed with execution")
	}
	if !eligibleClientPlatform(a.GOOS, a.GOARCH) {
		return a.commandError("remote wake", *asJSON, ExitBlocked, "Wake-on-LAN handoff clients target Linux, FreeBSD, OpenBSD, or NetBSD on amd64/arm64, or DragonFly BSD on amd64; current host is %s/%s", a.GOOS, a.GOARCH)
	}
	if strings.TrimSpace(*mac) == "" {
		return a.commandError("remote wake", *asJSON, ExitUsage, "--mac is required; provide the physical host's six-octet network-interface address")
	}
	cfg, usedPath, err := loadRemoteConfig(*configPath)
	if err != nil {
		return a.commandError("remote wake", *asJSON, ExitUsage, "%v", err)
	}
	_, route, err := cfg.ActiveRemote()
	if err != nil {
		return a.commandError("remote wake", *asJSON, ExitUsage, "%v", err)
	}
	if err := a.verifyRemoteHandoffContract(route); err != nil {
		return a.commandError("remote wake", *asJSON, ExitBlocked, "%v", err)
	}
	if err := cfg.Validate(); err != nil {
		location := "flags/defaults"
		if usedPath != "" {
			location = usedPath
		}
		return a.commandError("remote wake", *asJSON, ExitUsage, "invalid remote configuration (%s): %v", location, err)
	}
	confirmation := cfg.RemoteHost.PhysicalHostConfirmed
	confirmationOverridden := false
	set.Visit(func(option *flag.Flag) {
		if option.Name == "confirm-physical-host" {
			confirmationOverridden = true
		}
	})
	if confirmationOverridden {
		confirmation = *confirmed
	}
	plan, err := wol.BuildPlan(wol.Request{
		MAC:                     *mac,
		Destination:             *destination,
		Port:                    *port,
		PhysicalHostConfirmed:   confirmation,
		AcceptUnverifiedHandoff: *acknowledged,
	})
	if err != nil {
		return a.commandError("remote wake", *asJSON, ExitBlocked, "%v", err)
	}
	if *dryRun {
		if *asJSON {
			return a.writeJSON("remote wake", plan)
		}
		fmt.Fprintln(a.Stdout, "Validated Wake-on-LAN packet (no packet sent):")
		fmt.Fprintf(a.Stdout, "  mac: %s\n", plan.MAC)
		fmt.Fprintf(a.Stdout, "  destination: %s\n", plan.Destination)
		fmt.Fprintf(a.Stdout, "  port: %d\n", plan.Port)
		for _, warning := range plan.Warnings {
			fmt.Fprintf(a.Stdout, "  warning: %s\n", warning)
		}
		return ExitOK
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", warning)
	}
	executionCtx, cancel := context.WithTimeout(ctx, remoteControlTimeout)
	defer cancel()
	if err := wol.Execute(executionCtx, plan); err != nil {
		if ctx.Err() == nil && errors.Is(executionCtx.Err(), context.DeadlineExceeded) {
			return a.commandError("remote wake", false, ExitInternal, "Wake-on-LAN send timed out after %s; verify the local network and destination", remoteControlTimeout)
		}
		return a.commandError("remote wake", false, ExitInternal, "%v", err)
	}
	fmt.Fprintf(a.Stdout, "Wake-on-LAN packet sent to %s:%d for %s. Wait for the physical host, then run the remote pair/list/stream flow.\n", plan.Destination, plan.Port, plan.MAC)
	return ExitOK
}

func validateRemoteInputMappingFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("input mapping %q cannot be read: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("input mapping %q is not a regular file", path)
	}
	if info.Size() > remoteInputMappingFileLimit {
		return fmt.Errorf("input mapping %q exceeds the %d-byte limit", path, remoteInputMappingFileLimit)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("input mapping %q cannot be opened: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("input mapping %q cannot be closed: %w", path, err)
	}
	return nil
}

const embeddedStreamMappingRequirement = "Moonlight Embedded needs a readable gamecontrollerdb.txt for a non-SDL stream; install the Moonlight data package, set --input-mapping to an existing SDL mapping file, set SDL_GAMECONTROLLERCONFIG, or use Moonlight Qt"

// validateEmbeddedStreamMappingAvailability mirrors Moonlight Embedded's
// current controller-database lookup. The selected client owns parsing and
// using the file; LeagueBridge only prevents a known startup failure. The
// default file is not subject to the explicit --input-mapping size limit,
// because it is package-owned data and Moonlight is responsible for it.
func validateEmbeddedStreamMappingAvailability(inputMapping, platform string) error {
	if strings.TrimSpace(inputMapping) != "" {
		return validateRemoteInputMappingFile(strings.TrimSpace(inputMapping))
	}
	if strings.EqualFold(strings.TrimSpace(platform), "sdl") || strings.TrimSpace(os.Getenv("SDL_GAMECONTROLLERCONFIG")) != "" {
		return nil
	}
	for _, candidate := range moonlightEmbeddedMappingCandidates() {
		if readableRegularFile(candidate) {
			return nil
		}
	}
	return errors.New(embeddedStreamMappingRequirement)
}

func moonlightEmbeddedMappingCandidates() []string {
	const filename = "gamecontrollerdb.txt"
	candidates := []string{filename}
	appendRoot := func(root string) {
		root = strings.TrimSpace(root)
		if root == "" {
			return
		}
		candidates = append(candidates, filepath.Join(root, "moonlight", filename))
	}

	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" {
		if resolved, err := os.UserHomeDir(); err == nil {
			home = resolved
		}
	}
	if home != "" {
		appendRoot(home)
		appendRoot(filepath.Join(home, ".config"))
	}
	appendRoot(os.Getenv("XDG_CONFIG_DIR"))
	appendRoot(os.Getenv("XDG_CONFIG_HOME"))
	appendRoot(os.Getenv("XDG_DATA_HOME"))

	dataDirs := strings.TrimSpace(os.Getenv("XDG_DATA_DIRS"))
	if dataDirs == "" {
		for _, root := range []string{"/usr/share", "/usr/local/share"} {
			appendRoot(root)
		}
		return candidates
	}
	for _, root := range filepath.SplitList(dataDirs) {
		appendRoot(root)
	}
	return candidates
}

func readableRegularFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	return file.Close() == nil
}

func validateRemoteInputDevice(path string) error {
	return validateRemoteInputDeviceWithFlags(path, os.O_RDWR|syscall.O_NONBLOCK, "read/write")
}

func validateRemoteInputDeviceWithFlags(path string, flags int, access string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("input device %q cannot be read: %w", path, err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("input device %q is not a character device", path)
	}
	// Opening with O_NONBLOCK verifies the permission that the selected
	// Moonlight operation will need without risking a startup hang on a device
	// node. Keep the handle open only for this check; Moonlight owns the actual
	// device lifetime during mapping or streaming. O_RDWR requests permission
	// only; this code never writes to the device. The upstream `map` action
	// invokes evdev_create before its later read-only mapping open, so mapping
	// uses the same conservative permission check.
	device, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return fmt.Errorf("input device %q cannot be opened for %s: %w", path, access, err)
	}
	_ = device.Close()
	return nil
}

func validateRemoteInputDevices(paths []string) error {
	for index, path := range paths {
		if err := validateRemoteInputDevice(path); err != nil {
			return fmt.Errorf("input device %d: %w", index+1, err)
		}
	}
	return nil
}

func remoteReconnectStopped(ctx context.Context, err error) bool {
	return (ctx != nil && ctx.Err() != nil) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func waitForRemoteReconnect(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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

func (a *App) verifyHardwareKVMContract() error {
	manifest, err := compat.Embedded()
	if err != nil {
		return fmt.Errorf("embedded compatibility authority is invalid: %w", err)
	}
	freshness, err := manifest.FreshnessAt(a.now())
	if err != nil {
		return fmt.Errorf("compatibility evidence cannot be evaluated: %w", err)
	}
	if freshness.State != compat.FreshnessFresh {
		return fmt.Errorf("compatibility evidence is %s; install a current LeagueBridge release before hardware-KVM handoff", freshness.State)
	}
	for _, backend := range manifest.Backends {
		if backend.ID != compat.BackendHardwareKVMRemote {
			continue
		}
		if backend.State != compat.StateHandoffOnly || backend.LaunchMode != compat.LaunchRemote || backend.Kind != compat.KindRemoteHardwareKVM || backend.LaunchVerdict != compat.DecisionDeny || backend.Authorization != compat.AuthorizationUnverified {
			return errors.New("embedded hardware-KVM handoff safety contract is not satisfied")
		}
		return nil
	}
	return errors.New("embedded hardware-KVM handoff backend is missing")
}

func eligibleClientPlatform(goos, goarch string) bool {
	return target.IsSupported(goos, goarch)
}
