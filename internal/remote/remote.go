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
	"strconv"
	"strings"

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
	Unpair Operation = "unpair"
	List   Operation = "list"
	Stream Operation = "stream"
	Quit   Operation = "quit"
	Map    Operation = "map"
)

// ApplicationListed reports whether a Moonlight application-list response
// contains the requested application name. Moonlight clients do not expose a
// common machine-readable list format across Embedded and Qt, so this helper
// deliberately performs a conservative text check after removing terminal
// control sequences. It is a pre-stream configuration check, not evidence of
// a working League client or Vanguard session.
func ApplicationListed(output, application string) bool {
	return applicationListed(output, application, false)
}

// ApplicationListedForFlavor reports whether a Moonlight application-list
// response contains the requested application using the matching client's
// launch-name semantics. Moonlight Qt resolves application names
// case-insensitively, while Moonlight Embedded's documented lookup is
// case-sensitive. Keeping that distinction here avoids rejecting a Qt stream
// that the selected client would launch, without weakening Embedded's exact
// lookup contract.
func ApplicationListedForFlavor(output, application string, flavor Flavor) bool {
	caseInsensitive := flavor == FlavorQt || flavor == FlavorFlatpak
	return applicationListed(output, application, caseInsensitive)
}

func applicationListed(output, application string, caseInsensitive bool) bool {
	if err := config.ValidateAppName(application); err != nil {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(stripTerminalControlSequences(line))
		if applicationLineMatches(line, application, caseInsensitive) {
			return true
		}
	}
	return false
}

// applicationLineMatches accepts the plain and lightly decorated forms used
// by Moonlight clients while rejecting arbitrary diagnostic text. In
// particular, a connection banner or an error mentioning the requested app
// must not be enough to pass --require-app.
func applicationLineMatches(line, application string, caseInsensitive bool) bool {
	matches := func(candidate string) bool {
		if caseInsensitive {
			return strings.EqualFold(candidate, application)
		}
		return candidate == application
	}
	if matches(line) {
		return true
	}
	if colon := strings.IndexByte(line, ':'); colon > 0 {
		label := strings.TrimSpace(line[:colon])
		if strings.EqualFold(label, "application") || strings.EqualFold(label, "app") {
			return matches(strings.TrimSpace(line[colon+1:]))
		}
	}
	if len(line) > 1 && (line[0] == '-' || line[0] == '*') &&
		matches(strings.TrimSpace(line[1:])) {
		return true
	}
	if close := strings.IndexByte(line, ']'); len(line) > 2 && line[0] == '[' && close > 1 &&
		allASCIIDigits(line[1:close]) && matches(strings.TrimSpace(line[close+1:])) {
		return true
	}
	index := 0
	for index < len(line) && line[index] >= '0' && line[index] <= '9' {
		index++
	}
	if index > 0 && index < len(line) {
		switch line[index] {
		case '.', ')', ':', '-':
			return matches(strings.TrimSpace(line[index+1:]))
		}
	}
	return false
}

func allASCIIDigits(value string) bool {
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

func stripTerminalControlSequences(value string) string {
	var cleaned strings.Builder
	cleaned.Grow(len(value))
	const (
		plain = iota
		escape
		csi
		osc
		oscEscape
	)
	state := plain
	for i := 0; i < len(value); i++ {
		character := value[i]
		switch state {
		case plain:
			if character == 0x1b {
				state = escape
				continue
			}
			cleaned.WriteByte(character)
		case escape:
			switch character {
			case '[':
				state = csi
			case ']':
				state = osc
			default:
				// A two-byte ESC sequence has ended. The introducer and final
				// byte are control data and are both discarded.
				state = plain
			}
		case csi:
			// CSI parameters/intermediates may contain bytes below 0x40;
			// only a final byte in 0x40-0x7e ends the sequence.
			if character >= 0x40 && character <= 0x7e {
				state = plain
			}
		case osc:
			// OSC sequences terminate with BEL or the two-byte ST sequence.
			if character == 0x07 {
				state = plain
			} else if character == 0x1b {
				state = oscEscape
			}
		case oscEscape:
			if character == '\\' {
				state = plain
			} else if character == 0x1b {
				state = oscEscape
			} else {
				state = osc
			}
		}
	}
	return cleaned.String()
}

type Client struct {
	Flavor Flavor   `json:"flavor"`
	Binary string   `json:"binary"`
	Prefix []string `json:"prefix,omitempty"`

	// discovered is deliberately private and non-serialized. Only Discover
	// may mark a client as coming from the passive, real-environment resolver.
	// A hand-built client can still be used for pure argument planning, but its
	// plan must never cross the execution boundary.
	discovered bool

	// executableInfo is populated only by RealEnvironment after passive
	// discovery. It is deliberately private and non-serialized. The execution
	// boundary uses it to detect replacement of the discovered file before
	// handing control to the child-process runner.
	executableInfo os.FileInfo

	// discoveryBinding snapshots the exported client fields at the moment the
	// passive resolver returns. BuildDiscoveredPlan checks it before constructing
	// a plan so callers cannot mutate a discovered client into a different
	// launcher flavor or command prefix between discovery and planning.
	discoveryBinding clientBinding
}

// clientBinding is an immutable-in-practice snapshot of the exported Client
// fields that influence process selection. It is kept private, stored on a
// discovered Client, and copied into a Plan so mutating either Client before
// planning or Plan.Client after planning cannot redirect execution.
type clientBinding struct {
	flavor         Flavor
	binary         string
	prefix         []string
	executableInfo os.FileInfo
}

func bindClient(client Client) clientBinding {
	return clientBinding{
		flavor:         client.Flavor,
		binary:         client.Binary,
		prefix:         append([]string(nil), client.Prefix...),
		executableInfo: client.executableInfo,
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
	Route     config.Route
	Operation Operation
	Host      string
	App       string
	// PairingPIN is an invocation-only predefined PIN for Moonlight Qt or
	// Moonlight Embedded. It is deliberately not persisted or emitted in
	// dry-run output.
	PairingPIN string `json:"-"`
	// QtPlatform is an invocation-only QT_QPA_PLATFORM override for a live
	// Moonlight Qt or Qt-based Flatpak stream. It is deliberately not persisted.
	QtPlatform              string `json:"-"`
	PhysicalHostConfirmed   bool
	AcceptUnverifiedHandoff bool
	Stream                  StreamOptions
}

const (
	minCustomResolutionWidth  = 640
	maxCustomResolutionWidth  = 7680
	minCustomResolutionHeight = 360
	maxCustomResolutionHeight = 4320
)

// StreamOptions is the small bounded quality, display, audio, input-mode, and
// controller surface
// supported by the Moonlight Embedded and Moonlight Qt command-line clients.
// The two clients use slightly different syntax for resolution, packet size,
// codec, and audio selection, and only Qt exposes decoder, display-mode, and
// controller controls. Embedded additionally exposes a platform selector,
// audio/input device selectors (including multiple evdev inputs), an SDL
// mapping file, and a gamepad mouse-emulation toggle. arguments() translates
// the bounded values to each client's documented form.
// Zero values keep the selected client's own defaults. Options are
// invocation-scoped and are never persisted with LeagueBridge configuration.
type StreamOptions struct {
	Resolution                   string   `json:"resolution,omitempty"`
	FPS                          int      `json:"fps,omitempty"`
	BitrateKbps                  int      `json:"bitrate_kbps,omitempty"`
	PacketSizeBytes              int      `json:"packet_size_bytes,omitempty"`
	Codec                        string   `json:"codec,omitempty"`
	AudioConfig                  string   `json:"audio_config,omitempty"`
	AudioOnHost                  bool     `json:"audio_on_host,omitempty"`
	AudioDevice                  string   `json:"audio_device,omitempty"`
	PreserveHostSettings         bool     `json:"preserve_host_settings,omitempty"`
	DisableGamepadMouseEmulation bool     `json:"disable_gamepad_mouse_emulation,omitempty"`
	InputDevice                  string   `json:"input_device,omitempty"`
	InputDevices                 []string `json:"input_devices,omitempty"`
	InputMapping                 string   `json:"input_mapping,omitempty"`
	NetworkMode                  string   `json:"network_mode,omitempty"`
	FramePacing                  string   `json:"frame_pacing,omitempty"`
	VSync                        string   `json:"vsync,omitempty"`
	KeepAwake                    bool     `json:"keep_awake,omitempty"`
	QuitAfter                    bool     `json:"quit_after,omitempty"`
	CaptureSystemKeys            string   `json:"capture_system_keys,omitempty"`
	Platform                     string   `json:"platform,omitempty"`
	Decoder                      string   `json:"decoder,omitempty"`
	DisplayMode                  string   `json:"display_mode,omitempty"`
	MouseMode                    string   `json:"mouse_mode,omitempty"`
	MultiController              bool     `json:"multi_controller,omitempty"`
	MouseButtonsSwap             bool     `json:"mouse_buttons_swap,omitempty"`
	TouchscreenTrackpad          bool     `json:"touchscreen_trackpad,omitempty"`
	MuteOnFocusLoss              bool     `json:"mute_on_focus_loss,omitempty"`
	BackgroundGamepad            bool     `json:"background_gamepad,omitempty"`
	ReverseScrollDirection       bool     `json:"reverse_scroll_direction,omitempty"`
	SwapGamepadButtons           bool     `json:"swap_gamepad_buttons,omitempty"`
	PerformanceOverlay           bool     `json:"performance_overlay,omitempty"`
	HDR                          bool     `json:"hdr,omitempty"`
	YUV444                       bool     `json:"yuv444,omitempty"`
}

func (options StreamOptions) empty() bool {
	return options.Resolution == "" && options.FPS == 0 && options.BitrateKbps == 0 && options.PacketSizeBytes == 0 && options.Codec == "" && options.AudioConfig == "" && !options.AudioOnHost && options.AudioDevice == "" && !options.PreserveHostSettings && !options.DisableGamepadMouseEmulation && options.InputDevice == "" && len(options.InputDevices) == 0 && options.InputMapping == "" && options.NetworkMode == "" && options.FramePacing == "" && options.VSync == "" && !options.KeepAwake && !options.QuitAfter && options.CaptureSystemKeys == "" && options.Platform == "" && options.Decoder == "" && options.DisplayMode == "" && options.MouseMode == "" && !options.MultiController && !options.MouseButtonsSwap && !options.TouchscreenTrackpad && !options.MuteOnFocusLoss && !options.BackgroundGamepad && !options.ReverseScrollDirection && !options.SwapGamepadButtons && !options.PerformanceOverlay && !options.HDR && !options.YUV444
}

// Validate checks the bounded quality values before they can reach a
// Moonlight argument vector.
func (options StreamOptions) Validate() error {
	if options.Resolution != "" {
		if _, err := parseResolutionSpec(options.Resolution); err != nil {
			return err
		}
	}
	if options.FPS != 0 && (options.FPS < 10 || options.FPS > 480) {
		return fmt.Errorf("fps must be between 10 and 480, got %d", options.FPS)
	}
	if options.BitrateKbps != 0 && (options.BitrateKbps < 500 || options.BitrateKbps > 500000) {
		return fmt.Errorf("bitrate must be between 500 and 500000 Kbps, got %d", options.BitrateKbps)
	}
	if options.PacketSizeBytes != 0 {
		if err := validatePacketSize(options.PacketSizeBytes); err != nil {
			return err
		}
	}
	if options.Codec != "" {
		switch strings.ToLower(strings.TrimSpace(options.Codec)) {
		case "auto", "h264", "h265", "hevc", "av1":
		default:
			return fmt.Errorf("codec must be auto, h264, h265, hevc, or av1, got %q", options.Codec)
		}
		if options.HDR && strings.EqualFold(strings.TrimSpace(options.Codec), "h264") {
			return errors.New("HDR streaming cannot use H.264; choose HEVC or AV1, or omit --codec")
		}
	}
	if options.AudioConfig != "" {
		switch strings.ToLower(strings.TrimSpace(options.AudioConfig)) {
		case "stereo", "5.1-surround", "7.1-surround":
		default:
			return fmt.Errorf("audio config must be stereo, 5.1-surround, or 7.1-surround, got %q", options.AudioConfig)
		}
	}
	if options.AudioDevice != "" {
		if err := validateDeviceSelector(options.AudioDevice, "audio device"); err != nil {
			return err
		}
	}
	if options.InputDevice != "" {
		if err := validateEmbeddedInputDevice(options.InputDevice); err != nil {
			return err
		}
	}
	if options.InputDevice != "" && len(options.InputDevices) > 0 {
		return errors.New("input_device and input_devices cannot be combined")
	}
	if len(options.InputDevices) > maxEmbeddedInputDevices {
		return fmt.Errorf("input devices must not exceed %d devices", maxEmbeddedInputDevices)
	}
	for index, inputDevice := range options.InputDevices {
		if err := validateEmbeddedInputDevice(inputDevice); err != nil {
			return fmt.Errorf("input device %d: %w", index+1, err)
		}
	}
	if options.InputMapping != "" {
		if err := validateInputMappingPath(options.InputMapping); err != nil {
			return err
		}
	}
	if options.NetworkMode != "" {
		switch strings.ToLower(strings.TrimSpace(options.NetworkMode)) {
		case "auto", "lan", "wan":
		default:
			return fmt.Errorf("network mode must be auto, lan, or wan, got %q", options.NetworkMode)
		}
	}
	if options.FramePacing != "" {
		switch strings.ToLower(strings.TrimSpace(options.FramePacing)) {
		case "auto", "on", "off":
		default:
			return fmt.Errorf("frame pacing must be auto, on, or off, got %q", options.FramePacing)
		}
	}
	if options.VSync != "" {
		switch strings.ToLower(strings.TrimSpace(options.VSync)) {
		case "auto", "on", "off":
		default:
			return fmt.Errorf("vsync must be auto, on, or off, got %q", options.VSync)
		}
	}
	if options.CaptureSystemKeys != "" {
		switch strings.ToLower(strings.TrimSpace(options.CaptureSystemKeys)) {
		case "auto", "never", "fullscreen", "always":
		default:
			return fmt.Errorf("capture system keys must be auto, never, fullscreen, or always, got %q", options.CaptureSystemKeys)
		}
	}
	if options.Platform != "" {
		switch strings.ToLower(strings.TrimSpace(options.Platform)) {
		case "auto", "x11", "x11_vdpau", "x11_vaapi", "sdl":
		default:
			return fmt.Errorf("platform must be auto, x11, x11_vdpau, x11_vaapi, or sdl, got %q", options.Platform)
		}
		if strings.EqualFold(strings.TrimSpace(options.Platform), "sdl") {
			if options.AudioDevice != "" {
				return errors.New("audio device cannot be used with the Embedded SDL platform; select x11, x11_vdpau, or x11_vaapi, or omit the audio device")
			}
			if options.InputDevice != "" || len(options.InputDevices) > 0 {
				return errors.New("explicit input devices cannot be used with the Embedded SDL platform; SDL discovers controllers automatically")
			}
		}
	}
	if options.Decoder != "" {
		switch strings.ToLower(strings.TrimSpace(options.Decoder)) {
		case "auto", "software", "hardware":
		default:
			return fmt.Errorf("decoder must be auto, software, or hardware, got %q", options.Decoder)
		}
	}
	if options.DisplayMode != "" {
		switch strings.ToLower(strings.TrimSpace(options.DisplayMode)) {
		case "fullscreen", "windowed", "borderless":
		default:
			return fmt.Errorf("display mode must be fullscreen, windowed, or borderless, got %q", options.DisplayMode)
		}
	}
	if options.MouseMode != "" {
		switch strings.ToLower(strings.TrimSpace(options.MouseMode)) {
		case "absolute", "relative":
		default:
			return fmt.Errorf("mouse mode must be absolute or relative, got %q", options.MouseMode)
		}
	}
	return nil
}

func (options StreamOptions) arguments(flavor Flavor) ([]string, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	optionFlavor := streamOptionFlavor(flavor)
	arguments := make([]string, 0, 12)
	if options.Resolution != "" {
		resolution, err := parseResolutionSpec(options.Resolution)
		if err != nil {
			return nil, err
		}
		switch resolution.name {
		case "1440":
			if optionFlavor == FlavorQt {
				arguments = append(arguments, "-1440")
			} else {
				// Embedded documents 1440p through its width/height
				// options rather than a dedicated -1440 flag.
				arguments = append(arguments, "-width", "2560", "-height", "1440")
			}
		case "4k":
			if optionFlavor == FlavorQt {
				arguments = append(arguments, "-4K")
			} else {
				arguments = append(arguments, "-4k")
			}
		case "720", "1080":
			arguments = append(arguments, "-"+resolution.name)
		default:
			if optionFlavor == FlavorQt {
				arguments = append(arguments, "-resolution", resolution.name)
			} else {
				arguments = append(arguments, "-width", strconv.Itoa(resolution.width), "-height", strconv.Itoa(resolution.height))
			}
		}
	}
	if options.FPS != 0 {
		arguments = append(arguments, "-fps", strconv.Itoa(options.FPS))
	}
	if options.BitrateKbps != 0 {
		arguments = append(arguments, "-bitrate", strconv.Itoa(options.BitrateKbps))
	}
	if options.PacketSizeBytes != 0 {
		option := "-packetsize"
		if optionFlavor == FlavorQt {
			option = "-packet-size"
		}
		arguments = append(arguments, option, strconv.Itoa(options.PacketSizeBytes))
	}
	if options.Codec != "" {
		codec := normalizedCodec(options.Codec)
		if optionFlavor == FlavorQt {
			arguments = append(arguments, "-video-codec", qtCodecName(codec))
		} else {
			arguments = append(arguments, "-codec", codec)
		}
	}
	if options.AudioConfig != "" {
		audioConfig := strings.ToLower(strings.TrimSpace(options.AudioConfig))
		switch optionFlavor {
		case FlavorQt:
			arguments = append(arguments, "-audio-config", audioConfig)
		case FlavorEmbedded:
			switch audioConfig {
			case "stereo":
				// Stereo is Embedded's default and has no documented flag.
			case "5.1-surround":
				arguments = append(arguments, "-surround", "5.1")
			case "7.1-surround":
				arguments = append(arguments, "-surround", "7.1")
			}
		default:
			return nil, fmt.Errorf("audio configuration is unsupported by Moonlight client flavor %q", optionFlavor)
		}
	}
	if options.AudioOnHost {
		switch optionFlavor {
		case FlavorEmbedded:
			arguments = append(arguments, "-localaudio")
		case FlavorQt:
			arguments = append(arguments, "-audio-on-host")
		default:
			return nil, fmt.Errorf("audio-on-host is unsupported by Moonlight client flavor %q", optionFlavor)
		}
	}
	if options.AudioDevice != "" {
		if optionFlavor != FlavorEmbedded {
			return nil, fmt.Errorf("audio-device is supported only by Moonlight Embedded; select --client moonlight-embedded or omit it (got %q)", optionFlavor)
		}
		arguments = append(arguments, "-audio", strings.TrimSpace(options.AudioDevice))
	}
	if options.PreserveHostSettings {
		switch optionFlavor {
		case FlavorEmbedded:
			arguments = append(arguments, "-nosops")
		case FlavorQt:
			arguments = append(arguments, "-no-game-optimization")
		default:
			return nil, fmt.Errorf("host-settings preservation is unsupported by Moonlight client flavor %q", optionFlavor)
		}
	}
	if options.DisableGamepadMouseEmulation {
		if optionFlavor != FlavorEmbedded {
			return nil, fmt.Errorf("gamepad mouse-emulation control is supported only by Moonlight Embedded; select --client moonlight-embedded or omit it (got %q)", optionFlavor)
		}
		arguments = append(arguments, "-nomouseemulation")
	}
	inputDevices := options.InputDevices
	if options.InputDevice != "" {
		inputDevices = []string{options.InputDevice}
	}
	if len(inputDevices) > 0 {
		if optionFlavor != FlavorEmbedded {
			return nil, fmt.Errorf("input-device is supported only by Moonlight Embedded; select --client moonlight-embedded or omit it (got %q)", optionFlavor)
		}
		for _, inputDevice := range inputDevices {
			arguments = append(arguments, "-input", strings.TrimSpace(inputDevice))
		}
	}
	if options.InputMapping != "" {
		if optionFlavor != FlavorEmbedded {
			return nil, fmt.Errorf("input-mapping is supported only by Moonlight Embedded; select --client moonlight-embedded or omit it (got %q)", optionFlavor)
		}
		arguments = append(arguments, "-mapping", strings.TrimSpace(options.InputMapping))
	}
	if options.NetworkMode != "" {
		if optionFlavor != FlavorEmbedded {
			return nil, fmt.Errorf("network mode selection is supported only by Moonlight Embedded; select --client moonlight-embedded or omit it (got %q)", optionFlavor)
		}
		mode := strings.ToLower(strings.TrimSpace(options.NetworkMode))
		remoteMode := map[string]string{"auto": "auto", "lan": "no", "wan": "yes"}[mode]
		arguments = append(arguments, "-remote", remoteMode)
	}
	if options.FramePacing != "" {
		if optionFlavor != FlavorQt {
			return nil, fmt.Errorf("frame-pacing selection is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", optionFlavor)
		}
		switch strings.ToLower(strings.TrimSpace(options.FramePacing)) {
		case "on":
			arguments = append(arguments, "-frame-pacing")
		case "off":
			arguments = append(arguments, "-no-frame-pacing")
		}
	}
	if options.VSync != "" {
		if optionFlavor != FlavorQt {
			return nil, fmt.Errorf("vsync selection is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", optionFlavor)
		}
		switch strings.ToLower(strings.TrimSpace(options.VSync)) {
		case "on":
			arguments = append(arguments, "-vsync")
		case "off":
			arguments = append(arguments, "-no-vsync")
		}
	}
	if options.KeepAwake {
		if optionFlavor != FlavorQt {
			return nil, fmt.Errorf("keep-awake is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", optionFlavor)
		}
		arguments = append(arguments, "-keep-awake")
	}
	if options.QuitAfter {
		switch optionFlavor {
		case FlavorEmbedded:
			arguments = append(arguments, "-quitappafter")
		case FlavorQt:
			arguments = append(arguments, "-quit-after")
		default:
			return nil, fmt.Errorf("quit-after is unsupported by Moonlight client flavor %q", optionFlavor)
		}
	}
	if options.CaptureSystemKeys != "" {
		if optionFlavor != FlavorQt {
			return nil, fmt.Errorf("system-key capture is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", optionFlavor)
		}
		captureMode := strings.ToLower(strings.TrimSpace(options.CaptureSystemKeys))
		if captureMode != "auto" {
			arguments = append(arguments, "-capture-system-keys", captureMode)
		}
	}
	if options.Platform != "" {
		if optionFlavor != FlavorEmbedded {
			return nil, fmt.Errorf("platform selection is supported only by Moonlight Embedded; select --client moonlight-embedded or omit it (got %q)", optionFlavor)
		}
		platform := strings.ToLower(strings.TrimSpace(options.Platform))
		if platform != "auto" {
			arguments = append(arguments, "-platform", platform)
		}
	}
	if options.Decoder != "" {
		if optionFlavor != FlavorQt {
			return nil, fmt.Errorf("decoder selection is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", optionFlavor)
		}
		arguments = append(arguments, "-video-decoder", strings.ToLower(strings.TrimSpace(options.Decoder)))
	}
	if options.DisplayMode != "" {
		displayMode := strings.ToLower(strings.TrimSpace(options.DisplayMode))
		if optionFlavor == FlavorEmbedded {
			switch displayMode {
			case "fullscreen":
				// Fullscreen is Embedded's default and has no documented flag.
			case "windowed":
				arguments = append(arguments, "-windowed")
			default:
				return nil, fmt.Errorf("borderless display mode is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", optionFlavor)
			}
		} else {
			arguments = append(arguments, "-display-mode", displayMode)
		}
	}
	if options.MouseMode != "" {
		if optionFlavor != FlavorQt {
			return nil, fmt.Errorf("mouse mode is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", optionFlavor)
		}
		if strings.EqualFold(strings.TrimSpace(options.MouseMode), "absolute") {
			arguments = append(arguments, "-absolute-mouse")
		} else {
			arguments = append(arguments, "-no-absolute-mouse")
		}
	}
	qtControls := []struct {
		enabled       bool
		option        string
		name          string
		embeddedValid bool
	}{
		{options.MultiController, "-multi-controller", "multi-controller", false},
		{options.MouseButtonsSwap, "-mouse-buttons-swap", "mouse button swapping", false},
		{options.TouchscreenTrackpad, "-touchscreen-trackpad", "touchscreen trackpad mode", false},
		{options.MuteOnFocusLoss, "-mute-on-focus-loss", "mute-on-focus-loss", false},
		{options.BackgroundGamepad, "-background-gamepad", "background gamepad input", false},
		{options.ReverseScrollDirection, "-reverse-scroll-direction", "reverse scroll direction", false},
		{options.SwapGamepadButtons, "-swap-gamepad-buttons", "gamepad button swapping", false},
		{options.PerformanceOverlay, "-performance-overlay", "performance overlay", false},
		{options.HDR, "-hdr", "HDR streaming", true},
		{options.YUV444, "-yuv444", "YUV444 streaming", false},
	}
	for _, control := range qtControls {
		if !control.enabled {
			continue
		}
		if optionFlavor != FlavorQt && !(control.embeddedValid && optionFlavor == FlavorEmbedded) {
			if control.embeddedValid {
				return nil, fmt.Errorf("%s is supported only by Moonlight Qt or Embedded (got %q)", control.name, optionFlavor)
			}
			return nil, fmt.Errorf("%s is supported only by Moonlight Qt; select --client moonlight-qt or omit it (got %q)", control.name, optionFlavor)
		}
		arguments = append(arguments, control.option)
	}
	return arguments, nil
}

type resolutionSpec struct {
	name   string
	width  int
	height int
}

func parseResolutionSpec(value string) (resolutionSpec, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "720", "1080", "1440", "4k":
		return resolutionSpec{name: normalized}, nil
	}
	parts := strings.Split(normalized, "x")
	if len(parts) != 2 {
		return resolutionSpec{}, fmt.Errorf("resolution must be 720, 1080, 1440, 4k, or WIDTHxHEIGHT, got %q", value)
	}
	width, err := parseResolutionDimension(parts[0], "width", minCustomResolutionWidth, maxCustomResolutionWidth)
	if err != nil {
		return resolutionSpec{}, fmt.Errorf("resolution %q is invalid: %w", value, err)
	}
	height, err := parseResolutionDimension(parts[1], "height", minCustomResolutionHeight, maxCustomResolutionHeight)
	if err != nil {
		return resolutionSpec{}, fmt.Errorf("resolution %q is invalid: %w", value, err)
	}
	return resolutionSpec{
		name:   strconv.Itoa(width) + "x" + strconv.Itoa(height),
		width:  width,
		height: height,
	}, nil
}

func parseResolutionDimension(value, label string, minimum, maximum int) (int, error) {
	if !decimalArgument(value) {
		return 0, fmt.Errorf("%s must be a decimal value", label)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d pixels", label, minimum, maximum)
	}
	return parsed, nil
}

func validatePacketSize(value int) error {
	if value < 1024 || value > 9000 {
		return fmt.Errorf("packet size must be between 1024 and 9000 bytes, got %d", value)
	}
	if value%16 != 0 {
		return fmt.Errorf("packet size must be a multiple of 16 bytes, got %d", value)
	}
	return nil
}

func normalizedCodec(codec string) string {
	switch strings.ToLower(strings.TrimSpace(codec)) {
	case "h265":
		return "hevc"
	default:
		return strings.ToLower(strings.TrimSpace(codec))
	}
}

func qtCodecName(codec string) string {
	switch codec {
	case "h264":
		return "H.264"
	case "hevc":
		return "HEVC"
	case "av1":
		return "AV1"
	default:
		return "auto"
	}
}

type Plan struct {
	Route     config.Route `json:"route"`
	Client    Client       `json:"client"`
	Arguments []string     `json:"arguments"`
	Warnings  []string     `json:"warnings"`
	Local     bool         `json:"local,omitempty"`
	// QtPlatform is the bounded QT_QPA_PLATFORM value applied to the child
	// Moonlight process. It is empty when the inherited environment is used.
	QtPlatform string `json:"qt_platform,omitempty"`

	// validated is deliberately not serialized. Only one of the discovered-plan
	// builders can create an executable plan; JSON or a hand-built value must
	// not bypass its route, physical-host confirmation, and acknowledgement
	// checks.
	validated bool

	// clientDiscovered is deliberately not serialized. It binds execution to a
	// Client returned by Discover, so a future caller cannot substitute an
	// arbitrary executable path after passive discovery has completed.
	clientDiscovered bool

	// clientBinding is deliberately not serialized. It snapshots every
	// exported Client field that affects process selection and detects mutation
	// after BuildDiscoveredPlan returns.
	clientBinding clientBinding

	// argumentBinding is deliberately not serialized. It snapshots the exact
	// fixed argv produced by the planner so a caller cannot retarget a validated
	// handoff by mutating a host or application argument before Execute.
	argumentBinding []string

	// qtPlatformBinding is deliberately not serialized. It detects mutation of
	// the process-environment override after a plan has been built.
	qtPlatformBinding string

	// local is deliberately not serialized. It distinguishes the local
	// Embedded `map` action from a host handoff, so a decoded or hand-built plan
	// cannot opt into the less restrictive local execution path.
	local bool
}

type Environment interface {
	LookPath(file string) (string, error)
}

type RealEnvironment struct{}

const moonlightFlatpakAppID = "com.moonlight_stream.Moonlight"

// executableBinder is intentionally unexported. Only the real environment
// provides a file identity; test or embedded environments can remain passive
// path fixtures without pretending that they have verified a host executable.
type executableBinder interface {
	bindExecutable(path string) (os.FileInfo, error)
}

func (RealEnvironment) bindExecutable(path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect Moonlight executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("resolved Moonlight client is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("resolved Moonlight client is not executable")
	}
	return info, nil
}

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
	if _, err := (RealEnvironment{}).bindExecutable(absolute); err != nil {
		return "", err
	}
	return absolute, nil
}

// flatpakApplicationChecker is intentionally private: only the real
// environment has enough filesystem authority to make this launch-time check.
// A passive fixture may still exercise argument planning without pretending
// that a Flatpak installation was inspected.
type flatpakApplicationChecker interface {
	flatpakApplicationInstalled() bool
}

// flatpakApplicationInstalled verifies the separate Moonlight Flatpak app
// object before a discovered `flatpak` launcher can enter an executable plan.
// `flatpak` being on PATH is not sufficient: the launcher can exist while the
// app is absent, which would otherwise defer a predictable configuration error
// until after the handoff starts.
func (RealEnvironment) flatpakApplicationInstalled() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	roots := []string{
		filepath.FromSlash("/var/lib/flatpak"),
		filepath.FromSlash("/usr/local/share/flatpak"),
		filepath.FromSlash("/usr/share/flatpak"),
	}
	appendRoot := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || !filepath.IsAbs(value) {
			return
		}
		roots = append(roots, filepath.Clean(value))
	}
	appendRoot(os.Getenv("FLATPAK_USER_DIR"))
	for _, value := range strings.Split(os.Getenv("FLATPAK_SYSTEM_DIR"), string(os.PathListSeparator)) {
		appendRoot(value)
	}
	if dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dataHome != "" && filepath.IsAbs(dataHome) {
		roots = append(roots, filepath.Join(filepath.Clean(dataHome), "flatpak"))
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" && filepath.IsAbs(home) {
		roots = append(roots, filepath.Join(filepath.Clean(home), ".local", "share", "flatpak"))
	}
	for _, dataDir := range strings.Split(os.Getenv("XDG_DATA_DIRS"), string(os.PathListSeparator)) {
		dataDir = strings.TrimSpace(dataDir)
		if dataDir != "" && filepath.IsAbs(dataDir) {
			roots = append(roots, filepath.Join(filepath.Clean(dataDir), "flatpak"))
		}
	}
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		root = filepath.Clean(root)
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		if flatpakApplicationDirectoryExists(filepath.Join(root, "app", moonlightFlatpakAppID)) {
			return true
		}
	}
	return false
}

func flatpakApplicationDirectoryExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func flatpakClient(env Environment, lookup func(string) (string, error)) (Client, error, bool) {
	path, err := lookup("flatpak")
	if err != nil {
		return Client{}, err, false
	}
	if checker, ok := env.(flatpakApplicationChecker); ok && !checker.flatpakApplicationInstalled() {
		return Client{}, errors.New("Moonlight Flatpak app is not installed"), true
	}
	return Client{
		Flavor:     FlavorFlatpak,
		Binary:     path,
		Prefix:     []string{"run", moonlightFlatpakAppID},
		discovered: true,
	}, nil, true
}

func bindDiscoveredClient(env Environment, client Client) (Client, error) {
	// Only the real environment crosses the process-execution boundary. Test
	// environments intentionally provide path fixtures without claiming that
	// they have resolved a host executable, while RealEnvironment must never
	// bind a caller-relative path.
	if _, ok := env.(executableBinder); ok && !filepath.IsAbs(client.Binary) {
		return Client{}, errors.New("discovered Moonlight executable path must be absolute")
	}
	if binder, ok := env.(executableBinder); ok {
		info, err := binder.bindExecutable(client.Binary)
		if err != nil {
			return Client{}, fmt.Errorf("bind Moonlight executable: %w", err)
		}
		client.executableInfo = info
	}
	client.discoveryBinding = bindClient(client)
	return client, nil
}

// Discover locates a known Moonlight client without starting it. It does not
// download software or execute any discovered binary, which keeps discovery
// and --dry-run passive even when an untrusted executable shadows PATH.
func Discover(ctx context.Context, env Environment, preferred string) (Client, error) {
	return DiscoverForPlatform(ctx, env, preferred, runtime.GOOS)
}

// AutomaticClientSelections returns the explicit native-client selections in
// the same priority order used by automatic discovery. It is exposed so the
// application layer can retry a failed live-stream preflight with another
// installed Moonlight backend without duplicating platform package rules.
// The list intentionally contains only native Moonlight clients; it never
// includes a compatibility layer, virtual machine, or other host runtime.
func AutomaticClientSelections(goos string) []string {
	selections := []string{"moonlight-qt", "moonlight-embedded", "moonlight"}
	if flatpakSupportedForPlatform(goos) {
		selections = append(selections, "flatpak")
	}
	return selections
}

// CanonicalAutomaticClientSelection resolves the ambiguous generic candidate
// according to the target platform's package convention. Automatic recovery
// must use the same flavor as the initial auto resolver: generic moonlight is
// Embedded on FreeBSD and DragonFly, and Qt on the other supported targets.
// Explicit "moonlight" selections intentionally remain Embedded aliases.
func CanonicalAutomaticClientSelection(goos, selection string) string {
	selection = strings.ToLower(strings.TrimSpace(selection))
	if selection == "moonlight" && !genericMoonlightIsEmbedded(goos) {
		return "moonlight-qt"
	}
	return selection
}

// DiscoverAutomaticClientForPlatform resolves one candidate from automatic
// recovery while preserving the platform-specific meaning of a generic
// executable. It deliberately does not alter explicit "moonlight" discovery,
// which remains the backwards-compatible Embedded alias.
func DiscoverAutomaticClientForPlatform(ctx context.Context, env Environment, selection, goos string) (Client, error) {
	selection = strings.ToLower(strings.TrimSpace(selection))
	if selection == "moonlight" && CanonicalAutomaticClientSelection(goos, selection) == "moonlight-qt" {
		client, err := DiscoverForPlatform(ctx, env, selection, goos)
		if err != nil {
			return Client{}, err
		}
		client.Flavor = FlavorQt
		client.discoveryBinding = bindClient(client)
		return client, nil
	}
	return DiscoverForPlatform(ctx, env, selection, goos)
}

// DiscoverForPlatform locates a known Moonlight client for the supplied target
// operating system without starting it. The application uses this entry point
// so discovery follows its target platform identity rather than the controller
// process's runtime.GOOS value.
func DiscoverForPlatform(ctx context.Context, env Environment, preferred, goos string) (Client, error) {
	return discoverForPlatform(ctx, env, preferred, goos)
}

func discoverForPlatform(ctx context.Context, env Environment, preferred, goos string) (Client, error) {
	if env == nil {
		return Client{}, errors.New("Moonlight discovery environment is nil")
	}
	preferred = strings.ToLower(strings.TrimSpace(preferred))
	goos = strings.ToLower(strings.TrimSpace(goos))
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
			return bindDiscoveredClient(env, Client{Flavor: FlavorQt, Binary: path, discovered: true})
		} else if lookupCanceled(err) {
			return Client{}, err
		}
		if path, err := lookup("moonlight-embedded"); err == nil {
			return bindDiscoveredClient(env, Client{Flavor: FlavorEmbedded, Binary: path, discovered: true})
		} else if lookupCanceled(err) {
			return Client{}, err
		}
		if path, err := lookup("moonlight"); err == nil {
			flavor := defaultMoonlightFlavorFor(goos)
			return bindDiscoveredClient(env, Client{Flavor: flavor, Binary: path, discovered: true})
		} else if lookupCanceled(err) {
			return Client{}, err
		}
		if flatpakSupportedForPlatform(goos) {
			if client, err, found := flatpakClient(env, lookup); found {
				if err != nil {
					return Client{}, err
				}
				return bindDiscoveredClient(env, client)
			} else if lookupCanceled(err) {
				return Client{}, err
			}
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
			return bindDiscoveredClient(env, Client{Flavor: FlavorQt, Binary: path, discovered: true})
		}
	case "flatpak":
		if !flatpakSupportedForPlatform(goos) {
			return Client{}, errors.New("Moonlight Flatpak is supported only on Linux client targets")
		}
		client, err, found := flatpakClient(env, lookup)
		if lookupCanceled(err) {
			return Client{}, err
		}
		if found {
			if err != nil {
				return Client{}, err
			}
			return bindDiscoveredClient(env, client)
		}
	case "moonlight", "moonlight-embedded":
		lookupName := "moonlight"
		if preferred == "moonlight-embedded" {
			lookupName = "moonlight-embedded"
		}
		path, err := lookup(lookupName)
		if err != nil && preferred == "moonlight-embedded" && !lookupCanceled(err) && genericMoonlightIsEmbedded(goos) {
			// Package managers normally install Embedded as the generic
			// "moonlight" command on FreeBSD and DragonFly, but Linux,
			// OpenBSD, and NetBSD conventionally use that name for Qt. Accept
			// the generic fallback only where the target package convention
			// identifies it as Embedded.
			path, err = lookup("moonlight")
		}
		if lookupCanceled(err) {
			return Client{}, err
		}
		if err == nil {
			// Both explicit names select Moonlight Embedded. The alias makes the
			// package identity explicit for BSD installations while retaining the
			// original "moonlight" configuration value for backwards compatibility.
			// Users of a downstream Qt package named "moonlight" can select
			// moonlight-qt, whose fallback above deliberately accepts that name.
			return bindDiscoveredClient(env, Client{Flavor: FlavorEmbedded, Binary: path, discovered: true})
		}
	default:
		return Client{}, fmt.Errorf("unsupported Moonlight client selection %q", preferred)
	}
	if err := ctx.Err(); err != nil {
		return Client{}, fmt.Errorf("Moonlight discovery canceled: %w", err)
	}
	return Client{}, errors.New("Moonlight was not found; install Moonlight Qt or Moonlight Embedded from your operating system's trusted package source and expose moonlight-qt, moonlight-embedded, or moonlight on PATH")
}

func flatpakSupportedForPlatform(goos string) bool {
	return strings.EqualFold(strings.TrimSpace(goos), "linux")
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
	goos = strings.ToLower(strings.TrimSpace(goos))
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
	endpoint, err := config.ParseHostEndpoint(req.Host)
	if err != nil {
		return Plan{}, fmt.Errorf("host: %w", err)
	}
	if req.Operation != Pair && req.Operation != Unpair && req.Operation != List && req.Operation != Stream && req.Operation != Quit {
		return Plan{}, fmt.Errorf("unsupported remote operation %q", req.Operation)
	}
	qtPlatform := ""
	if req.QtPlatform != "" {
		if req.Operation != Stream {
			return Plan{}, errors.New("Qt platform selection is only valid for the stream operation")
		}
		if client.Flavor != FlavorQt && client.Flavor != FlavorFlatpak {
			return Plan{}, fmt.Errorf("Qt platform selection is supported only by Moonlight Qt; select --client moonlight-qt or flatpak (got %q)", client.Flavor)
		}
		if err := ValidateQtPlatform(req.QtPlatform); err != nil {
			return Plan{}, err
		}
		qtPlatform = normalizeQtPlatform(req.QtPlatform)
	}
	if req.PairingPIN != "" {
		if req.Operation != Pair {
			return Plan{}, errors.New("pairing PIN is only valid for the pair operation")
		}
		if client.Flavor != FlavorEmbedded && client.Flavor != FlavorQt && client.Flavor != FlavorFlatpak {
			return Plan{}, fmt.Errorf("pairing PIN is unsupported by Moonlight client flavor %q", client.Flavor)
		}
		if err := validatePairingPIN(req.PairingPIN); err != nil {
			return Plan{}, err
		}
	}
	if req.Operation != Stream && !req.Stream.empty() {
		return Plan{}, errors.New("stream options are only valid for the stream operation")
	}
	if client.Binary == "" {
		return Plan{}, errors.New("Moonlight executable path is empty")
	}
	if err := validateClientPrefix(client); err != nil {
		return Plan{}, err
	}
	if req.Operation == Unpair && client.Flavor != FlavorEmbedded {
		return Plan{}, fmt.Errorf("unpair is supported only by Moonlight Embedded; select --client moonlight-embedded (got %q)", client.Flavor)
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
	if client.Flavor == FlavorFlatpak && qtPlatform != "" && qtPlatform != "auto" {
		// Flatpak's --env form is the authoritative in-sandbox override. The
		// process environment is also set by ExecRunner for normal Qt clients,
		// but an application manifest can override inherited values; placing the
		// bounded value before the app ID guarantees that an explicit selector
		// reaches Moonlight inside the sandbox.
		args = []string{client.Prefix[0], "--env=QT_QPA_PLATFORM=" + qtPlatform, client.Prefix[1]}
	}
	switch client.Flavor {
	case FlavorEmbedded:
		switch req.Operation {
		case Stream:
			streamOptions, err := req.Stream.arguments(client.Flavor)
			if err != nil {
				return Plan{}, fmt.Errorf("stream options: %w", err)
			}
			args = append(args, "stream")
			args = append(args, streamOptions...)
			args = append(args, "-app", req.App)
			args = appendEmbeddedEndpoint(args, endpoint)
		default:
			args = append(args, string(req.Operation))
			if req.Operation == Pair && req.PairingPIN != "" {
				// Moonlight Embedded's current parser accepts the same
				// predefined four-digit PIN form as Qt. Keep it after the
				// action and before the host, matching its documented
				// action/options/host grammar.
				args = append(args, "-pin", req.PairingPIN)
			}
			args = appendEmbeddedEndpoint(args, endpoint)
		}
	case FlavorQt, FlavorFlatpak:
		args = append(args, string(req.Operation))
		if req.Operation == Pair && req.PairingPIN != "" {
			// Moonlight Qt's CLI consumes the predefined PIN before the host
			// positional argument. Flatpak uses the same Qt grammar after its
			// fixed launcher prefix.
			args = append(args, "-pin", req.PairingPIN)
		}
		if req.Operation == Stream {
			streamOptions, err := req.Stream.arguments(client.Flavor)
			if err != nil {
				return Plan{}, fmt.Errorf("stream options: %w", err)
			}
			args = append(args, streamOptions...)
			args = append(args, req.Host, req.App)
		} else {
			args = append(args, req.Host)
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
	if req.Operation == Stream && route == config.RouteWindows {
		warnings = append(warnings, "For League mouse input, verify that the physical Windows host is using Sunshine's licensed Virtual HID Raw Input path with relative mouse mode; if the host is headless, keep a physical mouse attached while testing because Raw Input games can fail without one. A SendInput fallback may be rejected after League starts, so use the host's physical input or a hardware KVM instead. LeagueBridge never installs or alters that driver.")
	}
	if qtPlatform != "" && qtPlatform != "auto" {
		warnings = append(warnings, "QT_QPA_PLATFORM="+qtPlatform+" will be applied only to this Moonlight process; the parent shell environment is unchanged.")
	}
	return Plan{
		Route:             route,
		Client:            client,
		Arguments:         args,
		Warnings:          warnings,
		QtPlatform:        qtPlatform,
		validated:         true,
		clientDiscovered:  client.discovered,
		clientBinding:     bindClient(client),
		argumentBinding:   append([]string(nil), args...),
		qtPlatformBinding: qtPlatform,
	}, nil
}

func appendEmbeddedEndpoint(arguments []string, endpoint config.HostEndpoint) []string {
	arguments = append(arguments, endpoint.Address)
	if endpoint.Port != 0 {
		arguments = append(arguments, "-port", strconv.Itoa(endpoint.Port))
	}
	return arguments
}

// BuildDiscoveredPlan is the production handoff entry point. BuildPlan stays
// available as a pure planner for contract tests and dry-run composition, but
// this wrapper refuses a client that did not come from Discover before any
// executable plan is constructed. A passive fixture environment may still
// produce a discovered plan for dry-run composition; Execute additionally
// requires the executable identity bound by RealEnvironment.
func BuildDiscoveredPlan(client Client, req Request) (Plan, error) {
	if !client.discovered {
		return Plan{}, errors.New("Moonlight client was not discovered through the passive resolver")
	}
	if !client.discoveryBinding.matches(client) {
		return Plan{}, errors.New("Moonlight client changed after discovery")
	}
	return BuildPlan(client, req)
}

// BuildInputMappingPlan builds Moonlight Embedded's local controller-mapping
// action. It never accepts a host, route, acknowledgement, or stream option:
// upstream `map` reads one local evdev device and prints the SDL mapping.
// BuildInputMappingPlan remains a pure planner; Execute still requires a
// client discovered and bound by the real environment.
func BuildInputMappingPlan(client Client, inputDevice string) (Plan, error) {
	if client.Binary == "" {
		return Plan{}, errors.New("Moonlight executable path is empty")
	}
	if client.Flavor != FlavorEmbedded {
		return Plan{}, fmt.Errorf("controller mapping is supported only by Moonlight Embedded; select --client moonlight-embedded (got %q)", client.Flavor)
	}
	if err := validateClientPrefix(client); err != nil {
		return Plan{}, err
	}
	if err := validateEmbeddedInputDevice(inputDevice); err != nil {
		return Plan{}, err
	}
	args := append([]string(nil), client.Prefix...)
	args = append(args, string(Map), "-input", inputDevice)
	return Plan{
		Client:    client,
		Arguments: args,
		Warnings: []string{
			"Moonlight Embedded map is a local controller-mapping action; it does not pair with or stream from a host.",
			"Save the printed SDL mapping to a user-owned file and pass it with --input-mapping on a later remote stream.",
		},
		Local:            true,
		validated:        true,
		clientDiscovered: client.discovered,
		clientBinding:    bindClient(client),
		argumentBinding:  append([]string(nil), args...),
		local:            true,
	}, nil
}

// BuildDiscoveredInputMappingPlan is the production entry point for the local
// mapping action. It preserves the same passive-discovery provenance and
// executable binding requirements as a remote handoff.
func BuildDiscoveredInputMappingPlan(client Client, inputDevice string) (Plan, error) {
	if !client.discovered {
		return Plan{}, errors.New("Moonlight client was not discovered through the passive resolver")
	}
	if !client.discoveryBinding.matches(client) {
		return Plan{}, errors.New("Moonlight client changed after discovery")
	}
	return BuildInputMappingPlan(client, inputDevice)
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

// splitFlatpakPrefix validates the fixed Flatpak launcher prefix and removes
// the optional, LeagueBridge-generated Qt platform override before the
// Moonlight operation is parsed. Only QT_QPA_PLATFORM is accepted here; an
// arbitrary --env argument would turn a constrained handoff plan into a
// general-purpose sandbox launcher.
func splitFlatpakPrefix(args []string) (rest []string, qtPlatform string, err error) {
	if len(args) < 2 || args[0] != "run" {
		return nil, "", errors.New("Moonlight Flatpak argument vector must begin with the fixed run com.moonlight_stream.Moonlight prefix")
	}
	position := 1
	if strings.HasPrefix(args[position], "--env=") {
		const environmentPrefix = "--env=QT_QPA_PLATFORM="
		if !strings.HasPrefix(args[position], environmentPrefix) {
			return nil, "", errors.New("Moonlight Flatpak argument vector permits only the fixed QT_QPA_PLATFORM environment override")
		}
		qtPlatform = normalizeQtPlatform(strings.TrimPrefix(args[position], environmentPrefix))
		if qtPlatform == "auto" {
			return nil, "", errors.New("Moonlight Flatpak QT_QPA_PLATFORM override must be a concrete backend")
		}
		if err := ValidateQtPlatform(qtPlatform); err != nil {
			return nil, "", fmt.Errorf("Moonlight Flatpak QT_QPA_PLATFORM override: %w", err)
		}
		position++
	}
	if len(args) <= position || args[position] != moonlightFlatpakAppID {
		return nil, "", errors.New("Moonlight Flatpak argument vector must begin with the fixed run com.moonlight_stream.Moonlight prefix")
	}
	return args[position+1:], qtPlatform, nil
}

func validatePlanHostArguments(flavor Flavor, args []string) error {
	if flavor == FlavorEmbedded {
		if len(args) != 1 && len(args) != 3 {
			return errors.New("Embedded host arguments require ADDRESS or ADDRESS -port PORT")
		}
		endpoint, err := config.ParseHostEndpoint(args[0])
		if err != nil {
			return fmt.Errorf("host: %w", err)
		}
		// BuildPlan strips Qt's endpoint notation and inline ports before
		// invoking Embedded. Keep the execution boundary equally strict so a
		// caller cannot inject a client-incompatible bracketed or inline-port host.
		if endpoint.Address != args[0] || endpoint.Port != 0 {
			return errors.New("Embedded host must use a bare address with an optional separate -port argument")
		}
		if len(args) == 3 {
			if args[1] != "-port" {
				return errors.New("Embedded host port must use the fixed -port option")
			}
			if err := validateMoonlightPort(args[2]); err != nil {
				return err
			}
		}
		return nil
	}
	if len(args) != 1 {
		return errors.New("Moonlight host arguments require exactly one host endpoint")
	}
	if err := config.ValidateHost(args[0]); err != nil {
		return fmt.Errorf("host: %w", err)
	}
	return nil
}

// ValidatePairingPIN validates the short-lived PIN accepted by Moonlight Qt
// and Moonlight Embedded's `pair -pin` option. The PIN is intentionally kept
// out of configuration and dry-run JSON; callers should provide it only for a
// live pairing invocation.
func ValidatePairingPIN(value string) error {
	if len(value) != 4 || !decimalArgument(value) {
		return errors.New("pairing PIN must be exactly four ASCII digits")
	}
	return nil
}

// ValidateQtPlatform validates the allowlisted Qt QPA platform names that
// LeagueBridge may apply to a live Moonlight Qt or Qt-based Flatpak stream.
// Arbitrary environment values are intentionally rejected at the CLI and
// execution boundaries.
func ValidateQtPlatform(value string) error {
	switch normalizeQtPlatform(value) {
	case "auto", "xcb", "wayland", "eglfs", "linuxfb":
		return nil
	default:
		return errors.New("Qt platform must be auto, xcb, wayland, eglfs, or linuxfb")
	}
}

func normalizeQtPlatform(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validatePairingPIN(value string) error {
	return ValidatePairingPIN(value)
}

func validatePairArguments(flavor Flavor, args []string) error {
	if flavor != FlavorEmbedded && flavor != FlavorQt {
		return validatePlanHostArguments(flavor, args)
	}
	if len(args) == 1 {
		return validatePlanHostArguments(flavor, args)
	}
	if len(args) != 3 || args[0] != "-pin" {
		return fmt.Errorf("Moonlight %s pair arguments require HOST or -pin PIN HOST", flavor)
	}
	if err := validatePairingPIN(args[1]); err != nil {
		return err
	}
	return validatePlanHostArguments(flavor, args[2:])
}

func validateMoonlightPort(value string) error {
	if value == "" || len(value) > 5 || !decimalArgument(value) {
		return errors.New("host port must be a decimal port from 1 to 65535")
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != value {
		return errors.New("host port must be a decimal port from 1 to 65535")
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
		var err error
		if rest, _, err = splitFlatpakPrefix(args); err != nil {
			return err
		}
	}
	if len(rest) == 0 {
		return errors.New("Moonlight argument vector has no operation")
	}

	switch rest[0] {
	case string(Map):
		if client.Flavor != FlavorEmbedded {
			return errors.New("map is supported only by Moonlight Embedded")
		}
		if len(rest) != 3 || rest[1] != "-input" {
			return errors.New("map operation requires exactly one -input EVDEV argument")
		}
		if err := validateEmbeddedInputDevice(rest[2]); err != nil {
			return fmt.Errorf("input device: %w", err)
		}
	case string(Pair):
		if err := validatePairArguments(streamOptionFlavor(client.Flavor), rest[1:]); err != nil {
			return fmt.Errorf("%s operation: %w", rest[0], err)
		}
	case string(List), string(Quit):
		if err := validatePlanHostArguments(streamOptionFlavor(client.Flavor), rest[1:]); err != nil {
			return fmt.Errorf("%s operation: %w", rest[0], err)
		}
	case string(Unpair):
		if client.Flavor != FlavorEmbedded {
			return errors.New("unpair is supported only by Moonlight Embedded")
		}
		if err := validatePlanHostArguments(FlavorEmbedded, rest[1:]); err != nil {
			return fmt.Errorf("%s operation: %w", rest[0], err)
		}
	case string(Stream):
		streamArgs, err := splitStreamOptions(client.Flavor, rest[1:])
		if err != nil {
			return err
		}
		if client.Flavor == FlavorEmbedded {
			if (len(streamArgs) != 3 && len(streamArgs) != 5) || streamArgs[0] != "-app" {
				return errors.New("stream operation for Moonlight Embedded requires the fixed stream -app APP HOST [-port PORT] argument shape")
			}
			if err := config.ValidateAppName(streamArgs[1]); err != nil {
				return fmt.Errorf("app: %w", err)
			}
			if err := validatePlanHostArguments(FlavorEmbedded, streamArgs[2:]); err != nil {
				return err
			}
			return nil
		}
		if len(streamArgs) != 2 {
			return errors.New("stream operation for Moonlight Qt requires the fixed stream HOST APP argument shape")
		}
		if err := validatePlanHostArguments(streamOptionFlavor(client.Flavor), streamArgs[:1]); err != nil {
			return err
		}
		if err := config.ValidateAppName(streamArgs[1]); err != nil {
			return fmt.Errorf("app: %w", err)
		}
	default:
		return fmt.Errorf("unsupported Moonlight operation %q", rest[0])
	}
	return nil
}

// splitStreamOptions parses only the fixed quality and input-mode options that
// LeagueBridge itself can generate. They must precede the host/app positional
// arguments; arbitrary Moonlight flags are intentionally rejected at the
// execution boundary.
func splitStreamOptions(flavor Flavor, args []string) ([]string, error) {
	flavor = streamOptionFlavor(flavor)
	position := 0
	seenResolution := false
	seenFPS := false
	seenBitrate := false
	seenPacketSize := false
	seenCodec := false
	streamCodec := ""
	seenAudioConfig := false
	seenAudioOnHost := false
	seenAudioDevice := false
	seenHostSettings := false
	seenDisableGamepadMouseEmulation := false
	inputDeviceCount := 0
	seenInputMapping := false
	seenNetworkMode := false
	seenFramePacing := false
	seenVSync := false
	seenKeepAwake := false
	seenQuitAfter := false
	seenCaptureSystemKeys := false
	seenPlatform := false
	streamPlatform := ""
	seenDecoder := false
	seenDisplayMode := false
	seenMouseMode := false
	seenQtControls := make(map[string]bool)
	seenEmbeddedWidth := false
	seenEmbeddedHeight := false
	for position < len(args) && strings.HasPrefix(args[position], "-") {
		option := args[position]
		if flavor == FlavorEmbedded && option == "-app" {
			break
		}
		switch option {
		case "-720", "-1080", "-1440":
			if flavor == FlavorEmbedded && option == "-1440" {
				return nil, errors.New("stream argument vector uses the Qt-only -1440 option for Moonlight Embedded")
			}
			if seenResolution {
				return nil, errors.New("stream argument vector repeats the resolution option")
			}
			seenResolution = true
			position++
		case "-width", "-height":
			if flavor != FlavorEmbedded {
				return nil, fmt.Errorf("stream argument vector contains the Embedded-only option %q", option)
			}
			if position+1 >= len(args) || !decimalArgument(args[position+1]) {
				return nil, fmt.Errorf("stream argument %s requires a decimal value", option)
			}
			switch option {
			case "-width":
				if seenResolution || seenEmbeddedWidth {
					return nil, errors.New("stream argument vector repeats the Embedded custom resolution")
				}
				if _, err := parseResolutionDimension(args[position+1], "width", minCustomResolutionWidth, maxCustomResolutionWidth); err != nil {
					return nil, fmt.Errorf("stream argument vector: %w", err)
				}
				seenResolution = true
				seenEmbeddedWidth = true
			case "-height":
				if !seenEmbeddedWidth || seenEmbeddedHeight {
					return nil, errors.New("stream argument vector contains an invalid Embedded custom resolution height")
				}
				if _, err := parseResolutionDimension(args[position+1], "height", minCustomResolutionHeight, maxCustomResolutionHeight); err != nil {
					return nil, fmt.Errorf("stream argument vector: %w", err)
				}
				seenEmbeddedHeight = true
			}
			position += 2
		case "-resolution":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only -resolution option for Moonlight Embedded")
			}
			if seenResolution {
				return nil, errors.New("stream argument vector repeats the resolution option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -resolution requires a WIDTHxHEIGHT value")
			}
			resolution, err := parseResolutionSpec(args[position+1])
			if err != nil || resolution.name == "720" || resolution.name == "1080" || resolution.name == "1440" || resolution.name == "4k" {
				return nil, fmt.Errorf("stream argument vector contains an invalid Qt custom resolution %q", args[position+1])
			}
			seenResolution = true
			position += 2
		case "-4K", "-4k":
			if flavor == FlavorQt && option != "-4K" || flavor != FlavorQt && option != "-4k" {
				return nil, errors.New("stream argument vector uses the wrong 4K option for the selected Moonlight client")
			}
			if seenResolution {
				return nil, errors.New("stream argument vector repeats the resolution option")
			}
			seenResolution = true
			position++
		case "-fps", "-bitrate":
			isFPS := option == "-fps"
			if isFPS && seenFPS || !isFPS && seenBitrate {
				return nil, errors.New("stream argument vector repeats a numeric quality option")
			}
			if position+1 >= len(args) || !decimalArgument(args[position+1]) {
				return nil, fmt.Errorf("stream argument %s requires a decimal value", option)
			}
			value, _ := strconv.Atoi(args[position+1])
			if isFPS {
				if value < 10 || value > 480 {
					return nil, fmt.Errorf("stream argument fps must be between 10 and 480, got %d", value)
				}
				seenFPS = true
			} else {
				if value < 500 || value > 500000 {
					return nil, fmt.Errorf("stream argument bitrate must be between 500 and 500000 Kbps, got %d", value)
				}
				seenBitrate = true
			}
			position += 2
		case "-packet-size", "-packetsize":
			if flavor == FlavorEmbedded && option != "-packetsize" {
				return nil, errors.New("stream argument vector uses the Qt-only -packet-size option for Moonlight Embedded")
			}
			if flavor == FlavorQt && option != "-packet-size" {
				return nil, errors.New("stream argument vector uses the Embedded-only -packetsize option for Moonlight Qt")
			}
			if seenPacketSize {
				return nil, errors.New("stream argument vector repeats the packet-size option")
			}
			if position+1 >= len(args) || !decimalArgument(args[position+1]) {
				return nil, fmt.Errorf("stream argument %s requires a decimal value", option)
			}
			value, _ := strconv.Atoi(args[position+1])
			if err := validatePacketSize(value); err != nil {
				return nil, fmt.Errorf("stream argument vector: %w", err)
			}
			seenPacketSize = true
			position += 2
		case "-codec", "-video-codec":
			if flavor == FlavorEmbedded && option != "-codec" {
				return nil, errors.New("stream argument vector uses the Qt-only -video-codec option for Moonlight Embedded")
			}
			if flavor == FlavorQt && option != "-video-codec" {
				return nil, errors.New("stream argument vector uses the Embedded-only -codec option for Moonlight Qt")
			}
			if seenCodec {
				return nil, errors.New("stream argument vector repeats the codec option")
			}
			if position+1 >= len(args) {
				return nil, fmt.Errorf("stream argument %s requires a codec value", option)
			}
			codec := strings.ToLower(strings.TrimSpace(args[position+1]))
			if codec == "h265" {
				codec = "hevc"
			}
			switch {
			case flavor == FlavorEmbedded && (codec == "auto" || codec == "h264" || codec == "hevc" || codec == "av1"):
			case flavor == FlavorQt && (codec == "auto" || codec == "hevc" || codec == "av1" || codec == "h264"):
			default:
				return nil, fmt.Errorf("stream argument %s contains unsupported codec %q", option, args[position+1])
			}
			streamCodec = codec
			seenCodec = true
			position += 2
		case "-audio-config", "-surround":
			if flavor == FlavorEmbedded && option != "-surround" {
				return nil, errors.New("stream argument vector uses the Qt-only -audio-config option for Moonlight Embedded")
			}
			if flavor == FlavorQt && option != "-audio-config" {
				return nil, errors.New("stream argument vector uses the Embedded-only -surround option for Moonlight Qt")
			}
			if seenAudioConfig {
				return nil, errors.New("stream argument vector repeats the audio configuration option")
			}
			if position+1 >= len(args) {
				return nil, fmt.Errorf("stream argument %s requires an audio configuration value", option)
			}
			audioConfig := strings.ToLower(strings.TrimSpace(args[position+1]))
			if flavor == FlavorEmbedded {
				if audioConfig != "5.1" && audioConfig != "7.1" {
					return nil, fmt.Errorf("stream argument -surround contains unsupported audio configuration %q", args[position+1])
				}
			} else {
				switch audioConfig {
				case "stereo", "5.1-surround", "7.1-surround":
				default:
					return nil, fmt.Errorf("stream argument -audio-config contains unsupported audio configuration %q", args[position+1])
				}
			}
			seenAudioConfig = true
			position += 2
		case "-audio-on-host", "-localaudio":
			if flavor == FlavorEmbedded && option != "-localaudio" {
				return nil, errors.New("stream argument vector uses the Qt-only -audio-on-host option for Moonlight Embedded")
			}
			if flavor == FlavorQt && option != "-audio-on-host" {
				return nil, errors.New("stream argument vector uses the Embedded-only -localaudio option for Moonlight Qt")
			}
			if seenAudioOnHost {
				return nil, errors.New("stream argument vector repeats the host-audio option")
			}
			seenAudioOnHost = true
			position++
		case "-audio":
			if flavor != FlavorEmbedded {
				return nil, errors.New("stream argument vector uses the Embedded-only -audio option for Moonlight Qt")
			}
			if seenAudioDevice {
				return nil, errors.New("stream argument vector repeats the audio-device option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -audio requires a device value")
			}
			if err := validateDeviceSelector(args[position+1], "audio device"); err != nil {
				return nil, fmt.Errorf("stream argument vector: %w", err)
			}
			seenAudioDevice = true
			position += 2
		case "-nosops", "-no-game-optimization":
			if flavor == FlavorEmbedded && option != "-nosops" {
				return nil, errors.New("stream argument vector uses the Qt-only -no-game-optimization option for Moonlight Embedded")
			}
			if flavor == FlavorQt && option != "-no-game-optimization" {
				return nil, errors.New("stream argument vector uses the Embedded-only -nosops option for Moonlight Qt")
			}
			if seenHostSettings {
				return nil, errors.New("stream argument vector repeats the host-settings option")
			}
			seenHostSettings = true
			position++
		case "-nomouseemulation":
			if flavor != FlavorEmbedded {
				return nil, errors.New("stream argument vector uses the Embedded-only -nomouseemulation option for Moonlight Qt")
			}
			if seenDisableGamepadMouseEmulation {
				return nil, errors.New("stream argument vector repeats the gamepad mouse-emulation option")
			}
			seenDisableGamepadMouseEmulation = true
			position++
		case "-input":
			if flavor != FlavorEmbedded {
				return nil, errors.New("stream argument vector uses the Embedded-only -input option for Moonlight Qt")
			}
			if inputDeviceCount >= maxEmbeddedInputDevices {
				return nil, fmt.Errorf("stream argument vector contains more than %d input devices", maxEmbeddedInputDevices)
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -input requires a device path")
			}
			if err := validateEmbeddedInputDevice(args[position+1]); err != nil {
				return nil, fmt.Errorf("stream argument vector: %w", err)
			}
			inputDeviceCount++
			position += 2
		case "-mapping":
			if flavor != FlavorEmbedded {
				return nil, errors.New("stream argument vector uses the Embedded-only -mapping option for Moonlight Qt")
			}
			if seenInputMapping {
				return nil, errors.New("stream argument vector repeats the input-mapping option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -mapping requires a file path")
			}
			if err := validateInputMappingPath(args[position+1]); err != nil {
				return nil, fmt.Errorf("stream argument vector: %w", err)
			}
			seenInputMapping = true
			position += 2
		case "-remote":
			if flavor != FlavorEmbedded {
				return nil, errors.New("stream argument vector uses the Embedded-only -remote option for Moonlight Qt")
			}
			if seenNetworkMode {
				return nil, errors.New("stream argument vector repeats the network-mode option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -remote requires a value")
			}
			switch strings.ToLower(strings.TrimSpace(args[position+1])) {
			case "auto", "yes", "no":
			default:
				return nil, fmt.Errorf("stream argument -remote contains unsupported network mode %q", args[position+1])
			}
			seenNetworkMode = true
			position += 2
		case "-frame-pacing", "-no-frame-pacing":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only frame-pacing option for Moonlight Embedded")
			}
			if seenFramePacing {
				return nil, errors.New("stream argument vector repeats the frame-pacing option")
			}
			seenFramePacing = true
			position++
		case "-vsync", "-no-vsync":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only VSync option for Moonlight Embedded")
			}
			if seenVSync {
				return nil, errors.New("stream argument vector repeats the VSync option")
			}
			seenVSync = true
			position++
		case "-keep-awake":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only -keep-awake option for Moonlight Embedded")
			}
			if seenKeepAwake {
				return nil, errors.New("stream argument vector repeats the keep-awake option")
			}
			seenKeepAwake = true
			position++
		case "-quit-after", "-quitappafter":
			if flavor == FlavorEmbedded && option != "-quitappafter" {
				return nil, errors.New("stream argument vector uses the Qt-only -quit-after option for Moonlight Embedded")
			}
			if flavor == FlavorQt && option != "-quit-after" {
				return nil, errors.New("stream argument vector uses the Embedded-only -quitappafter option for Moonlight Qt")
			}
			if seenQuitAfter {
				return nil, errors.New("stream argument vector repeats the quit-after option")
			}
			seenQuitAfter = true
			position++
		case "-capture-system-keys":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only -capture-system-keys option for Moonlight Embedded")
			}
			if seenCaptureSystemKeys {
				return nil, errors.New("stream argument vector repeats the system-key capture option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -capture-system-keys requires a value")
			}
			switch strings.ToLower(strings.TrimSpace(args[position+1])) {
			case "never", "fullscreen", "always":
			default:
				return nil, fmt.Errorf("stream argument -capture-system-keys contains unsupported mode %q", args[position+1])
			}
			seenCaptureSystemKeys = true
			position += 2
		case "-platform":
			if flavor != FlavorEmbedded {
				return nil, errors.New("stream argument vector uses the Embedded-only -platform option for Moonlight Qt")
			}
			if seenPlatform {
				return nil, errors.New("stream argument vector repeats the platform option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -platform requires a value")
			}
			streamPlatform = strings.ToLower(strings.TrimSpace(args[position+1]))
			switch streamPlatform {
			case "auto", "x11", "x11_vdpau", "x11_vaapi", "sdl":
			default:
				return nil, fmt.Errorf("stream argument -platform contains unsupported platform %q", args[position+1])
			}
			seenPlatform = true
			position += 2
		case "-video-decoder":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only -video-decoder option for Moonlight Embedded")
			}
			if seenDecoder {
				return nil, errors.New("stream argument vector repeats the decoder option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -video-decoder requires a decoder value")
			}
			decoder := strings.ToLower(strings.TrimSpace(args[position+1]))
			switch decoder {
			case "auto", "software", "hardware":
			default:
				return nil, fmt.Errorf("stream argument -video-decoder contains unsupported decoder %q", args[position+1])
			}
			seenDecoder = true
			position += 2
		case "-display-mode":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only -display-mode option for Moonlight Embedded")
			}
			if seenDisplayMode {
				return nil, errors.New("stream argument vector repeats the display-mode option")
			}
			if position+1 >= len(args) {
				return nil, errors.New("stream argument -display-mode requires a value")
			}
			switch strings.ToLower(args[position+1]) {
			case "fullscreen", "windowed", "borderless":
			default:
				return nil, fmt.Errorf("stream argument display mode must be fullscreen, windowed, or borderless, got %q", args[position+1])
			}
			seenDisplayMode = true
			position += 2
		case "-windowed":
			if flavor != FlavorEmbedded {
				return nil, errors.New("stream argument vector uses the Embedded-only -windowed option for Moonlight Qt")
			}
			if seenDisplayMode {
				return nil, errors.New("stream argument vector repeats the display mode option")
			}
			seenDisplayMode = true
			position++
		case "-absolute-mouse", "-no-absolute-mouse":
			if flavor != FlavorQt {
				return nil, errors.New("stream argument vector uses the Qt-only mouse mode option for Moonlight Embedded")
			}
			if seenMouseMode {
				return nil, errors.New("stream argument vector repeats the mouse mode option")
			}
			seenMouseMode = true
			position++
		case "-hdr":
			if flavor != FlavorEmbedded && flavor != FlavorQt {
				return nil, fmt.Errorf("stream argument vector uses the Qt or Embedded-only %s option for the selected client", option)
			}
			if seenQtControls[option] {
				return nil, fmt.Errorf("stream argument vector repeats the stream control option %s", option)
			}
			seenQtControls[option] = true
			position++
		case "-multi-controller", "-mouse-buttons-swap", "-touchscreen-trackpad", "-mute-on-focus-loss", "-background-gamepad", "-reverse-scroll-direction", "-swap-gamepad-buttons", "-performance-overlay", "-yuv444":
			if flavor != FlavorQt {
				return nil, fmt.Errorf("stream argument vector uses the Qt-only %s option for Moonlight Embedded", option)
			}
			if seenQtControls[option] {
				return nil, fmt.Errorf("stream argument vector repeats the Qt control option %s", option)
			}
			seenQtControls[option] = true
			position++
		default:
			return nil, fmt.Errorf("stream argument vector contains unsupported option %q", option)
		}
	}
	if seenEmbeddedWidth && !seenEmbeddedHeight {
		return nil, errors.New("stream argument vector must pair the Embedded custom resolution width with its height")
	}
	if streamPlatform == "sdl" {
		if seenAudioDevice {
			return nil, errors.New("stream argument vector cannot combine -platform sdl with -audio; select an X11 backend or omit the audio device")
		}
		if inputDeviceCount > 0 {
			return nil, errors.New("stream argument vector cannot combine -platform sdl with -input; SDL discovers controllers automatically")
		}
	}
	if seenQtControls["-hdr"] && streamCodec == "h264" {
		return nil, errors.New("stream argument vector cannot combine -hdr with H.264; choose HEVC or AV1")
	}
	return args[position:], nil
}

func streamOptionFlavor(flavor Flavor) Flavor {
	if flavor == FlavorFlatpak {
		// The Flatpak application is Moonlight Qt; only its process prefix is
		// different from a directly installed Qt client.
		return FlavorQt
	}
	return flavor
}

const (
	maxDeviceSelectorLength = 128
	// Moonlight Embedded's current upstream config.h defines MAX_INPUTS as 6.
	// Keep the controller's bound at or below that parser limit so a valid
	// LeagueBridge request cannot be rejected only after Moonlight starts.
	maxEmbeddedInputDevices   = 6
	maxInputMappingPathLength = 4096
)

// validateDeviceSelector accepts the short device names understood by
// Moonlight Embedded/ALSA while rejecting control characters and option-like
// values. The value is still passed as one argv element; this validation keeps
// the public request contract deterministic and avoids turning a device name
// into a second option at any downstream parsing boundary.
func validateDeviceSelector(value, label string) error {
	return validateBoundedSelector(value, label, maxDeviceSelectorLength)
}

func validateBoundedSelector(value, label string, maximum int) error {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if normalized != value {
		return fmt.Errorf("%s must not have leading or trailing whitespace", label)
	}
	if len(normalized) > maximum {
		return fmt.Errorf("%s must not exceed %d characters", label, maximum)
	}
	if strings.HasPrefix(normalized, "-") {
		return fmt.Errorf("%s must not start with '-'", label)
	}
	for _, character := range normalized {
		if character == '\x00' || character < 0x20 || character == 0x7f {
			return fmt.Errorf("%s must not contain control characters", label)
		}
	}
	return nil
}

// Moonlight Embedded documents -input as an evdev path. Keep this selector
// limited to the documented /dev/input/eventN family instead of allowing an
// arbitrary filesystem path into a remote process invocation.
func validateEmbeddedInputDevice(value string) error {
	if err := validateDeviceSelector(value, "input device"); err != nil {
		return err
	}
	const prefix = "/dev/input/event"
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("input device must be an evdev path under /dev/input/eventN, got %q", value)
	}
	if !decimalArgument(strings.TrimPrefix(value, prefix)) {
		return fmt.Errorf("input device must be an evdev path under /dev/input/eventN, got %q", value)
	}
	return nil
}

// Moonlight Embedded documents -mapping as an SDL gamecontroller database
// path. It is a local data file, not an executable or a config overlay for
// LeagueBridge, so only its absolute POSIX path shape is accepted here; the
// selected Moonlight build remains responsible for opening and parsing it.
func validateInputMappingPath(value string) error {
	if err := validateBoundedSelector(value, "input mapping", maxInputMappingPathLength); err != nil {
		return err
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("input mapping must be an absolute Linux/BSD path, got %q", value)
	}
	return nil
}

func decimalArgument(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func argumentsMatch(binding, arguments []string) bool {
	if len(binding) != len(arguments) {
		return false
	}
	for i, argument := range binding {
		if argument != arguments[i] {
			return false
		}
	}
	return true
}

type Runner interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error
}

// QtPlatformRunner is an optional Runner extension used only when a validated
// plan carries a bounded QT_QPA_PLATFORM override. Keeping it optional
// preserves the simple Runner contract for callers that do not need an
// environment override; Execute fails closed if a custom runner cannot honor
// the requested platform.
type QtPlatformRunner interface {
	RunWithQtPlatform(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, qtPlatform, name string, args ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	return runExecutable(ctx, stdin, stdout, stderr, name, nil, args...)
}

func (ExecRunner) RunWithQtPlatform(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, qtPlatform, name string, args ...string) error {
	if err := ValidateQtPlatform(qtPlatform); err != nil {
		return err
	}
	qtPlatform = normalizeQtPlatform(qtPlatform)
	if qtPlatform == "auto" {
		return runExecutable(ctx, stdin, stdout, stderr, name, nil, args...)
	}
	return runExecutable(ctx, stdin, stdout, stderr, name, []string{"QT_QPA_PLATFORM=" + qtPlatform}, args...)
}

func runExecutable(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, overrides []string, args ...string) error {
	if name == "" {
		return errors.New("refusing to execute an empty Moonlight executable path")
	}
	if !filepath.IsAbs(name) {
		return errors.New("refusing to execute a non-absolute Moonlight executable path")
	}
	info, err := os.Stat(name)
	if err != nil {
		return fmt.Errorf("refusing to execute an unavailable Moonlight executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to execute a non-regular Moonlight executable")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return errors.New("refusing to execute a non-executable Moonlight file")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if len(overrides) > 0 {
		cmd.Env = environmentWithOverrides(os.Environ(), overrides)
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func environmentWithOverrides(base, overrides []string) []string {
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		keep := true
		for _, override := range overrides {
			key, _, ok := strings.Cut(override, "=")
			if ok && strings.HasPrefix(entry, key+"=") {
				keep = false
				break
			}
		}
		if keep {
			result = append(result, entry)
		}
	}
	return append(result, overrides...)
}

func Execute(ctx context.Context, runner Runner, stdin io.Reader, stdout, stderr io.Writer, plan Plan) error {
	if plan.Client.Binary == "" {
		return errors.New("refusing to execute an empty client path")
	}
	if plan.local {
		if plan.Route != "" {
			return errors.New("refusing to execute a local plan with a physical-host route")
		}
	} else if err := validatePlanRoute(plan.Route); err != nil {
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
	operationArguments := plan.Arguments
	flatpakQtPlatform := ""
	if plan.Client.Flavor == FlavorFlatpak {
		var err error
		if operationArguments, flatpakQtPlatform, err = splitFlatpakPrefix(plan.Arguments); err != nil {
			return fmt.Errorf("refusing to execute an invalid Moonlight Flatpak prefix: %w", err)
		}
		expected := normalizeQtPlatform(plan.QtPlatform)
		if flatpakQtPlatform != expected && !(flatpakQtPlatform == "" && (expected == "" || expected == "auto")) {
			return errors.New("refusing to execute a Flatpak plan whose QT_QPA_PLATFORM argument does not match its planned platform")
		}
	}
	if plan.qtPlatformBinding != normalizeQtPlatform(plan.QtPlatform) {
		return errors.New("refusing to execute a plan whose Qt platform was changed after planning")
	}
	if plan.QtPlatform != "" {
		if err := ValidateQtPlatform(plan.QtPlatform); err != nil {
			return fmt.Errorf("refusing to execute an invalid Qt platform: %w", err)
		}
		if plan.Client.Flavor != FlavorQt && plan.Client.Flavor != FlavorFlatpak {
			return errors.New("refusing to execute a Qt platform plan with a non-Qt Moonlight client")
		}
		if len(operationArguments) == 0 || operationArguments[0] != string(Stream) {
			return errors.New("refusing to execute a Qt platform plan for a non-stream operation")
		}
	}
	if plan.local {
		if plan.Client.Flavor != FlavorEmbedded || len(plan.Arguments) == 0 || plan.Arguments[0] != string(Map) {
			return errors.New("refusing to execute a local plan that is not Moonlight Embedded map")
		}
	} else if plan.Client.Flavor == FlavorEmbedded && len(plan.Arguments) > 0 && plan.Arguments[0] == string(Map) {
		return errors.New("refusing to execute a local controller-mapping plan without its planner marker")
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
	if !argumentsMatch(plan.argumentBinding, plan.Arguments) {
		return errors.New("refusing to execute a plan whose argument vector was changed after planning")
	}
	if plan.clientBinding.executableInfo == nil {
		return errors.New("refusing to execute a plan whose Moonlight executable was not bound by the real environment")
	}
	current, err := os.Stat(plan.Client.Binary)
	if err != nil {
		return fmt.Errorf("refusing to execute a plan whose Moonlight executable is unavailable after discovery: %w", err)
	}
	if !os.SameFile(plan.clientBinding.executableInfo, current) {
		return errors.New("refusing to execute a plan whose Moonlight executable changed after discovery")
	}
	var runErr error
	if plan.QtPlatform != "" && normalizeQtPlatform(plan.QtPlatform) != "auto" {
		platformRunner, ok := runner.(QtPlatformRunner)
		if !ok {
			return errors.New("refusing to execute a Qt platform plan with a runner that cannot apply environment overrides")
		}
		runErr = platformRunner.RunWithQtPlatform(ctx, stdin, stdout, stderr, plan.QtPlatform, plan.Client.Binary, plan.Arguments...)
	} else {
		runErr = runner.Run(ctx, stdin, stdout, stderr, plan.Client.Binary, plan.Arguments...)
	}
	if runErr != nil {
		return fmt.Errorf("Moonlight handoff failed: %w", runErr)
	}
	return nil
}
