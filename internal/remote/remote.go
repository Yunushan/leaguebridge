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
	List   Operation = "list"
	Stream Operation = "stream"
)

// ApplicationListed reports whether a Moonlight application-list response
// contains the requested application name. Moonlight clients do not expose a
// common machine-readable list format across Embedded and Qt, so this helper
// deliberately performs a conservative text check after removing terminal
// control sequences. It is a pre-stream configuration check, not evidence of
// a working League client or Vanguard session.
func ApplicationListed(output, application string) bool {
	if err := config.ValidateAppName(application); err != nil {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(stripTerminalControlSequences(line))
		if applicationLineMatches(line, application) {
			return true
		}
	}
	return false
}

// applicationLineMatches accepts the plain and lightly decorated forms used
// by Moonlight clients while rejecting arbitrary diagnostic text. In
// particular, a connection banner or an error mentioning the requested app
// must not be enough to pass --require-app.
func applicationLineMatches(line, application string) bool {
	if line == application {
		return true
	}
	if colon := strings.IndexByte(line, ':'); colon > 0 {
		label := strings.TrimSpace(line[:colon])
		if strings.EqualFold(label, "application") || strings.EqualFold(label, "app") {
			return strings.TrimSpace(line[colon+1:]) == application
		}
	}
	if len(line) > 1 && (line[0] == '-' || line[0] == '*') &&
		strings.TrimSpace(line[1:]) == application {
		return true
	}
	if close := strings.IndexByte(line, ']'); len(line) > 2 && line[0] == '[' && close > 1 &&
		allASCIIDigits(line[1:close]) && strings.TrimSpace(line[close+1:]) == application {
		return true
	}
	index := 0
	for index < len(line) && line[index] >= '0' && line[index] <= '9' {
		index++
	}
	if index > 0 && index < len(line) {
		switch line[index] {
		case '.', ')', ':', '-':
			return strings.TrimSpace(line[index+1:]) == application
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
	Route                   config.Route
	Operation               Operation
	Host                    string
	App                     string
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

// StreamOptions is the small bounded quality, display, input-mode, and
// Embedded-backend surface
// supported by the Moonlight Embedded and Moonlight Qt command-line clients.
// The two clients use slightly different syntax for resolution, packet size,
// codec, and audio selection, and only Qt exposes decoder, display-mode, and
// absolute-mouse controls. Embedded additionally exposes a platform selector,
// so arguments() translates the bounded values to each client's documented
// form.
// Zero values keep the selected client's own defaults. Options are
// invocation-scoped and are never persisted with LeagueBridge configuration.
type StreamOptions struct {
	Resolution           string `json:"resolution,omitempty"`
	FPS                  int    `json:"fps,omitempty"`
	BitrateKbps          int    `json:"bitrate_kbps,omitempty"`
	PacketSizeBytes      int    `json:"packet_size_bytes,omitempty"`
	Codec                string `json:"codec,omitempty"`
	AudioConfig          string `json:"audio_config,omitempty"`
	PreserveHostSettings bool   `json:"preserve_host_settings,omitempty"`
	NetworkMode          string `json:"network_mode,omitempty"`
	Platform             string `json:"platform,omitempty"`
	Decoder              string `json:"decoder,omitempty"`
	DisplayMode          string `json:"display_mode,omitempty"`
	MouseMode            string `json:"mouse_mode,omitempty"`
}

func (options StreamOptions) empty() bool {
	return options.Resolution == "" && options.FPS == 0 && options.BitrateKbps == 0 && options.PacketSizeBytes == 0 && options.Codec == "" && options.AudioConfig == "" && !options.PreserveHostSettings && options.NetworkMode == "" && options.Platform == "" && options.Decoder == "" && options.DisplayMode == "" && options.MouseMode == ""
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
			return fmt.Errorf("codec must be auto, h264, hevc, or av1, got %q", options.Codec)
		}
	}
	if options.AudioConfig != "" {
		switch strings.ToLower(strings.TrimSpace(options.AudioConfig)) {
		case "stereo", "5.1-surround", "7.1-surround":
		default:
			return fmt.Errorf("audio config must be stereo, 5.1-surround, or 7.1-surround, got %q", options.AudioConfig)
		}
	}
	if options.NetworkMode != "" {
		switch strings.ToLower(strings.TrimSpace(options.NetworkMode)) {
		case "auto", "lan", "wan":
		default:
			return fmt.Errorf("network mode must be auto, lan, or wan, got %q", options.NetworkMode)
		}
	}
	if options.Platform != "" {
		switch strings.ToLower(strings.TrimSpace(options.Platform)) {
		case "auto", "x11", "x11_vdpau", "sdl":
		default:
			return fmt.Errorf("platform must be auto, x11, x11_vdpau, or sdl, got %q", options.Platform)
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
	if options.NetworkMode != "" {
		if optionFlavor != FlavorEmbedded {
			return nil, fmt.Errorf("network mode selection is supported only by Moonlight Embedded; select --client moonlight-embedded or omit it (got %q)", optionFlavor)
		}
		mode := strings.ToLower(strings.TrimSpace(options.NetworkMode))
		remoteMode := map[string]string{"auto": "auto", "lan": "no", "wan": "yes"}[mode]
		arguments = append(arguments, "-remote", remoteMode)
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

	// validated is deliberately not serialized. Only BuildDiscoveredPlan can
	// create an executable plan; JSON or a hand-built value must not bypass its
	// route, physical-host confirmation, and acknowledgement checks.
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
}

type Environment interface {
	LookPath(file string) (string, error)
}

type RealEnvironment struct{}

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
	return discoverForPlatform(ctx, env, preferred, runtime.GOOS)
}

func discoverForPlatform(ctx context.Context, env Environment, preferred, goos string) (Client, error) {
	if env == nil {
		return Client{}, errors.New("Moonlight discovery environment is nil")
	}
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
		if path, err := lookup("flatpak"); err == nil {
			return bindDiscoveredClient(env, Client{Flavor: FlavorFlatpak, Binary: path, Prefix: []string{"run", "com.moonlight_stream.Moonlight"}, discovered: true})
		} else if lookupCanceled(err) {
			return Client{}, err
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
		path, err := lookup("flatpak")
		if lookupCanceled(err) {
			return Client{}, err
		}
		if err == nil {
			return bindDiscoveredClient(env, Client{Flavor: FlavorFlatpak, Binary: path, Prefix: []string{"run", "com.moonlight_stream.Moonlight"}, discovered: true})
		}
	case "moonlight", "moonlight-embedded":
		lookupName := "moonlight"
		if preferred == "moonlight-embedded" {
			lookupName = "moonlight-embedded"
		}
		path, err := lookup(lookupName)
		if err != nil && preferred == "moonlight-embedded" && !lookupCanceled(err) {
			// Package managers normally install Embedded as the generic
			// "moonlight" command, but accept the explicit executable name
			// first when a downstream package preserves the flavor in PATH.
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
	if err := config.ValidateHost(req.Host); err != nil {
		return Plan{}, fmt.Errorf("host: %w", err)
	}
	if req.Operation != Pair && req.Operation != List && req.Operation != Stream {
		return Plan{}, fmt.Errorf("unsupported remote operation %q", req.Operation)
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
			args = append(args, "-app", req.App, req.Host)
		default:
			args = append(args, string(req.Operation), req.Host)
		}
	case FlavorQt, FlavorFlatpak:
		args = append(args, string(req.Operation))
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
	return Plan{
		Route:            route,
		Client:           client,
		Arguments:        args,
		Warnings:         warnings,
		validated:        true,
		clientDiscovered: client.discovered,
		clientBinding:    bindClient(client),
		argumentBinding:  append([]string(nil), args...),
	}, nil
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

// validatePlanArguments re-checks the complete Moonlight argument grammar at
// the execution boundary. Plans are exported values, so a caller can bypass
// BuildPlan and otherwise smuggle arbitrary flags or a different operation to
// the runner. Keeping this grammar fixed makes Execute fail closed even when a
// hand-built Plan is supplied by another package or a future CLI path.
func validatePlanArguments(client Client, args []string) error {
	rest := args
	if client.Flavor == FlavorFlatpak {
		if len(args) < 2 || args[0] != "run" || args[1] != "com.moonlight_stream.Moonlight" {
			return errors.New("Moonlight Flatpak argument vector must begin with the fixed run com.moonlight_stream.Moonlight prefix")
		}
		rest = args[2:]
	}
	if len(rest) == 0 {
		return errors.New("Moonlight argument vector has no operation")
	}

	switch rest[0] {
	case string(Pair), string(List):
		if len(rest) != 2 {
			return fmt.Errorf("%s operation requires exactly one host argument", rest[0])
		}
		if err := config.ValidateHost(rest[1]); err != nil {
			return fmt.Errorf("host: %w", err)
		}
	case string(Stream):
		streamArgs, err := splitStreamOptions(client.Flavor, rest[1:])
		if err != nil {
			return err
		}
		if client.Flavor == FlavorEmbedded {
			if len(streamArgs) != 3 || streamArgs[0] != "-app" {
				return errors.New("stream operation for Moonlight Embedded requires the fixed stream -app APP HOST argument shape")
			}
			if err := config.ValidateAppName(streamArgs[1]); err != nil {
				return fmt.Errorf("app: %w", err)
			}
			if err := config.ValidateHost(streamArgs[2]); err != nil {
				return fmt.Errorf("host: %w", err)
			}
			return nil
		}
		if len(streamArgs) != 2 {
			return errors.New("stream operation for Moonlight Qt requires the fixed stream HOST APP argument shape")
		}
		if err := config.ValidateHost(streamArgs[0]); err != nil {
			return fmt.Errorf("host: %w", err)
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
	seenAudioConfig := false
	seenHostSettings := false
	seenNetworkMode := false
	seenPlatform := false
	seenDecoder := false
	seenDisplayMode := false
	seenMouseMode := false
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
			switch strings.ToLower(strings.TrimSpace(args[position+1])) {
			case "auto", "x11", "x11_vdpau", "sdl":
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
		default:
			return nil, fmt.Errorf("stream argument vector contains unsupported option %q", option)
		}
	}
	if seenEmbeddedWidth && !seenEmbeddedHeight {
		return nil, errors.New("stream argument vector must pair the Embedded custom resolution width with its height")
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

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
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
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func Execute(ctx context.Context, runner Runner, stdin io.Reader, stdout, stderr io.Writer, plan Plan) error {
	if plan.Client.Binary == "" {
		return errors.New("refusing to execute an empty client path")
	}
	if err := validatePlanRoute(plan.Route); err != nil {
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
	if err := runner.Run(ctx, stdin, stdout, stderr, plan.Client.Binary, plan.Arguments...); err != nil {
		return fmt.Errorf("Moonlight handoff failed: %w", err)
	}
	return nil
}
