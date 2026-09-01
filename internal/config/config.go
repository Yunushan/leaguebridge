// Package config loads LeagueBridge's local, credential-free configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
)

const (
	SchemaVersion       = 2
	LegacySchemaVersion = 1
	MaxFileSize         = 64 * 1024
	MaxKVMEndpointSize  = 2048

	// DefaultRemoteApplication is the exact League application name that a
	// physical Sunshine host should publish. Starting with the game entry keeps
	// a normal remote stream from silently opening a generic desktop; operators
	// can still choose another published host application with --app or direct
	// configuration editing.
	DefaultRemoteApplication = "League of Legends"
)

var ErrNotFound = errors.New("LeagueBridge configuration not found")

var ErrExists = errors.New("LeagueBridge configuration already exists")

// Config intentionally contains no username, password, token, Riot session, or
// streaming key. Pairing and authentication remain inside the official clients.
type Config struct {
	SchemaVersion int        `json:"schema_version"`
	RouteID       Route      `json:"route_id"`
	RemoteHost    RemoteHost `json:"remote_host"`
	KVM           *KVMConfig `json:"kvm,omitempty"`
}

type RemoteHost struct {
	Host                  string `json:"host"`
	App                   string `json:"app"`
	Client                string `json:"client"`
	PhysicalHostConfirmed bool   `json:"physical_host_confirmed"`
}

// KVMConfig stores only a clean device endpoint. Browser credentials, session
// tokens, device authentication, and HTTP exceptions remain invocation-only;
// they are never accepted or persisted in LeagueBridge configuration.
type KVMConfig struct {
	Endpoint string `json:"endpoint"`
}

type Route string

const (
	RouteWindows Route = "physical-windows-remote"
	RouteMacOS   Route = "physical-macos-remote"

	legacyBackendRemotePhysicalWindows = "remote-physical-windows"
)

type legacyConfigV1 struct {
	SchemaVersion int        `json:"schema_version"`
	Backend       string     `json:"backend"`
	RemoteWindows RemoteHost `json:"remote_windows"`
}

func Default() Config {
	cfg, _ := DefaultForRoute(RouteWindows)
	return cfg
}

// DefaultForRoute returns a credential-free configuration for one explicit
// physical-host route. The Windows route remains the default for compatibility.
func DefaultForRoute(route Route) (Config, error) {
	target := RemoteHost{
		App:    DefaultRemoteApplication,
		Client: "auto",
	}
	switch route {
	case RouteWindows, RouteMacOS:
		return Config{
			SchemaVersion: SchemaVersion,
			RouteID:       route,
			RemoteHost:    target,
		}, nil
	default:
		return Config{}, fmt.Errorf("route must be windows or macos, got %q", route)
	}
}

// ParseRoute validates a user-selected physical-host route.
func ParseRoute(value string) (Route, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "windows", string(RouteWindows):
		return RouteWindows, nil
	case "macos", string(RouteMacOS):
		return RouteMacOS, nil
	default:
		return "", fmt.Errorf("route must be windows or macos, got %q", value)
	}
}

// Route reports the exact compatibility-manifest route identifier.
func (c Config) Route() (Route, error) {
	switch c.RouteID {
	case RouteWindows, RouteMacOS:
		return c.RouteID, nil
	default:
		return "", fmt.Errorf("unsupported route_id %q", c.RouteID)
	}
}

// ActiveRemote returns the route-selected target. It does not validate target
// fields so callers may apply CLI overrides before calling Validate.
func (c *Config) ActiveRemote() (*RemoteHost, Route, error) {
	if c == nil {
		return nil, "", errors.New("configuration is nil")
	}
	route, err := c.Route()
	if err != nil {
		return nil, "", err
	}
	return &c.RemoteHost, route, nil
}

// Clone returns an independent value copy.
func (c Config) Clone() Config {
	clone := c
	if c.KVM != nil {
		clone.KVM = &KVMConfig{Endpoint: c.KVM.Endpoint}
	}
	return clone
}

// DefaultPath respects an explicit override and otherwise uses the operating
// system's per-user configuration directory.
func DefaultPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv("LEAGUEBRIDGE_CONFIG")); path != "" {
		return filepath.Clean(path), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user configuration directory: %w", err)
	}
	return filepath.Join(dir, "leaguebridge", "config.json"), nil
}

func LoadDefault() (Config, string, error) {
	path, err := DefaultPath()
	if err != nil {
		return Config{}, "", err
	}
	cfg, err := Load(path)
	return cfg, path, err
}

// Load parses a bounded JSON file, rejects unknown fields, and validates every
// value before it can influence a child process.
func Load(path string) (Config, error) {
	f, err := fileinput.OpenRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, ErrNotFound
	}
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if len(data) > MaxFileSize {
		return Config{}, fmt.Errorf("configuration exceeds %d bytes", MaxFileSize)
	}

	return parse(data)
}

func parse(data []byte) (Config, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}
	schemaVersion, err := decodeConfigHeader(data)
	if err != nil {
		return Config{}, err
	}
	switch schemaVersion {
	case SchemaVersion:
		if err := exactjson.ValidateKeys(data, &Config{}); err != nil {
			return Config{}, fmt.Errorf("parse configuration: %w", err)
		}
		var cfg Config
		if err := decodeConfig(data, &cfg, true); err != nil {
			return Config{}, err
		}
		if err := cfg.Validate(); err != nil {
			return Config{}, err
		}
		return cfg, nil
	case LegacySchemaVersion:
		if err := exactjson.ValidateKeys(data, &legacyConfigV1{}); err != nil {
			return Config{}, fmt.Errorf("parse configuration: %w", err)
		}
		var legacy legacyConfigV1
		if err := decodeConfig(data, &legacy, true); err != nil {
			return Config{}, err
		}
		if legacy.Backend != legacyBackendRemotePhysicalWindows {
			return Config{}, fmt.Errorf("unsupported legacy backend %q", legacy.Backend)
		}
		if err := validateRemoteHost("remote_windows", legacy.RemoteWindows); err != nil {
			return Config{}, err
		}
		return Config{
			SchemaVersion: SchemaVersion,
			RouteID:       RouteWindows,
			RemoteHost:    legacy.RemoteWindows,
		}, nil
	default:
		return Config{}, fmt.Errorf("unsupported configuration schema_version %d (expected %d; legacy %d is read-only compatible)", schemaVersion, SchemaVersion, LegacySchemaVersion)
	}
}

func decodeConfigHeader(data []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var document map[string]json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		return 0, fmt.Errorf("parse configuration: %w", err)
	}
	if document == nil {
		return 0, errors.New("parse configuration: top-level value must be an object")
	}
	if err := ensureEOF(decoder); err != nil {
		return 0, err
	}
	rawVersion, ok := document["schema_version"]
	if !ok {
		return 0, errors.New("parse configuration: exact field \"schema_version\" is required")
	}
	if bytes.Equal(bytes.TrimSpace(rawVersion), []byte("null")) {
		return 0, errors.New("parse configuration: schema_version must be an integer")
	}
	var schemaVersion int
	if err := json.Unmarshal(rawVersion, &schemaVersion); err != nil {
		return 0, fmt.Errorf("parse configuration: schema_version must be an integer: %w", err)
	}
	return schemaVersion, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkConfigJSON(decoder, "$", 0); err != nil {
		return err
	}
	return nil
}

func walkConfigJSON(decoder *json.Decoder, location string, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds 32 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s object key is not a string", location)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s has duplicate key %q", location, key)
			}
			seen[key] = struct{}{}
			if err := walkConfigJSON(decoder, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		index := 0
		for decoder.More() {
			if err := walkConfigJSON(decoder, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
			index++
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("%s has unexpected JSON delimiter %q", location, delimiter)
	}
}

func decodeConfig(data []byte, destination any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("parse configuration: %w", err)
	}
	return ensureEOF(decoder)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration contains multiple JSON values")
		}
		return fmt.Errorf("parse trailing configuration data: %w", err)
	}
	return nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported configuration schema_version %d (expected %d)", c.SchemaVersion, SchemaVersion)
	}
	if _, err := c.Route(); err != nil {
		return err
	}
	if err := validateRemoteHost("remote_host", c.RemoteHost); err != nil {
		return err
	}
	if c.KVM != nil {
		if err := ValidateKVMEndpoint(c.KVM.Endpoint, false); err != nil {
			return fmt.Errorf("kvm.endpoint: %w", err)
		}
	}
	return nil
}

// ValidateKVMEndpoint accepts a clean HTTP(S) hardware-KVM UI endpoint. It is
// shared by configuration loading and the runtime launcher so a stored value
// cannot bypass the same credential/token and scheme checks used by --url.
func ValidateKVMEndpoint(endpoint string, allowHTTP bool) error {
	if endpoint == "" {
		return errors.New("KVM endpoint URL is required")
	}
	if len(endpoint) > MaxKVMEndpointSize {
		return fmt.Errorf("KVM endpoint URL exceeds the %d-byte limit", MaxKVMEndpointSize)
	}
	if strings.TrimSpace(endpoint) != endpoint || strings.ContainsAny(endpoint, "\r\n\t") {
		return errors.New("KVM endpoint URL must not contain surrounding whitespace or control characters")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid KVM endpoint URL: %w", err)
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return errors.New("KVM endpoint URL must be an absolute URL with a host")
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return errors.New("KVM endpoint uses HTTP; pass --allow-http only for a trusted LAN bootstrap or device that cannot use HTTPS")
		}
	default:
		return errors.New("KVM endpoint URL must use https (or explicit http with --allow-http)")
	}
	if parsed.User != nil {
		return errors.New("KVM endpoint URL must not contain embedded credentials")
	}
	if parsed.RawQuery != "" {
		return errors.New("KVM endpoint URL must not contain query parameters or session tokens")
	}
	if parsed.Fragment != "" {
		return errors.New("KVM endpoint URL must not contain a fragment")
	}
	return nil
}

func validateRemoteHost(field string, target RemoteHost) error {
	if err := ValidateHost(target.Host); err != nil {
		return fmt.Errorf("%s.host: %w", field, err)
	}
	if err := ValidateAppName(target.App); err != nil {
		return fmt.Errorf("%s.app: %w", field, err)
	}
	switch target.Client {
	case "auto", "moonlight", "moonlight-embedded", "moonlight-qt", "flatpak":
	default:
		return fmt.Errorf("%s.client must be auto, moonlight, moonlight-embedded, moonlight-qt, or flatpak, got %q", field, target.Client)
	}
	return nil
}

// ValidateAppName accepts a bounded, printable Sunshine application name.
// Although LeagueBridge never invokes a shell, an option-like value or control
// character could still be interpreted by a downstream command-line parser.
func ValidateAppName(app string) error {
	if app == "" {
		return errors.New("must be non-empty")
	}
	if !utf8.ValidString(app) {
		return errors.New("must be valid UTF-8")
	}
	if strings.TrimSpace(app) != app {
		return errors.New("must not contain surrounding whitespace")
	}
	if strings.HasPrefix(app, "-") {
		return errors.New("must not begin with '-'")
	}
	if len(app) > 128 {
		return errors.New("must not exceed 128 bytes")
	}
	for _, r := range app {
		if unicode.IsControl(r) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// HostEndpoint is a validated Moonlight host address with an optional TCP
// control port. Port is zero when the client default should be used.
//
// Bracketed IPv6 endpoints are accepted because Moonlight Qt uses the
// [address]:port form for manually supplied hosts. Moonlight Embedded uses the
// Address and Port fields separately when LeagueBridge builds its argv.
type HostEndpoint struct {
	Address string
	Port    int
}

// ParseHostEndpoint accepts IP literals and conservative DNS/mDNS names, with
// an optional port written as HOST:PORT for DNS/IPv4 names or [IPv6]:PORT for
// IPv6 literals. It rejects option-like, URL-like, or shell-like values even
// though LeagueBridge never invokes a shell.
func ParseHostEndpoint(host string) (HostEndpoint, error) {
	if host == "" || !utf8.ValidString(host) {
		return HostEndpoint{}, errors.New("must be non-empty valid UTF-8")
	}
	for _, r := range host {
		if unicode.IsControl(r) {
			return HostEndpoint{}, errors.New("must not contain control characters")
		}
	}
	if strings.TrimSpace(host) != host {
		return HostEndpoint{}, errors.New("must be non-empty without surrounding whitespace")
	}
	if len(host) > 253 {
		return HostEndpoint{}, errors.New("exceeds 253 bytes")
	}
	if strings.HasPrefix(host, "-") || strings.Contains(host, "://") || strings.ContainsAny(host, "\x00/\\@ \t\r\n;&|`$<>(){}") {
		return HostEndpoint{}, errors.New("must be an IP address or DNS name, not a URL, option, path, or command")
	}

	addressText := host
	port := 0
	bracketed := false
	if strings.HasPrefix(host, "[") {
		bracketed = true
		close := strings.IndexByte(host, ']')
		if close < 0 {
			return HostEndpoint{}, errors.New("invalid bracketed IPv6 endpoint")
		}
		addressText = host[1:close]
		suffix := host[close+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return HostEndpoint{}, errors.New("invalid bracketed IPv6 endpoint suffix")
			}
			parsedPort, err := parseHostEndpointPort(suffix[1:])
			if err != nil {
				return HostEndpoint{}, err
			}
			port = parsedPort
		}
	} else if strings.ContainsAny(host, "[]") {
		return HostEndpoint{}, errors.New("brackets are allowed only around an IPv6 literal")
	} else if strings.Count(host, ":") == 1 {
		// A single colon cannot be part of an IPv6 literal. Treat it as the
		// unambiguous HOST:PORT form used by Moonlight Qt and normalize it to
		// Address plus Port for Moonlight Embedded.
		separator := strings.LastIndexByte(host, ':')
		addressText = host[:separator]
		parsedPort, err := parseHostEndpointPort(host[separator+1:])
		if err != nil {
			return HostEndpoint{}, err
		}
		port = parsedPort
	}

	// Colons are allowed only for valid IPv6 literals. Moonlight Qt receives the
	// original bracketed endpoint, where RFC 6874 represents a link-local zone
	// delimiter as %25 (for example [fe80::1%25em0]:47989). Embedded receives a
	// decoded zone through Address, so both clients use the form they document.
	if strings.Contains(addressText, ":") {
		decodedAddressText, err := decodeIPv6Zone(addressText)
		if err != nil {
			return HostEndpoint{}, err
		}
		address, err := netip.ParseAddr(decodedAddressText)
		if err != nil || !address.Is6() {
			return HostEndpoint{}, errors.New("invalid IPv6 literal")
		}
		return HostEndpoint{Address: decodedAddressText, Port: port}, nil
	}
	if bracketed {
		return HostEndpoint{}, errors.New("brackets are allowed only around an IPv6 literal")
	}
	labels := strings.Split(addressText, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return HostEndpoint{}, errors.New("invalid DNS label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				return HostEndpoint{}, errors.New("invalid DNS character")
			}
		}
	}
	return HostEndpoint{Address: addressText, Port: port}, nil
}

// ValidateHost validates the host endpoint without exposing a parsed value to
// callers that only need a yes/no check.
func ValidateHost(host string) error {
	_, err := ParseHostEndpoint(host)
	return err
}

func parseHostEndpointPort(value string) (int, error) {
	if value == "" || len(value) > 5 || !allASCIIDigits(value) {
		return 0, errors.New("invalid host port; expected a decimal port from 1 to 65535")
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != value {
		return 0, errors.New("invalid host port; expected a decimal port from 1 to 65535")
	}
	return port, nil
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// decodeIPv6Zone accepts the URL-escaped zone delimiter used inside a
// bracketed IPv6 endpoint and converts it to the scoped-address form accepted
// by netip and Moonlight Embedded. The rest of the zone is intentionally left
// untouched; interface names are not URL-decoded by this parser.
func decodeIPv6Zone(value string) (string, error) {
	zone := strings.IndexByte(value, '%')
	if zone < 0 {
		return value, nil
	}
	if zone+3 <= len(value) && value[zone:zone+3] == "%25" {
		decoded := value[:zone] + "%" + value[zone+3:]
		if strings.ContainsRune(decoded[zone+1:], '%') {
			return "", errors.New("invalid IPv6 interface zone")
		}
		return decoded, nil
	}
	if strings.ContainsRune(value[zone+1:], '%') {
		return "", errors.New("invalid IPv6 interface zone")
	}
	return value, nil
}

func MarshalExample() ([]byte, error) {
	return MarshalExampleForRoute(RouteWindows)
}

// MarshalExampleForRoute emits a complete example for one selected route.
func MarshalExampleForRoute(route Route) ([]byte, error) {
	cfg, err := DefaultForRoute(route)
	if err != nil {
		return nil, err
	}
	target, _, err := cfg.ActiveRemote()
	if err != nil {
		return nil, err
	}
	if route == RouteMacOS {
		target.Host = "gaming-mac.local"
	} else {
		target.Host = "gaming-pc.local"
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// WriteNew validates and atomically creates a configuration file. It requests
// mode 0600, creates the parent directory when needed, and never overwrites any
// object. On Windows, os.Chmod does not replace the inherited directory DACL;
// callers must not describe that inherited ACL as owner-only without checking.
func WriteNew(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	data = append(data, '\n')
	target, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve configuration path: %w", err)
	}
	directory := filepath.Dir(target)
	if err := fileinput.EnsureDirectoryTree(directory, 0o700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	if _, err := os.Lstat(target); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect configuration destination: %w", err)
	}
	root, err := fileinput.OpenDirectoryRoot(directory)
	if err != nil {
		return fmt.Errorf("open configuration directory: %w", err)
	}
	defer root.Close()
	targetName := filepath.Base(target)
	if targetName == "" || targetName == "." || targetName == string(filepath.Separator) {
		return errors.New("configuration destination is not a regular child path")
	}

	temporary, temporaryName, err := fileinput.CreateTempFile(root, ".leaguebridge-config-", 0o600)
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set configuration permissions: %w", err)
	}
	if n, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write configuration: %w", err)
	} else if n != len(data) {
		return fmt.Errorf("write configuration: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	closed = true
	if err := fileinput.LinkInRoot(root, temporaryName, targetName); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("publish configuration with an exclusive hard link (destination filesystem must support same-directory hard links; otherwise create it on a local supported filesystem): %w", err)
	}
	return nil
}
