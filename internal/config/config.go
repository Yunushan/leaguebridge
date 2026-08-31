// Package config loads LeagueBridge's local, credential-free configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
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
)

var ErrNotFound = errors.New("LeagueBridge configuration not found")

var ErrExists = errors.New("LeagueBridge configuration already exists")

// Config intentionally contains no username, password, token, Riot session, or
// streaming key. Pairing and authentication remain inside the official clients.
type Config struct {
	SchemaVersion int        `json:"schema_version"`
	RouteID       Route      `json:"route_id"`
	RemoteHost    RemoteHost `json:"remote_host"`
}

type RemoteHost struct {
	Host                  string `json:"host"`
	App                   string `json:"app"`
	Client                string `json:"client"`
	PhysicalHostConfirmed bool   `json:"physical_host_confirmed"`
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
		App:    "League of Legends",
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
	return c
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
	return validateRemoteHost("remote_host", c.RemoteHost)
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

// ValidateHost accepts IP literals and conservative DNS/mDNS names. It rejects
// option-like, URL-like, or shell-like values even though LeagueBridge never
// invokes a shell.
func ValidateHost(host string) error {
	if host == "" || !utf8.ValidString(host) {
		return errors.New("must be non-empty valid UTF-8")
	}
	for _, r := range host {
		if unicode.IsControl(r) {
			return errors.New("must not contain control characters")
		}
	}
	if strings.TrimSpace(host) != host {
		return errors.New("must be non-empty without surrounding whitespace")
	}
	if len(host) > 253 {
		return errors.New("exceeds 253 bytes")
	}
	if strings.HasPrefix(host, "-") || strings.Contains(host, "://") || strings.ContainsAny(host, "\x00/\\@[] \t\r\n;&|`$<>(){}") {
		return errors.New("must be an IP address or DNS name, not a URL, option, path, or command")
	}
	// Colons are allowed only for valid IPv6 literals. netip also handles an
	// interface zone for link-local addresses without accepting URL brackets.
	if strings.Contains(host, ":") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return errors.New("invalid IPv6 literal")
		}
		return nil
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				return errors.New("invalid DNS character")
			}
		}
	}
	return nil
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
