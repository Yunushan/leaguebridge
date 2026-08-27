package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

func TestLoadValidAndDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"gaming-pc.local","app":"League of Legends","client":"auto","physical_host_confirmed":true}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != SchemaVersion || cfg.RouteID != RouteWindows || cfg.RemoteHost.Host != "gaming-pc.local" || !cfg.RemoteHost.PhysicalHostConfirmed {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestSchemaV2MacOSRoundTripAndLegacyV1Normalization(t *testing.T) {
	dir := t.TempDir()
	macPath := filepath.Join(dir, "macos.json")
	mac, err := DefaultForRoute(RouteMacOS)
	if err != nil {
		t.Fatal(err)
	}
	mac.RemoteHost.Host = "gaming-mac.local"
	mac.RemoteHost.PhysicalHostConfirmed = true
	if err := WriteNew(macPath, mac); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(macPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"schema_version": 2`, `"route_id": "physical-macos-remote"`, `"remote_host"`} {
		if !strings.Contains(text, want) {
			t.Errorf("schema-v2 config lacks %s:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{`"backend"`, `"remote_windows"`, `"remote_macos"`} {
		if strings.Contains(text, forbidden) {
			t.Errorf("schema-v2 config contains legacy/parallel field %s:\n%s", forbidden, text)
		}
	}
	loaded, err := Load(macPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != mac {
		t.Fatalf("Load(macOS) = %+v, want %+v", loaded, mac)
	}

	legacyPath := filepath.Join(dir, "legacy-v1.json")
	legacy := `{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true}}`
	if err := os.WriteFile(legacyPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	normalized, err := Load(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.SchemaVersion != SchemaVersion || normalized.RouteID != RouteWindows || normalized.RemoteHost.Host != "pc.local" {
		t.Fatalf("legacy normalization = %+v", normalized)
	}
}

func TestConfigRoutesRejectAmbiguityAndUnknownFields(t *testing.T) {
	for _, value := range []string{"windows", "physical-windows-remote", "macos", "physical-macos-remote"} {
		if _, err := ParseRoute(value); err != nil {
			t.Errorf("ParseRoute(%q): %v", value, err)
		}
	}
	if _, err := ParseRoute("darwin"); err == nil {
		t.Fatal("ParseRoute accepted an unknown route")
	}

	dir := t.TempDir()
	invalid := []string{
		`{"schema_version":2,"route_id":"physical-macos-remote","remote_host":{"host":"mac.local","app":"League","client":"auto","physical_host_confirmed":true},"remote_windows":{"host":"pc.local"}}`,
		`{"schema_version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true},"backend":"remote-physical-windows"}`,
		`{"schema_version":1,"backend":"remote-physical-macos","remote_windows":{"host":"mac.local","app":"League","client":"auto","physical_host_confirmed":true}}`,
		`{"schema_version":2,"route_id":"physical-windows-remote","route_id":"physical-macos-remote","remote_host":{"host":"mac.local","app":"League","client":"auto","physical_host_confirmed":true}}`,
		`{"schema_version":2,"route_id":"physical-macos-remote","remote_host":{"host":"mac.local","host":"other.local","app":"League","client":"auto","physical_host_confirmed":true}}`,
		`{"Schema_Version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true}}`,
		`{"schema_version":2,"Route_ID":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true}}`,
		`{"schema_version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","PHYSICAL_HOST_CONFIRMED":true}}`,
		`{"schema_version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":false,"PHYSICAL_HOST_CONFIRMED":true}}`,
		`{"schema_version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto"}}`,
		`{"schema_version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":null}}`,
		`{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc.local","app":"League","client":"auto"}}`,
		`{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":null}}`,
		`{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":false,"Physical_Host_Confirmed":true}}`,
	}
	for i, body := range invalid {
		path := filepath.Join(dir, fmt.Sprintf("invalid-%d.json", i))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load accepted ambiguous/unknown config %d", i)
		}
	}
}

func TestLoadRejectsUnknownTrailingAndLarge(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"unknown", `{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc","app":"League","client":"auto","physical_host_confirmed":true},"command":"oops"}`},
		{"trailing", `{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc","app":"League","client":"auto","physical_host_confirmed":true}} {}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxFileSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestLoadNotFound(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestValidateHost(t *testing.T) {
	valid := []string{"gaming-pc.local", "192.168.1.8", "2001:db8::1", "pc_name"}
	for _, host := range valid {
		if err := ValidateHost(host); err != nil {
			t.Errorf("ValidateHost(%q): %v", host, err)
		}
	}
	invalid := []string{
		"", " host", "-option", "https://pc", "pc;shutdown", "pc/name", "bad..name", "[::1]",
		string([]byte{'p', 'c', 0xff}), "fe80::1%bad\x1bzone", "pc\u0085name",
	}
	for _, host := range invalid {
		if err := ValidateHost(host); err == nil {
			t.Errorf("ValidateHost(%q) unexpectedly passed", host)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	cfg := Default()
	cfg.RemoteHost.Host = "pc.local"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	mutations := []func(*Config){
		func(c *Config) { c.SchemaVersion = 99 },
		func(c *Config) { c.RouteID = "wine" },
		func(c *Config) { c.RemoteHost.App = "" },
		func(c *Config) { c.RemoteHost.Client = "sh -c" },
	}
	for i, mutate := range mutations {
		bad := cfg
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("mutation %d unexpectedly passed", i)
		}
	}
}

func TestValidateAppName(t *testing.T) {
	valid := []string{
		"League of Legends",
		"LoL",
		"Léague 日本",
		strings.Repeat("é", 64), // Exactly 128 UTF-8 bytes.
	}
	for _, app := range valid {
		t.Run("valid_"+app, func(t *testing.T) {
			if err := ValidateAppName(app); err != nil {
				t.Fatalf("ValidateAppName(%q): %v", app, err)
			}
		})
	}

	invalid := []struct {
		name string
		app  string
		want string
	}{
		{name: "empty", app: "", want: "non-empty"},
		{name: "leading space", app: " League", want: "surrounding whitespace"},
		{name: "trailing Unicode space", app: "League\u2003", want: "surrounding whitespace"},
		{name: "option-like", app: "-League", want: "must not begin"},
		{name: "too many bytes", app: strings.Repeat("é", 64) + "a", want: "128 bytes"},
		{name: "invalid UTF-8", app: string([]byte{'L', 0xff}), want: "valid UTF-8"},
		{name: "C0 tab", app: "League\tClient", want: "control characters"},
		{name: "DEL", app: "League\u007f", want: "control characters"},
		{name: "C1 next line", app: "League\u0085Client", want: "control characters"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAppName(tt.app)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateAppName(%q) error = %v, want %q", tt.app, err, tt.want)
			}
		})
	}

	// Verify the contract against every rune in Unicode's Control category,
	// including all ASCII C0/DEL and Unicode C1 control characters.
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.IsControl(r) {
			continue
		}
		if err := ValidateAppName("League" + string(r) + "Client"); err == nil {
			t.Fatalf("ValidateAppName accepted control character U+%04X", r)
		}
	}
}

func TestWriteNewRoundTripAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	cfg := Default()
	cfg.RemoteHost.Host = "pc.local"
	cfg.RemoteHost.PhysicalHostConfirmed = true
	if err := WriteNew(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RemoteHost.Host != cfg.RemoteHost.Host {
		t.Fatalf("unexpected config: %+v", loaded)
	}
	if err := WriteNew(path, cfg); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
}
