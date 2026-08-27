package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultPathSources(t *testing.T) {
	override := filepath.Join(t.TempDir(), "nested", "..", "config.json")
	t.Setenv("LEAGUEBRIDGE_CONFIG", "  "+override+"  ")
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath() with override: %v", err)
	}
	if want := filepath.Clean(override); got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}

	t.Setenv("LEAGUEBRIDGE_CONFIG", "")
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir(): %v", err)
	}
	got, err = DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath() with user directory: %v", err)
	}
	if want := filepath.Join(dir, "leaguebridge", "config.json"); got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestDefaultPathReportsMissingUserDirectory(t *testing.T) {
	t.Setenv("LEAGUEBRIDGE_CONFIG", "")
	switch runtime.GOOS {
	case "windows":
		t.Setenv("AppData", "")
	case "plan9":
		t.Setenv("home", "")
	default:
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "")
	}
	if _, err := DefaultPath(); err == nil || !strings.Contains(err.Error(), "locate user configuration directory") {
		t.Fatalf("DefaultPath() error = %v", err)
	}
}

func TestLoadDefaultSuccessAndNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := Default()
	cfg.RemoteHost.Host = "pc.local"
	cfg.RemoteHost.PhysicalHostConfirmed = true
	if err := WriteNew(path, cfg); err != nil {
		t.Fatalf("WriteNew(): %v", err)
	}
	t.Setenv("LEAGUEBRIDGE_CONFIG", path)

	loaded, gotPath, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault(): %v", err)
	}
	if gotPath != path || loaded != cfg {
		t.Fatalf("LoadDefault() = (%+v, %q), want (%+v, %q)", loaded, gotPath, cfg, path)
	}

	missing := filepath.Join(dir, "missing.json")
	t.Setenv("LEAGUEBRIDGE_CONFIG", missing)
	_, gotPath, err = LoadDefault()
	if !errors.Is(err, ErrNotFound) || gotPath != missing {
		t.Fatalf("LoadDefault() = (_, %q, %v), want path %q and ErrNotFound", gotPath, err, missing)
	}
}

func TestLoadReportsOpenReadParseAndValidationErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load("invalid\x00path"); err == nil || !strings.Contains(err.Error(), "open configuration") {
		t.Fatalf("Load() open error = %v", err)
	}

	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Load() directory error = %v", err)
	}

	valid := `{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true}}`
	tests := []struct {
		name    string
		data    string
		message string
	}{
		{name: "malformed", data: `{`, message: "parse configuration"},
		{name: "malformed trailing value", data: valid + ` {`, message: "parse trailing configuration data"},
		{name: "invalid value", data: strings.Replace(valid, `"schema_version":1`, `"schema_version":99`, 1), message: "unsupported configuration schema_version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("Load() error = %v, want message containing %q", err, tt.message)
			}
		})
	}
}

func TestValidateCoversAllConfigConstraints(t *testing.T) {
	valid := Default()
	valid.RemoteHost.Host = "pc.local"

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "invalid host", mutate: func(c *Config) { c.RemoteHost.Host = "bad host" }},
		{name: "app whitespace", mutate: func(c *Config) { c.RemoteHost.App = " League" }},
		{name: "app too long", mutate: func(c *Config) { c.RemoteHost.App = strings.Repeat("a", 129) }},
		{name: "app control character", mutate: func(c *Config) { c.RemoteHost.App = "League\n" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}

	for _, client := range []string{"auto", "moonlight", "moonlight-qt", "flatpak"} {
		cfg := valid
		cfg.RemoteHost.Client = client
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() rejected client %q: %v", client, err)
		}
	}
}

func TestValidateHostBoundaryCases(t *testing.T) {
	valid := []string{
		"localhost",
		strings.Repeat("a", 63) + ".local",
		"fe80::1%eth0",
	}
	for _, host := range valid {
		if err := ValidateHost(host); err != nil {
			t.Errorf("ValidateHost(%q): %v", host, err)
		}
	}

	invalid := []string{
		strings.Repeat("a", 254),
		"host:1234",
		"bad..local",
		strings.Repeat("a", 64) + ".local",
		"-bad.local",
		"bad-.local",
		"bad!.local",
	}
	for _, host := range invalid {
		if err := ValidateHost(host); err == nil {
			t.Errorf("ValidateHost(%q) unexpectedly succeeded", host)
		}
	}
}

func TestMarshalExampleIsLoadable(t *testing.T) {
	data, err := MarshalExample()
	if err != nil {
		t.Fatalf("MarshalExample(): %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("MarshalExample() did not append a newline: %q", data)
	}
	path := filepath.Join(t.TempDir(), "example.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(example): %v", err)
	}
	if cfg.RemoteHost.Host != "gaming-pc.local" {
		t.Fatalf("example host = %q", cfg.RemoteHost.Host)
	}
}

func TestWriteNewRejectsInvalidConfigAndUncreatableDirectory(t *testing.T) {
	invalid := Default()
	if err := WriteNew(filepath.Join(t.TempDir(), "config.json"), invalid); err == nil {
		t.Fatal("WriteNew() accepted an invalid configuration")
	}

	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := Default()
	valid.RemoteHost.Host = "pc.local"
	err := WriteNew(filepath.Join(blocker, "config.json"), valid)
	if err == nil || !strings.Contains(err.Error(), "create configuration directory") {
		t.Fatalf("WriteNew() error = %v", err)
	}
}
