package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/config"
	"github.com/Yunushan/leaguebridge/internal/diagnostics"
	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/remote"
)

var fixedNow = time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)

type scriptedProber struct {
	reports  map[probe.Profile]probe.Report
	profiles []probe.Profile
	contexts []context.Context
}

func (p *scriptedProber) Run(ctx context.Context, profile probe.Profile) probe.Report {
	p.profiles = append(p.profiles, profile)
	p.contexts = append(p.contexts, ctx)
	if report, ok := p.reports[profile]; ok {
		return report
	}
	return probeReport(profile, probe.StatusPass)
}

type fakeRemoteEnvironment struct {
	paths map[string]string
}

func (e fakeRemoteEnvironment) LookPath(file string) (string, error) {
	if path := e.paths[file]; path != "" {
		return path, nil
	}
	return "", errors.New("not found")
}

type recordingRemoteRunner struct {
	name        string
	args        []string
	stdin       io.Reader
	ctx         context.Context
	called      int
	output      string
	errorOutput string
	err         error
}

func (r *recordingRemoteRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	r.called++
	r.ctx = ctx
	r.stdin = stdin
	r.name = name
	r.args = append([]string(nil), args...)
	if r.err == nil {
		output := r.output
		if output == "" {
			output = "moonlight output\n"
		}
		_, _ = io.WriteString(stdout, output)
		if r.errorOutput != "" {
			_, _ = io.WriteString(stderr, r.errorOutput)
		}
	}
	return r.err
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func probeReport(profile probe.Profile, status probe.Status) probe.Report {
	checkStatus := status
	if checkStatus == "" {
		checkStatus = probe.StatusPass
	}
	return probe.Report{
		SchemaVersion: probe.SchemaVersion,
		Profile:       profile,
		OS:            "linux",
		Architecture:  "amd64",
		Status:        status,
		Checks: []probe.Check{{
			ID:       "fixture.check",
			Status:   checkStatus,
			Summary:  "Fixture summary.",
			Guidance: "Fixture guidance.",
		}},
	}
}

func readyClientReport() probe.Report {
	return probe.Report{
		SchemaVersion: probe.SchemaVersion,
		Profile:       probe.ProfileClient,
		OS:            "linux",
		Architecture:  "amd64",
		Status:        probe.StatusPass,
		Checks: []probe.Check{
			{ID: "client.platform", Status: probe.StatusPass, Summary: "Fixture platform."},
			{ID: "client.graphical-session", Status: probe.StatusPass, Summary: "Fixture graphical session."},
			{ID: "client.input", Status: probe.StatusPass, Summary: "Fixture input path."},
			{ID: "client.moonlight", Status: probe.StatusPass, Summary: "Fixture Moonlight."},
			{ID: "client.audio", Status: probe.StatusPass, Summary: "Fixture audio."},
			{ID: "client.decoder-tools", Status: probe.StatusPass, Summary: "Fixture decoder."},
		},
	}
}

func newTestApp(t *testing.T) (*App, *bytes.Buffer, *bytes.Buffer, *scriptedProber, *recordingRemoteRunner) {
	t.Helper()
	defaultConfig := filepath.Join(t.TempDir(), "missing-default-config.json")
	t.Setenv("LEAGUEBRIDGE_CONFIG", defaultConfig)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	prober := &scriptedProber{reports: map[probe.Profile]probe.Report{
		probe.ProfileClient:      readyClientReport(),
		probe.ProfileWindowsHost: probeReport(probe.ProfileWindowsHost, probe.StatusPass),
		probe.ProfileMacOSHost:   probeReport(probe.ProfileMacOSHost, probe.StatusWarn),
	}}
	runner := &recordingRemoteRunner{}
	a := New(strings.NewReader("fixture input"), stdout, stderr)
	a.Now = func() time.Time { return fixedNow }
	a.GOOS = "linux"
	a.GOARCH = "amd64"
	a.NewProber = func() ProbeRunner { return prober }
	a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-qt": "/fixture/moonlight-qt"}}
	a.RemoteRunner = runner
	a.RepositoryEvidenceVerification = readiness.ExpectedRepositoryEvidenceVerification()
	return a, stdout, stderr, prober, runner
}

func useRealRemoteFixture(t *testing.T, a *App) string {
	t.Helper()
	directory := t.TempDir()
	name := "moonlight-qt"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	return path
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeConfigFile(t *testing.T, path string, mutate func(*config.Config)) {
	t.Helper()
	cfg := config.Default()
	cfg.RemoteHost.Host = "gaming-pc.local"
	cfg.RemoteHost.PhysicalHostConfirmed = true
	if mutate != nil {
		mutate(&cfg)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(data, '\n'))
}

func decodeEnvelope(t *testing.T, data []byte) jsonEnvelope {
	t.Helper()
	var envelope jsonEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode envelope: %v\n%s", err, data)
	}
	return envelope
}

func TestNewAndRunDispatch(t *testing.T) {
	stdin := strings.NewReader("")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	created := New(stdin, stdout, stderr)
	if created.Stdin != stdin || created.Stdout != stdout || created.Stderr != stderr {
		t.Fatal("New did not retain supplied streams")
	}
	if created.Now == nil || created.NewProber == nil || created.RemoteEnv == nil || created.RemoteRunner == nil {
		t.Fatal("New left a production dependency unset")
	}

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput string
		stderr     bool
	}{
		{name: "missing", wantCode: ExitUsage, wantOutput: "Usage:"},
		{name: "help", args: []string{"help"}, wantCode: ExitOK, wantOutput: "LeagueBridge"},
		{name: "short help", args: []string{"-h"}, wantCode: ExitOK, wantOutput: "Usage:"},
		{name: "long help", args: []string{"--help"}, wantCode: ExitOK, wantOutput: "Vanguard"},
		{name: "unknown", args: []string{"nope"}, wantCode: ExitUsage, wantOutput: `unknown command "nope"`, stderr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, _, _ := newTestApp(t)
			code := a.Run(nil, tt.args)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d", code, tt.wantCode)
			}
			got := out.String()
			if tt.stderr {
				got = errOut.String()
			}
			if !strings.Contains(got, tt.wantOutput) {
				t.Fatalf("output %q does not contain %q", got, tt.wantOutput)
			}
		})
	}
}

func TestOutputHelpers(t *testing.T) {
	t.Run("JSON success and escaping", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.writeJSON("fixture", map[string]string{"html": "<safe>"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), "<safe>") {
			t.Fatalf("HTML was unexpectedly escaped: %s", out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		if envelope.SchemaVersion != 1 || envelope.Command != "fixture" || !envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})

	t.Run("JSON encode failure", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.writeJSON("fixture", make(chan int)); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "encode output") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("human command error", func(t *testing.T) {
		a, out, errOut, _, _ := newTestApp(t)
		if code := a.commandError("fixture", false, ExitBlocked, "bad %s", "news"); code != ExitBlocked {
			t.Fatalf("code = %d", code)
		}
		if out.Len() != 0 || !strings.Contains(errOut.String(), "bad news") {
			t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
		}
	})

	t.Run("JSON command error", func(t *testing.T) {
		a, out, errOut, _, _ := newTestApp(t)
		if code := a.commandError("fixture", true, ExitUsage, "bad input"); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		if envelope.OK || envelope.Error != "bad input" || errOut.Len() != 0 {
			t.Fatalf("envelope=%+v stderr=%q", envelope, errOut.String())
		}
	})

	t.Run("JSON command error write failure", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Stdout = failingWriter{errors.New("closed")}
		if code := a.commandError("fixture", true, ExitUsage, "original failure"); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "original failure") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("flag and generic JSON helpers", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		set := a.flagSet("fixture")
		value := set.Bool("ok", false, "fixture")
		if err := parseFlags(set, []string{"--ok"}); err != nil || !*value {
			t.Fatalf("parse = %v, value = %v", err, *value)
		}
		set = a.flagSet("fixture")
		if err := parseFlags(set, []string{"extra"}); err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
			t.Fatalf("unexpected parse error: %v", err)
		}
		set = a.flagSet("fixture")
		if err := parseFlags(set, []string{"--missing"}); err == nil || errOut.Len() == 0 {
			t.Fatalf("unexpected flag parse result: %v, stderr=%q", err, errOut.String())
		}
		var out bytes.Buffer
		if err := printJSONValue(&out, map[string]string{"x": "<y>"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "<y>") {
			t.Fatalf("output = %q", out.String())
		}
		if err := printJSONValue(failingWriter{errors.New("closed")}, struct{}{}); err == nil {
			t.Fatal("expected write failure")
		}
	})
}

func TestVersionHumanJSONAndUsageError(t *testing.T) {
	t.Run("human", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"version"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		for _, want := range []string{"LeagueBridge", "commit:", "built:", "Go:"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output %q lacks %q", out.String(), want)
			}
		}
	})

	t.Run("JSON", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"version", "--json"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.Command != "version" || !envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})

	t.Run("JSON usage error", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"version", "--json", "extra"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.OK || !strings.Contains(envelope.Error, "unexpected arguments") {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})
}

func TestStatusHumanJSONAndErrors(t *testing.T) {
	t.Run("human", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"status"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		for _, want := range []string{"Evidence: FRESH", "Engineering readiness: 74/100", "Repository evidence: VERIFIED", "physical-windows-remote", "physical-macos-remote", "no aggregate support score", "gamepad hosting is unavailable", "linux/amd64", "UNVALIDATED", "native-linux", "No flag can turn"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output lacks %q:\n%s", want, out.String())
			}
		}
	})

	t.Run("JSON", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"status", "--json"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		if envelope.Command != "status" || !envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
		data, ok := envelope.Data.(map[string]any)
		remoteHandoffs, remoteOK := data["remote_handoffs"].([]any)
		if !ok || data["manifest_id"] == "" || data["backends"] == nil || data["engineering_score"] != float64(74) || data["repository_evidence_verified"] != true || !remoteOK || len(remoteHandoffs) != 2 {
			t.Fatalf("unexpected status data: %#v", envelope.Data)
		}
		for _, value := range remoteHandoffs {
			remote := value.(map[string]any)
			if remote["score"] != float64(0) || remote["platforms"] == nil {
				t.Fatalf("unexpected remote status: %#v", remote)
			}
		}
	})

	t.Run("usage", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"status", "extra"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "unexpected arguments") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("zero evaluation time", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Now = func() time.Time { return time.Time{} }
		if code := a.Run(context.Background(), []string{"status"}); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "freshness") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})
}

func TestAssessDeniesHumanAndJSON(t *testing.T) {
	t.Run("missing backend", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"assess"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "--backend is required") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("human denial", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"assess", "--backend", "wine", "--platform", "linux", "--arch", "amd64"})
		if code != ExitBlocked {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), "DENY:") || !strings.Contains(out.String(), "https://") {
			t.Fatalf("output = %q", out.String())
		}
	})

	t.Run("JSON denial and DragonFly normalization", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"assess", "--backend", "native-bsd", "--platform", "DragonFly", "--arch", "amd64", "--json"})
		if code != ExitBlocked {
			t.Fatalf("code = %d", code)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		if !envelope.OK || envelope.Command != "assess" {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
		verdict := envelope.Data.(map[string]any)
		if verdict["decision"] != "deny" || verdict["code"] == "UNKNOWN_HOST_PLATFORM" {
			t.Fatalf("unexpected verdict: %#v", verdict)
		}
	})

	t.Run("JSON flag error", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"assess", "--json", "--bad"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})

	platforms := map[string]compat.Platform{
		"dragonfly":    compat.PlatformDragonFlyBSD,
		"DragonFlyBSD": compat.PlatformDragonFlyBSD,
		"LINUX":        compat.PlatformLinux,
	}
	for input, want := range platforms {
		if got := normalizeCompatPlatform(input); got != want {
			t.Errorf("normalizeCompatPlatform(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestManifestCommands(t *testing.T) {
	t.Run("dispatch errors", func(t *testing.T) {
		for _, args := range [][]string{{"manifest"}, {"manifest", "unknown"}, {"manifest", "show", "extra"}} {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), args); code != ExitUsage {
				t.Fatalf("%v code = %d", args, code)
			}
			if errOut.Len() == 0 {
				t.Fatalf("%v emitted no error", args)
			}
		}
	})

	t.Run("show", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"manifest", "show"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		var manifest compat.Manifest
		if err := json.Unmarshal(out.Bytes(), &manifest); err != nil || manifest.ManifestID == "" {
			t.Fatalf("manifest=%+v err=%v", manifest, err)
		}
	})

	t.Run("show write failure", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Stdout = failingWriter{errors.New("closed")}
		if code := a.Run(context.Background(), []string{"manifest", "show"}); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "write manifest") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("verify human fresh", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"manifest", "verify"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), "structurally valid") || !strings.Contains(out.String(), "fresh") {
			t.Fatalf("output = %q", out.String())
		}
	})

	t.Run("verify JSON", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"manifest", "verify", "--json"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.Command != "manifest verify" || !envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})

	t.Run("verify stale", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		a.Now = func() time.Time { return fixedNow.AddDate(2, 0, 0) }
		if code := a.Run(context.Background(), []string{"manifest", "verify"}); code != ExitBlocked {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), "stale") {
			t.Fatalf("output = %q", out.String())
		}
	})

	t.Run("verify invalid time", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Now = func() time.Time { return time.Time{} }
		if code := a.Run(context.Background(), []string{"manifest", "verify"}); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "freshness check failed") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("verify JSON usage", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"manifest", "verify", "--json", "extra"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})
}

func TestManifestValidateAndReadBounded(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.json")
	writeFile(t, valid, compat.EmbeddedJSON())

	t.Run("valid", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"manifest", "validate", "--file", valid}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), "informational only") {
			t.Fatalf("output = %q", out.String())
		}
	})

	tests := []struct {
		name     string
		args     []string
		prepare  func(t *testing.T) string
		wantCode int
		want     string
	}{
		{name: "missing flag", args: []string{"manifest", "validate"}, wantCode: ExitUsage, want: "--file is required"},
		{name: "unexpected argument", args: []string{"manifest", "validate", "extra"}, wantCode: ExitUsage, want: "unexpected arguments"},
		{name: "missing file", args: []string{"manifest", "validate", "--file", filepath.Join(dir, "missing")}, wantCode: ExitUsage, want: "read manifest"},
		{name: "directory", prepare: func(t *testing.T) string {
			return t.TempDir()
		}, wantCode: ExitUsage, want: "not a regular file"},
		{name: "symlink", prepare: func(t *testing.T) string {
			directory := t.TempDir()
			target := filepath.Join(directory, "manifest.json")
			writeFile(t, target, compat.EmbeddedJSON())
			link := filepath.Join(directory, "manifest-link.json")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			return link
		}, wantCode: ExitUsage, want: "not a regular file"},
		{name: "empty", prepare: func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "empty.json")
			writeFile(t, path, nil)
			return path
		}, wantCode: ExitUsage, want: "file is empty"},
		{name: "invalid", prepare: func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "bad.json")
			writeFile(t, path, []byte("{}"))
			return path
		}, wantCode: ExitBlocked, want: "manifest is invalid"},
		{name: "too large", prepare: func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "large.json")
			writeFile(t, path, bytes.Repeat([]byte{'x'}, compat.MaxManifestBytes+1))
			return path
		}, wantCode: ExitUsage, want: "file exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string(nil), tt.args...)
			if tt.prepare != nil {
				args = []string{"manifest", "validate", "--file", tt.prepare(t)}
			}
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), args); code != tt.wantCode {
				t.Fatalf("code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(errOut.String(), tt.want) {
				t.Fatalf("stderr %q does not contain %q", errOut.String(), tt.want)
			}
		})
	}

	data, err := readBounded(valid, compat.MaxManifestBytes)
	if err != nil || !bytes.Equal(data, compat.EmbeddedJSON()) {
		t.Fatalf("readBounded valid: len=%d err=%v", len(data), err)
	}
	if _, err := readBounded(filepath.Join(dir, "missing"), 1); err == nil {
		t.Fatal("readBounded unexpectedly opened missing file")
	}
}

func TestReadinessHumanJSONAndUsage(t *testing.T) {
	t.Run("human", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"readiness"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		for _, want := range []string{"Engineering readiness: 74/100", "Repository evidence: VERIFIED", "Local Linux/BSD gameplay:", "Remote physical-host handoffs", "no aggregate support score", "physical-windows-remote", "physical-macos-remote", "gamepad hosting is unavailable", "linux/amd64", "dragonflybsd/amd64", "physical-host", "UNVALIDATED"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output lacks %q:\n%s", want, out.String())
			}
		}
	})

	t.Run("JSON", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"readiness", "--json"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		data := envelope.Data.(map[string]any)
		remoteHandoffs, remoteOK := data["remote_handoffs"].([]any)
		engineering, engineeringOK := data["engineering"].([]any)
		if envelope.Command != "readiness" || data["engineering_score"] != float64(74) || data["repository_evidence_verified"] != true || !engineeringOK || len(engineering) != 7 || data["schema_version"] != float64(3) || !remoteOK || len(remoteHandoffs) != 2 {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
		for _, value := range remoteHandoffs {
			remote := value.(map[string]any)
			if remote["score"] != float64(0) || remote["state"] != "unvalidated" || remote["platforms"] == nil {
				t.Fatalf("unexpected remote evaluation: %+v", remote)
			}
		}
		firstCategory := engineering[0].(map[string]any)
		if firstCategory["score"] != float64(10) || firstCategory["weight"] != float64(10) || firstCategory["earned"] != nil {
			t.Fatalf("category score is not derived cleanly: %+v", firstCategory)
		}
	})

	t.Run("JSON usage", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"readiness", "--json", "extra"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})
}

func TestUserFacingEngineeringScoreFailsClosedWithoutBuildVerification(t *testing.T) {
	for _, command := range []string{"status", "readiness"} {
		t.Run(command, func(t *testing.T) {
			a, out, _, _, _ := newTestApp(t)
			a.RepositoryEvidenceVerification = ""
			if code := a.Run(context.Background(), []string{command, "--json"}); code != ExitOK {
				t.Fatalf("code = %d", code)
			}
			data := decodeEnvelope(t, out.Bytes()).Data.(map[string]any)
			if data["engineering_score"] != float64(0) || data["repository_evidence_verified"] != false || !strings.Contains(data["repository_evidence_verification_reason"].(string), "absent or does not match") {
				t.Fatalf("unverified %s data = %#v", command, data)
			}
			if categories, ok := data["engineering"].([]any); ok {
				for _, category := range categories {
					if category.(map[string]any)["score"] != float64(0) {
						t.Fatalf("unverified category retained points: %#v", category)
					}
				}
			}
		})
	}

	t.Run("bundle", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		a.RepositoryEvidenceVerification = ""
		if code := a.Run(context.Background(), []string{"bundle", "--preview"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		var report diagnostics.Report
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		for _, check := range report.Checks {
			if check.ID == "readiness.engineering" {
				if check.Status != diagnostics.StatusFail || !strings.Contains(check.Summary, "0 of 100") || !strings.Contains(check.Detail, "absent or does not match") {
					t.Fatalf("unverified readiness check = %+v", check)
				}
				return
			}
		}
		t.Fatal("readiness.engineering check is missing")
	})
}

func TestDoctorPassFailProfilesAndErrors(t *testing.T) {
	t.Run("human pass default client", func(t *testing.T) {
		a, out, _, prober, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"doctor"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), "Preflight client") || !strings.Contains(out.String(), "[PASS] client.platform") {
			t.Fatalf("output = %q", out.String())
		}
		if !reflect.DeepEqual(prober.profiles, []probe.Profile{probe.ProfileClient}) || prober.contexts[0] == nil {
			t.Fatalf("profiles=%v contexts=%v", prober.profiles, prober.contexts)
		}
	})

	t.Run("JSON fail", func(t *testing.T) {
		a, out, _, prober, _ := newTestApp(t)
		prober.reports[probe.ProfileWindowsHost] = probeReport(probe.ProfileWindowsHost, probe.StatusFail)
		if code := a.Run(context.Background(), []string{"doctor", "--profile", "WINDOWS-HOST", "--json"}); code != ExitBlocked {
			t.Fatalf("code = %d", code)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		data := envelope.Data.(map[string]any)
		if data["status"] != "fail" || data["profile"] != "windows-host" {
			t.Fatalf("unexpected report: %#v", data)
		}
	})

	t.Run("Windows default", func(t *testing.T) {
		a, _, _, prober, _ := newTestApp(t)
		a.GOOS = "WINDOWS"
		if code := a.Run(context.Background(), []string{"doctor"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if got := prober.profiles[0]; got != probe.ProfileWindowsHost {
			t.Fatalf("profile = %q", got)
		}
	})

	t.Run("macOS default remains blocked", func(t *testing.T) {
		a, _, _, prober, _ := newTestApp(t)
		a.GOOS = "DARWIN"
		if code := a.Run(context.Background(), []string{"doctor"}); code != ExitBlocked {
			t.Fatalf("code = %d", code)
		}
		if got := prober.profiles[0]; got != probe.ProfileMacOSHost {
			t.Fatalf("profile = %q", got)
		}
	})

	t.Run("invalid profile", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"doctor", "--profile", "server"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "profile must be client, windows-host, macos-host, or compatibility") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("JSON usage", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"doctor", "--json", "extra"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.OK {
			t.Fatalf("unexpected envelope: %+v", envelope)
		}
	})

	if got := defaultProfileName("LiNuX"); got != "client" {
		t.Errorf("Linux default profile = %q", got)
	}
	if got := defaultProfileName("DaRwIn"); got != "macos-host" {
		t.Errorf("macOS default profile = %q", got)
	}
	for _, value := range []string{" client ", "WINDOWS-HOST", "MACOS-HOST"} {
		if _, err := parseProfile(value); err != nil {
			t.Errorf("parseProfile(%q): %v", value, err)
		}
	}
}

func TestBundlePreviewWriteAndNoOverwrite(t *testing.T) {
	t.Run("preview default", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"bundle"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		var report diagnostics.Report
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatalf("decode preview: %v\n%s", err, out.String())
		}
		if report.SchemaVersion != diagnostics.SchemaVersion || len(report.Checks) < 4 {
			t.Fatalf("unexpected report: %+v", report)
		}
	})

	t.Run("explicit preview", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"bundle", "--preview", "--profile", "windows-host"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), `"fixture.check"`) {
			t.Fatalf("output = %q", out.String())
		}
	})

	t.Run("write and refuse overwrite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "support.zip")
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"bundle", "--output", path}); code != ExitOK {
			t.Fatalf("write code = %d", code)
		}
		if !strings.Contains(out.String(), "Inspect it") {
			t.Fatalf("stdout = %q", out.String())
		}
		archive, err := zip.OpenReader(path)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, file := range archive.File {
			names = append(names, file.Name)
		}
		_ = archive.Close()
		if !reflect.DeepEqual(names, []string{"README.txt", "report.json"}) {
			t.Fatalf("archive entries = %v", names)
		}

		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"bundle", "--output", path}); code != ExitUsage {
			t.Fatalf("overwrite code = %d", code)
		}
		if !strings.Contains(errOut.String(), "refusing to overwrite") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("argument errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.zip")
		for _, args := range [][]string{
			{"bundle", "--preview", "--output", path},
			{"bundle", "--profile", "unknown"},
			{"bundle", "extra"},
		} {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), args); code != ExitUsage {
				t.Fatalf("%v code = %d", args, code)
			}
			if errOut.Len() == 0 {
				t.Fatalf("%v emitted no error", args)
			}
		}
	})

	t.Run("preview writer failure", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Stdout = failingWriter{errors.New("closed")}
		if code := a.Run(context.Background(), []string{"bundle", "--preview"}); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "write preview") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("invalid output parent", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		path := filepath.Join(t.TempDir(), "missing", "support.zip")
		if code := a.Run(context.Background(), []string{"bundle", "--output", path}); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "write support bundle") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})
}

func TestDiagnosticReportAndStatusMapping(t *testing.T) {
	a, _, _, _, _ := newTestApp(t)
	report := probe.Report{
		SchemaVersion: probe.SchemaVersion,
		Profile:       probe.ProfileClient,
		OS:            "linux",
		Architecture:  "amd64",
		Status:        probe.StatusWarn,
		Checks: []probe.Check{
			{ID: "a", Status: probe.StatusPass, Summary: "pass"},
			{ID: "b", Status: probe.StatusWarn, Summary: "warn"},
			{ID: "c", Status: probe.StatusFail, Summary: "fail"},
			{ID: "d", Status: probe.Status("mystery"), Summary: "unknown"},
		},
	}
	diagnostic, err := a.diagnosticReport(report)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]diagnostics.Status{}
	for _, check := range diagnostic.Checks {
		statuses[check.ID] = check.Status
	}
	want := map[string]diagnostics.Status{
		"a":                     diagnostics.StatusPass,
		"b":                     diagnostics.StatusWarn,
		"c":                     diagnostics.StatusFail,
		"d":                     diagnostics.StatusInfo,
		"manifest.freshness":    diagnostics.StatusPass,
		"compat.gameplay-local": diagnostics.StatusFail,
		"compat.remote-handoff": diagnostics.StatusInfo,
		"readiness.engineering": diagnostics.StatusInfo,
	}
	for id, status := range want {
		if statuses[id] != status {
			t.Errorf("%s status = %q, want %q", id, statuses[id], status)
		}
	}

	a.Now = func() time.Time { return fixedNow.AddDate(2, 0, 0) }
	diagnostic, err = a.diagnosticReport(probeReport(probe.ProfileClient, probe.StatusPass))
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range diagnostic.Checks {
		if check.ID == "manifest.freshness" && check.Status != diagnostics.StatusFail {
			t.Errorf("stale freshness status = %q", check.Status)
		}
	}

	a.Now = func() time.Time { return time.Time{} }
	if _, err := a.diagnosticReport(probeReport(probe.ProfileClient, probe.StatusPass)); err == nil {
		t.Fatal("zero evaluation time unexpectedly succeeded")
	}

	statusCases := map[probe.Status]diagnostics.Status{
		probe.StatusPass:        diagnostics.StatusPass,
		probe.StatusWarn:        diagnostics.StatusWarn,
		probe.StatusFail:        diagnostics.StatusFail,
		probe.Status("unknown"): diagnostics.StatusInfo,
	}
	for input, expected := range statusCases {
		if got := diagnosticStatus(input); got != expected {
			t.Errorf("diagnosticStatus(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestConfigCommands(t *testing.T) {
	t.Run("dispatch errors", func(t *testing.T) {
		for _, args := range [][]string{{"config"}, {"config", "unknown"}, {"config", "example", "extra"}, {"config", "path", "extra"}} {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), args); code != ExitUsage {
				t.Fatalf("%v code = %d", args, code)
			}
			if errOut.Len() == 0 {
				t.Fatalf("%v emitted no error", args)
			}
		}
	})

	t.Run("example", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"config", "example"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		var cfg config.Config
		if err := json.Unmarshal(out.Bytes(), &cfg); err != nil || cfg.RemoteHost.Host != "gaming-pc.local" {
			t.Fatalf("config=%+v err=%v", cfg, err)
		}
	})

	t.Run("macOS example uses one schema-v2 target", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"config", "example", "--route", "macos"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		var raw map[string]any
		if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		if raw["schema_version"] != float64(2) || raw["route_id"] != string(config.RouteMacOS) || raw["remote_host"] == nil {
			t.Fatalf("macOS example = %#v", raw)
		}
		for _, forbidden := range []string{"backend", "remote_windows", "remote_macos"} {
			if _, ok := raw[forbidden]; ok {
				t.Errorf("macOS example contains %q: %#v", forbidden, raw)
			}
		}
	})

	t.Run("example writer failure", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Stdout = failingWriter{errors.New("closed")}
		if code := a.Run(context.Background(), []string{"config", "example"}); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "write example") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("path", func(t *testing.T) {
		a, out, _, _, _ := newTestApp(t)
		want := filepath.Join(t.TempDir(), "custom.json")
		t.Setenv("LEAGUEBRIDGE_CONFIG", want)
		if code := a.Run(context.Background(), []string{"config", "path"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if strings.TrimSpace(out.String()) != filepath.Clean(want) {
			t.Fatalf("path = %q, want %q", out.String(), filepath.Clean(want))
		}
	})

	t.Run("init validate and no overwrite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "config.json")
		a, out, _, _, _ := newTestApp(t)
		args := []string{"config", "init", "--file", path, "--host", "gaming-pc.local", "--app", "League", "--client", "moonlight-qt", "--confirm-physical-host"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("init code = %d", code)
		}
		if !strings.Contains(out.String(), "Created credential-free") {
			t.Fatalf("stdout = %q", out.String())
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RemoteHost.Host != "gaming-pc.local" || cfg.RemoteHost.App != "League" || !cfg.RemoteHost.PhysicalHostConfirmed {
			t.Fatalf("written config = %+v", cfg)
		}

		a, out, _, _, _ = newTestApp(t)
		if code := a.Run(context.Background(), []string{"config", "validate", "--file", path}); code != ExitOK {
			t.Fatalf("validate code = %d", code)
		}
		if !strings.Contains(out.String(), path) {
			t.Fatalf("stdout = %q", out.String())
		}

		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), args); code != ExitUsage {
			t.Fatalf("overwrite code = %d", code)
		}
		if !strings.Contains(errOut.String(), "refusing to overwrite") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("initialized config feeds the route-bound stream plan", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "remote.json")
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{
			"config", "init", "--file", path, "--host", "gaming-pc.local",
			"--app", "League", "--client", "moonlight-qt", "--confirm-physical-host",
		}); code != ExitOK {
			t.Fatalf("init code = %d; stderr=%q", code, errOut.String())
		}

		a, out, errOut, _, runner := newTestApp(t)
		if code := a.Run(context.Background(), []string{
			"remote", "stream", "--config", path, "--resolution", "1440",
			"--acknowledge-unverified-handoff", "--dry-run", "--json",
		}); code != ExitOK {
			t.Fatalf("stream code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-1440", "gaming-pc.local", "League"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("init default path with warning", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "default", "config.json")
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		a, out, _, _, _ := newTestApp(t)
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		if code := a.Run(context.Background(), []string{"config", "init", "--host", "pc.local"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out.String(), "Remote operations remain blocked") {
			t.Fatalf("stdout = %q", out.String())
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("init macOS route", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "macos.json")
		a, _, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"config", "init", "--file", path, "--route", "macos", "--host", "gaming-mac.local", "--confirm-physical-host"}); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SchemaVersion != config.SchemaVersion || cfg.RouteID != config.RouteMacOS || cfg.RemoteHost.Host != "gaming-mac.local" {
			t.Fatalf("macOS config = %+v", cfg)
		}
	})

	t.Run("init validation and parsing failures", func(t *testing.T) {
		for _, args := range [][]string{
			{"config", "init", "--file", filepath.Join(t.TempDir(), "bad.json"), "--host", "-bad"},
			{"config", "init", "--file", filepath.Join(t.TempDir(), "route.json"), "--route", "darwin", "--host", "mac.local"},
			{"config", "init", "extra"},
		} {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), args); code != ExitUsage {
				t.Fatalf("%v code = %d", args, code)
			}
			if errOut.Len() == 0 {
				t.Fatalf("%v emitted no error", args)
			}
		}
	})

	t.Run("init rejects option-like app without writing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		a, _, errOut, _, _ := newTestApp(t)
		args := []string{"config", "init", "--file", path, "--host", "pc.local", "--app=-League"}
		if code := a.Run(context.Background(), args); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "remote_host.app") || !strings.Contains(errOut.String(), "must not begin") {
			t.Fatalf("stderr = %q", errOut.String())
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected configuration created destination: %v", err)
		}
	})

	t.Run("validate default and invalid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "default.json")
		writeConfigFile(t, path, nil)
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		a, out, _, _, _ := newTestApp(t)
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		if code := a.Run(context.Background(), []string{"config", "validate"}); code != ExitOK {
			t.Fatalf("default validate code = %d", code)
		}
		if !strings.Contains(out.String(), path) {
			t.Fatalf("stdout = %q", out.String())
		}

		invalid := filepath.Join(t.TempDir(), "invalid.json")
		writeFile(t, invalid, []byte("{}"))
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"config", "validate", "--file", invalid}); code != ExitBlocked {
			t.Fatalf("invalid validate code = %d", code)
		}
		if !strings.Contains(errOut.String(), "invalid configuration") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("validate parsing failure", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"config", "validate", "extra"}); code != ExitUsage {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "unexpected arguments") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})
}

func TestLoadRemoteConfig(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, nil)
		cfg, used, err := loadRemoteConfig(path)
		if err != nil || used != path || cfg.RemoteHost.Host != "gaming-pc.local" {
			t.Fatalf("cfg=%+v used=%q err=%v", cfg, used, err)
		}
	})

	t.Run("explicit missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.json")
		if _, used, err := loadRemoteConfig(path); err == nil || used != path || !strings.Contains(err.Error(), "load configuration") {
			t.Fatalf("used=%q err=%v", used, err)
		}
	})

	t.Run("default absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.json")
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		cfg, used, err := loadRemoteConfig("")
		if err != nil || used != "" || cfg.RemoteHost.App == "" {
			t.Fatalf("cfg=%+v used=%q err=%v", cfg, used, err)
		}
	})

	t.Run("default absent selects macOS", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.json")
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		cfg, used, err := loadRemoteConfig("", "macos")
		if err != nil || used != "" || cfg.RouteID != config.RouteMacOS || cfg.RemoteHost.App == "" {
			t.Fatalf("cfg=%+v used=%q err=%v", cfg, used, err)
		}
	})

	t.Run("explicit route conflict is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, nil)
		if _, used, err := loadRemoteConfig(path, "macos"); err == nil || used != path || !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("used=%q err=%v", used, err)
		}
	})

	t.Run("unknown route is rejected before file access", func(t *testing.T) {
		if _, _, err := loadRemoteConfig("invalid\x00path", "darwin"); err == nil || !strings.Contains(err.Error(), "route must be") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("default valid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, nil)
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		cfg, used, err := loadRemoteConfig("")
		if err != nil || used != path || cfg.RemoteHost.Host != "gaming-pc.local" {
			t.Fatalf("cfg=%+v used=%q err=%v", cfg, used, err)
		}
	})

	t.Run("default invalid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.json")
		writeFile(t, path, []byte("{}"))
		t.Setenv("LEAGUEBRIDGE_CONFIG", path)
		if _, used, err := loadRemoteConfig(""); err == nil || used != path || !strings.Contains(err.Error(), "load default configuration") {
			t.Fatalf("used=%q err=%v", used, err)
		}
	})
}

func TestRemoteDryRunAndExecution(t *testing.T) {
	t.Run("pair and list allow headless control operations", func(t *testing.T) {
		for _, operation := range []string{"pair", "list"} {
			t.Run(operation, func(t *testing.T) {
				a, out, errOut, prober, runner := newTestApp(t)
				prober.reports[probe.ProfileClient] = probe.Report{
					SchemaVersion: probe.SchemaVersion,
					Profile:       probe.ProfileClient,
					OS:            "linux",
					Architecture:  "amd64",
					Status:        probe.StatusFail,
					Checks: []probe.Check{
						{ID: "client.platform", Status: probe.StatusPass},
						{ID: "client.graphical-session", Status: probe.StatusFail},
						{ID: "client.input", Status: probe.StatusWarn},
						{ID: "client.moonlight", Status: probe.StatusPass},
						{ID: "client.audio", Status: probe.StatusWarn},
						{ID: "client.decoder-tools", Status: probe.StatusWarn},
					},
				}
				args := []string{"remote", operation, "--host", "gaming-pc.local", "--confirm-physical-host", "--dry-run"}
				if code := a.Run(context.Background(), args); code != ExitOK {
					t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
				}
				if runner.called != 0 || !strings.Contains(out.String(), "Validated argument vector") {
					t.Fatalf("runner.called=%d output=%q", runner.called, out.String())
				}
			})
		}
	})

	t.Run("stream dry-run only requires control-plane prerequisites", func(t *testing.T) {
		a, out, errOut, prober, runner := newTestApp(t)
		prober.reports[probe.ProfileClient] = probe.Report{
			SchemaVersion: probe.SchemaVersion,
			Profile:       probe.ProfileClient,
			OS:            "linux",
			Architecture:  "amd64",
			Status:        probe.StatusFail,
			Checks: []probe.Check{
				{ID: "client.platform", Status: probe.StatusPass},
				{ID: "client.graphical-session", Status: probe.StatusFail},
				{ID: "client.input", Status: probe.StatusWarn},
				{ID: "client.moonlight", Status: probe.StatusPass},
				{ID: "client.audio", Status: probe.StatusWarn},
				{ID: "client.decoder-tools", Status: probe.StatusWarn},
			},
		}
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(out.String(), "Validated argument vector") || runner.called != 0 {
			t.Fatalf("stdout=%q stderr=%q runner.called=%d", out.String(), errOut.String(), runner.called)
		}
	})

	t.Run("dry run discovery starts no process", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{
			paths: map[string]string{"moonlight": "/fixture/moonlight"},
		}
		args := []string{"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q", code, out.String())
		}
		if runner.called != 0 {
			t.Fatalf("dry run invoked the remote runner %d time(s)", runner.called)
		}
	})

	t.Run("human dry run", func(t *testing.T) {
		a, out, _, prober, runner := newTestApp(t)
		args := []string{"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		for _, want := range []string{"Validated argument vector", `executable: "/fixture/moonlight-qt"`, `argv[1]: "list"`, "warning:"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output lacks %q:\n%s", want, out.String())
			}
		}
		if runner.called != 0 || !reflect.DeepEqual(prober.profiles, []probe.Profile{probe.ProfileClient}) {
			t.Fatalf("runner.called=%d profiles=%v", runner.called, prober.profiles)
		}
	})

	t.Run("JSON dry run", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		if envelope.Command != "remote stream" || arguments[len(arguments)-1] != "League of Legends" || runner.called != 0 {
			t.Fatalf("envelope=%+v runner.called=%d", envelope, runner.called)
		}
	})

	t.Run("stream quality options are forwarded as fixed arguments", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--resolution", "1080", "--fps", "60", "--bitrate", "20000", "--packet-size", "1392", "--codec", "h264", "--audio-config", "5.1-surround", "--preserve-host-settings", "--decoder", "hardware", "--display-mode", "borderless", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-1080", "-fps", "60", "-bitrate", "20000", "-packet-size", "1392", "-video-codec", "H.264", "-audio-config", "5.1-surround", "-no-game-optimization", "-video-decoder", "hardware", "-display-mode", "borderless", "gaming-pc.local", "League of Legends"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("custom resolution is forwarded to the selected Qt client", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--resolution", "3440x1440", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-resolution", "3440x1440", "gaming-pc.local", "League of Legends"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("Embedded platform option is forwarded as a fixed argument", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight": "/fixture/moonlight"}}
		args := []string{"remote", "stream", "--client", "moonlight-embedded", "--platform", "sdl", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-platform", "sdl", "-app", "League of Legends", "gaming-pc.local"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("Embedded audio configuration is translated to surround syntax", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight": "/fixture/moonlight"}}
		args := []string{"remote", "stream", "--client", "moonlight-embedded", "--audio-config", "7.1-surround", "--preserve-host-settings", "--network-mode", "wan", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-surround", "7.1", "-nosops", "-remote", "yes", "-app", "League of Legends", "gaming-pc.local"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("macOS JSON dry run is route-bound and unvalidated", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "stream", "--route", "macos", "--host", "gaming-mac.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		if plan["route"] != string(config.RouteMacOS) || runner.called != 0 {
			t.Fatalf("plan=%#v runner.called=%d", plan, runner.called)
		}
		warnings, _ := plan["warnings"].([]any)
		encodedWarnings, _ := json.Marshal(warnings)
		for _, want := range []string{"experimental", "gamepad hosting is unavailable", "unvalidated", "not endorsed"} {
			if !strings.Contains(string(encodedWarnings), want) {
				t.Errorf("warnings lack %q: %s", want, encodedWarnings)
			}
		}
	})

	t.Run("execute", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		moonlightPath := useRealRemoteFixture(t, a)
		args := []string{"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if runner.called != 1 || runner.name != moonlightPath || !reflect.DeepEqual(runner.args, []string{"pair", "gaming-pc.local"}) {
			t.Fatalf("runner=%+v", runner)
		}
		if runner.stdin != a.Stdin || !strings.Contains(out.String(), "moonlight output") || !strings.Contains(errOut.String(), "warning:") {
			t.Fatalf("stdout=%q stderr=%q stdin retained=%v", out.String(), errOut.String(), runner.stdin == a.Stdin)
		}
		deadline, ok := runner.ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= 0 || remaining > remoteControlTimeout {
			t.Fatalf("pair context deadline = %v, remaining=%v; want a %s deadline", deadline, remaining, remoteControlTimeout)
		}
	})

	t.Run("interactive stream keeps caller lifetime", func(t *testing.T) {
		a, _, _, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nLeague of Legends\n"
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		if runner.ctx == nil {
			t.Fatal("stream runner did not receive a context")
		}
		if deadline, ok := runner.ctx.Deadline(); ok {
			t.Fatalf("stream unexpectedly had deadline %v", deadline)
		}
	})

	t.Run("execution failure", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.err = errors.New("exit 7")
		args := []string{"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host"}
		if code := a.Run(context.Background(), args); code != ExitInternal {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "Moonlight handoff failed") || runner.called != 1 {
			t.Fatalf("stderr=%q runner.called=%d", errOut.String(), runner.called)
		}
	})
}

func TestRemoteListCanRequireAdvertisedApplication(t *testing.T) {
	t.Run("listed application passes", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nLeague of Legends\n"
		args := []string{
			"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 || !strings.Contains(out.String(), "League of Legends") {
			t.Fatalf("runner.called=%d stdout=%q", runner.called, out.String())
		}
	})

	t.Run("configured application passes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, func(cfg *config.Config) {
			cfg.RemoteHost.App = "Custom League Entry"
		})
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nCustom League Entry\n"
		args := []string{
			"remote", "list", "--config", path, "--require-configured-app",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 || !strings.Contains(out.String(), "Custom League Entry") {
			t.Fatalf("runner.called=%d stdout=%q", runner.called, out.String())
		}
	})

	t.Run("stream configured application is checked before launch", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, func(cfg *config.Config) {
			cfg.RemoteHost.App = "Custom League Entry"
		})
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nCustom League Entry\n"
		args := []string{
			"remote", "stream", "--config", path, "--require-configured-app",
			"--acknowledge-unverified-handoff",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 2 || !reflect.DeepEqual(runner.args, []string{"stream", "gaming-pc.local", "Custom League Entry"}) {
			t.Fatalf("runner.called=%d args=%#v; want configured preflight and stream", runner.called, runner.args)
		}
	})

	t.Run("missing application blocks", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nSteam\n"
		args := []string{
			"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "was not advertised") || runner.called != 1 {
			t.Fatalf("stderr=%q runner.called=%d", errOut.String(), runner.called)
		}
	})

	t.Run("stderr mention does not satisfy application", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nSteam\n"
		runner.errorOutput = "warning: League of Legends could not be started\n"
		args := []string{
			"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "was not advertised") || runner.called != 1 {
			t.Fatalf("stderr=%q runner.called=%d", errOut.String(), runner.called)
		}
	})

	t.Run("application check capture is bounded", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = strings.Repeat("x", remoteApplicationListingCaptureLimit+128) + "\nLeague of Legends\n"
		args := []string{
			"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout length=%d stderr=%q", code, out.Len(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "was not advertised") {
			t.Fatalf("stderr=%q", errOut.String())
		}
		if out.Len() != len(runner.output) {
			t.Fatalf("stdout length=%d, want full listing length=%d", out.Len(), len(runner.output))
		}
	})

	t.Run("stream preflight passes before launching the application", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nLeague of Legends\n"
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 2 {
			t.Fatalf("runner.called=%d; want one list preflight and one stream", runner.called)
		}
		if !reflect.DeepEqual(runner.args, []string{"stream", "gaming-pc.local", "League of Legends"}) {
			t.Fatalf("final runner args=%#v; want stream args", runner.args)
		}
		if !strings.Contains(errOut.String(), "checking that the physical host advertises") {
			t.Fatalf("stderr=%q; want preflight notice", errOut.String())
		}
	})

	t.Run("live stream always preflights the configured application", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nLeague of Legends\n"
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 2 || !reflect.DeepEqual(runner.args, []string{"stream", "gaming-pc.local", "League of Legends"}) {
			t.Fatalf("runner.called=%d args=%#v; want a list preflight followed by the stream", runner.called, runner.args)
		}
	})

	t.Run("live stream blocks when the configured application is absent", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nSteam\n"
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 || !reflect.DeepEqual(runner.args, []string{"list", "gaming-pc.local"}) {
			t.Fatalf("runner.called=%d args=%#v; want only the list preflight", runner.called, runner.args)
		}
		if !strings.Contains(errOut.String(), "no stream was started") {
			t.Fatalf("stderr=%q; want no-stream result", errOut.String())
		}
	})

	t.Run("stream preflight blocks before launching a missing application", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nSteam\n"
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 || !reflect.DeepEqual(runner.args, []string{"list", "gaming-pc.local"}) {
			t.Fatalf("runner.called=%d args=%#v; want only the list preflight", runner.called, runner.args)
		}
		if !strings.Contains(errOut.String(), "no stream was started") {
			t.Fatalf("stderr=%q; want no-stream result", errOut.String())
		}
	})

	t.Run("stream preflight does not accept a diagnostic stderr mention", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nSteam\n"
		runner.errorOutput = "warning: League of Legends could not be started\n"
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 {
			t.Fatalf("runner.called=%d; want no stream after failed preflight", runner.called)
		}
		if !strings.Contains(errOut.String(), "no stream was started") {
			t.Fatalf("stderr=%q; want no-stream result", errOut.String())
		}
	})

	t.Run("stream preflight preserves timeout classification", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.err = context.DeadlineExceeded
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff",
		}
		if code := a.Run(context.Background(), args); code != ExitInternal {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 {
			t.Fatalf("runner.called=%d; want only the timed-out list preflight", runner.called)
		}
		if !strings.Contains(errOut.String(), "application-list preflight timed out") {
			t.Fatalf("stderr=%q; want timeout-specific guidance", errOut.String())
		}
	})

	t.Run("stream preflight must match the launch application", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--app", "League of Legends",
			"--confirm-physical-host", "--acknowledge-unverified-handoff", "--require-app", "Desktop",
		}
		if code := a.Run(context.Background(), args); code != ExitUsage {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 0 || !strings.Contains(errOut.String(), "must match the stream application") {
			t.Fatalf("runner.called=%d stderr=%q; want mismatch rejection before execution", runner.called, errOut.String())
		}
	})

	t.Run("configured and explicit application requirements must agree", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		args := []string{
			"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--require-app", "Desktop", "--require-configured-app",
		}
		if code := a.Run(context.Background(), args); code != ExitUsage {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 0 || !strings.Contains(errOut.String(), "must match the configured application") {
			t.Fatalf("runner.called=%d stderr=%q; want mismatch rejection before execution", runner.called, errOut.String())
		}
	})
}

func TestRemoteErrorsAndSafetyGates(t *testing.T) {
	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	tests := []struct {
		name     string
		args     []string
		mutate   func(*App, *scriptedProber)
		wantCode int
		want     string
		json     bool
	}{
		{name: "missing subcommand", args: []string{"remote"}, wantCode: ExitUsage, want: "expected pair, list, or stream"},
		{name: "unknown subcommand", args: []string{"remote", "shell"}, wantCode: ExitUsage, want: "unknown subcommand"},
		{name: "unexpected argument", args: []string{"remote", "pair", "extra"}, wantCode: ExitUsage, want: "unexpected arguments"},
		{name: "unknown route", args: []string{"remote", "pair", "--route", "darwin", "--dry-run"}, wantCode: ExitUsage, want: "route must be windows or macos"},
		{name: "JSON requires dry run", args: []string{"remote", "pair", "--json"}, wantCode: ExitUsage, want: "--json requires --dry-run", json: true},
		{name: "ineligible architecture", args: []string{"remote", "pair", "--dry-run", "--json"}, mutate: func(a *App, _ *scriptedProber) { a.GOARCH = "arm64" }, wantCode: ExitBlocked, want: "target Linux and BSD on amd64", json: true},
		{name: "ineligible OS", args: []string{"remote", "pair", "--dry-run"}, mutate: func(a *App, _ *scriptedProber) { a.GOOS = "windows" }, wantCode: ExitBlocked, want: "current host is windows/amd64"},
		{name: "stale evidence", args: []string{"remote", "pair", "--dry-run"}, mutate: func(a *App, _ *scriptedProber) { a.Now = func() time.Time { return fixedNow.AddDate(2, 0, 0) } }, wantCode: ExitBlocked, want: "evidence is stale"},
		{name: "future evidence", args: []string{"remote", "pair", "--dry-run"}, mutate: func(a *App, _ *scriptedProber) {
			a.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
		}, wantCode: ExitBlocked, want: "evidence is future"},
		{name: "invalid evaluation time", args: []string{"remote", "pair", "--dry-run"}, mutate: func(a *App, _ *scriptedProber) { a.Now = func() time.Time { return time.Time{} } }, wantCode: ExitBlocked, want: "cannot be evaluated"},
		{name: "preflight failure", args: []string{"remote", "pair", "--dry-run"}, mutate: func(_ *App, p *scriptedProber) {
			p.reports[probe.ProfileClient] = probeReport(probe.ProfileClient, probe.StatusFail)
		}, wantCode: ExitBlocked, want: "client preflight failed"},
		{name: "explicit config missing", args: []string{"remote", "pair", "--config", missingConfig, "--dry-run"}, wantCode: ExitUsage, want: "load configuration"},
		{name: "invalid config flags", args: []string{"remote", "pair", "--host=-bad", "--confirm-physical-host", "--dry-run"}, wantCode: ExitUsage, want: "invalid remote configuration"},
		{name: "empty host override", args: []string{"remote", "pair", "--host=", "--confirm-physical-host", "--dry-run"}, wantCode: ExitUsage, want: "invalid remote configuration"},
		{name: "empty app override", args: []string{"remote", "stream", "--host=gaming-pc.local", "--app=", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}, wantCode: ExitUsage, want: "invalid remote configuration"},
		{name: "empty client override", args: []string{"remote", "pair", "--host=gaming-pc.local", "--client=", "--confirm-physical-host", "--dry-run"}, wantCode: ExitUsage, want: "invalid remote configuration"},
		{name: "Moonlight missing", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host", "--dry-run"}, mutate: func(a *App, _ *scriptedProber) { a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{}} }, wantCode: ExitBlocked, want: "Moonlight was not found"},
		{name: "physical confirmation missing", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--dry-run"}, wantCode: ExitBlocked, want: "not confirmed as a physical Windows PC"},
		{name: "macOS physical confirmation missing", args: []string{"remote", "pair", "--route", "macos", "--host", "gaming-mac.local", "--dry-run"}, wantCode: ExitBlocked, want: "not confirmed as a physical Mac"},
		{name: "stream acknowledgement missing", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host", "--dry-run"}, wantCode: ExitBlocked, want: "pass explicit acknowledgement"},
		{name: "application expectation on stream dry-run", args: []string{"remote", "stream", "--require-app", "League", "--dry-run"}, wantCode: ExitUsage, want: "requires a live application-list preflight"},
		{name: "application expectation on list dry-run", args: []string{"remote", "list", "--require-app", "League", "--dry-run"}, wantCode: ExitUsage, want: "requires a live application-list preflight"},
		{name: "configured application expectation on stream dry-run", args: []string{"remote", "stream", "--require-configured-app", "--dry-run"}, wantCode: ExitUsage, want: "requires a live application-list preflight"},
		{name: "configured application expectation on list dry-run", args: []string{"remote", "list", "--require-configured-app", "--dry-run"}, wantCode: ExitUsage, want: "requires a live application-list preflight"},
		{name: "configured application expectation on pair", args: []string{"remote", "pair", "--require-configured-app"}, wantCode: ExitUsage, want: "require the list or stream operation"},
		{name: "false configured application expectation", args: []string{"remote", "list", "--require-configured-app=false"}, wantCode: ExitUsage, want: "must be true when supplied"},
		{name: "invalid application expectation", args: []string{"remote", "list", "--require-app", "-League", "--dry-run"}, wantCode: ExitUsage, want: "invalid required application"},
		{name: "stream options on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--fps", "60", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "codec on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--codec", "h264", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "audio config on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--audio-config", "stereo", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "host settings on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--preserve-host-settings", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "network mode on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--network-mode", "lan", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "packet size on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--packet-size", "1392", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "platform on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--platform", "sdl", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "display mode on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--display-mode", "borderless", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "stream app on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--app", "League", "--dry-run"}, wantCode: ExitUsage, want: "--app require the stream operation"},
		{name: "stream acknowledgement on list", args: []string{"remote", "list", "--host", "gaming-pc.local", "--acknowledge-unverified-handoff", "--dry-run"}, wantCode: ExitUsage, want: "--acknowledge-unverified-handoff require the stream operation"},
		{name: "invalid stream resolution", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--resolution", "2160", "--dry-run"}, wantCode: ExitUsage, want: "resolution must be"},
		{name: "invalid stream codec", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--codec", "vp9", "--dry-run"}, wantCode: ExitUsage, want: "codec must be"},
		{name: "invalid stream audio config", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--audio-config", "2.1-surround", "--dry-run"}, wantCode: ExitUsage, want: "audio config must be"},
		{name: "invalid stream network mode", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--network-mode", "internet", "--dry-run"}, wantCode: ExitUsage, want: "network mode must be"},
		{name: "invalid stream packet size", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--packet-size", "1025", "--dry-run"}, wantCode: ExitUsage, want: "packet size must be"},
		{name: "invalid stream platform", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--platform", "wayland", "--dry-run"}, wantCode: ExitUsage, want: "platform must be"},
		{name: "invalid stream decoder", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--decoder", "vp9", "--dry-run"}, wantCode: ExitUsage, want: "decoder must be"},
		{name: "invalid stream display mode", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--display-mode", "maximized", "--dry-run"}, wantCode: ExitUsage, want: "display mode must be"},
		{name: "option-like app", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--app=-League", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}, wantCode: ExitUsage, want: "remote_host.app"},
		{name: "unsupported client", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--client", "other", "--confirm-physical-host", "--dry-run"}, wantCode: ExitUsage, want: "remote_host.client"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, prober, _ := newTestApp(t)
			if tt.mutate != nil {
				tt.mutate(a, prober)
			}
			if code := a.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("code = %d, want %d; stdout=%q stderr=%q", code, tt.wantCode, out.String(), errOut.String())
			}
			got := errOut.String()
			if tt.json {
				envelope := decodeEnvelope(t, out.Bytes())
				if envelope.OK {
					t.Fatalf("unexpected successful envelope: %+v", envelope)
				}
				got = envelope.Error
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("output %q does not contain %q", got, tt.want)
			}
		})
	}
}

func TestRemoteConfigOverridesAndHelpers(t *testing.T) {
	t.Run("host override cannot inherit persisted physical confirmation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, func(cfg *config.Config) {
			cfg.RemoteHost.Host = "old.local"
			cfg.RemoteHost.PhysicalHostConfirmed = true
		})
		a, out, errOut, _, runner := newTestApp(t)
		args := []string{"remote", "pair", "--config", path, "--host", "new.local", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "not confirmed as a physical Windows PC") {
			t.Fatalf("stderr=%q", errOut.String())
		}
		if runner.called != 0 {
			t.Fatalf("remote runner called %d time(s)", runner.called)
		}
	})

	t.Run("explicit false revokes persisted physical confirmation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, func(cfg *config.Config) {
			cfg.RemoteHost.PhysicalHostConfirmed = true
		})
		a, out, errOut, _, runner := newTestApp(t)
		args := []string{"remote", "pair", "--config", path, "--confirm-physical-host=false", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "not confirmed as a physical Windows PC") || runner.called != 0 {
			t.Fatalf("stderr=%q runner.called=%d", errOut.String(), runner.called)
		}
	})

	t.Run("explicit config overridden by flags", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeConfigFile(t, path, func(cfg *config.Config) {
			cfg.RemoteHost.Host = "old.local"
			cfg.RemoteHost.App = "Old App"
			cfg.RemoteHost.Client = "moonlight"
			cfg.RemoteHost.PhysicalHostConfirmed = false
		})
		a, out, _, _, _ := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{
			paths: map[string]string{"moonlight": "/fixture/moonlight"},
		}
		args := []string{"remote", "stream", "--config", path, "--host", "new.local", "--app", "New App", "--client", "moonlight", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d", code)
		}
		for _, want := range []string{`executable: "/fixture/moonlight"`, `argv[2]: "-app"`, `"New App"`, `"new.local"`} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output lacks %q:\n%s", want, out.String())
			}
		}
	})

	platformTests := []struct {
		goos, arch string
		want       bool
	}{
		{"linux", "amd64", true},
		{"FREEBSD", "AMD64", true},
		{"openbsd", "amd64", true},
		{"netbsd", "amd64", true},
		{"dragonfly", "amd64", true},
		{"dragonflybsd", "amd64", false},
		{"windows", "amd64", false},
		{"linux", "arm64", false},
	}
	for _, tt := range platformTests {
		if got := eligibleClientPlatform(tt.goos, tt.arch); got != tt.want {
			t.Errorf("eligibleClientPlatform(%q, %q) = %v, want %v", tt.goos, tt.arch, got, tt.want)
		}
	}

	a, _, _, _, _ := newTestApp(t)
	if err := a.verifyRemoteHandoffContract(); err != nil {
		t.Fatalf("fresh embedded contract: %v", err)
	}
	if err := a.verifyRemoteHandoffContract(config.RouteMacOS); err != nil {
		t.Fatalf("fresh embedded macOS contract: %v", err)
	}
	a.Now = func() time.Time { return fixedNow.AddDate(2, 0, 0) }
	if err := a.verifyRemoteHandoffContract(); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale contract error = %v", err)
	}
}

func TestAppFallbackHelpers(t *testing.T) {
	a, _, _, _, _ := newTestApp(t)
	a.Now = nil
	if a.now().IsZero() {
		t.Fatal("nil Now fallback returned zero")
	}
	a.NewProber = nil
	if a.prober() == nil {
		t.Fatal("nil NewProber fallback returned nil")
	}
}
