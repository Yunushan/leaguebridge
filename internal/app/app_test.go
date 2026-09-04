package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
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

var fixedNow = time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)

type scriptedProber struct {
	reports          map[probe.Profile]probe.Report
	clientReports    map[string]probe.Report
	profiles         []probe.Profile
	contexts         []context.Context
	clientSelections []string
	beforeClient     func(string)
}

type streamAwareScriptedProber struct {
	*scriptedProber
	streamSelections   []string
	streamPlatforms    []string
	qtStreamSelections []string
	qtStreamPlatforms  []string
}

func (p *scriptedProber) Run(ctx context.Context, profile probe.Profile) probe.Report {
	p.profiles = append(p.profiles, profile)
	p.contexts = append(p.contexts, ctx)
	if report, ok := p.reports[profile]; ok {
		return report
	}
	return probeReport(profile, probe.StatusPass)
}

func (p *scriptedProber) ClientFor(ctx context.Context, preferred string) probe.Report {
	p.clientSelections = append(p.clientSelections, preferred)
	if p.beforeClient != nil {
		p.beforeClient(preferred)
	}
	if report, ok := p.clientReports[preferred]; ok {
		return report
	}
	return p.Run(ctx, probe.ProfileClient)
}

func (p *streamAwareScriptedProber) ClientForStream(ctx context.Context, preferred, outputPlatform string) probe.Report {
	p.streamSelections = append(p.streamSelections, preferred)
	p.streamPlatforms = append(p.streamPlatforms, outputPlatform)
	if report, ok := p.clientReports[preferred]; ok {
		return report
	}
	return p.Run(ctx, probe.ProfileClient)
}

func (p *streamAwareScriptedProber) ClientForStreamWithQtPlatform(ctx context.Context, preferred, outputPlatform, qtPlatform string) probe.Report {
	p.qtStreamSelections = append(p.qtStreamSelections, preferred)
	p.qtStreamPlatforms = append(p.qtStreamPlatforms, qtPlatform)
	if report, ok := p.clientReports[preferred]; ok {
		return report
	}
	return p.Run(ctx, probe.ProfileClient)
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
	qtPlatform  string
	stdin       io.Reader
	ctx         context.Context
	called      int
	argsHistory [][]string
	output      string
	outputs     []string
	errorOutput string
	err         error
	results     []error
}

func (r *recordingRemoteRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	r.called++
	r.ctx = ctx
	r.stdin = stdin
	r.name = name
	r.args = append([]string(nil), args...)
	r.argsHistory = append(r.argsHistory, append([]string(nil), args...))
	err := r.err
	if len(r.results) >= r.called {
		err = r.results[r.called-1]
	}
	if err == nil {
		output := r.output
		if len(r.outputs) >= r.called {
			output = r.outputs[r.called-1]
		}
		if output == "" {
			output = "moonlight output\n"
		}
		_, _ = io.WriteString(stdout, output)
		if r.errorOutput != "" {
			_, _ = io.WriteString(stderr, r.errorOutput)
		}
	}
	return err
}

func (r *recordingRemoteRunner) RunWithQtPlatform(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, qtPlatform, name string, args ...string) error {
	r.qtPlatform = qtPlatform
	return r.Run(ctx, stdin, stdout, stderr, name, args...)
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
	// Keep launcher discovery hermetic: an installed host Flatpak or another
	// Moonlight binary must not change the fallback path under test.
	t.Setenv("PATH", directory)
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

	t.Run("Qt stream selection mirrors live preflight", func(t *testing.T) {
		a, _, errOut, prober, _ := newTestApp(t)
		aware := &streamAwareScriptedProber{scriptedProber: prober}
		a.NewProber = func() ProbeRunner { return aware }
		if code := a.Run(context.Background(), []string{"doctor", "--profile", "client", "--client", "moonlight-qt", "--qt-platform", "xcb"}); code != ExitOK {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		if !reflect.DeepEqual(aware.qtStreamSelections, []string{"moonlight-qt"}) || !reflect.DeepEqual(aware.qtStreamPlatforms, []string{"xcb"}) {
			t.Fatalf("Qt selections=%v platforms=%v", aware.qtStreamSelections, aware.qtStreamPlatforms)
		}
	})

	t.Run("Embedded stream selection mirrors live preflight", func(t *testing.T) {
		a, _, errOut, prober, _ := newTestApp(t)
		aware := &streamAwareScriptedProber{scriptedProber: prober}
		a.NewProber = func() ProbeRunner { return aware }
		if code := a.Run(context.Background(), []string{"doctor", "--profile", "client", "--platform", "sdl"}); code != ExitOK {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		if !reflect.DeepEqual(aware.streamSelections, []string{"moonlight-embedded"}) || !reflect.DeepEqual(aware.streamPlatforms, []string{"sdl"}) {
			t.Fatalf("Embedded selections=%v platforms=%v", aware.streamSelections, aware.streamPlatforms)
		}
	})

	t.Run("backend flags reject incompatible profile and flavor", func(t *testing.T) {
		tests := []struct {
			name string
			args []string
			want string
		}{
			{name: "host profile", args: []string{"doctor", "--profile", "windows-host", "--qt-platform", "xcb"}, want: "require the client profile"},
			{name: "Qt flag with Embedded", args: []string{"doctor", "--client", "moonlight-embedded", "--qt-platform", "xcb"}, want: "requires --client moonlight-qt or flatpak"},
			{name: "Embedded flag with Qt", args: []string{"doctor", "--client", "moonlight-qt", "--platform", "sdl"}, want: "cannot be combined with --client moonlight-qt"},
			{name: "invalid Qt backend", args: []string{"doctor", "--qt-platform", "offscreen"}, want: "must be auto, xcb, wayland, eglfs, or linuxfb"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				a, _, errOut, _, _ := newTestApp(t)
				if code := a.Run(context.Background(), tt.args); code != ExitUsage || !strings.Contains(errOut.String(), tt.want) {
					t.Fatalf("code=%d stderr=%q; want usage containing %q", code, errOut.String(), tt.want)
				}
			})
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
		want := []any{"stream", "-1440", "-no-absolute-mouse", "gaming-pc.local", "League"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("initialized config stores and feeds the KVM endpoint", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kvm.json")
		a, _, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{
			"config", "init", "--file", path, "--host", "gaming-pc.local",
			"--kvm-url", "https://kvm.lan/", "--confirm-physical-host",
		}); code != ExitOK {
			t.Fatalf("init code = %d; stderr=%q", code, errOut.String())
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.KVM == nil || cfg.KVM.Endpoint != "https://kvm.lan/" {
			t.Fatalf("stored KVM config = %+v", cfg.KVM)
		}

		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
		if code := a.Run(context.Background(), []string{
			"remote", "kvm", "--config", path,
			"--acknowledge-unverified-handoff", "--dry-run", "--json",
		}); code != ExitOK {
			t.Fatalf("KVM code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		if !reflect.DeepEqual(plan["arguments"].([]any), []any{"https://kvm.lan/"}) || runner.called != 0 {
			t.Fatalf("plan=%#v runner.called=%d; want configured endpoint and no process", plan, runner.called)
		}

		a, out, errOut, _, runner = newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
		if code := a.Run(context.Background(), []string{
			"remote", "kvm", "--config", path, "--confirm-physical-host=false",
			"--acknowledge-unverified-handoff", "--dry-run",
		}); code != ExitBlocked {
			t.Fatalf("revoked confirmation code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "not confirmed as a physical") || runner.called != 0 {
			t.Fatalf("revoked confirmation stderr=%q runner.called=%d", errOut.String(), runner.called)
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
	t.Run("pair, list, and quit allow headless control operations", func(t *testing.T) {
		for _, operation := range []string{"pair", "list", "quit"} {
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

	t.Run("Embedded unpair allows pairing recovery", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
		args := []string{"remote", "unpair", "--client", "moonlight-embedded", "--host", "gaming-pc.local", "--confirm-physical-host", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"unpair", "gaming-pc.local"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("automatic unpair selects Embedded", func(t *testing.T) {
		a, out, errOut, prober, runner := newTestApp(t)
		directory := t.TempDir()
		fileName := "moonlight-embedded"
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		moonlightPath := filepath.Join(directory, fileName)
		if err := os.WriteFile(moonlightPath, []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
		a.RemoteEnv = remote.RealEnvironment{}
		args := []string{"remote", "unpair", "--host", "gaming-pc.local", "--confirm-physical-host"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 || runner.name != moonlightPath || !reflect.DeepEqual(runner.args, []string{"unpair", "gaming-pc.local"}) {
			t.Fatalf("runner=%+v; want one Embedded unpair operation", runner)
		}
		if !reflect.DeepEqual(prober.clientSelections, []string{"moonlight-embedded"}) {
			t.Fatalf("client selections=%#v; want the Embedded operation-specific selection", prober.clientSelections)
		}
	})

	t.Run("quit terminates a remote application with the control timeout", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		moonlightPath := useRealRemoteFixture(t, a)
		args := []string{"remote", "quit", "--host", "gaming-pc.local", "--confirm-physical-host"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 || runner.name != moonlightPath || !reflect.DeepEqual(runner.args, []string{"quit", "gaming-pc.local"}) {
			t.Fatalf("runner=%+v; want quit operation", runner)
		}
		if runner.ctx == nil {
			t.Fatal("quit runner did not receive a context")
		}
		if deadline, ok := runner.ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > remoteControlTimeout {
			t.Fatalf("quit context deadline = %v; want a %s deadline", deadline, remoteControlTimeout)
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

	t.Run("play alias applies the League session defaults", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "play", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-1080", "-fps", "60", "-bitrate", "20000", "-packet-size", "1392", "-video-codec", "H.264", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication}
		if envelope.Command != "remote play" || !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("envelope=%+v arguments=%#v runner.called=%d; want the guarded stream defaults and no process", envelope, arguments, runner.called)
		}
	})

	t.Run("play alias selects a HDR-compatible codec by default", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "play", "--host", "gaming-pc.local", "--hdr", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-1080", "-fps", "60", "-bitrate", "20000", "-packet-size", "1392", "-video-codec", "auto", "-no-absolute-mouse", "-hdr", "gaming-pc.local", config.DefaultRemoteApplication}
		if envelope.Command != "remote play" || !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("envelope=%+v arguments=%#v runner.called=%d; want HDR-compatible defaults and no process", envelope, arguments, runner.called)
		}
	})

	t.Run("play alias preserves explicit quality overrides", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "play", "--host", "gaming-pc.local", "--resolution", "1440", "--fps", "120", "--bitrate", "30000", "--packet-size", "1408", "--codec", "hevc", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-1440", "-fps", "120", "-bitrate", "30000", "-packet-size", "1408", "-video-codec", "HEVC", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want explicit overrides and no process", arguments, runner.called)
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
		if envelope.Command != "remote stream" || arguments[len(arguments)-1] != config.DefaultRemoteApplication || runner.called != 0 {
			t.Fatalf("envelope=%+v runner.called=%d", envelope, runner.called)
		}
	})

	t.Run("stream dry-run includes the opt-in Wake-on-LAN plan", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "00:11:22:33:44:55",
			"--wake-broadcast", "192.0.2.255", "--wake-port", "4009", "--wake-wait", "30",
			"--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		wake := plan["wake"].(map[string]any)
		wakeRetry := plan["wake_retry"].(map[string]any)
		if wake["mac"] != "00:11:22:33:44:55" || wake["destination"] != "192.0.2.255" || wake["port"] != float64(4009) || wakeRetry["additional_attempts"] != float64(3) || wakeRetry["delay_seconds"] != float64(5) || runner.called != 0 {
			t.Fatalf("wake=%#v wake_retry=%#v runner.called=%d; want normalized no-I/O wake and retry plans", wake, wakeRetry, runner.called)
		}
	})

	t.Run("pair dry-run includes the opt-in Wake-on-LAN plan", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{
			"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "AA-BB-CC-DD-EE-FF",
			"--wake-broadcast", "192.0.2.255", "--wake-port", "4009", "--wake-wait", "30",
			"--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		wake := plan["wake"].(map[string]any)
		if envelope.Command != "remote pair" || wake["mac"] != "aa:bb:cc:dd:ee:ff" || wake["destination"] != "192.0.2.255" || wake["port"] != float64(4009) || runner.called != 0 {
			t.Fatalf("envelope=%+v runner.called=%d; want normalized no-I/O pairing wake plan", envelope, runner.called)
		}
	})

	t.Run("list dry-run includes the opt-in Wake-on-LAN plan", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{
			"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "AA-BB-CC-DD-EE-FF",
			"--wake-broadcast", "192.0.2.255", "--wake-port", "4009", "--wake-wait", "30",
			"--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		wake := plan["wake"].(map[string]any)
		if envelope.Command != "remote list" || wake["mac"] != "aa:bb:cc:dd:ee:ff" || wake["destination"] != "192.0.2.255" || wake["port"] != float64(4009) || runner.called != 0 {
			t.Fatalf("envelope=%+v runner.called=%d; want normalized no-I/O listing wake plan", envelope, runner.called)
		}
	})

	t.Run("Wake-on-LAN is available for pairing, listing, and streaming and requires a MAC", func(t *testing.T) {
		t.Run("unpair rejects wake flags", func(t *testing.T) {
			a, _, errOut, _, runner := newTestApp(t)
			code := a.Run(context.Background(), []string{
				"remote", "unpair", "--wake-mac", "00:11:22:33:44:55",
			})
			if code != ExitUsage || !strings.Contains(errOut.String(), "require the stream operation") || runner.called != 0 {
				t.Fatalf("code=%d stderr=%q runner.called=%d", code, errOut.String(), runner.called)
			}
		})

		t.Run("pair wake requires explicit acknowledgement", func(t *testing.T) {
			a, _, errOut, _, runner := newTestApp(t)
			code := a.Run(context.Background(), []string{
				"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host",
				"--wake-mac", "00:11:22:33:44:55", "--dry-run",
			})
			if code != ExitBlocked || !strings.Contains(errOut.String(), "pass explicit acknowledgement") || runner.called != 0 {
				t.Fatalf("code=%d stderr=%q runner.called=%d", code, errOut.String(), runner.called)
			}
		})

		t.Run("stream rejects wake transport overrides without a MAC", func(t *testing.T) {
			a, _, errOut, _, runner := newTestApp(t)
			code := a.Run(context.Background(), []string{
				"remote", "stream", "--wake-port", "4009",
			})
			if code != ExitUsage || !strings.Contains(errOut.String(), "require --wake-mac") || runner.called != 0 {
				t.Fatalf("code=%d stderr=%q runner.called=%d", code, errOut.String(), runner.called)
			}
		})

		t.Run("wake retry flags are limited to list and stream", func(t *testing.T) {
			a, _, errOut, _, runner := newTestApp(t)
			code := a.Run(context.Background(), []string{
				"remote", "pair", "--wake-mac", "00:11:22:33:44:55", "--wake-retries", "1",
			})
			if code != ExitUsage || !strings.Contains(errOut.String(), "require the list or stream operation") || runner.called != 0 {
				t.Fatalf("code=%d stderr=%q runner.called=%d", code, errOut.String(), runner.called)
			}
		})

		t.Run("wake retry delay requires retries", func(t *testing.T) {
			a, _, errOut, _, runner := newTestApp(t)
			code := a.Run(context.Background(), []string{
				"remote", "list", "--wake-mac", "00:11:22:33:44:55", "--wake-retries", "0", "--wake-retry-delay", "1",
			})
			if code != ExitUsage || !strings.Contains(errOut.String(), "requires --wake-retries greater than zero") || runner.called != 0 {
				t.Fatalf("code=%d stderr=%q runner.called=%d", code, errOut.String(), runner.called)
			}
		})
	})

	t.Run("stream quality options are forwarded as fixed arguments", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--resolution", "1080", "--fps", "60", "--bitrate", "20000", "--packet-size", "1392", "--codec", "h264", "--audio-config", "5.1-surround", "--preserve-host-settings", "--frame-pacing", "on", "--vsync", "on", "--keep-awake", "--quit-after", "--capture-system-keys", "always", "--decoder", "hardware", "--display-mode", "borderless", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-1080", "-fps", "60", "-bitrate", "20000", "-packet-size", "1392", "-video-codec", "H.264", "-audio-config", "5.1-surround", "-no-game-optimization", "-frame-pacing", "-vsync", "-keep-awake", "-quit-after", "-capture-system-keys", "always", "-video-decoder", "hardware", "-display-mode", "borderless", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication}
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
		want := []any{"stream", "-resolution", "3440x1440", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("Embedded platform option is forwarded as a fixed argument", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
		args := []string{"remote", "stream", "--client", "moonlight-embedded", "--platform", "sdl", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-platform", "sdl", "-app", config.DefaultRemoteApplication, "gaming-pc.local"}
		if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
			t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
		}
	})

	t.Run("auto client selection follows the Embedded platform selector", func(t *testing.T) {
		a, out, errOut, prober, runner := newTestApp(t)
		aware := &streamAwareScriptedProber{scriptedProber: prober}
		a.NewProber = func() ProbeRunner { return aware }
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{
			"moonlight-qt":       "/fixture/moonlight-qt",
			"moonlight-embedded": "/fixture/moonlight-embedded",
		}}
		args := []string{"remote", "stream", "--platform", "sdl", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if len(aware.qtStreamSelections) != 1 || aware.qtStreamSelections[0] != "moonlight-embedded" {
			t.Fatalf("Qt-aware stream selections=%v; want the effective Embedded selection", aware.qtStreamSelections)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		client := plan["client"].(map[string]any)
		if client["flavor"] != string(remote.FlavorEmbedded) || runner.called != 0 {
			t.Fatalf("client=%#v runner.called=%d; want Embedded discovery and no process", client, runner.called)
		}
	})

	t.Run("auto client selection follows the Qt platform selector", func(t *testing.T) {
		a, out, errOut, prober, runner := newTestApp(t)
		aware := &streamAwareScriptedProber{scriptedProber: prober}
		a.NewProber = func() ProbeRunner { return aware }
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{
			"moonlight-qt":       "/fixture/moonlight-qt",
			"moonlight-embedded": "/fixture/moonlight-embedded",
		}}
		args := []string{"remote", "stream", "--qt-platform", "xcb", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if len(aware.qtStreamSelections) != 1 || aware.qtStreamSelections[0] != "moonlight-qt" {
			t.Fatalf("Qt-aware stream selections=%v; want the effective Qt selection", aware.qtStreamSelections)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		client := plan["client"].(map[string]any)
		if client["flavor"] != string(remote.FlavorQt) || runner.called != 0 {
			t.Fatalf("client=%#v runner.called=%d; want Qt discovery and no process", client, runner.called)
		}
	})

	t.Run("stream backend selectors cannot be combined", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		args := []string{"remote", "stream", "--platform", "sdl", "--qt-platform", "xcb", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitUsage || !strings.Contains(errOut.String(), "cannot be combined") || runner.called != 0 {
			t.Fatalf("code=%d stderr=%q runner.called=%d; want early selector rejection", code, errOut.String(), runner.called)
		}
	})

	t.Run("Embedded audio configuration is translated to surround syntax", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
		args := []string{"remote", "stream", "--client", "moonlight-embedded", "--audio-config", "7.1-surround", "--preserve-host-settings", "--network-mode", "wan", "--host", "gaming-pc.local", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; output=%q", code, out.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-surround", "7.1", "-nosops", "-remote", "yes", "-app", config.DefaultRemoteApplication, "gaming-pc.local"}
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

	t.Run("fully explicit Mac stream ignores an unrelated default config", func(t *testing.T) {
		defaultPath := filepath.Join(t.TempDir(), "default-windows.json")
		writeConfigFile(t, defaultPath, nil)
		a, out, errOut, _, runner := newTestApp(t)
		// newTestApp supplies a missing config path for isolation; this test
		// deliberately replaces it with a valid Windows config to ensure the
		// explicit Mac invocation does not accidentally consult that route.
		t.Setenv("LEAGUEBRIDGE_CONFIG", defaultPath)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-qt": "/fixture/moonlight-qt"}}
		code := a.Run(context.Background(), []string{
			"remote", "stream", "--route", "macos", "--host", "gaming-mac.local",
			"--app", "League of Legends", "--client", "moonlight-qt",
			"--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json",
		})
		if code != ExitOK || runner.called != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d", code, out.String(), errOut.String(), runner.called)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		if plan["route"] != string(config.RouteMacOS) || plan["qt_platform"] != nil {
			t.Fatalf("plan=%#v; want explicit Mac route without an implicit Qt platform override", plan)
		}
		arguments := plan["arguments"].([]any)
		want := []any{"stream", "-no-absolute-mouse", "gaming-mac.local", "League of Legends"}
		if !reflect.DeepEqual(arguments, want) {
			t.Fatalf("arguments=%#v; want %#v", arguments, want)
		}
	})

	t.Run("named config remains authoritative for an explicit route", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "default-windows.json")
		writeConfigFile(t, configPath, nil)
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-qt": "/fixture/moonlight-qt"}}
		code := a.Run(context.Background(), []string{
			"remote", "stream", "--config", configPath, "--route", "macos",
			"--host", "gaming-mac.local", "--app", "League of Legends",
			"--client", "moonlight-qt", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--dry-run", "--json",
		})
		if code != ExitUsage || runner.called != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want named-config route conflict", code, out.String(), errOut.String(), runner.called)
		}
		envelope := decodeEnvelope(t, out.Bytes())
		if envelope.OK || !strings.Contains(envelope.Error, "conflicts with configuration route") {
			t.Fatalf("envelope=%+v; want named-config route conflict", envelope)
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

	t.Run("native pairing PIN is forwarded only for a live pair", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		args := []string{"remote", "pair", "--host", "gaming-pc.local", "--pin", "0427", "--confirm-physical-host"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		if runner.called != 1 || !reflect.DeepEqual(runner.args, []string{"pair", "-pin", "0427", "gaming-pc.local"}) {
			t.Fatalf("runner=%+v; want native pair PIN argv", runner)
		}
	})

	t.Run("pairing PIN never enters dry-run JSON", func(t *testing.T) {
		a, out, _, _, runner := newTestApp(t)
		code := a.Run(context.Background(), []string{"remote", "pair", "--host", "gaming-pc.local", "--pin", "0427", "--confirm-physical-host", "--dry-run", "--json"})
		if code != ExitUsage || !strings.Contains(out.String(), "pairing PIN") || strings.Contains(out.String(), "0427") || runner.called != 0 {
			t.Fatalf("code=%d output=%q runner.called=%d; want rejected secret-free dry run", code, out.String(), runner.called)
		}
	})

	t.Run("Embedded pairing PIN is forwarded", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		directory := t.TempDir()
		name := "moonlight-embedded"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
		a.RemoteEnv = remote.RealEnvironment{}
		code := a.Run(context.Background(), []string{"remote", "pair", "--client", "moonlight-embedded", "--host", "gaming-pc.local", "--pin", "0427", "--confirm-physical-host"})
		if code != ExitOK || runner.called != 1 || !reflect.DeepEqual(runner.args, []string{"pair", "-pin", "0427", "gaming-pc.local"}) {
			t.Fatalf("code=%d stderr=%q runner=%+v; want Embedded pair PIN argv", code, errOut.String(), runner)
		}
	})

	t.Run("Qt platform override is forwarded to a live stream", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.outputs = []string{"Desktop\nLeague of Legends\n", "stream output\n"}
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--qt-platform", "xcb", "--confirm-physical-host", "--acknowledge-unverified-handoff"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		if runner.qtPlatform != "xcb" || runner.called != 2 {
			t.Fatalf("runner Qt platform=%q calls=%d; want xcb and list preflight plus stream", runner.qtPlatform, runner.called)
		}
		want := []string{"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication}
		if !reflect.DeepEqual(runner.args, want) {
			t.Fatalf("stream args=%#v; want %#v", runner.args, want)
		}
	})

	t.Run("Qt platform override is available in dry-run JSON", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		args := []string{"remote", "stream", "--host", "gaming-pc.local", "--qt-platform", "wayland", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		if plan["qt_platform"] != "wayland" || runner.called != 0 {
			t.Fatalf("plan=%#v runner.called=%d; want a dry-run Qt platform and no process", plan, runner.called)
		}
	})

	t.Run("Qt platform rejects non-stream operations", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		code := a.Run(context.Background(), []string{"remote", "pair", "--host", "gaming-pc.local", "--qt-platform", "xcb"})
		if code != ExitUsage || !strings.Contains(errOut.String(), "requires the stream operation") || runner.called != 0 {
			t.Fatalf("code=%d stderr=%q runner.called=%d; want stream-only rejection", code, errOut.String(), runner.called)
		}
	})

	t.Run("live pairing sends Wake-on-LAN before the Moonlight pair operation", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		packetCh := make(chan []byte, 1)
		go func() {
			buffer := make([]byte, 2048)
			_ = listener.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				packetCh <- nil
				return
			}
			packetCh <- append([]byte(nil), buffer[:n]...)
		}()
		args := []string{
			"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "00:11:22:33:44:55",
			"--wake-broadcast", "127.0.0.1", "--wake-port", strconv.Itoa(port), "--wake-wait", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		packet := <-packetCh
		if len(packet) != 102 {
			t.Fatalf("Wake-on-LAN packet length = %d; want 102", len(packet))
		}
		for index := 0; index < 6; index++ {
			if packet[index] != 0xff {
				t.Fatalf("packet prefix byte %d = %#x; want ff", index, packet[index])
			}
		}
		mac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
		for repeat := 0; repeat < 16; repeat++ {
			if !bytes.Equal(packet[6+repeat*6:6+(repeat+1)*6], mac) {
				t.Fatalf("packet MAC repeat %d = %x; want %x", repeat, packet[6+repeat*6:6+(repeat+1)*6], mac)
			}
		}
		if runner.called != 1 || len(runner.argsHistory) != 1 || !reflect.DeepEqual(runner.argsHistory[0], []string{"pair", "gaming-pc.local"}) {
			t.Fatalf("runner calls=%d history=%#v; want one pair operation after wake", runner.called, runner.argsHistory)
		}
		if !strings.Contains(out.String(), "Wake-on-LAN packet sent") || !strings.Contains(out.String(), "moonlight output") {
			t.Fatalf("stdout=%q stderr=%q; want wake confirmation and pair output", out.String(), errOut.String())
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

	t.Run("live stream sends Wake-on-LAN before host application preflight", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		packetCh := make(chan []byte, 1)
		go func() {
			buffer := make([]byte, 2048)
			_ = listener.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				packetCh <- nil
				return
			}
			packetCh <- append([]byte(nil), buffer[:n]...)
		}()
		runner.outputs = []string{"Desktop\nLeague of Legends\n", "stream output\n"}
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "00:11:22:33:44:55",
			"--wake-broadcast", "127.0.0.1", "--wake-port", strconv.Itoa(port), "--wake-wait", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		packet := <-packetCh
		if len(packet) != 102 {
			t.Fatalf("Wake-on-LAN packet length = %d; want 102", len(packet))
		}
		for index := 0; index < 6; index++ {
			if packet[index] != 0xff {
				t.Fatalf("packet prefix byte %d = %#x; want ff", index, packet[index])
			}
		}
		mac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
		for repeat := 0; repeat < 16; repeat++ {
			if !bytes.Equal(packet[6+repeat*6:6+(repeat+1)*6], mac) {
				t.Fatalf("packet MAC repeat %d = %x; want %x", repeat, packet[6+repeat*6:6+(repeat+1)*6], mac)
			}
		}
		if runner.called != 2 || len(runner.argsHistory) != 2 || runner.argsHistory[0][0] != "list" || runner.argsHistory[1][0] != "stream" {
			t.Fatalf("runner calls=%d history=%#v; want list preflight followed by stream", runner.called, runner.argsHistory)
		}
		if !strings.Contains(out.String(), "Wake-on-LAN packet sent") || !strings.Contains(errOut.String(), "preflight:") {
			t.Fatalf("stdout=%q stderr=%q; want wake confirmation and host preflight", out.String(), errOut.String())
		}
	})

	t.Run("WOL retries a slow host application list before streaming", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		packetCh := make(chan []byte, 1)
		go func() {
			buffer := make([]byte, 2048)
			_ = listener.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				packetCh <- nil
				return
			}
			packetCh <- append([]byte(nil), buffer[:n]...)
		}()
		runner.results = []error{errors.New("host still booting"), nil, nil}
		runner.outputs = []string{"", "Desktop\nLeague of Legends\n", "stream output\n"}
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "00:11:22:33:44:55",
			"--wake-broadcast", "127.0.0.1", "--wake-port", strconv.Itoa(port), "--wake-wait", "0",
			"--wake-retries", "1", "--wake-retry-delay", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if packet := <-packetCh; len(packet) != 102 {
			t.Fatalf("Wake-on-LAN packet length = %d; want 102", len(packet))
		}
		wantHistory := [][]string{
			{"list", "gaming-pc.local"},
			{"list", "gaming-pc.local"},
			{"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication},
		}
		if runner.called != 3 || !reflect.DeepEqual(runner.argsHistory, wantHistory) {
			t.Fatalf("runner calls=%d history=%#v; want one failed list, one retry, and one stream", runner.called, runner.argsHistory)
		}
		if !strings.Contains(errOut.String(), "Wake-on-LAN retry attempt(s) remaining") {
			t.Fatalf("stderr=%q; want bounded WOL retry notice", errOut.String())
		}
	})

	t.Run("WOL does not retry a successful listing that lacks the app", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		runner.outputs = []string{"Steam\n"}
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "00:11:22:33:44:55",
			"--wake-broadcast", "127.0.0.1", "--wake-port", strconv.Itoa(port), "--wake-wait", "0",
			"--wake-retries", "3", "--wake-retry-delay", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		if runner.called != 1 || strings.Contains(errOut.String(), "retrying") {
			t.Fatalf("runner calls=%d stderr=%q; want one fail-closed listing check", runner.called, errOut.String())
		}
	})

	t.Run("stream reconnect retries a failed session with the same plan", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nLeague of Legends\n"
		runner.results = []error{nil, errors.New("temporary connection loss"), nil, nil}
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--reconnect-attempts", "1", "--reconnect-delay", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		if runner.called != 4 {
			t.Fatalf("runner.called=%d; want initial list preflight, failed stream, retry list preflight, and successful stream", runner.called)
		}
		wantHistory := [][]string{
			{"list", "gaming-pc.local"},
			{"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication},
			{"list", "gaming-pc.local"},
			{"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication},
		}
		if !reflect.DeepEqual(runner.argsHistory, wantHistory) {
			t.Fatalf("runner.argsHistory=%#v; want %#v", runner.argsHistory, wantHistory)
		}
		if !reflect.DeepEqual(runner.args, []string{"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication}) {
			t.Fatalf("final runner args=%#v; want the original fixed stream plan", runner.args)
		}
		if !strings.Contains(errOut.String(), "reconnect attempt(s) remaining") {
			t.Fatalf("stderr=%q; want retry notice", errOut.String())
		}
	})

	t.Run("stream reconnect rechecks application before launching retry", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.results = []error{nil, errors.New("temporary connection loss"), nil}
		runner.outputs = []string{"Desktop\nLeague of Legends\n", "", "Steam\n"}
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--reconnect-attempts", "1", "--reconnect-delay", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitBlocked {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		wantHistory := [][]string{
			{"list", "gaming-pc.local"},
			{"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication},
			{"list", "gaming-pc.local"},
		}
		if !reflect.DeepEqual(runner.argsHistory, wantHistory) {
			t.Fatalf("runner.argsHistory=%#v; want %#v", runner.argsHistory, wantHistory)
		}
		if strings.Contains(errOut.String(), "stream attempt 2") {
			t.Fatalf("stderr=%q; retry stream must not start after application disappears", errOut.String())
		}
		if !strings.Contains(errOut.String(), "no stream was started") {
			t.Fatalf("stderr=%q; want fail-closed application check", errOut.String())
		}
	})

	t.Run("stream reconnect never retries cancellation", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		useRealRemoteFixture(t, a)
		runner.output = "Desktop\nLeague of Legends\n"
		runner.results = []error{nil, context.Canceled}
		args := []string{
			"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--reconnect-attempts", "2", "--reconnect-delay", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitInternal {
			t.Fatalf("code = %d; stderr=%q", code, errOut.String())
		}
		if runner.called != 2 {
			t.Fatalf("runner.called=%d; want one list preflight and one canceled stream", runner.called)
		}
		if strings.Contains(errOut.String(), "retrying") {
			t.Fatalf("stderr=%q; cancellation must not trigger a retry", errOut.String())
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

func TestRemoteEmbeddedStreamRequiresControllerMapping(t *testing.T) {
	t.Chdir(t.TempDir())
	a, _, errOut, _, runner := newTestApp(t)
	a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
	t.Setenv("HOME", t.TempDir())
	for _, name := range []string{"SDL_GAMECONTROLLERCONFIG", "XDG_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_DATA_DIRS"} {
		t.Setenv(name, "")
	}

	code := a.Run(context.Background(), []string{
		"remote", "stream", "--client", "moonlight-embedded", "--host", "gaming-pc.local",
		"--confirm-physical-host", "--acknowledge-unverified-handoff",
	})
	if code != ExitBlocked || runner.called != 0 {
		t.Fatalf("code=%d stderr=%q runner.called=%d; want early mapping block and no process", code, errOut.String(), runner.called)
	}
	if !strings.Contains(errOut.String(), "gamecontrollerdb.txt") || !strings.Contains(errOut.String(), "--input-mapping") {
		t.Fatalf("stderr=%q; want actionable controller-mapping guidance", errOut.String())
	}
}

func TestEmbeddedStreamMappingAvailability(t *testing.T) {
	t.Chdir(t.TempDir())
	resetEnvironment := func(t *testing.T) {
		t.Helper()
		t.Setenv("HOME", t.TempDir())
		for _, name := range []string{"SDL_GAMECONTROLLERCONFIG", "XDG_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_DATA_DIRS"} {
			t.Setenv(name, "")
		}
	}

	t.Run("missing mapping is rejected for non-SDL streams", func(t *testing.T) {
		resetEnvironment(t)
		err := validateEmbeddedStreamMappingAvailability("", "auto")
		if err == nil || !strings.Contains(err.Error(), "gamecontrollerdb.txt") {
			t.Fatalf("error=%v; want missing mapping error", err)
		}
	})

	t.Run("explicit SDL backend does not require the database", func(t *testing.T) {
		resetEnvironment(t)
		if err := validateEmbeddedStreamMappingAvailability("", "sdl"); err != nil {
			t.Fatalf("unexpected SDL mapping error: %v", err)
		}
	})

	t.Run("environment mapping does not require a file path", func(t *testing.T) {
		resetEnvironment(t)
		t.Setenv("SDL_GAMECONTROLLERCONFIG", "030000005e0400008e02000000000000,Example Controller")
		if err := validateEmbeddedStreamMappingAvailability("", "x11"); err != nil {
			t.Fatalf("unexpected environment mapping error: %v", err)
		}
	})

	t.Run("home package data is discovered", func(t *testing.T) {
		resetEnvironment(t)
		home := t.TempDir()
		t.Setenv("HOME", home)
		mappingDir := filepath.Join(home, "moonlight")
		if err := os.MkdirAll(mappingDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mappingDir, "gamecontrollerdb.txt"), []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validateEmbeddedStreamMappingAvailability("", "x11"); err != nil {
			t.Fatalf("unexpected package mapping error: %v", err)
		}
	})

	t.Run("explicit mapping is opened and bounded", func(t *testing.T) {
		resetEnvironment(t)
		mapping := filepath.Join(t.TempDir(), "mapping.txt")
		if err := os.WriteFile(mapping, []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validateEmbeddedStreamMappingAvailability(mapping, "x11"); err != nil {
			t.Fatalf("unexpected explicit mapping error: %v", err)
		}
	})

	t.Run("missing explicit mapping is rejected", func(t *testing.T) {
		resetEnvironment(t)
		mapping := filepath.Join(t.TempDir(), "missing.txt")
		err := validateEmbeddedStreamMappingAvailability(mapping, "x11")
		if err == nil || !strings.Contains(err.Error(), "cannot be read") {
			t.Fatalf("error=%v; want explicit mapping read error", err)
		}
	})
}

func TestRemoteStreamAutomaticallyFallsBackToReadyNativeClient(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	// The fake runner does not provide Moonlight's package-owned mapping data;
	// model the environment variable that makes Embedded accept its input path.
	t.Setenv("SDL_GAMECONTROLLERCONFIG", "fixture-controller-map")
	directory := t.TempDir()
	for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
		fileName := clientName
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	qtBlocked := readyClientReport()
	qtBlocked.Status = probe.StatusFail
	qtBlocked.Checks[1].Status = probe.StatusFail
	qtBlocked.Checks[2].Status = probe.StatusFail
	prober.clientReports = map[string]probe.Report{
		"auto":               qtBlocked,
		"moonlight-qt":       qtBlocked,
		"moonlight-embedded": readyClientReport(),
	}
	runner.outputs = []string{"League of Legends\n", "stream output\n"}

	code := a.Run(context.Background(), []string{
		"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--acknowledge-unverified-handoff",
	})
	if code != ExitOK || runner.called != 2 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want application preflight plus stream execution", code, out.String(), errOut.String(), runner.called)
	}
	if !strings.Contains(errOut.String(), "automatic Moonlight selection used moonlight-embedded") {
		t.Fatalf("stderr=%q; want fallback warning", errOut.String())
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto", "moonlight-qt", "moonlight-embedded"}) {
		t.Fatalf("client selections=%#v; want automatic fallback sequence", prober.clientSelections)
	}
	if !strings.Contains(out.String(), "stream output") {
		t.Fatalf("stdout=%q; want stream output", out.String())
	}
}

func TestRemoteStreamAutomaticQtSelectionUsesFlatpakWhenNativeQtIsMissing(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	directory := t.TempDir()
	flatpakName := "flatpak"
	if runtime.GOOS == "windows" {
		flatpakName += ".exe"
	}
	flatpakPath := filepath.Join(directory, flatpakName)
	a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"flatpak": flatpakPath}}
	blockedQt := readyClientReport()
	blockedQt.Status = probe.StatusFail
	blockedQt.Checks[3].Status = probe.StatusFail
	prober.clientReports = map[string]probe.Report{
		"moonlight-qt":       blockedQt,
		"moonlight-embedded": readyClientReport(),
		"moonlight":          readyClientReport(),
		"flatpak":            readyClientReport(),
	}
	code := a.Run(context.Background(), []string{
		"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--acknowledge-unverified-handoff", "--decoder", "software", "--dry-run", "--json",
	})
	if code != ExitOK || runner.called != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d selections=%#v; want a Flatpak dry-run plan", code, out.String(), errOut.String(), runner.called, prober.clientSelections)
	}
	if !strings.Contains(out.String(), `"flavor": "moonlight-flatpak"`) || !strings.Contains(out.String(), `"binary":`) || !strings.Contains(out.String(), flatpakName) {
		t.Fatalf("stdout=%q; want the discovered Flatpak client", out.String())
	}
	if !strings.Contains(out.String(), `"-video-decoder"`) || !strings.Contains(out.String(), `"software"`) {
		t.Fatalf("stdout=%q; want the Qt-only decoder option", out.String())
	}
	if !strings.Contains(out.String(), "automatic Moonlight selection used flatpak") {
		t.Fatalf("stdout=%q; want Flatpak selection warning", out.String())
	}
}

func TestAutomaticFallbackKeepsLinuxGenericMoonlightQtFlavor(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		find func(context.Context, ProbeRunner, remote.Environment, string) (remote.Client, probe.Report, string, bool)
	}{
		{
			name: "stream",
			find: func(ctx context.Context, prober ProbeRunner, environment remote.Environment, excluded string) (remote.Client, probe.Report, string, bool) {
				return discoverAutomaticStreamClientForFlavorExcluding(ctx, prober, environment, "linux", "", "", remote.FlavorQt, excluded)
			},
		},
		{
			name: "control",
			find: func(ctx context.Context, prober ProbeRunner, environment remote.Environment, excluded string) (remote.Client, probe.Report, string, bool) {
				return discoverAutomaticControlClientExcluding(ctx, prober, environment, "linux", excluded)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			blocked := readyClientReport()
			blocked.Status = probe.StatusFail
			blocked.Checks[0].Status = probe.StatusFail
			prober := &scriptedProber{
				clientReports: map[string]probe.Report{
					"moonlight-qt":       readyClientReport(),
					"moonlight-embedded": blocked,
					"moonlight":          readyClientReport(),
				},
			}
			environment := fakeRemoteEnvironment{paths: map[string]string{
				"moonlight-qt":       "/fixture/preferred-qt",
				"moonlight-embedded": "/fixture/embedded",
				"moonlight":          "/fixture/generic-qt",
			}}
			client, _, selection, found := tt.find(context.Background(), prober, environment, "/fixture/preferred-qt")
			if !found {
				t.Fatalf("automatic fallback did not find the generic Qt candidate; selections=%#v", prober.clientSelections)
			}
			if client.Binary != "/fixture/generic-qt" || client.Flavor != remote.FlavorQt || selection != "moonlight" {
				t.Fatalf("client=%+v selection=%q; want generic binary classified as Qt", client, selection)
			}
			if !reflect.DeepEqual(prober.clientSelections, []string{"moonlight-qt", "moonlight-embedded", "moonlight"}) {
				t.Fatalf("client selections=%#v; want distinct generic candidate after preferred Qt", prober.clientSelections)
			}
		})
	}
}

func TestRemoteStreamRetriesAutomaticDiscoveryAfterTransientLookupFailure(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	t.Setenv("SDL_GAMECONTROLLERCONFIG", "fixture-controller-map")
	directory := t.TempDir()
	setExecutable := func() {
		fileName := "moonlight-embedded"
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The initial automatic preflight is intentionally optimistic in this
	// fixture. The client appears on PATH only while the fallback is probing the
	// first explicit candidate, modeling a package/PATH change between preflight
	// and passive discovery.
	prober.beforeClient = func(selection string) {
		if selection == "moonlight-qt" {
			setExecutable()
		}
	}
	t.Setenv("PATH", directory)
	a.RemoteEnv = remote.RealEnvironment{}
	prober.clientReports = map[string]probe.Report{
		"auto":               readyClientReport(),
		"moonlight-qt":       readyClientReport(),
		"moonlight-embedded": readyClientReport(),
	}
	runner.outputs = []string{"League of Legends\n", "stream output\n"}

	code := a.Run(context.Background(), []string{
		"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--acknowledge-unverified-handoff",
	})
	if code != ExitOK || runner.called != 2 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want application preflight plus stream execution", code, out.String(), errOut.String(), runner.called)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto", "moonlight-qt", "moonlight-embedded"}) {
		t.Fatalf("client selections=%#v; want automatic discovery retry sequence", prober.clientSelections)
	}
	if !strings.Contains(errOut.String(), "automatic Moonlight selection used moonlight-embedded") {
		t.Fatalf("stderr=%q; want fallback warning", errOut.String())
	}
	if !strings.Contains(out.String(), "stream output") {
		t.Fatalf("stdout=%q; want stream output", out.String())
	}
}

func TestRemoteStreamRetriesAutomaticClientAfterApplicationListFailure(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	t.Setenv("SDL_GAMECONTROLLERCONFIG", "fixture-controller-map")
	directory := t.TempDir()
	for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
		fileName := clientName
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	prober.clientReports = map[string]probe.Report{
		"auto":               readyClientReport(),
		"moonlight-qt":       readyClientReport(),
		"moonlight-embedded": readyClientReport(),
	}
	runner.results = []error{errors.New("Qt application-list handshake failed"), nil, nil}
	runner.outputs = []string{"", "League of Legends\n", "stream output\n"}

	code := a.Run(context.Background(), []string{
		"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--acknowledge-unverified-handoff",
	})
	if code != ExitOK || runner.called != 3 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want failed Qt list, Embedded list, and stream", code, out.String(), errOut.String(), runner.called)
	}
	wantHistory := [][]string{
		{"list", "gaming-pc.local"},
		{"list", "gaming-pc.local"},
		{"stream", "-app", config.DefaultRemoteApplication, "gaming-pc.local"},
	}
	if !reflect.DeepEqual(runner.argsHistory, wantHistory) {
		t.Fatalf("runner.argsHistory=%#v; want %#v", runner.argsHistory, wantHistory)
	}
	if !strings.Contains(errOut.String(), "failed the host application-list preflight") {
		t.Fatalf("stderr=%q; want automatic client recovery warning", errOut.String())
	}
	if !strings.Contains(out.String(), "stream output") {
		t.Fatalf("stdout=%q; want stream output", out.String())
	}
}

func TestRemoteStreamRetriesAutomaticClientAfterReconnectListFailure(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	t.Setenv("SDL_GAMECONTROLLERCONFIG", "fixture-controller-map")
	directory := t.TempDir()
	for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
		fileName := clientName
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	prober.clientReports = map[string]probe.Report{
		"auto":               readyClientReport(),
		"moonlight-qt":       readyClientReport(),
		"moonlight-embedded": readyClientReport(),
	}
	runner.results = []error{
		nil,
		errors.New("preferred stream failed"),
		errors.New("preferred reconnect application-list failed"),
		nil,
		nil,
	}
	runner.outputs = []string{"League of Legends\n", "", "", "League of Legends\n", "stream output\n"}

	code := a.Run(context.Background(), []string{
		"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--acknowledge-unverified-handoff", "--reconnect-attempts", "1", "--reconnect-delay", "0",
	})
	if code != ExitOK || runner.called != 5 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want initial list, failed stream, failed reconnect list, fallback list, and stream", code, out.String(), errOut.String(), runner.called)
	}
	wantFallbackStream := []string{"stream", "-app", config.DefaultRemoteApplication, "gaming-pc.local"}
	if !reflect.DeepEqual(runner.argsHistory[4], wantFallbackStream) {
		t.Fatalf("reconnect stream args=%#v; want Embedded stream args %#v", runner.argsHistory[4], wantFallbackStream)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto", "moonlight-qt", "moonlight-embedded"}) {
		t.Fatalf("client selections=%#v; want one bounded fallback after reconnect-list failure", prober.clientSelections)
	}
	if !strings.Contains(errOut.String(), "failed the host application-list preflight") {
		t.Fatalf("stderr=%q; want reconnect fallback warning", errOut.String())
	}
	if !strings.Contains(out.String(), "stream output") {
		t.Fatalf("stdout=%q; want recovered stream output", out.String())
	}
}

func TestRemoteStreamDoesNotReplaceAutomaticClientAfterMissingApplication(t *testing.T) {
	a, _, errOut, prober, runner := newTestApp(t)
	directory := t.TempDir()
	for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
		fileName := clientName
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	prober.clientReports = map[string]probe.Report{
		"auto":               readyClientReport(),
		"moonlight-qt":       readyClientReport(),
		"moonlight-embedded": readyClientReport(),
	}
	runner.output = "Desktop\nSteam\n"

	code := a.Run(context.Background(), []string{
		"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--acknowledge-unverified-handoff",
	})
	if code != ExitBlocked || runner.called != 1 {
		t.Fatalf("code=%d stderr=%q runner.called=%d; want one blocked list preflight", code, errOut.String(), runner.called)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto"}) {
		t.Fatalf("client selections=%#v; a successful list without the requested app must not trigger client replacement", prober.clientSelections)
	}
	if !strings.Contains(errOut.String(), "no stream was started") {
		t.Fatalf("stderr=%q; want fail-closed missing-application result", errOut.String())
	}
}

func TestRemoteListRetriesAutomaticClientAfterExecutionFailure(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	directory := t.TempDir()
	for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
		fileName := clientName
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	prober.clientReports = map[string]probe.Report{
		"auto":               readyClientReport(),
		"moonlight-qt":       readyClientReport(),
		"moonlight-embedded": readyClientReport(),
	}
	runner.results = []error{errors.New("Qt application-list operation failed"), nil}
	runner.outputs = []string{"", "League of Legends\n"}

	code := a.Run(context.Background(), []string{
		"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--require-app", "League of Legends",
	})
	if code != ExitOK || runner.called != 2 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want failed Qt list followed by Embedded list", code, out.String(), errOut.String(), runner.called)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto", "moonlight-qt", "moonlight-embedded"}) {
		t.Fatalf("client selections=%#v; want automatic control fallback sequence", prober.clientSelections)
	}
	if !strings.Contains(errOut.String(), "failed the application-list operation") {
		t.Fatalf("stderr=%q; want automatic client recovery warning", errOut.String())
	}
	if !strings.Contains(out.String(), "League of Legends") {
		t.Fatalf("stdout=%q; want the successful listing", out.String())
	}
}

func TestRemoteListAutomaticallyFallsBackWhenControlPreflightBlocksPreferredClient(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	directory := t.TempDir()
	for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
		fileName := clientName
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	blocked := readyClientReport()
	blocked.Status = probe.StatusFail
	blocked.Checks[0].Status = probe.StatusFail
	prober.clientReports = map[string]probe.Report{
		"auto":               blocked,
		"moonlight-qt":       blocked,
		"moonlight-embedded": readyClientReport(),
	}
	runner.output = "Desktop\nLeague of Legends\n"

	code := a.Run(context.Background(), []string{
		"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--require-app", "League of Legends",
	})
	if code != ExitOK || runner.called != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want one Embedded list operation", code, out.String(), errOut.String(), runner.called)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto", "moonlight-qt", "moonlight-embedded"}) {
		t.Fatalf("client selections=%#v; want control-preflight fallback sequence", prober.clientSelections)
	}
	if !strings.Contains(errOut.String(), "used moonlight-embedded after the preferred automatic client could not be used for application listing") {
		t.Fatalf("stderr=%q; want preflight fallback warning", errOut.String())
	}
}

func TestRemoteListDoesNotReplaceAutomaticClientAfterMissingApplication(t *testing.T) {
	a, _, errOut, prober, runner := newTestApp(t)
	directory := t.TempDir()
	for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
		fileName := clientName
		if runtime.GOOS == "windows" {
			fileName += ".exe"
		}
		if err := os.WriteFile(filepath.Join(directory, fileName), []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	a.RemoteEnv = remote.RealEnvironment{}
	prober.clientReports = map[string]probe.Report{
		"auto":               readyClientReport(),
		"moonlight-qt":       readyClientReport(),
		"moonlight-embedded": readyClientReport(),
	}
	runner.output = "Desktop\nSteam\n"

	code := a.Run(context.Background(), []string{
		"remote", "list", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--require-app", "League of Legends",
	})
	if code != ExitBlocked || runner.called != 1 {
		t.Fatalf("code=%d stderr=%q runner.called=%d; want one blocked list operation", code, errOut.String(), runner.called)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto"}) {
		t.Fatalf("client selections=%#v; a successful list without the requested app must not trigger client replacement", prober.clientSelections)
	}
	if !strings.Contains(errOut.String(), "was not advertised") {
		t.Fatalf("stderr=%q; want fail-closed missing-application result", errOut.String())
	}
}

func TestRemoteControlRetriesAutomaticClientAfterExecutionFailure(t *testing.T) {
	for _, operation := range []string{"pair", "quit"} {
		t.Run(operation, func(t *testing.T) {
			a, out, errOut, prober, runner := newTestApp(t)
			directory := t.TempDir()
			paths := make(map[string]string)
			for _, clientName := range []string{"moonlight-qt", "moonlight-embedded"} {
				fileName := clientName
				if runtime.GOOS == "windows" {
					fileName += ".exe"
				}
				path := filepath.Join(directory, fileName)
				if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
					t.Fatal(err)
				}
				paths[clientName] = path
			}
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			a.RemoteEnv = remote.RealEnvironment{}
			prober.clientReports = map[string]probe.Report{
				"auto":               readyClientReport(),
				"moonlight-qt":       readyClientReport(),
				"moonlight-embedded": readyClientReport(),
			}
			runner.results = []error{errors.New("preferred control operation failed"), nil}

			code := a.Run(context.Background(), []string{
				"remote", operation, "--host", "gaming-pc.local", "--confirm-physical-host",
			})
			if code != ExitOK || runner.called != 2 {
				t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want failed preferred %s followed by Embedded retry", code, out.String(), errOut.String(), runner.called, operation)
			}
			if runner.name != paths["moonlight-embedded"] || !reflect.DeepEqual(runner.argsHistory, [][]string{{operation, "gaming-pc.local"}, {operation, "gaming-pc.local"}}) {
				t.Fatalf("runner name=%q args=%#v; want Embedded retry with fixed %s argv", runner.name, runner.argsHistory, operation)
			}
			if !reflect.DeepEqual(prober.clientSelections, []string{"auto", "moonlight-qt", "moonlight-embedded"}) {
				t.Fatalf("client selections=%#v; want automatic control fallback sequence", prober.clientSelections)
			}
			if !strings.Contains(errOut.String(), "failed the "+operation+" operation") {
				t.Fatalf("stderr=%q; want automatic client recovery warning", errOut.String())
			}
		})
	}
}

func TestRemoteControlFallsBackWhenAutomaticPreflightBlocksPreferred(t *testing.T) {
	for _, operation := range []string{"pair", "quit"} {
		t.Run(operation, func(t *testing.T) {
			a, out, errOut, prober, runner := newTestApp(t)
			directory := t.TempDir()
			embeddedName := "moonlight-embedded"
			qtName := "moonlight-qt"
			if runtime.GOOS == "windows" {
				embeddedName += ".exe"
				qtName += ".exe"
			}
			embeddedPath := filepath.Join(directory, embeddedName)
			qtPath := filepath.Join(directory, qtName)
			for _, path := range []string{embeddedPath, qtPath} {
				if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			a.RemoteEnv = remote.RealEnvironment{}
			blocked := readyClientReport()
			blocked.Status = probe.StatusFail
			blocked.Checks[0].Status = probe.StatusFail
			prober.clientReports = map[string]probe.Report{
				"auto":               blocked,
				"moonlight-qt":       blocked,
				"moonlight-embedded": readyClientReport(),
			}

			code := a.Run(context.Background(), []string{
				"remote", operation, "--host", "gaming-pc.local", "--confirm-physical-host",
			})
			if code != ExitOK || runner.called != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want one Embedded %s operation", code, out.String(), errOut.String(), runner.called, operation)
			}
			if runner.name != embeddedPath || !reflect.DeepEqual(runner.args, []string{operation, "gaming-pc.local"}) {
				t.Fatalf("runner name=%q args=%#v; want Embedded %s argv", runner.name, runner.args, operation)
			}
			if !reflect.DeepEqual(prober.clientSelections, []string{"auto", "moonlight-qt", "moonlight-embedded"}) {
				t.Fatalf("client selections=%#v; want automatic preflight fallback sequence", prober.clientSelections)
			}
			if !strings.Contains(errOut.String(), "could not be used for "+operation+" operation") {
				t.Fatalf("stderr=%q; want operation-specific preflight warning", errOut.String())
			}
		})
	}
}

func TestRemoteControlDoesNotFallbackAfterCancellation(t *testing.T) {
	a, _, errOut, prober, runner := newTestApp(t)
	useRealRemoteFixture(t, a)
	runner.results = []error{context.Canceled}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code := a.Run(ctx, []string{
		"remote", "pair", "--host", "gaming-pc.local", "--confirm-physical-host",
	})
	if code != ExitBlocked || runner.called != 0 {
		t.Fatalf("code=%d stderr=%q runner.called=%d; want cancellation to stop before operation execution", code, errOut.String(), runner.called)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto"}) {
		t.Fatalf("client selections=%#v; cancellation must not probe a fallback client", prober.clientSelections)
	}
}

func TestRemoteStreamDryRunDoesNotProbeAutomaticFallback(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{
		"moonlight-qt":       "/fixture/moonlight-qt",
		"moonlight-embedded": "/fixture/moonlight-embedded",
	}}
	blocked := readyClientReport()
	blocked.Status = probe.StatusFail
	blocked.Checks[1].Status = probe.StatusFail
	blocked.Checks[2].Status = probe.StatusFail
	prober.clientReports = map[string]probe.Report{
		"auto":               blocked,
		"moonlight-qt":       readyClientReport(),
		"moonlight-embedded": readyClientReport(),
	}

	code := a.Run(context.Background(), []string{
		"remote", "stream", "--host", "gaming-pc.local", "--confirm-physical-host",
		"--acknowledge-unverified-handoff", "--dry-run", "--json",
	})
	if code != ExitBlocked || runner.called != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want a blocked dry-run without fallback or execution", code, out.String(), errOut.String(), runner.called)
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"auto"}) {
		t.Fatalf("client selections=%#v; want only the initial dry-run preflight", prober.clientSelections)
	}
}

func TestEffectiveRemoteStreamClientSelectionHonorsOptionSurface(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		options    remote.StreamOptions
		wantClient string
	}{
		{name: "Qt decoder", options: remote.StreamOptions{Decoder: "hardware"}, wantClient: "moonlight-qt"},
		{name: "Embedded input", options: remote.StreamOptions{InputDevice: "/dev/input/event4"}, wantClient: "moonlight-embedded"},
		{name: "Qt mouse mode", options: remote.StreamOptions{MouseMode: "relative"}, wantClient: "moonlight-qt"},
		{name: "Embedded platform", options: remote.StreamOptions{Platform: "sdl"}, wantClient: "moonlight-embedded"},
		{name: "shared fullscreen mode", options: remote.StreamOptions{DisplayMode: "fullscreen"}, wantClient: "auto"},
		{name: "Qt borderless", options: remote.StreamOptions{DisplayMode: "borderless"}, wantClient: "moonlight-qt"},
		{name: "shared windowed mode", options: remote.StreamOptions{DisplayMode: "windowed"}, wantClient: "auto"},
		{name: "HDR is shared", options: remote.StreamOptions{HDR: true}, wantClient: "auto"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := effectiveRemoteStreamClientSelection("auto", "", "", tt.options)
			if err != nil {
				t.Fatalf("selection error = %v", err)
			}
			if got != tt.wantClient {
				t.Fatalf("selection = %q, want %q", got, tt.wantClient)
			}
		})
	}
	if _, err := effectiveRemoteStreamClientSelection("auto", "", "", remote.StreamOptions{
		Decoder: "hardware", InputDevice: "/dev/input/event4",
	}); err == nil || !strings.Contains(err.Error(), "both Embedded and Qt") {
		t.Fatalf("mixed backend options error = %v; want conflict", err)
	}
	if got, err := effectiveRemoteStreamClientSelection(" MOONLIGHT-QT ", "", "", remote.StreamOptions{}); err != nil || got != "moonlight-qt" {
		t.Fatalf("case-insensitive client selection = %q, error=%v; want moonlight-qt", got, err)
	}
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
		if runner.called != 2 || !reflect.DeepEqual(runner.args, []string{"stream", "-no-absolute-mouse", "gaming-pc.local", "Custom League Entry"}) {
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
			"--acknowledge-unverified-handoff", "--app", "League of Legends", "--require-app", "League of Legends",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 2 {
			t.Fatalf("runner.called=%d; want one list preflight and one stream", runner.called)
		}
		if !reflect.DeepEqual(runner.args, []string{"stream", "-no-absolute-mouse", "gaming-pc.local", "League of Legends"}) {
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
		if runner.called != 2 || !reflect.DeepEqual(runner.args, []string{"stream", "-no-absolute-mouse", "gaming-pc.local", config.DefaultRemoteApplication}) {
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
			"--acknowledge-unverified-handoff", "--app", "League of Legends", "--require-app", "League of Legends",
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
			"--acknowledge-unverified-handoff", "--app", "League of Legends", "--require-app", "League of Legends",
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

func TestRemotePreflightUsesSelectedMoonlightClient(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
	args := []string{
		"remote", "pair", "--client", "moonlight-embedded", "--host", "gaming-pc.local",
		"--confirm-physical-host", "--dry-run",
	}
	if code := a.Run(context.Background(), args); code != ExitOK {
		t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !reflect.DeepEqual(prober.clientSelections, []string{"moonlight-embedded"}) {
		t.Fatalf("client selections = %#v, want explicit Embedded selection", prober.clientSelections)
	}
	if runner.called != 0 {
		t.Fatalf("dry run invoked remote runner %d time(s)", runner.called)
	}
}

func TestRemoteWakeUsesConfiguredPhysicalRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wake.json")
	a, out, errOut, _, runner := newTestApp(t)
	if code := a.Run(context.Background(), []string{
		"config", "init", "--file", path, "--host", "gaming-pc.local", "--confirm-physical-host",
	}); code != ExitOK {
		t.Fatalf("init code = %d; stderr=%q", code, errOut.String())
	}

	a, out, errOut, _, runner = newTestApp(t)
	if code := a.Run(context.Background(), []string{
		"remote", "wake", "--config", path, "--mac", "AA-BB-CC-DD-EE-FF",
		"--acknowledge-unverified-handoff", "--dry-run", "--json",
	}); code != ExitOK {
		t.Fatalf("wake code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	envelope := decodeEnvelope(t, out.Bytes())
	plan := envelope.Data.(map[string]any)
	if envelope.Command != "remote wake" || plan["mac"] != "aa:bb:cc:dd:ee:ff" || plan["destination"] != "255.255.255.255" || plan["port"] != float64(9) || runner.called != 0 {
		t.Fatalf("envelope=%+v runner.called=%d; want normalized dry-run plan", envelope, runner.called)
	}

	a, out, errOut, _, runner = newTestApp(t)
	if code := a.Run(context.Background(), []string{
		"remote", "wake", "--config", path, "--mac", "00:11:22:33:44:55",
		"--confirm-physical-host=false", "--acknowledge-unverified-handoff", "--dry-run",
	}); code != ExitBlocked {
		t.Fatalf("revoked confirmation code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if runner.called != 0 || !strings.Contains(errOut.String(), "physical") {
		t.Fatalf("revoked confirmation stderr=%q runner.called=%d", errOut.String(), runner.called)
	}
}

func TestRemoteKVMOpensOnlyAnExplicitCleanEndpoint(t *testing.T) {
	t.Run("dry-run builds a shell-free xdg-open vector", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
		args := []string{
			"remote", "kvm", "--url", "https://kvm.lan/", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		launcher := plan["launcher"].(map[string]any)
		arguments := plan["arguments"].([]any)
		if envelope.Command != "remote kvm" || launcher["name"] != "xdg-open" || launcher["binary"] != "/fixture/xdg-open" || !reflect.DeepEqual(arguments, []any{"https://kvm.lan/"}) || runner.called != 0 {
			t.Fatalf("envelope=%+v runner.called=%d", envelope, runner.called)
		}
	})

	t.Run("dry-run honors an explicit physical Mac route", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
		args := []string{
			"remote", "kvm", "--route", "macos", "--url", "https://kvm.lan/", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 0 {
			t.Fatalf("runner.called=%d; dry-run must not launch the browser", runner.called)
		}
		if !strings.Contains(out.String(), "https://kvm.lan/") {
			t.Fatalf("stdout=%q; want selected KVM endpoint", out.String())
		}
	})

	t.Run("fully explicit Mac route ignores an unrelated default config", func(t *testing.T) {
		defaultPath := filepath.Join(t.TempDir(), "default-windows.json")
		writeConfigFile(t, defaultPath, nil)
		a, out, errOut, _, runner := newTestApp(t)
		// newTestApp supplies a missing config path for isolation; this test
		// deliberately replaces it with a valid Windows config to ensure the
		// explicit Mac invocation does not accidentally consult that route.
		t.Setenv("LEAGUEBRIDGE_CONFIG", defaultPath)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
		code := a.Run(context.Background(), []string{
			"remote", "kvm", "--route", "macos", "--url", "https://kvm.lan/",
			"--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json",
		})
		if code != ExitOK || runner.called != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q runner.called=%d; want explicit route to remain self-contained", code, out.String(), errOut.String(), runner.called)
		}
		if !strings.Contains(out.String(), "https://kvm.lan/") {
			t.Fatalf("stdout=%q; want selected KVM endpoint", out.String())
		}
	})

	t.Run("explicit route must agree with configured route", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mac-kvm.json")
		a, _, errOut, _, runner := newTestApp(t)
		if code := a.Run(context.Background(), []string{
			"config", "init", "--file", path, "--route", "macos", "--host", "gaming-mac.local",
			"--kvm-url", "https://kvm.lan/", "--confirm-physical-host",
		}); code != ExitOK {
			t.Fatalf("config init code = %d; stderr=%q", code, errOut.String())
		}
		a, _, errOut, _, runner = newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
		code := a.Run(context.Background(), []string{
			"remote", "kvm", "--config", path, "--route", "windows",
			"--acknowledge-unverified-handoff", "--dry-run",
		})
		if code != ExitUsage || !strings.Contains(errOut.String(), "conflicts with configuration route") || runner.called != 0 {
			t.Fatalf("code=%d stderr=%q runner.called=%d; want route-conflict rejection", code, errOut.String(), runner.called)
		}
	})

	t.Run("dry-run builds an endpoint-only direct browser vector", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"firefox": "/fixture/firefox"}}
		args := []string{
			"remote", "kvm", "--browser", "firefox", "--url", "https://kvm.lan/", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		launcher := plan["launcher"].(map[string]any)
		arguments := plan["arguments"].([]any)
		if launcher["name"] != "firefox" || launcher["binary"] != "/fixture/firefox" || !reflect.DeepEqual(arguments, []any{"https://kvm.lan/"}) || runner.called != 0 {
			t.Fatalf("envelope=%+v runner.called=%d", envelope, runner.called)
		}
	})

	t.Run("dry-run includes the opt-in Wake-on-LAN plan", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
		args := []string{
			"remote", "kvm", "--url", "https://kvm.lan/", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "00:11:22:33:44:55",
			"--wake-broadcast", "192.0.2.255", "--wake-port", "4009", "--wake-wait", "30",
			"--dry-run", "--json",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		plan := envelope.Data.(map[string]any)
		wake := plan["wake"].(map[string]any)
		if wake["mac"] != "00:11:22:33:44:55" || wake["destination"] != "192.0.2.255" || wake["port"] != float64(4009) || runner.called != 0 {
			t.Fatalf("wake=%#v runner.called=%d; want normalized no-I/O wake plan", wake, runner.called)
		}
	})

	t.Run("wake transport overrides require a MAC", func(t *testing.T) {
		a, _, errOut, _, runner := newTestApp(t)
		code := a.Run(context.Background(), []string{"remote", "kvm", "--url", "https://kvm.lan/", "--wake-port", "4009"})
		if code != ExitUsage || !strings.Contains(errOut.String(), "require --wake-mac") || runner.called != 0 {
			t.Fatalf("code=%d stderr=%q runner.called=%d", code, errOut.String(), runner.called)
		}
	})

	t.Run("live launch uses the discovered opener and bounded context", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		directory := t.TempDir()
		name := "xdg-open"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
		a.RemoteEnv = remote.RealEnvironment{}
		args := []string{
			"remote", "kvm", "--url", "https://kvm.lan/", "--confirm-physical-host",
			"--acknowledge-unverified-handoff",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 1 || runner.name != path || !reflect.DeepEqual(runner.args, []string{"https://kvm.lan/"}) {
			t.Fatalf("runner=%+v; want one xdg-open launch", runner)
		}
		if runner.ctx == nil {
			t.Fatal("KVM runner did not receive a context")
		}
		if deadline, ok := runner.ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > remoteControlTimeout {
			t.Fatalf("KVM runner deadline = %v; want a %s deadline", deadline, remoteControlTimeout)
		}
	})

	t.Run("live launch sends Wake-on-LAN before opening the KVM UI", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		directory := t.TempDir()
		name := "xdg-open"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
		a.RemoteEnv = remote.RealEnvironment{}
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		packetCh := make(chan []byte, 1)
		go func() {
			buffer := make([]byte, 2048)
			_ = listener.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				packetCh <- nil
				return
			}
			packetCh <- append([]byte(nil), buffer[:n]...)
		}()
		args := []string{
			"remote", "kvm", "--url", "https://kvm.lan/", "--confirm-physical-host",
			"--acknowledge-unverified-handoff", "--wake-mac", "00:11:22:33:44:55",
			"--wake-broadcast", "127.0.0.1", "--wake-port", strconv.Itoa(port), "--wake-wait", "0",
		}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		packet := <-packetCh
		if len(packet) != 102 {
			t.Fatalf("Wake-on-LAN packet length = %d; want 102", len(packet))
		}
		for index := 0; index < 6; index++ {
			if packet[index] != 0xff {
				t.Fatalf("packet prefix byte %d = %#x; want ff", index, packet[index])
			}
		}
		if runner.called != 1 || runner.name != path || !reflect.DeepEqual(runner.args, []string{"https://kvm.lan/"}) {
			t.Fatalf("runner=%+v; want one xdg-open launch after wake", runner)
		}
		if !strings.Contains(out.String(), "Wake-on-LAN packet sent") || !strings.Contains(errOut.String(), "warning:") {
			t.Fatalf("stdout=%q stderr=%q; want wake confirmation and warnings", out.String(), errOut.String())
		}
	})
}

func TestRemoteKVMRejectsCredentialsAndUnacknowledgedHandoffs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing physical confirmation", args: []string{"remote", "kvm", "--url", "https://kvm.lan/", "--acknowledge-unverified-handoff", "--dry-run"}, want: "not confirmed as a physical"},
		{name: "missing acknowledgement", args: []string{"remote", "kvm", "--url", "https://kvm.lan/", "--confirm-physical-host", "--dry-run"}, want: "pass explicit acknowledgement"},
		{name: "embedded credentials", args: []string{"remote", "kvm", "--url", "https://user:secret@kvm.lan/", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}, want: "must not contain embedded credentials"},
		{name: "query token", args: []string{"remote", "kvm", "--url", "https://kvm.lan/?token=secret", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}, want: "must not contain query parameters"},
		{name: "unencrypted endpoint", args: []string{"remote", "kvm", "--url", "http://kvm.lan/", "--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run"}, want: "pass --allow-http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, _, runner := newTestApp(t)
			a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
			if code := a.Run(context.Background(), tt.args); code != ExitUsage && code != ExitBlocked {
				t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if !strings.Contains(errOut.String(), tt.want) || runner.called != 0 {
				t.Fatalf("stderr=%q runner.called=%d; want %q and no process", errOut.String(), runner.called, tt.want)
			}
		})
	}
}

func TestRemoteKVMRequiresFreshPhysicalHostContracts(t *testing.T) {
	a, out, errOut, _, runner := newTestApp(t)
	a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"xdg-open": "/fixture/xdg-open"}}
	a.Now = func() time.Time { return fixedNow.AddDate(2, 0, 0) }
	args := []string{
		"remote", "kvm", "--url", "https://kvm.lan/", "--confirm-physical-host",
		"--acknowledge-unverified-handoff", "--dry-run",
	}
	if code := a.Run(context.Background(), args); code != ExitBlocked {
		t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "physical-host handoff contract") || !strings.Contains(errOut.String(), "evidence is stale") {
		t.Fatalf("stderr=%q; want stale physical-host contract failure", errOut.String())
	}
	if runner.called != 0 {
		t.Fatalf("runner.called=%d; stale KVM contract must not discover or execute a browser", runner.called)
	}
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
		{name: "missing subcommand", args: []string{"remote"}, wantCode: ExitUsage, want: "expected map, kvm, wake, pair, unpair, list, play, stream, or quit"},
		{name: "unknown subcommand", args: []string{"remote", "shell"}, wantCode: ExitUsage, want: "unknown subcommand"},
		{name: "unexpected argument", args: []string{"remote", "pair", "extra"}, wantCode: ExitUsage, want: "unexpected arguments"},
		{name: "unknown route", args: []string{"remote", "pair", "--route", "darwin", "--dry-run"}, wantCode: ExitUsage, want: "route must be windows or macos"},
		{name: "JSON requires dry run", args: []string{"remote", "pair", "--json"}, wantCode: ExitUsage, want: "--json requires --dry-run", json: true},
		{name: "ineligible architecture", args: []string{"remote", "pair", "--dry-run", "--json"}, mutate: func(a *App, _ *scriptedProber) { a.GOARCH = "386" }, wantCode: ExitBlocked, want: "target Linux, FreeBSD, OpenBSD, or NetBSD on amd64/arm64", json: true},
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
		{name: "reconnect attempts on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--reconnect-attempts", "1", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "reconnect attempts are bounded", args: []string{"remote", "stream", "--reconnect-attempts", "6", "--dry-run"}, wantCode: ExitUsage, want: "--reconnect-attempts must be between"},
		{name: "reconnect delay needs attempts", args: []string{"remote", "stream", "--reconnect-delay", "1", "--dry-run"}, wantCode: ExitUsage, want: "requires --reconnect-attempts"},
		{name: "codec on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--codec", "h264", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "audio config on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--audio-config", "stereo", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "host settings on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--preserve-host-settings", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "network mode on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--network-mode", "lan", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "frame pacing on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--frame-pacing", "on", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "keep awake on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--keep-awake", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "system-key capture on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--capture-system-keys", "always", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "vsync on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--vsync", "on", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "packet size on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--packet-size", "1392", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "platform on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--platform", "sdl", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "display mode on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--display-mode", "borderless", "--dry-run"}, wantCode: ExitUsage, want: "require the stream operation"},
		{name: "stream app on pair", args: []string{"remote", "pair", "--host", "gaming-pc.local", "--app", "League", "--dry-run"}, wantCode: ExitUsage, want: "--app require the stream operation"},
		{name: "stream acknowledgement on list", args: []string{"remote", "list", "--host", "gaming-pc.local", "--acknowledge-unverified-handoff", "--dry-run"}, wantCode: ExitUsage, want: "--acknowledge-unverified-handoff require the stream operation"},
		{name: "invalid stream resolution", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--resolution", "2160", "--dry-run"}, wantCode: ExitUsage, want: "resolution must be"},
		{name: "invalid stream codec", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--codec", "vp9", "--dry-run"}, wantCode: ExitUsage, want: "codec must be"},
		{name: "invalid stream audio config", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--audio-config", "2.1-surround", "--dry-run"}, wantCode: ExitUsage, want: "audio config must be"},
		{name: "invalid stream network mode", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--network-mode", "internet", "--dry-run"}, wantCode: ExitUsage, want: "network mode must be"},
		{name: "invalid stream frame pacing", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--frame-pacing", "adaptive", "--dry-run"}, wantCode: ExitUsage, want: "frame pacing must be"},
		{name: "invalid stream system-key capture", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--capture-system-keys", "focused", "--dry-run"}, wantCode: ExitUsage, want: "capture system keys must be"},
		{name: "invalid stream vsync", args: []string{"remote", "stream", "--host", "gaming-pc.local", "--vsync", "adaptive", "--dry-run"}, wantCode: ExitUsage, want: "vsync must be"},
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
		{"linux", "arm64", true},
		{"dragonfly", "arm64", false},
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

func TestRemoteMapIsLocalEmbeddedOnly(t *testing.T) {
	a, out, errOut, prober, runner := newTestApp(t)
	a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
	args := []string{"remote", "map", "--client", "moonlight-embedded", "--input-device", "/dev/input/event4", "--dry-run", "--json"}
	if code := a.Run(context.Background(), args); code != ExitOK {
		t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	envelope := decodeEnvelope(t, out.Bytes())
	plan := envelope.Data.(map[string]any)
	arguments := plan["arguments"].([]any)
	if envelope.Command != "remote map" || plan["local"] != true || plan["route"] != "" || !reflect.DeepEqual(arguments, []any{"map", "-input", "/dev/input/event4"}) {
		t.Fatalf("envelope=%+v", envelope)
	}
	if runner.called != 0 || !reflect.DeepEqual(prober.clientSelections, []string{"moonlight-embedded"}) {
		t.Fatalf("runner.called=%d clientSelections=%#v", runner.called, prober.clientSelections)
	}

	t.Run("automatic selection resolves Embedded", func(t *testing.T) {
		a, out, errOut, prober, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
		args := []string{"remote", "map", "--client", "auto", "--input-device", "/dev/input/event4", "--dry-run", "--json"}
		if code := a.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if runner.called != 0 || !reflect.DeepEqual(prober.clientSelections, []string{"moonlight-embedded"}) {
			t.Fatalf("runner.called=%d clientSelections=%#v; want no execution and Embedded selection", runner.called, prober.clientSelections)
		}
	})
}

func TestRemoteMapRejectsUnsupportedClientAndMissingDevice(t *testing.T) {
	t.Run("unsupported client", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-qt": "/fixture/moonlight-qt"}}
		args := []string{"remote", "map", "--client", "moonlight-qt", "--input-device", "/dev/input/event4", "--dry-run"}
		if code := a.Run(context.Background(), args); code != ExitUsage {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "requires Moonlight Embedded") || runner.called != 0 {
			t.Fatalf("stderr=%q runner.called=%d", errOut.String(), runner.called)
		}
	})

	t.Run("live missing device", func(t *testing.T) {
		a, out, errOut, _, runner := newTestApp(t)
		a.RemoteEnv = fakeRemoteEnvironment{paths: map[string]string{"moonlight-embedded": "/fixture/moonlight-embedded"}}
		args := []string{"remote", "map", "--input-device", "/dev/input/event999999999"}
		if code := a.Run(context.Background(), args); code != ExitUsage {
			t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		if !strings.Contains(errOut.String(), "input device") || runner.called != 0 {
			t.Fatalf("stderr=%q runner.called=%d", errOut.String(), runner.called)
		}
	})
}
