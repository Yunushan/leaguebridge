package remote

import (
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

	"github.com/Yunushan/leaguebridge/internal/config"
)

// Discovery environments expose only passive command lookup; they cannot start
// a located executable.
type passiveEnv struct {
	paths map[string]string
}

func (e passiveEnv) LookPath(file string) (string, error) {
	if path := e.paths[file]; path != "" {
		return path, nil
	}
	return "", errors.New("not found")
}

func TestDiscoverExplicitSelectionsAndFailures(t *testing.T) {
	ctx := context.Background()
	autoGenericFlavor := FlavorQt
	if genericMoonlightIsEmbedded(runtime.GOOS) {
		autoGenericFlavor = FlavorEmbedded
	}
	tests := []struct {
		name      string
		preferred string
		env       passiveEnv
		want      Client
	}{
		{
			name:      "explicit qt",
			preferred: "moonlight-qt",
			env:       passiveEnv{paths: map[string]string{"moonlight-qt": "/opt/moonlight-qt"}},
			want:      Client{Flavor: FlavorQt, Binary: "/opt/moonlight-qt", discovered: true},
		},
		{
			name:      "explicit generic is embedded",
			preferred: "moonlight",
			env:       passiveEnv{paths: map[string]string{"moonlight": "/opt/moonlight"}},
			want:      Client{Flavor: FlavorEmbedded, Binary: "/opt/moonlight", discovered: true},
		},
		{
			name:      "auto generic stays passive",
			preferred: "auto",
			env:       passiveEnv{paths: map[string]string{"moonlight": "/opt/moonlight"}},
			want:      Client{Flavor: autoGenericFlavor, Binary: "/opt/moonlight", discovered: true},
		},
		{
			name:      "auto flatpak stays passive",
			preferred: "auto",
			env:       passiveEnv{paths: map[string]string{"flatpak": "/opt/flatpak"}},
			want: Client{
				Flavor: FlavorFlatpak,
				Binary: "/opt/flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
				discovered: true,
			},
		},
		{
			name:      "explicit flatpak",
			preferred: "flatpak",
			env:       passiveEnv{paths: map[string]string{"flatpak": "/opt/flatpak"}},
			want: Client{
				Flavor: FlavorFlatpak,
				Binary: "/opt/flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
				discovered: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Discover(ctx, tt.env, tt.preferred)
			if err != nil {
				t.Fatalf("Discover(): %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Discover() = %+v, want %+v", got, tt.want)
			}
		})
	}

	for _, preferred := range []string{"auto", "moonlight", "moonlight-qt", "flatpak"} {
		t.Run("missing "+preferred, func(t *testing.T) {
			if _, err := Discover(ctx, passiveEnv{paths: map[string]string{}}, preferred); err == nil || !strings.Contains(err.Error(), "Moonlight was not found") {
				t.Fatalf("Discover() error = %v", err)
			}
		})
	}
	if _, err := Discover(ctx, passiveEnv{}, "unsafe-client"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("Discover() unsupported selection error = %v", err)
	}
}

func TestDefaultMoonlightFlavorUsesPlatformConvention(t *testing.T) {
	want := FlavorQt
	if genericMoonlightIsEmbedded(runtime.GOOS) {
		want = FlavorEmbedded
	}
	if got := defaultMoonlightFlavor(); got != want {
		t.Fatalf("defaultMoonlightFlavor() = %q, want %q on %s", got, want, runtime.GOOS)
	}
}

func TestBuildPlanPairAndListVariants(t *testing.T) {
	tests := []struct {
		name      string
		client    Client
		operation Operation
		want      []string
	}{
		{
			name:      "embedded pair",
			client:    Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			operation: Pair,
			want:      []string{"pair", "pc.local"},
		},
		{
			name:      "qt list",
			client:    Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			operation: List,
			want:      []string{"list", "pc.local"},
		},
		{
			name:      "flatpak prefix",
			client:    Client{Flavor: FlavorFlatpak, Binary: "flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}},
			operation: Pair,
			want:      []string{"run", "com.moonlight_stream.Moonlight", "pair", "pc.local"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := BuildPlan(tt.client, Request{
				Operation:             tt.operation,
				Host:                  "pc.local",
				PhysicalHostConfirmed: true,
			})
			if err != nil {
				t.Fatalf("BuildPlan(): %v", err)
			}
			if !reflect.DeepEqual(plan.Arguments, tt.want) {
				t.Fatalf("arguments = %#v, want %#v", plan.Arguments, tt.want)
			}
			if len(plan.Warnings) != 2 {
				t.Fatalf("warnings = %#v", plan.Warnings)
			}
		})
	}
}

func TestBuildPlanAdditionalFailures(t *testing.T) {
	baseClient := Client{Flavor: FlavorQt, Binary: "moonlight-qt"}
	base := Request{
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	tests := []struct {
		name   string
		client Client
		mutate func(*Request)
	}{
		{name: "empty binary", client: Client{Flavor: FlavorQt}, mutate: func(*Request) {}},
		{name: "unsupported flavor", client: Client{Flavor: "unknown", Binary: "moonlight"}, mutate: func(*Request) {}},
		{name: "app whitespace", client: baseClient, mutate: func(r *Request) { r.App = " League" }},
		{name: "app too long", client: baseClient, mutate: func(r *Request) { r.App = strings.Repeat("a", 129) }},
		{name: "app newline", client: baseClient, mutate: func(r *Request) { r.App = "League\n" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			tt.mutate(&req)
			if _, err := BuildPlan(tt.client, req); err == nil {
				t.Fatal("BuildPlan() unexpectedly succeeded")
			}
		})
	}
}

func TestExecuteRejectsEmptyClient(t *testing.T) {
	err := Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, Plan{})
	if err == nil || !strings.Contains(err.Error(), "empty client path") {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestRealEnvironmentLookPath(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	real := RealEnvironment{}
	if path, err := real.LookPath(executable); err != nil || path == "" {
		t.Fatalf("LookPath(%q) = (%q, %v)", executable, path, err)
	}
}

func TestRealEnvironmentLookPathNormalizesAndChecksTarget(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path, err := (RealEnvironment{}).LookPath(executable)
	if err != nil {
		t.Fatalf("LookPath(%q): %v", executable, err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("LookPath(%q) returned non-absolute path %q", executable, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat resolved path %q: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("resolved path %q has non-regular mode %s", path, info.Mode())
	}
}

func TestExecRunnerConnectsProcessIO(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_LEAGUEBRIDGE_REMOTE_HELPER", "echo")
	var stdout bytes.Buffer
	err = (ExecRunner{}).Run(
		context.Background(),
		strings.NewReader("input reaches child"),
		&stdout,
		io.Discard,
		executable,
		"-test.run=^TestRemoteHelperProcess$",
	)
	if err != nil {
		t.Fatalf("ExecRunner.Run(): %v", err)
	}
	if !strings.Contains(stdout.String(), "input reaches child") {
		t.Fatalf("child stdout = %q", stdout.String())
	}
}

func TestExecRunnerTreatsNilContextAsBackground(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_LEAGUEBRIDGE_REMOTE_HELPER", "echo")
	if err := (ExecRunner{}).Run(nil, strings.NewReader("nil context"), io.Discard, io.Discard, executable, "-test.run=^TestRemoteHelperProcess$"); err != nil {
		t.Fatalf("ExecRunner.Run(nil): %v", err)
	}
}

func TestDiscoverRejectsNilEnvironment(t *testing.T) {
	if _, err := discoverForPlatform(context.Background(), nil, "auto", "linux"); err == nil || !strings.Contains(err.Error(), "environment is nil") {
		t.Fatalf("discoverForPlatform(nil) error = %v", err)
	}
}

func TestExecuteRejectsNilRunner(t *testing.T) {
	err := Execute(context.Background(), nil, nil, io.Discard, io.Discard, Plan{Route: config.RouteWindows, Client: Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight"}, Arguments: []string{"stream", "pc.local", "League"}, validated: true})
	if err == nil || !strings.Contains(err.Error(), "nil runner") {
		t.Fatalf("Execute(nil) error = %v", err)
	}
}

func TestExecuteRejectsDecodedPlan(t *testing.T) {
	planned, err := BuildPlan(Client{Flavor: FlavorQt, Binary: "moonlight-qt"}, Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(planned)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "validated") {
		t.Fatalf("serialized plan exposed the private validation marker: %s", encoded)
	}
	if strings.Contains(string(encoded), "discovered") {
		t.Fatalf("serialized plan exposed the private discovery marker: %s", encoded)
	}
	var decoded Plan
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	err = Execute(context.Background(), runner, nil, io.Discard, io.Discard, decoded)
	if err == nil || !strings.Contains(err.Error(), "unvalidated remote plan") {
		t.Fatalf("Execute() error = %v; want decoded-plan rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for a decoded plan: %q", runner.name)
	}
}

func TestBuildDiscoveredPlanRequiresPassiveDiscovery(t *testing.T) {
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Pair,
		Host:                    "pc.local",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	if _, err := BuildDiscoveredPlan(Client{Flavor: FlavorQt, Binary: "/opt/moonlight-qt"}, request); err == nil || !strings.Contains(err.Error(), "not discovered") {
		t.Fatalf("BuildDiscoveredPlan() error = %v; want discovery provenance rejection", err)
	}

	client, err := Discover(context.Background(), passiveEnv{paths: map[string]string{"moonlight-qt": "/opt/moonlight-qt"}}, "moonlight-qt")
	if err != nil {
		t.Fatalf("Discover(): %v", err)
	}
	plan, err := BuildDiscoveredPlan(client, request)
	if err != nil {
		t.Fatalf("BuildDiscoveredPlan() with discovered client: %v", err)
	}
	if !plan.clientDiscovered {
		t.Fatal("discovered client provenance was not bound to the plan")
	}
	plan.Client.Binary = "/opt/replaced-moonlight"
	runner := &recordingRunner{}
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err == nil || !strings.Contains(err.Error(), "changed after planning") {
		t.Fatalf("Execute() after client mutation error = %v; want mutation rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called after client mutation: %q", runner.name)
	}
}

func TestExecuteRejectsPlanWithUnboundClientProvenance(t *testing.T) {
	runner := &recordingRunner{}
	plan := Plan{
		Route:            config.RouteWindows,
		Client:           Client{Flavor: FlavorQt, Binary: "moonlight-qt", discovered: true},
		Arguments:        []string{"pair", "pc.local"},
		validated:        true,
		clientDiscovered: false,
	}
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err == nil || !strings.Contains(err.Error(), "not discovered") {
		t.Fatalf("Execute() error = %v; want discovery provenance rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for an unbound client plan: %q", runner.name)
	}
}

func TestRemoteHelperProcess(t *testing.T) {
	switch os.Getenv("GO_WANT_LEAGUEBRIDGE_REMOTE_HELPER") {
	case "":
		return
	case "echo":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	default:
		os.Exit(8)
	}
}
