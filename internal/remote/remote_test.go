package remote

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/config"
)

type fakeEnv struct {
	paths map[string]string
}

func (f fakeEnv) LookPath(file string) (string, error) {
	if path := f.paths[file]; path != "" {
		return path, nil
	}
	return "", errors.New("not found")
}

type cancelingEnv struct {
	cancel context.CancelFunc
	calls  int
}

func (e *cancelingEnv) LookPath(string) (string, error) {
	e.calls++
	if e.calls == 1 {
		e.cancel()
		return "/bin/moonlight-qt", nil
	}
	return "", errors.New("not found")
}

func TestDiscover(t *testing.T) {
	tests := []struct {
		name      string
		preferred string
		env       fakeEnv
		want      Flavor
	}{
		{"qt-first", "auto", fakeEnv{paths: map[string]string{"moonlight-qt": "/bin/moonlight-qt"}}, FlavorQt},
		{"explicit-embedded", "moonlight", fakeEnv{paths: map[string]string{"moonlight": "/bin/moonlight"}}, FlavorEmbedded},
		{"flatpak", "auto", fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}}, FlavorFlatpak},
		{"explicit-flatpak", "flatpak", fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}}, FlavorFlatpak},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := Discover(context.Background(), tt.env, tt.preferred)
			if err != nil {
				t.Fatal(err)
			}
			if client.Flavor != tt.want {
				t.Fatalf("got %s, want %s", client.Flavor, tt.want)
			}
		})
	}
}

func TestDiscoverRejectsCanceledContextBeforeLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, fakeEnv{paths: map[string]string{"moonlight": "/bin/moonlight"}}, "auto"); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("Discover() error = %v, want cancellation", err)
	}
}

func TestDiscoverRejectsCancellationRacingWithLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	env := &cancelingEnv{cancel: cancel}
	if _, err := Discover(ctx, env, "auto"); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("Discover() error = %v, want cancellation", err)
	}
	if env.calls != 1 {
		t.Fatalf("LookPath calls = %d, want one lookup before cancellation stopped discovery", env.calls)
	}
}

func TestDiscoverQtFallbackRejectsKnownEmbeddedBinaryNames(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv{paths: map[string]string{"moonlight": "/opt/moonlight"}}
	for _, goos := range []string{"freebsd", "dragonfly"} {
		if _, err := discoverForPlatform(ctx, env, "moonlight-qt", goos); err == nil {
			t.Errorf("%s moonlight Embedded binary was accepted as Moonlight Qt", goos)
		}
		client, err := discoverForPlatform(ctx, env, "auto", goos)
		if err != nil || client.Flavor != FlavorEmbedded {
			t.Errorf("%s generic auto discovery = %+v, %v; want Embedded", goos, client, err)
		}
	}
	client, err := discoverForPlatform(ctx, env, "moonlight-qt", "openbsd")
	if err != nil {
		t.Fatalf("OpenBSD generic Qt binary rejected: %v", err)
	}
	if client.Flavor != FlavorQt || client.Binary != "/opt/moonlight" {
		t.Fatalf("OpenBSD generic Qt discovery = %+v", client)
	}
}

func TestBuildPlan(t *testing.T) {
	base := Request{Operation: Stream, Host: "gaming-pc.local", App: "League of Legends", PhysicalHostConfirmed: true, AcceptUnverifiedHandoff: true}
	tests := []struct {
		flavor Flavor
		want   []string
	}{
		{FlavorEmbedded, []string{"stream", "-app", "League of Legends", "gaming-pc.local"}},
		{FlavorQt, []string{"stream", "gaming-pc.local", "League of Legends"}},
		{FlavorFlatpak, []string{"run", "com.moonlight_stream.Moonlight", "stream", "gaming-pc.local", "League of Legends"}},
	}
	for _, tt := range tests {
		client := Client{Flavor: tt.flavor, Binary: "/usr/bin/client"}
		if tt.flavor == FlavorFlatpak {
			client.Prefix = []string{"run", "com.moonlight_stream.Moonlight"}
		}
		plan, err := BuildPlan(client, base)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(plan.Arguments, tt.want) {
			t.Fatalf("%s args = %#v, want %#v", tt.flavor, plan.Arguments, tt.want)
		}
	}
}

func TestBuildPlanMacOSRouteRemainsExplicitlyUnvalidated(t *testing.T) {
	client := Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"}
	plan, err := BuildPlan(client, Request{
		Route:                   config.RouteMacOS,
		Operation:               Stream,
		Host:                    "gaming-mac.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Route != config.RouteMacOS {
		t.Fatalf("route = %q", plan.Route)
	}
	if !reflect.DeepEqual(plan.Arguments, []string{"stream", "gaming-mac.local", "League of Legends"}) {
		t.Fatalf("arguments = %#v", plan.Arguments)
	}
	warnings := strings.Join(plan.Warnings, " ")
	for _, required := range []string{"native client", "experimental", "unvalidated", "not endorsed"} {
		if !strings.Contains(warnings, required) {
			t.Errorf("warnings lack %q: %q", required, warnings)
		}
	}
}

func TestBuildPlanRejectsUnknownRouteAndUnconfirmedMac(t *testing.T) {
	client := Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"}
	base := Request{Route: config.RouteMacOS, Operation: Pair, Host: "gaming-mac.local", App: "League", PhysicalHostConfirmed: true}
	unknown := base
	unknown.Route = config.Route("physical-linux-remote")
	if _, err := BuildPlan(client, unknown); err == nil || !strings.Contains(err.Error(), "unsupported physical-host route") {
		t.Fatalf("unknown route error = %v", err)
	}
	unconfirmed := base
	unconfirmed.PhysicalHostConfirmed = false
	if _, err := BuildPlan(client, unconfirmed); err == nil || !strings.Contains(err.Error(), "physical Mac") {
		t.Fatalf("unconfirmed Mac error = %v", err)
	}
}

func TestBuildPlanFailsClosed(t *testing.T) {
	client := Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight"}
	base := Request{Operation: Stream, Host: "pc.local", App: "League", PhysicalHostConfirmed: true, AcceptUnverifiedHandoff: true}
	mutations := []func(*Request){
		func(r *Request) { r.Host = "-host" },
		func(r *Request) { r.App = "" },
		func(r *Request) { r.PhysicalHostConfirmed = false },
		func(r *Request) { r.AcceptUnverifiedHandoff = false },
		func(r *Request) { r.Operation = "shell" },
	}
	for i, mutate := range mutations {
		req := base
		mutate(&req)
		if _, err := BuildPlan(client, req); err == nil {
			t.Errorf("mutation %d unexpectedly passed", i)
		}
	}
}

func TestBuildPlanRejectsMutableClientPrefixes(t *testing.T) {
	request := Request{
		Operation:               Pair,
		Host:                    "pc.local",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	tests := []Client{
		{Flavor: FlavorEmbedded, Binary: "moonlight", Prefix: []string{"--unsafe"}},
		{Flavor: FlavorQt, Binary: "moonlight-qt", Prefix: []string{"--unsafe"}},
		{Flavor: FlavorFlatpak, Binary: "flatpak"},
		{Flavor: FlavorFlatpak, Binary: "flatpak", Prefix: []string{"run", "com.example.Other"}},
	}
	for _, client := range tests {
		if _, err := BuildPlan(client, request); err == nil || !strings.Contains(err.Error(), "prefix") {
			t.Fatalf("BuildPlan(%+v) error = %v; want fixed-prefix rejection", client, err)
		}
	}
}

func TestBuildPlanValidatesAppName(t *testing.T) {
	client := Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"}
	base := Request{
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}

	for _, app := range []string{"Léague 日本", strings.Repeat("é", 64)} {
		req := base
		req.App = app
		plan, err := BuildPlan(client, req)
		if err != nil {
			t.Fatalf("BuildPlan rejected valid app %q: %v", app, err)
		}
		if got := plan.Arguments[len(plan.Arguments)-1]; got != app {
			t.Fatalf("app argument = %q, want %q", got, app)
		}
	}

	invalid := []struct {
		name string
		app  string
	}{
		{name: "option-like", app: "-League"},
		{name: "invalid UTF-8", app: string([]byte{'L', 0xff})},
		{name: "C0 escape", app: "League\u001bClient"},
		{name: "DEL", app: "League\u007fClient"},
		{name: "C1 control", app: "League\u0085Client"},
		{name: "too many UTF-8 bytes", app: strings.Repeat("é", 64) + "a"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			req.App = tt.app
			if _, err := BuildPlan(client, req); err == nil || !strings.Contains(err.Error(), "app:") {
				t.Fatalf("BuildPlan app %q error = %v", tt.app, err)
			}
		})
	}
}

type recordingRunner struct {
	name string
	args []string
	err  error
}

func (r *recordingRunner) Run(_ context.Context, _ io.Reader, _, _ io.Writer, name string, args ...string) error {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.err
}

func TestExecuteUsesArgumentVectorWithoutShell(t *testing.T) {
	runner := &recordingRunner{}
	client := Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight", discovered: true}
	plan := Plan{Route: config.RouteWindows, Client: client, Arguments: []string{"stream", "pc.local", "League of Legends"}, validated: true, clientDiscovered: true, clientBinding: bindClient(client)}
	if err := Execute(context.Background(), runner, strings.NewReader(""), io.Discard, io.Discard, plan); err != nil {
		t.Fatal(err)
	}
	if runner.name != "/usr/bin/moonlight" || !reflect.DeepEqual(runner.args, plan.Arguments) {
		t.Fatalf("unexpected execution: %q %#v", runner.name, runner.args)
	}
}

func TestExecuteRejectsEmptyArgumentVector(t *testing.T) {
	runner := &recordingRunner{}
	err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, Plan{Route: config.RouteWindows, Client: Client{Flavor: FlavorQt, Binary: "moonlight"}})
	if err == nil || !strings.Contains(err.Error(), "empty argument vector") {
		t.Fatalf("Execute() error = %v, want empty argument-vector rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for an invalid plan: %q", runner.name)
	}
}

func TestExecuteWrapsError(t *testing.T) {
	runner := &recordingRunner{err: errors.New("exit 2")}
	client := Client{Flavor: FlavorQt, Binary: "moonlight", discovered: true}
	err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, Plan{Route: config.RouteWindows, Client: client, Arguments: []string{"stream", "pc.local", "League"}, validated: true, clientDiscovered: true, clientBinding: bindClient(client)})
	if err == nil || !strings.Contains(err.Error(), "Moonlight handoff failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteRejectsCanceledContextBeforeRunner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &recordingRunner{}
	client := Client{Flavor: FlavorQt, Binary: "moonlight", discovered: true}
	err := Execute(ctx, runner, nil, io.Discard, io.Discard, Plan{Route: config.RouteWindows, Client: client, Arguments: []string{"stream", "pc.local", "League"}, validated: true, clientDiscovered: true, clientBinding: bindClient(client)})
	if err == nil || !strings.Contains(err.Error(), "canceled handoff") {
		t.Fatalf("Execute() error = %v, want cancellation", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for canceled context: %q", runner.name)
	}
}

func TestExecuteRejectsMutableClientPrefix(t *testing.T) {
	runner := &recordingRunner{}
	plan := Plan{
		Route:     config.RouteWindows,
		Client:    Client{Flavor: FlavorQt, Binary: "moonlight-qt", Prefix: []string{"--unsafe"}},
		Arguments: []string{"stream", "pc.local", "League of Legends"},
	}
	err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan)
	if err == nil || !strings.Contains(err.Error(), "invalid Moonlight client") {
		t.Fatalf("Execute() error = %v; want invalid-client rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for an invalid plan: %q", runner.name)
	}
}

func TestExecuteAcceptsFixedArgumentShapes(t *testing.T) {
	tests := []struct {
		name   string
		client Client
		args   []string
	}{
		{
			name:   "embedded stream",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight", discovered: true},
			args:   []string{"stream", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "qt pair",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt", discovered: true},
			args:   []string{"pair", "pc.local"},
		},
		{
			name: "flatpak stream",
			client: Client{
				Flavor:     FlavorFlatpak,
				Binary:     "flatpak",
				Prefix:     []string{"run", "com.moonlight_stream.Moonlight"},
				discovered: true,
			},
			args: []string{"run", "com.moonlight_stream.Moonlight", "stream", "pc.local", "League"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingRunner{}
			if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, Plan{Route: config.RouteWindows, Client: tt.client, Arguments: tt.args, validated: true, clientDiscovered: true, clientBinding: bindClient(tt.client)}); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if !reflect.DeepEqual(runner.args, tt.args) {
				t.Fatalf("runner args = %#v, want %#v", runner.args, tt.args)
			}
		})
	}
}

func TestExecuteRejectsInvalidArgumentVectors(t *testing.T) {
	tests := []struct {
		name   string
		client Client
		args   []string
	}{
		{
			name:   "unknown operation",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"shell", "pc.local"},
		},
		{
			name:   "option-like host",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"pair", "--host"},
		},
		{
			name:   "extra qt argument",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "pc.local", "League", "--unsafe"},
		},
		{
			name:   "embedded wrong shape",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "pc.local", "League"},
		},
		{
			name: "flatpak missing fixed prefix",
			client: Client{
				Flavor: FlavorFlatpak,
				Binary: "flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
			},
			args: []string{"stream", "pc.local", "League"},
		},
		{
			name: "flatpak alternate app",
			client: Client{
				Flavor: FlavorFlatpak,
				Binary: "flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
			},
			args: []string{"run", "com.example.Other", "pair", "pc.local"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingRunner{}
			err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, Plan{Route: config.RouteWindows, Client: tt.client, Arguments: tt.args, validated: true})
			if err == nil || !strings.Contains(err.Error(), "invalid Moonlight argument vector") {
				t.Fatalf("Execute() error = %v; want argument-vector rejection", err)
			}
			if runner.name != "" {
				t.Fatalf("runner was called for an invalid plan: %q", runner.name)
			}
		})
	}
}

func TestExecuteRejectsUnvalidatedPlan(t *testing.T) {
	runner := &recordingRunner{}
	plan := Plan{
		Route:     config.RouteWindows,
		Client:    Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
		Arguments: []string{"stream", "pc.local", "League"},
	}
	err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan)
	if err == nil || !strings.Contains(err.Error(), "unvalidated remote plan") {
		t.Fatalf("Execute() error = %v; want unvalidated-plan rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for an unvalidated plan: %q", runner.name)
	}
}

func TestExecuteRejectsUnknownPlanRoute(t *testing.T) {
	runner := &recordingRunner{}
	plan := Plan{
		Route:     config.Route("physical-linux-remote"),
		Client:    Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
		Arguments: []string{"stream", "pc.local", "League"},
		validated: true,
	}
	err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan)
	if err == nil || !strings.Contains(err.Error(), "invalid remote plan") {
		t.Fatalf("Execute() error = %v; want route rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for an invalid route: %q", runner.name)
	}
}
