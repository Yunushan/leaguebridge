package remote

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/config"
)

type fakeEnv struct {
	paths map[string]string
}

func boundTestClient(t *testing.T, flavor Flavor) Client {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	return Client{
		Flavor:         flavor,
		Binary:         executable,
		discovered:     true,
		executableInfo: info,
	}
}

func bindTestPlan(plan Plan) Plan {
	plan.argumentBinding = append([]string(nil), plan.Arguments...)
	return plan
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
		{"explicit-embedded-alias", "moonlight-embedded", fakeEnv{paths: map[string]string{"moonlight": "/bin/moonlight"}}, FlavorEmbedded},
		{"explicit-embedded-executable", "moonlight-embedded", fakeEnv{paths: map[string]string{"moonlight-embedded": "/bin/moonlight-embedded"}}, FlavorEmbedded},
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

func TestDiscoverAutoUsesExpectedFlavorForEveryNativeClient(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv{paths: map[string]string{"moonlight": "/opt/moonlight"}}
	tests := []struct {
		goos string
		want Flavor
	}{
		{goos: "linux", want: FlavorQt},
		{goos: "freebsd", want: FlavorEmbedded},
		{goos: "openbsd", want: FlavorQt},
		{goos: "netbsd", want: FlavorQt},
		{goos: "dragonfly", want: FlavorEmbedded},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			client, err := discoverForPlatform(ctx, env, "auto", tt.goos)
			if err != nil {
				t.Fatalf("discoverForPlatform(): %v", err)
			}
			if client.Flavor != tt.want {
				t.Fatalf("generic Moonlight flavor = %s, want %s", client.Flavor, tt.want)
			}
			if client.Binary != "/opt/moonlight" {
				t.Fatalf("generic Moonlight binary = %q, want /opt/moonlight", client.Binary)
			}
		})
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

func TestApplicationListedStripsTerminalControlSequences(t *testing.T) {
	const application = "League of Legends"
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "exact line", output: "Desktop\nLeague of Legends\n", want: true},
		{name: "descriptive line", output: "Application: League of Legends\n", want: true},
		{name: "colored line", output: "\x1b[32mLeague of Legends\x1b[0m\n", want: true},
		{name: "terminal title BEL", output: "\x1b]0;Moonlight\x07League of Legends\n", want: true},
		{name: "terminal title ST", output: "\x1b]0;Moonlight\x1b\\League of Legends\n", want: true},
		{name: "numbered line", output: "1) Desktop\n2. League of Legends\n", want: true},
		{name: "bracketed line", output: "[1] Desktop\n[2] League of Legends\n", want: true},
		{name: "bullet line", output: "* Desktop\n- League of Legends\n", want: true},
		{name: "absent", output: "Desktop\nSteam\n", want: false},
		{name: "diagnostic mention", output: "Connecting to League of Legends\n", want: false},
		{name: "error mention", output: "Error: could not start League of Legends\n", want: false},
		{name: "invalid requested name", output: "League\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requested := application
			if tt.name == "invalid requested name" {
				requested = "-League"
			}
			if got := ApplicationListed(tt.output, requested); got != tt.want {
				t.Fatalf("ApplicationListed(%q, %q) = %v, want %v", tt.output, requested, got, tt.want)
			}
		})
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
	client := boundTestClient(t, FlavorQt)
	plan := bindTestPlan(Plan{Route: config.RouteWindows, Client: client, Arguments: []string{"stream", "pc.local", "League of Legends"}, validated: true, clientDiscovered: true, clientBinding: bindClient(client)})
	if err := Execute(context.Background(), runner, strings.NewReader(""), io.Discard, io.Discard, plan); err != nil {
		t.Fatal(err)
	}
	if runner.name != client.Binary || !reflect.DeepEqual(runner.args, plan.Arguments) {
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
	client := boundTestClient(t, FlavorQt)
	err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, bindTestPlan(Plan{Route: config.RouteWindows, Client: client, Arguments: []string{"stream", "pc.local", "League"}, validated: true, clientDiscovered: true, clientBinding: bindClient(client)}))
	if err == nil || !strings.Contains(err.Error(), "Moonlight handoff failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteRejectsCanceledContextBeforeRunner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &recordingRunner{}
	client := boundTestClient(t, FlavorQt)
	err := Execute(ctx, runner, nil, io.Discard, io.Discard, bindTestPlan(Plan{Route: config.RouteWindows, Client: client, Arguments: []string{"stream", "pc.local", "League"}, validated: true, clientDiscovered: true, clientBinding: bindClient(client)}))
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
			name:   "embedded custom resolution stream",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight", discovered: true},
			args:   []string{"stream", "-width", "3440", "-height", "1440", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "embedded surround stream",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight", discovered: true},
			args:   []string{"stream", "-surround", "7.1", "-nosops", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "embedded WAN optimization stream",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight", discovered: true},
			args:   []string{"stream", "-remote", "yes", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "qt custom resolution stream",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt", discovered: true},
			args:   []string{"stream", "-resolution", "3440x1440", "pc.local", "League of Legends"},
		},
		{
			name:   "qt stereo stream",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt", discovered: true},
			args:   []string{"stream", "-audio-config", "stereo", "-no-game-optimization", "pc.local", "League of Legends"},
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
			client := boundTestClient(t, tt.client.Flavor)
			client.Prefix = append([]string(nil), tt.client.Prefix...)
			if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, bindTestPlan(Plan{Route: config.RouteWindows, Client: client, Arguments: tt.args, validated: true, clientDiscovered: true, clientBinding: bindClient(client)})); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if !reflect.DeepEqual(runner.args, tt.args) {
				t.Fatalf("runner args = %#v, want %#v", runner.args, tt.args)
			}
		})
	}
}

func TestExecuteRejectsArgumentMutationAfterPlanning(t *testing.T) {
	runner := &recordingRunner{}
	client := boundTestClient(t, FlavorQt)
	plan := bindTestPlan(Plan{
		Route:            config.RouteWindows,
		Client:           client,
		Arguments:        []string{"stream", "pc.local", "League"},
		validated:        true,
		clientDiscovered: true,
		clientBinding:    bindClient(client),
	})
	plan.Arguments[1] = "other-host.local"
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err == nil || !strings.Contains(err.Error(), "argument vector was changed") {
		t.Fatalf("Execute() after argument mutation error = %v; want mutation rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called after argument mutation: %q", runner.name)
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
			name:   "embedded Qt-only 1440 flag",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-1440", "-app", "League", "pc.local"},
		},
		{
			name:   "embedded incomplete 1440 pair",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-width", "2560", "-app", "League", "pc.local"},
		},
		{
			name:   "qt Embedded-only width",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-width", "2560", "-height", "1440", "pc.local", "League"},
		},
		{
			name:   "qt Embedded-only surround",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-surround", "5.1", "pc.local", "League"},
		},
		{
			name:   "embedded Qt-only audio config",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-audio-config", "5.1-surround", "-app", "League", "pc.local"},
		},
		{
			name:   "embedded invalid surround value",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-surround", "stereo", "-app", "League", "pc.local"},
		},
		{
			name:   "qt invalid audio config value",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-audio-config", "5.1", "pc.local", "League"},
		},
		{
			name:   "qt Embedded-only host settings",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-nosops", "pc.local", "League"},
		},
		{
			name:   "embedded Qt-only host settings",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-no-game-optimization", "-app", "League", "pc.local"},
		},
		{
			name:   "qt Embedded-only network mode",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-remote", "yes", "pc.local", "League"},
		},
		{
			name:   "embedded invalid network mode",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-remote", "lan", "-app", "League", "pc.local"},
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

func TestExecuteRejectsPassiveDiscoveryWithoutExecutableBinding(t *testing.T) {
	client, err := Discover(context.Background(), passiveEnv{paths: map[string]string{"moonlight-qt": "/opt/moonlight-qt"}}, "moonlight-qt")
	if err != nil {
		t.Fatalf("Discover(): %v", err)
	}
	plan, err := BuildDiscoveredPlan(client, Request{
		Route:                 config.RouteWindows,
		Operation:             Pair,
		Host:                  "pc.local",
		PhysicalHostConfirmed: true,
	})
	if err != nil {
		t.Fatalf("BuildDiscoveredPlan(): %v", err)
	}
	if plan.clientBinding.executableInfo != nil {
		t.Fatal("passive discovery unexpectedly bound an executable identity")
	}

	runner := &recordingRunner{}
	err = Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan)
	if err == nil || !strings.Contains(err.Error(), "not bound by the real environment") {
		t.Fatalf("Execute() error = %v; want real-environment binding rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for a passively discovered client: %q", runner.name)
	}
}

func TestExecRunnerRejectsNonAbsolutePath(t *testing.T) {
	err := (ExecRunner{}).Run(context.Background(), nil, io.Discard, io.Discard, "moonlight-qt")
	if err == nil || !strings.Contains(err.Error(), "non-absolute") {
		t.Fatalf("ExecRunner.Run() error = %v; want non-absolute-path rejection", err)
	}
}

func TestExecRunnerRejectsNonRegularPath(t *testing.T) {
	err := (ExecRunner{}).Run(context.Background(), nil, io.Discard, io.Discard, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("ExecRunner.Run() error = %v; want non-regular-path rejection", err)
	}
}

func TestBuildPlanStreamOptionsUseClientSpecificSyntax(t *testing.T) {
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream: StreamOptions{
			Resolution:           "4k",
			FPS:                  60,
			BitrateKbps:          20000,
			PacketSizeBytes:      1392,
			Codec:                "hevc",
			AudioConfig:          "5.1-surround",
			PreserveHostSettings: true,
		},
	}
	tests := []struct {
		name   string
		client Client
		want   []string
	}{
		{
			name:   "embedded",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			want:   []string{"stream", "-4k", "-fps", "60", "-bitrate", "20000", "-packetsize", "1392", "-codec", "hevc", "-surround", "5.1", "-nosops", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "qt",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			want:   []string{"stream", "-4K", "-fps", "60", "-bitrate", "20000", "-packet-size", "1392", "-video-codec", "HEVC", "-audio-config", "5.1-surround", "-no-game-optimization", "pc.local", "League of Legends"},
		},
		{
			name: "flatpak qt",
			client: Client{
				Flavor: FlavorFlatpak,
				Binary: "flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
			},
			want: []string{"run", "com.moonlight_stream.Moonlight", "stream", "-4K", "-fps", "60", "-bitrate", "20000", "-packet-size", "1392", "-video-codec", "HEVC", "-audio-config", "5.1-surround", "-no-game-optimization", "pc.local", "League of Legends"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := BuildPlan(tt.client, request)
			if err != nil {
				t.Fatalf("BuildPlan(): %v", err)
			}
			if !reflect.DeepEqual(plan.Arguments, tt.want) {
				t.Fatalf("arguments = %#v, want %#v", plan.Arguments, tt.want)
			}
			if err := validatePlanArguments(tt.client, plan.Arguments); err != nil {
				t.Fatalf("generated arguments rejected: %v", err)
			}
		})
	}
}

func TestBuildPlanEmbeddedNetworkModeUsesDocumentedRemoteSyntax(t *testing.T) {
	base := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	for _, tt := range []struct {
		name string
		mode string
		want string
	}{
		{name: "auto", mode: "auto", want: "auto"},
		{name: "LAN", mode: "lan", want: "no"},
		{name: "WAN", mode: "wan", want: "yes"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := base
			request.Stream = StreamOptions{NetworkMode: tt.mode}
			client := Client{Flavor: FlavorEmbedded, Binary: "moonlight"}
			plan, err := BuildPlan(client, request)
			if err != nil {
				t.Fatalf("BuildPlan(): %v", err)
			}
			want := []string{"stream", "-remote", tt.want, "-app", "League of Legends", "pc.local"}
			if !reflect.DeepEqual(plan.Arguments, want) {
				t.Fatalf("arguments = %#v, want %#v", plan.Arguments, want)
			}
			if err := validatePlanArguments(client, plan.Arguments); err != nil {
				t.Fatalf("generated arguments rejected: %v", err)
			}
		})
	}
	for _, client := range []Client{
		{Flavor: FlavorQt, Binary: "moonlight-qt"},
		{Flavor: FlavorFlatpak, Binary: "flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}},
	} {
		request := base
		request.Stream = StreamOptions{NetworkMode: "lan"}
		if _, err := BuildPlan(client, request); err == nil || !strings.Contains(err.Error(), "only by Moonlight Embedded") || !strings.Contains(err.Error(), "moonlight-embedded") {
			t.Errorf("BuildPlan(%s) error = %v; want Embedded-only guidance", client.Flavor, err)
		}
	}
}

func TestBuildPlan1440UsesDocumentedClientSpecificSyntax(t *testing.T) {
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream:                  StreamOptions{Resolution: "1440"},
	}
	tests := []struct {
		name   string
		client Client
		want   []string
	}{
		{
			name:   "embedded width and height",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			want:   []string{"stream", "-width", "2560", "-height", "1440", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "qt dedicated flag",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			want:   []string{"stream", "-1440", "pc.local", "League of Legends"},
		},
		{
			name: "flatpak qt dedicated flag",
			client: Client{
				Flavor: FlavorFlatpak,
				Binary: "flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
			},
			want: []string{"run", "com.moonlight_stream.Moonlight", "stream", "-1440", "pc.local", "League of Legends"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := BuildPlan(tt.client, request)
			if err != nil {
				t.Fatalf("BuildPlan(): %v", err)
			}
			if !reflect.DeepEqual(plan.Arguments, tt.want) {
				t.Fatalf("arguments = %#v, want %#v", plan.Arguments, tt.want)
			}
			if err := validatePlanArguments(tt.client, plan.Arguments); err != nil {
				t.Fatalf("generated arguments rejected: %v", err)
			}
		})
	}
}

func TestBuildPlanCustomResolutionUsesDocumentedClientSpecificSyntax(t *testing.T) {
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream:                  StreamOptions{Resolution: "3440x1440"},
	}
	tests := []struct {
		name   string
		client Client
		want   []string
	}{
		{
			name:   "embedded width and height",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			want:   []string{"stream", "-width", "3440", "-height", "1440", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "qt custom resolution",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			want:   []string{"stream", "-resolution", "3440x1440", "pc.local", "League of Legends"},
		},
		{
			name: "flatpak qt custom resolution",
			client: Client{
				Flavor: FlavorFlatpak,
				Binary: "flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
			},
			want: []string{"run", "com.moonlight_stream.Moonlight", "stream", "-resolution", "3440x1440", "pc.local", "League of Legends"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := BuildPlan(tt.client, request)
			if err != nil {
				t.Fatalf("BuildPlan(): %v", err)
			}
			if !reflect.DeepEqual(plan.Arguments, tt.want) {
				t.Fatalf("arguments = %#v, want %#v", plan.Arguments, tt.want)
			}
			if err := validatePlanArguments(tt.client, plan.Arguments); err != nil {
				t.Fatalf("generated arguments rejected: %v", err)
			}
		})
	}
}

func TestBuildPlanDecoderSelectionUsesQtSyntax(t *testing.T) {
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream:                  StreamOptions{Decoder: "software"},
	}
	for _, client := range []Client{
		{Flavor: FlavorQt, Binary: "moonlight-qt"},
		{Flavor: FlavorFlatpak, Binary: "flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}},
	} {
		plan, err := BuildPlan(client, request)
		if err != nil {
			t.Fatalf("BuildPlan(%s): %v", client.Flavor, err)
		}
		want := "-video-decoder"
		if client.Flavor == FlavorFlatpak {
			if len(plan.Arguments) < 2 || plan.Arguments[0] != "run" {
				t.Fatalf("Flatpak arguments = %#v", plan.Arguments)
			}
		}
		if !containsAdjacentArguments(plan.Arguments, want, "software") {
			t.Fatalf("BuildPlan(%s) arguments = %#v; want %q software pair", client.Flavor, plan.Arguments, want)
		}
		if err := validatePlanArguments(client, plan.Arguments); err != nil {
			t.Fatalf("generated %s arguments rejected: %v", client.Flavor, err)
		}
	}
	if _, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, request); err == nil || !strings.Contains(err.Error(), "only by Moonlight Qt") || !strings.Contains(err.Error(), "select --client moonlight-qt") {
		t.Fatalf("Embedded decoder selection error = %v; want Qt-only rejection", err)
	}
}

func TestBuildPlanDisplayModeUsesClientSyntax(t *testing.T) {
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream:                  StreamOptions{DisplayMode: "borderless"},
	}
	for _, client := range []Client{
		{Flavor: FlavorQt, Binary: "moonlight-qt"},
		{Flavor: FlavorFlatpak, Binary: "flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}},
	} {
		plan, err := BuildPlan(client, request)
		if err != nil {
			t.Fatalf("BuildPlan(%s): %v", client.Flavor, err)
		}
		if !containsAdjacentArguments(plan.Arguments, "-display-mode", "borderless") {
			t.Fatalf("BuildPlan(%s) arguments = %#v; want display-mode borderless pair", client.Flavor, plan.Arguments)
		}
		if err := validatePlanArguments(client, plan.Arguments); err != nil {
			t.Fatalf("generated %s arguments rejected: %v", client.Flavor, err)
		}
	}
	embeddedRequest := request
	embeddedRequest.Stream.DisplayMode = "windowed"
	embeddedPlan, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, embeddedRequest)
	if err != nil {
		t.Fatalf("BuildPlan(embedded windowed): %v", err)
	}
	if !containsArgument(embeddedPlan.Arguments, "-windowed") {
		t.Fatalf("Embedded arguments = %#v; want -windowed", embeddedPlan.Arguments)
	}
	if err := validatePlanArguments(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, embeddedPlan.Arguments); err != nil {
		t.Fatalf("generated Embedded windowed arguments rejected: %v", err)
	}

	borderlessRequest := request
	borderlessRequest.Stream.DisplayMode = "borderless"
	if _, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, borderlessRequest); err == nil || !strings.Contains(err.Error(), "only by Moonlight Qt") || !strings.Contains(err.Error(), "select --client moonlight-qt") {
		t.Fatalf("Embedded borderless selection error = %v; want Qt-only rejection", err)
	}
}

func TestBuildPlanEmbeddedPlatformUsesDocumentedSyntax(t *testing.T) {
	base := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	for _, platform := range []string{"x11", "x11_vdpau", "sdl"} {
		request := base
		request.Stream = StreamOptions{Platform: platform}
		client := Client{Flavor: FlavorEmbedded, Binary: "moonlight"}
		plan, err := BuildPlan(client, request)
		if err != nil {
			t.Fatalf("BuildPlan(%s): %v", platform, err)
		}
		if !containsAdjacentArguments(plan.Arguments, "-platform", platform) {
			t.Fatalf("BuildPlan(%s) arguments = %#v; want platform pair", platform, plan.Arguments)
		}
		if err := validatePlanArguments(client, plan.Arguments); err != nil {
			t.Fatalf("generated Embedded %s arguments rejected: %v", platform, err)
		}
	}
	autoRequest := base
	autoRequest.Stream = StreamOptions{Platform: "auto"}
	autoPlan, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, autoRequest)
	if err != nil {
		t.Fatalf("BuildPlan(auto): %v", err)
	}
	if containsArgument(autoPlan.Arguments, "-platform") {
		t.Fatalf("auto platform arguments = %#v; want the Embedded default without an override", autoPlan.Arguments)
	}

	for _, client := range []Client{
		{Flavor: FlavorQt, Binary: "moonlight-qt"},
		{Flavor: FlavorFlatpak, Binary: "flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}},
	} {
		request := base
		request.Stream = StreamOptions{Platform: "sdl"}
		if _, err := BuildPlan(client, request); err == nil || !strings.Contains(err.Error(), "only by Moonlight Embedded") || !strings.Contains(err.Error(), "select --client moonlight-embedded") {
			t.Fatalf("%s platform selection error = %v; want Embedded-only rejection", client.Flavor, err)
		}
	}
}

func containsAdjacentArguments(arguments []string, first, second string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == first && arguments[index+1] == second {
			return true
		}
	}
	return false
}

func containsArgument(arguments []string, want string) bool {
	for _, argument := range arguments {
		if argument == want {
			return true
		}
	}
	return false
}

func TestBuildPlanRejectsInvalidStreamOptions(t *testing.T) {
	base := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	for _, options := range []StreamOptions{
		{Resolution: "2160"},
		{Resolution: "3440"},
		{Resolution: "0x1080"},
		{Resolution: "8192x4320"},
		{Resolution: "3440x1440x2"},
		{FPS: 9},
		{FPS: 481},
		{BitrateKbps: 499},
		{BitrateKbps: 500001},
		{PacketSizeBytes: 1023},
		{PacketSizeBytes: 1025},
		{PacketSizeBytes: 9001},
		{Codec: "vp9"},
		{AudioConfig: "2.1-surround"},
		{NetworkMode: "internet"},
		{Platform: "wayland"},
		{Decoder: "vp9"},
		{DisplayMode: "maximized"},
	} {
		request := base
		request.Stream = options
		if _, err := BuildPlan(Client{Flavor: FlavorQt, Binary: "moonlight-qt"}, request); err == nil || !strings.Contains(err.Error(), "stream options") {
			t.Fatalf("options %+v error = %v; want stream-options rejection", options, err)
		}
	}
	request := base
	request.Operation = Pair
	request.Stream = StreamOptions{FPS: 60}
	if _, err := BuildPlan(Client{Flavor: FlavorQt, Binary: "moonlight-qt"}, request); err == nil || !strings.Contains(err.Error(), "only valid for the stream") {
		t.Fatalf("non-stream options error = %v; want operation rejection", err)
	}
}
