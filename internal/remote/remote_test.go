package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type flatpakFixtureEnv struct {
	fakeEnv
	installed bool
}

func (e flatpakFixtureEnv) flatpakApplicationInstalled() bool {
	return e.installed
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
	plan.qtPlatformBinding = plan.QtPlatform
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
		goos      string
		env       fakeEnv
		want      Flavor
	}{
		{"qt-first", "auto", "linux", fakeEnv{paths: map[string]string{"moonlight-qt": "/bin/moonlight-qt"}}, FlavorQt},
		{"explicit-embedded", "moonlight", "linux", fakeEnv{paths: map[string]string{"moonlight": "/bin/moonlight"}}, FlavorEmbedded},
		{"explicit-embedded-alias", "moonlight-embedded", "freebsd", fakeEnv{paths: map[string]string{"moonlight": "/bin/moonlight"}}, FlavorEmbedded},
		{"explicit-embedded-executable", "moonlight-embedded", "linux", fakeEnv{paths: map[string]string{"moonlight-embedded": "/bin/moonlight-embedded"}}, FlavorEmbedded},
		{"flatpak", "auto", "linux", fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}}, FlavorFlatpak},
		{"explicit-flatpak", "flatpak", "linux", fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}}, FlavorFlatpak},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := discoverForPlatform(context.Background(), tt.env, tt.preferred, tt.goos)
			if err != nil {
				t.Fatal(err)
			}
			if client.Flavor != tt.want {
				t.Fatalf("got %s, want %s", client.Flavor, tt.want)
			}
		})
	}
}

func TestDiscoverNormalizesClientSelection(t *testing.T) {
	client, err := DiscoverForPlatform(context.Background(), fakeEnv{paths: map[string]string{
		"moonlight-qt": "/bin/moonlight-qt",
	}}, " MOONLIGHT-QT ", "linux")
	if err != nil {
		t.Fatalf("DiscoverForPlatform(): %v", err)
	}
	if client.Flavor != FlavorQt || client.Binary != "/bin/moonlight-qt" {
		t.Fatalf("client = %+v; want Qt /bin/moonlight-qt", client)
	}
}

func TestDiscoverFlatpakRequiresInstalledApplicationWhenEnvironmentCanCheckIt(t *testing.T) {
	for _, preferred := range []string{"auto", "flatpak"} {
		t.Run(preferred+"-missing-app", func(t *testing.T) {
			env := flatpakFixtureEnv{
				fakeEnv:   fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}},
				installed: false,
			}
			if _, err := discoverForPlatform(context.Background(), env, preferred, "linux"); err == nil || !strings.Contains(err.Error(), "Flatpak app is not installed") {
				t.Fatalf("discoverForPlatform(%q) error = %v; want missing-app rejection", preferred, err)
			}
		})
		t.Run(preferred+"-installed-app", func(t *testing.T) {
			env := flatpakFixtureEnv{
				fakeEnv:   fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}},
				installed: true,
			}
			client, err := discoverForPlatform(context.Background(), env, preferred, "linux")
			if err != nil {
				t.Fatalf("discoverForPlatform(%q): %v", preferred, err)
			}
			if client.Flavor != FlavorFlatpak || client.Binary != "/bin/flatpak" {
				t.Fatalf("discovered client = %+v; want Flatpak /bin/flatpak", client)
			}
		})
	}
}

func TestDiscoverDoesNotUseFlatpakOnBSD(t *testing.T) {
	for _, goos := range []string{"freebsd", "openbsd", "netbsd", "dragonfly"} {
		t.Run(goos+"-auto", func(t *testing.T) {
			env := fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}}
			if _, err := discoverForPlatform(context.Background(), env, "auto", goos); err == nil || !strings.Contains(err.Error(), "Moonlight was not found") {
				t.Fatalf("BSD auto discovery error = %v; want native-client not-found error", err)
			}
		})
		t.Run(goos+"-explicit", func(t *testing.T) {
			env := fakeEnv{paths: map[string]string{"flatpak": "/bin/flatpak"}}
			if _, err := discoverForPlatform(context.Background(), env, "flatpak", goos); err == nil || !strings.Contains(err.Error(), "only on Linux") {
				t.Fatalf("BSD Flatpak discovery error = %v; want Linux-only rejection", err)
			}
		})
	}
}

func TestDiscoverExplicitEmbeddedRejectsGenericQtConvention(t *testing.T) {
	env := fakeEnv{paths: map[string]string{"moonlight": "/opt/moonlight"}}
	for _, goos := range []string{"linux", "openbsd", "netbsd"} {
		t.Run(goos, func(t *testing.T) {
			if _, err := discoverForPlatform(context.Background(), env, "moonlight-embedded", goos); err == nil {
				t.Fatalf("generic Qt-convention Moonlight binary was accepted as Embedded on %s", goos)
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

func TestAutomaticClientSelectionsMatchPlatformPolicy(t *testing.T) {
	if got, want := AutomaticClientSelections("linux"), []string{"moonlight-qt", "moonlight-embedded", "moonlight", "flatpak"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Linux automatic selections = %#v, want %#v", got, want)
	}
	for _, goos := range []string{"freebsd", "openbsd", "netbsd", "dragonfly"} {
		if got, want := AutomaticClientSelections(goos), []string{"moonlight-qt", "moonlight-embedded", "moonlight"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s automatic selections = %#v, want %#v", goos, got, want)
		}
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

func TestPairingPINIsSupportedByNativeClientsAndValidated(t *testing.T) {
	tests := []struct {
		name    string
		client  Client
		request Request
		want    []string
		wantErr string
	}{
		{
			name:    "valid Qt PIN",
			client:  Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"},
			request: Request{Operation: Pair, Host: "gaming-pc.local", PairingPIN: "0427", PhysicalHostConfirmed: true},
			want:    []string{"pair", "-pin", "0427", "gaming-pc.local"},
		},
		{
			name:    "valid Flatpak PIN",
			client:  Client{Flavor: FlavorFlatpak, Binary: "/usr/bin/flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}},
			request: Request{Operation: Pair, Host: "gaming-pc.local", PairingPIN: "0427", PhysicalHostConfirmed: true},
			want:    []string{"run", "com.moonlight_stream.Moonlight", "pair", "-pin", "0427", "gaming-pc.local"},
		},
		{
			name:    "valid Embedded PIN",
			client:  Client{Flavor: FlavorEmbedded, Binary: "/usr/bin/moonlight"},
			request: Request{Operation: Pair, Host: "gaming-pc.local", PairingPIN: "0427", PhysicalHostConfirmed: true},
			want:    []string{"pair", "-pin", "0427", "gaming-pc.local"},
		},
		{
			name:    "invalid PIN",
			client:  Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"},
			request: Request{Operation: Pair, Host: "gaming-pc.local", PairingPIN: "04a7", PhysicalHostConfirmed: true},
			wantErr: "exactly four ASCII digits",
		},
		{
			name:    "PIN only pairs",
			client:  Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"},
			request: Request{Operation: List, Host: "gaming-pc.local", PairingPIN: "0427", PhysicalHostConfirmed: true},
			wantErr: "only valid for the pair operation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := BuildPlan(tt.client, tt.request)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("BuildPlan() error = %v; want %q", err, tt.wantErr)
				}
				return
			}
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

func TestQtPlatformIsOperationAwareAndBounded(t *testing.T) {
	base := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "gaming-pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	tests := []struct {
		name      string
		client    Client
		operation Operation
		platform  string
		want      string
		wantError string
	}{
		{
			name:     "Qt xcb",
			client:   Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"},
			platform: "XCB",
			want:     "xcb",
		},
		{
			name:     "Flatpak linuxfb",
			client:   Client{Flavor: FlavorFlatpak, Binary: "/usr/bin/flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}},
			platform: "linuxfb",
			want:     "linuxfb",
		},
		{
			name:      "Embedded rejects Qt platform",
			client:    Client{Flavor: FlavorEmbedded, Binary: "/usr/bin/moonlight"},
			platform:  "xcb",
			wantError: "only by Moonlight Qt",
		},
		{
			name:      "pair accepts Qt platform",
			client:    Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"},
			operation: Pair,
			platform:  "xcb",
			want:      "xcb",
		},
		{
			name:      "invalid platform",
			client:    Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"},
			platform:  "offscreen",
			wantError: "must be auto, xcb, wayland, eglfs, or linuxfb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := base
			if tt.operation != "" {
				request.Operation = tt.operation
			}
			request.QtPlatform = tt.platform
			plan, err := BuildPlan(tt.client, request)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("BuildPlan() error = %v; want %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildPlan(): %v", err)
			}
			if plan.QtPlatform != tt.want || plan.qtPlatformBinding != tt.want {
				t.Fatalf("QtPlatform=%q binding=%q; want %q", plan.QtPlatform, plan.qtPlatformBinding, tt.want)
			}
			if err := validatePlanArguments(tt.client, plan.Arguments); err != nil {
				t.Fatalf("generated arguments rejected: %v", err)
			}
		})
	}
}

func TestFlatpakQtPlatformIsBoundInsideSandbox(t *testing.T) {
	client := boundTestClient(t, FlavorFlatpak)
	client.Prefix = []string{"run", moonlightFlatpakAppID}
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "gaming-pc.local",
		App:                     "League of Legends",
		QtPlatform:              "XCB",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	plan, err := BuildPlan(client, request)
	if err != nil {
		t.Fatalf("BuildPlan(): %v", err)
	}
	want := []string{"run", "--env=QT_QPA_PLATFORM=xcb", moonlightFlatpakAppID, "stream", "gaming-pc.local", "League of Legends"}
	if !reflect.DeepEqual(plan.Arguments, want) {
		t.Fatalf("Flatpak arguments = %#v, want %#v", plan.Arguments, want)
	}
	if err := validatePlanArguments(client, plan.Arguments); err != nil {
		t.Fatalf("generated Flatpak arguments rejected: %v", err)
	}

	runner := &recordingRunner{}
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err != nil {
		t.Fatalf("Execute(): %v", err)
	}
	if runner.qtPlatform != "xcb" {
		t.Fatalf("runner Qt platform = %q, want xcb", runner.qtPlatform)
	}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("runner arguments = %#v, want %#v", runner.args, want)
	}

	mismatched := plan
	mismatched.Arguments = append([]string(nil), plan.Arguments...)
	mismatched.Arguments[1] = "--env=QT_QPA_PLATFORM=wayland"
	if err := Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, mismatched); err == nil || !strings.Contains(err.Error(), "does not match its planned platform") {
		t.Fatalf("Execute() mismatch error = %v; want Flatpak platform mismatch rejection", err)
	}
}

func TestFlatpakQtPlatformPrefixRejectsUnboundedEnvironment(t *testing.T) {
	client := Client{
		Flavor: FlavorFlatpak,
		Binary: "flatpak",
		Prefix: []string{"run", moonlightFlatpakAppID},
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "arbitrary environment",
			args: []string{"run", "--env=PATH=/tmp", moonlightFlatpakAppID, "stream", "pc.local", "League"},
			want: "only the fixed QT_QPA_PLATFORM",
		},
		{
			name: "auto environment",
			args: []string{"run", "--env=QT_QPA_PLATFORM=auto", moonlightFlatpakAppID, "stream", "pc.local", "League"},
			want: "must be a concrete backend",
		},
		{
			name: "invalid backend",
			args: []string{"run", "--env=QT_QPA_PLATFORM=offscreen", moonlightFlatpakAppID, "stream", "pc.local", "League"},
			want: "must be auto, xcb, wayland, eglfs, or linuxfb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePlanArguments(client, tt.args); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validatePlanArguments() error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestValidateQtPlatform(t *testing.T) {
	for _, tt := range []struct {
		value string
		valid bool
	}{
		{value: "auto", valid: true},
		{value: "XCB", valid: true},
		{value: "wayland", valid: true},
		{value: "eglfs", valid: true},
		{value: "linuxfb", valid: true},
		{value: "offscreen", valid: false},
		{value: "", valid: false},
	} {
		t.Run(tt.value, func(t *testing.T) {
			err := ValidateQtPlatform(tt.value)
			if (err == nil) != tt.valid {
				t.Fatalf("ValidateQtPlatform(%q) = %v, valid=%v", tt.value, err, tt.valid)
			}
		})
	}
}

func TestValidatePairingPIN(t *testing.T) {
	for _, tt := range []struct {
		value string
		valid bool
	}{
		{value: "0427", valid: true},
		{value: "0000", valid: true},
		{value: "427", valid: false},
		{value: "04270", valid: false},
		{value: "04a7", valid: false},
		{value: " 427", valid: false},
	} {
		t.Run(tt.value, func(t *testing.T) {
			err := ValidatePairingPIN(tt.value)
			if (err == nil) != tt.valid {
				t.Fatalf("ValidatePairingPIN(%q) = %v, valid=%v", tt.value, err, tt.valid)
			}
		})
	}
}

func TestBuildPlanBracketedIPv6EndpointUsesClientSpecificPortSyntax(t *testing.T) {
	streamRequest := Request{
		Operation:               Stream,
		Host:                    "[2001:db8::1]:47989",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	listRequest := streamRequest
	listRequest.Operation = List
	listRequest.App = ""

	tests := []struct {
		name       string
		host       string
		client     Client
		streamWant []string
		listWant   []string
	}{
		{
			name:       "embedded",
			host:       "[2001:db8::1]:47989",
			client:     Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			streamWant: []string{"stream", "-app", "League of Legends", "2001:db8::1", "-port", "47989"},
			listWant:   []string{"list", "2001:db8::1", "-port", "47989"},
		},
		{
			name:       "qt",
			host:       "[2001:db8::1]:47989",
			client:     Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			streamWant: []string{"stream", "[2001:db8::1]:47989", "League of Legends"},
			listWant:   []string{"list", "[2001:db8::1]:47989"},
		},
		{
			name:       "embedded link-local zone",
			host:       "[fe80::1%25em0]:47989",
			client:     Client{Flavor: FlavorEmbedded, Binary: "moonlight-embedded"},
			streamWant: []string{"stream", "-app", "League of Legends", "fe80::1%em0", "-port", "47989"},
			listWant:   []string{"list", "fe80::1%em0", "-port", "47989"},
		},
		{
			name:       "qt link-local zone",
			host:       "[fe80::1%25em0]:47989",
			client:     Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			streamWant: []string{"stream", "[fe80::1%25em0]:47989", "League of Legends"},
			listWant:   []string{"list", "[fe80::1%25em0]:47989"},
		},
		{
			name:       "embedded IPv4 endpoint",
			host:       "192.0.2.10:47989",
			client:     Client{Flavor: FlavorEmbedded, Binary: "moonlight-embedded"},
			streamWant: []string{"stream", "-app", "League of Legends", "192.0.2.10", "-port", "47989"},
			listWant:   []string{"list", "192.0.2.10", "-port", "47989"},
		},
		{
			name:       "qt DNS endpoint",
			host:       "gaming-pc.local:47989",
			client:     Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			streamWant: []string{"stream", "gaming-pc.local:47989", "League of Legends"},
			listWant:   []string{"list", "gaming-pc.local:47989"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			streamRequest.Host = tt.host
			listRequest.Host = tt.host
			streamPlan, err := BuildPlan(tt.client, streamRequest)
			if err != nil {
				t.Fatalf("BuildPlan(stream): %v", err)
			}
			if !reflect.DeepEqual(streamPlan.Arguments, tt.streamWant) {
				t.Fatalf("stream arguments = %#v, want %#v", streamPlan.Arguments, tt.streamWant)
			}
			if err := validatePlanArguments(tt.client, streamPlan.Arguments); err != nil {
				t.Fatalf("stream arguments rejected: %v", err)
			}

			listPlan, err := BuildPlan(tt.client, listRequest)
			if err != nil {
				t.Fatalf("BuildPlan(list): %v", err)
			}
			if !reflect.DeepEqual(listPlan.Arguments, tt.listWant) {
				t.Fatalf("list arguments = %#v, want %#v", listPlan.Arguments, tt.listWant)
			}
			if err := validatePlanArguments(tt.client, listPlan.Arguments); err != nil {
				t.Fatalf("list arguments rejected: %v", err)
			}
		})
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

func TestApplicationListedForFlavorUsesClientNameSemantics(t *testing.T) {
	const requested = "League of Legends"
	tests := []struct {
		name   string
		output string
		flavor Flavor
		want   bool
	}{
		{name: "Qt is case insensitive", output: "league of legends\n", flavor: FlavorQt, want: true},
		{name: "Flatpak uses Qt semantics", output: "LEAGUE OF LEGENDS\n", flavor: FlavorFlatpak, want: true},
		{name: "Embedded remains exact", output: "league of legends\n", flavor: FlavorEmbedded, want: false},
		{name: "Qt decorated line is case insensitive", output: "2. LEAGUE OF LEGENDS\n", flavor: FlavorQt, want: true},
		{name: "diagnostic mention remains rejected", output: "Connecting to league of legends\n", flavor: FlavorQt, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ApplicationListedForFlavor(tt.output, requested, tt.flavor); got != tt.want {
				t.Fatalf("ApplicationListedForFlavor(%q, %q, %q) = %v, want %v", tt.output, requested, tt.flavor, got, tt.want)
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

func TestBuildPlanWindowsRouteExplainsHostInputContract(t *testing.T) {
	client := Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"}
	plan, err := BuildPlan(client, Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "gaming-pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(plan.Warnings, " ")
	for _, required := range []string{"licensed Virtual HID Raw Input", "relative mouse mode", "physical mouse", "headless", "SendInput fallback", "hardware KVM", "never installs or alters"} {
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
	name       string
	args       []string
	qtPlatform string
	err        error
}

func (r *recordingRunner) Run(_ context.Context, _ io.Reader, _, _ io.Writer, name string, args ...string) error {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.err
}

func (r *recordingRunner) RunWithQtPlatform(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, qtPlatform, name string, args ...string) error {
	r.qtPlatform = qtPlatform
	return r.Run(ctx, stdin, stdout, stderr, name, args...)
}

func TestQtPlatformProcessHelper(t *testing.T) {
	if os.Getenv("LEAGUEBRIDGE_QT_PLATFORM_HELPER") != "1" {
		return
	}
	_, _ = io.WriteString(os.Stdout, os.Getenv("QT_QPA_PLATFORM"))
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

func TestExecuteAppliesQtPlatformThroughRunnerExtension(t *testing.T) {
	runner := &recordingRunner{}
	client := boundTestClient(t, FlavorQt)
	plan := bindTestPlan(Plan{
		Route:            config.RouteWindows,
		Client:           client,
		Arguments:        []string{"stream", "pc.local", "League of Legends"},
		QtPlatform:       "xcb",
		validated:        true,
		clientDiscovered: true,
		clientBinding:    bindClient(client),
	})
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err != nil {
		t.Fatalf("Execute(): %v", err)
	}
	if runner.qtPlatform != "xcb" {
		t.Fatalf("runner Qt platform = %q, want xcb", runner.qtPlatform)
	}
}

func TestExecuteRejectsQtPlatformMutation(t *testing.T) {
	runner := &recordingRunner{}
	client := boundTestClient(t, FlavorQt)
	plan := bindTestPlan(Plan{
		Route:            config.RouteWindows,
		Client:           client,
		Arguments:        []string{"stream", "pc.local", "League"},
		QtPlatform:       "xcb",
		validated:        true,
		clientDiscovered: true,
		clientBinding:    bindClient(client),
	})
	plan.QtPlatform = "wayland"
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err == nil || !strings.Contains(err.Error(), "Qt platform was changed") {
		t.Fatalf("Execute() error = %v; want Qt platform mutation rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called after Qt platform mutation: %q", runner.name)
	}
}

func TestEnvironmentWithOverridesReplacesExistingValue(t *testing.T) {
	got := environmentWithOverrides([]string{"QT_QPA_PLATFORM=wayland", "PATH=/usr/bin"}, []string{"QT_QPA_PLATFORM=xcb"})
	if !reflect.DeepEqual(got, []string{"PATH=/usr/bin", "QT_QPA_PLATFORM=xcb"}) {
		t.Fatalf("environmentWithOverrides() = %#v", got)
	}
}

func TestExecRunnerPassesQtPlatformToChildProcess(t *testing.T) {
	t.Setenv("LEAGUEBRIDGE_QT_PLATFORM_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	err = (ExecRunner{}).RunWithQtPlatform(context.Background(), nil, &stdout, &stderr, "xcb", executable, "-test.run=^TestQtPlatformProcessHelper$")
	if err != nil {
		t.Fatalf("ExecRunner.RunWithQtPlatform(): %v; stderr=%q", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "xcb") {
		t.Fatalf("child output = %q; want QT_QPA_PLATFORM=xcb", stdout.String())
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
			name:   "qt session stability stream",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt", discovered: true},
			args:   []string{"stream", "-frame-pacing", "-vsync", "-keep-awake", "-capture-system-keys", "always", "pc.local", "League of Legends"},
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
			name:   "embedded Qt-only frame pacing",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-frame-pacing", "-app", "League", "pc.local"},
		},
		{
			name:   "embedded Qt-only keep awake",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-keep-awake", "-app", "League", "pc.local"},
		},
		{
			name:   "embedded Qt-only system-key capture",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-capture-system-keys", "always", "-app", "League", "pc.local"},
		},
		{
			name:   "embedded Qt-only VSync",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-vsync", "-app", "League", "pc.local"},
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

func TestBuildPlanQtSessionStabilityUsesDocumentedToggles(t *testing.T) {
	base := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	tests := []struct {
		name    string
		options StreamOptions
		want    []string
	}{
		{
			name:    "enabled and keep awake",
			options: StreamOptions{FramePacing: "on", VSync: "on", KeepAwake: true, CaptureSystemKeys: "always"},
			want:    []string{"stream", "-frame-pacing", "-vsync", "-keep-awake", "-capture-system-keys", "always", "pc.local", "League of Legends"},
		},
		{
			name:    "disabled",
			options: StreamOptions{FramePacing: "off"},
			want:    []string{"stream", "-no-frame-pacing", "pc.local", "League of Legends"},
		},
		{
			name:    "auto keeps client default",
			options: StreamOptions{FramePacing: "auto", KeepAwake: true},
			want:    []string{"stream", "-keep-awake", "pc.local", "League of Legends"},
		},
		{
			name:    "quit host app after session",
			options: StreamOptions{QuitAfter: true},
			want:    []string{"stream", "-quit-after", "pc.local", "League of Legends"},
		},
	}
	client := Client{Flavor: FlavorQt, Binary: "moonlight-qt"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := base
			request.Stream = tt.options
			plan, err := BuildPlan(client, request)
			if err != nil {
				t.Fatalf("BuildPlan(): %v", err)
			}
			if !reflect.DeepEqual(plan.Arguments, tt.want) {
				t.Fatalf("arguments = %#v, want %#v", plan.Arguments, tt.want)
			}
			if err := validatePlanArguments(client, plan.Arguments); err != nil {
				t.Fatalf("generated arguments rejected: %v", err)
			}
		})
	}
	for _, options := range []StreamOptions{{FramePacing: "on"}, {KeepAwake: true}} {
		request := base
		request.Stream = options
		client := Client{Flavor: FlavorEmbedded, Binary: "moonlight"}
		if _, err := BuildPlan(client, request); err == nil || !strings.Contains(err.Error(), "only by Moonlight Qt") || !strings.Contains(err.Error(), "moonlight-qt") {
			t.Errorf("BuildPlan(%s, %#v) error = %v; want Qt-only rejection", client.Flavor, options, err)
		}
	}
	embeddedRequest := base
	embeddedRequest.Stream = StreamOptions{QuitAfter: true}
	embeddedClient := Client{Flavor: FlavorEmbedded, Binary: "moonlight"}
	embeddedPlan, err := BuildPlan(embeddedClient, embeddedRequest)
	if err != nil {
		t.Fatalf("BuildPlan(embedded quit-after): %v", err)
	}
	embeddedWant := []string{"stream", "-quitappafter", "-app", "League of Legends", "pc.local"}
	if !reflect.DeepEqual(embeddedPlan.Arguments, embeddedWant) {
		t.Fatalf("Embedded quit-after arguments = %#v, want %#v", embeddedPlan.Arguments, embeddedWant)
	}
	if err := validatePlanArguments(embeddedClient, embeddedPlan.Arguments); err != nil {
		t.Fatalf("Embedded quit-after arguments rejected: %v", err)
	}
	flatpak := Client{Flavor: FlavorFlatpak, Binary: "flatpak", Prefix: []string{"run", "com.moonlight_stream.Moonlight"}}
	request := base
	request.Stream = StreamOptions{FramePacing: "on", VSync: "on", KeepAwake: true, CaptureSystemKeys: "always"}
	plan, err := BuildPlan(flatpak, request)
	if err != nil {
		t.Fatalf("BuildPlan(flatpak): %v", err)
	}
	want := []string{"run", "com.moonlight_stream.Moonlight", "stream", "-frame-pacing", "-vsync", "-keep-awake", "-capture-system-keys", "always", "pc.local", "League of Legends"}
	if !reflect.DeepEqual(plan.Arguments, want) {
		t.Fatalf("Flatpak arguments = %#v, want %#v", plan.Arguments, want)
	}
	if err := validatePlanArguments(flatpak, plan.Arguments); err != nil {
		t.Fatalf("Flatpak generated arguments rejected: %v", err)
	}
}

func TestBuildPlanAudioAndControllerControlsUseDocumentedSyntax(t *testing.T) {
	base := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}

	t.Run("Embedded audio and mouse-emulation controls", func(t *testing.T) {
		request := base
		request.Stream = StreamOptions{
			AudioOnHost:                  true,
			AudioDevice:                  "hw:0,0",
			DisableGamepadMouseEmulation: true,
			InputDevice:                  "/dev/input/event0",
			InputMapping:                 "/etc/moonlight/gamecontrollerdb.txt",
		}
		client := Client{Flavor: FlavorEmbedded, Binary: "moonlight"}
		plan, err := BuildPlan(client, request)
		if err != nil {
			t.Fatalf("BuildPlan(): %v", err)
		}
		want := []string{"stream", "-localaudio", "-audio", "hw:0,0", "-nomouseemulation", "-input", "/dev/input/event0", "-mapping", "/etc/moonlight/gamecontrollerdb.txt", "-app", "League of Legends", "pc.local"}
		if !reflect.DeepEqual(plan.Arguments, want) {
			t.Fatalf("arguments = %#v, want %#v", plan.Arguments, want)
		}
		if err := validatePlanArguments(client, plan.Arguments); err != nil {
			t.Fatalf("generated Embedded arguments rejected: %v", err)
		}
	})

	qtOptions := StreamOptions{
		AudioOnHost:            true,
		MultiController:        true,
		MouseButtonsSwap:       true,
		TouchscreenTrackpad:    true,
		MuteOnFocusLoss:        true,
		BackgroundGamepad:      true,
		ReverseScrollDirection: true,
		SwapGamepadButtons:     true,
		PerformanceOverlay:     true,
		HDR:                    true,
		YUV444:                 true,
	}
	wantQt := []string{
		"stream", "-audio-on-host", "-multi-controller", "-mouse-buttons-swap",
		"-touchscreen-trackpad", "-mute-on-focus-loss", "-background-gamepad",
		"-reverse-scroll-direction", "-swap-gamepad-buttons", "-performance-overlay",
		"-hdr", "-yuv444", "pc.local", "League of Legends",
	}
	for _, tt := range []struct {
		name   string
		client Client
		want   []string
	}{
		{name: "Qt", client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"}, want: wantQt},
		{
			name: "Flatpak Qt",
			client: Client{
				Flavor: FlavorFlatpak,
				Binary: "flatpak",
				Prefix: []string{"run", "com.moonlight_stream.Moonlight"},
			},
			want: append([]string{"run", "com.moonlight_stream.Moonlight"}, wantQt...),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := base
			request.Stream = qtOptions
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

	embeddedQtControlRequest := base
	embeddedQtControlRequest.Stream = StreamOptions{MultiController: true}
	if _, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, embeddedQtControlRequest); err == nil || !strings.Contains(err.Error(), "only by Moonlight Qt") {
		t.Fatalf("Embedded Qt-control error = %v; want Qt-only rejection", err)
	}
	qtEmbeddedControlRequest := base
	qtEmbeddedControlRequest.Stream = StreamOptions{DisableGamepadMouseEmulation: true}
	if _, err := BuildPlan(Client{Flavor: FlavorQt, Binary: "moonlight-qt"}, qtEmbeddedControlRequest); err == nil || !strings.Contains(err.Error(), "only by Moonlight Embedded") {
		t.Fatalf("Qt Embedded-control error = %v; want Embedded-only rejection", err)
	}
	for _, tt := range []struct {
		name   string
		client Client
		args   []string
	}{
		{
			name:   "Embedded rejects Qt audio flag",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-audio-on-host", "-app", "League", "pc.local"},
		},
		{
			name:   "Qt rejects Embedded audio flag",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-localaudio", "pc.local", "League"},
		},
		{
			name:   "Qt rejects Embedded audio device flag",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-audio", "hw:0,0", "pc.local", "League"},
		},
		{
			name:   "Qt rejects Embedded input device flag",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-input", "/dev/input/event0", "pc.local", "League"},
		},
		{
			name:   "Qt rejects Embedded input mapping flag",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-mapping", "/etc/moonlight/gamecontrollerdb.txt", "pc.local", "League"},
		},
		{
			name:   "Qt rejects Embedded mouse-emulation flag",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-nomouseemulation", "pc.local", "League"},
		},
		{
			name:   "Embedded rejects Qt controller flag",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-multi-controller", "-app", "League", "pc.local"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePlanArguments(tt.client, tt.args); err == nil {
				t.Fatal("validatePlanArguments() unexpectedly accepted a client-specific option")
			}
		})
	}
}

func TestBuildPlanHDRUsesDocumentedNativeSyntax(t *testing.T) {
	base := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream:                  StreamOptions{HDR: true},
	}
	for _, tt := range []struct {
		name   string
		client Client
		want   []string
	}{
		{
			name:   "Embedded",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			want:   []string{"stream", "-hdr", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "Qt",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			want:   []string{"stream", "-hdr", "pc.local", "League of Legends"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := BuildPlan(tt.client, base)
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
	if err := validatePlanArguments(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, []string{"stream", "-hdr", "-app", "League", "pc.local"}); err != nil {
		t.Fatalf("Embedded HDR argument rejected: %v", err)
	}
	if err := validatePlanArguments(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, []string{"stream", "-hdr", "-hdr", "-app", "League", "pc.local"}); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatalf("duplicate Embedded HDR argument error = %v; want duplicate rejection", err)
	}
}

func TestStreamOptionsRejectHDRWithH264(t *testing.T) {
	t.Parallel()
	for _, codec := range []string{"h264", "H264"} {
		err := (StreamOptions{Codec: codec, HDR: true}).Validate()
		if err == nil || !strings.Contains(err.Error(), "HDR streaming cannot use H.264") {
			t.Fatalf("Validate(codec=%q, hdr=true) = %v; want H.264/HDR rejection", codec, err)
		}
	}
	for _, codec := range []string{"auto", "h265", "hevc", "av1"} {
		if err := (StreamOptions{Codec: codec, HDR: true}).Validate(); err != nil {
			t.Fatalf("Validate(codec=%q, hdr=true) = %v; want accepted codec", codec, err)
		}
	}
}

func TestStreamOptionsUnknownCodecErrorListsAcceptedValues(t *testing.T) {
	t.Parallel()
	err := (StreamOptions{Codec: "vp9"}).Validate()
	if err == nil {
		t.Fatal("Validate(codec=vp9) unexpectedly succeeded")
	}
	for _, accepted := range []string{"auto", "h264", "h265", "hevc", "av1"} {
		if !strings.Contains(err.Error(), accepted) {
			t.Fatalf("Validate(codec=vp9) error = %v; missing accepted codec %q", err, accepted)
		}
	}
}

func TestValidatePlanArgumentsRejectsHDRWithH264(t *testing.T) {
	for _, test := range []struct {
		name   string
		client Client
		args   []string
	}{
		{
			name:   "Embedded",
			client: Client{Flavor: FlavorEmbedded, Binary: "moonlight"},
			args:   []string{"stream", "-hdr", "-codec", "h264", "-app", "League of Legends", "pc.local"},
		},
		{
			name:   "Qt",
			client: Client{Flavor: FlavorQt, Binary: "moonlight-qt"},
			args:   []string{"stream", "-hdr", "-video-codec", "H264", "pc.local", "League of Legends"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePlanArguments(test.client, test.args); err == nil || !strings.Contains(err.Error(), "cannot combine -hdr with H.264") {
				t.Fatalf("validatePlanArguments() error = %v; want HDR/H.264 rejection", err)
			}
		})
	}
}

func TestValidatePlanArgumentsRejectsSDLExclusiveDeviceSelectors(t *testing.T) {
	client := Client{Flavor: FlavorEmbedded, Binary: "moonlight"}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "audio device",
			args: []string{"stream", "-platform", "sdl", "-audio", "default", "-app", "League", "pc.local"},
			want: "cannot combine -platform sdl with -audio",
		},
		{
			name: "input device",
			args: []string{"stream", "-platform", "sdl", "-input", "/dev/input/event4", "-app", "League", "pc.local"},
			want: "cannot combine -platform sdl with -input",
		},
		{
			name: "input device before platform",
			args: []string{"stream", "-input", "/dev/input/event4", "-platform", "SDL", "-app", "League", "pc.local"},
			want: "cannot combine -platform sdl with -input",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePlanArguments(client, test.args); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validatePlanArguments() error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestStreamOptionsRejectUnsafeEmbeddedDeviceSelectors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		options StreamOptions
		want    string
	}{
		{name: "audio option-like", options: StreamOptions{AudioDevice: "-default"}, want: "must not start"},
		{name: "audio control character", options: StreamOptions{AudioDevice: "hw:0\n0"}, want: "control characters"},
		{name: "audio too long", options: StreamOptions{AudioDevice: strings.Repeat("a", maxDeviceSelectorLength+1)}, want: "must not exceed"},
		{name: "input relative", options: StreamOptions{InputDevice: "event0"}, want: "evdev path"},
		{name: "input missing index", options: StreamOptions{InputDevice: "/dev/input/event"}, want: "evdev path"},
		{name: "input traversal", options: StreamOptions{InputDevice: "/dev/input/event0/.."}, want: "evdev path"},
		{name: "mapping relative", options: StreamOptions{InputMapping: "gamecontrollerdb.txt"}, want: "absolute Linux/BSD path"},
		{name: "mapping option-like", options: StreamOptions{InputMapping: "-gamecontrollerdb.txt"}, want: "must not start"},
		{name: "mapping too long", options: StreamOptions{InputMapping: "/" + strings.Repeat("a", maxInputMappingPathLength)}, want: "must not exceed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.options.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestValidatePlanArgumentsUnpairRequiresEmbedded(t *testing.T) {
	args := []string{"unpair", "pc.local"}
	if err := validatePlanArguments(Client{Flavor: FlavorQt, Binary: "moonlight-qt"}, args); err == nil || !strings.Contains(err.Error(), "only by Moonlight Embedded") {
		t.Fatalf("Qt unpair validation error = %v; want Embedded-only rejection", err)
	}
	if err := validatePlanArguments(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, args); err != nil {
		t.Fatalf("Embedded unpair validation failed: %v", err)
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
	fullscreenRequest := request
	fullscreenRequest.Stream.DisplayMode = "fullscreen"
	fullscreenPlan, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, fullscreenRequest)
	if err != nil {
		t.Fatalf("BuildPlan(embedded fullscreen): %v", err)
	}
	if containsArgument(fullscreenPlan.Arguments, "-windowed") {
		t.Fatalf("Embedded fullscreen arguments = %#v; want Moonlight's fullscreen default without -windowed", fullscreenPlan.Arguments)
	}
	if err := validatePlanArguments(Client{Flavor: FlavorEmbedded, Binary: "moonlight"}, fullscreenPlan.Arguments); err != nil {
		t.Fatalf("generated Embedded fullscreen arguments rejected: %v", err)
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
	for _, platform := range []string{"x11", "x11_vdpau", "x11_vaapi", "sdl"} {
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
		{FramePacing: "adaptive"},
		{CaptureSystemKeys: "focused"},
		{VSync: "adaptive"},
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

func TestBuildInputMappingPlanUsesEmbeddedLocalGrammar(t *testing.T) {
	client := Client{Flavor: FlavorEmbedded, Binary: "/fixture/moonlight-embedded"}
	plan, err := BuildInputMappingPlan(client, "/dev/input/event4")
	if err != nil {
		t.Fatalf("BuildInputMappingPlan(): %v", err)
	}
	if plan.Route != "" || !plan.Local || !plan.local {
		t.Fatalf("local plan markers = route %q local=%v private=%v; want empty route and both local markers", plan.Route, plan.Local, plan.local)
	}
	want := []string{"map", "-input", "/dev/input/event4"}
	if !reflect.DeepEqual(plan.Arguments, want) {
		t.Fatalf("arguments = %#v, want %#v", plan.Arguments, want)
	}
	if len(plan.Warnings) != 2 || !strings.Contains(plan.Warnings[0], "does not pair") {
		t.Fatalf("warnings = %#v, want local-action warnings", plan.Warnings)
	}
}

func TestBuildInputMappingPlanRejectsNonEmbeddedAndUnsafeDevices(t *testing.T) {
	for _, tt := range []struct {
		name   string
		client Client
		device string
		want   string
	}{
		{name: "Qt", client: Client{Flavor: FlavorQt, Binary: "/fixture/moonlight-qt"}, device: "/dev/input/event0", want: "only by Moonlight Embedded"},
		{name: "Flatpak", client: Client{Flavor: FlavorFlatpak, Binary: "/fixture/flatpak", Prefix: []string{"run", moonlightFlatpakAppID}}, device: "/dev/input/event0", want: "only by Moonlight Embedded"},
		{name: "relative", client: Client{Flavor: FlavorEmbedded, Binary: "/fixture/moonlight"}, device: "event0", want: "evdev path"},
		{name: "missing index", client: Client{Flavor: FlavorEmbedded, Binary: "/fixture/moonlight"}, device: "/dev/input/event", want: "evdev path"},
		{name: "option-like", client: Client{Flavor: FlavorEmbedded, Binary: "/fixture/moonlight"}, device: "-input", want: "must not start"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BuildInputMappingPlan(tt.client, tt.device); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("BuildInputMappingPlan(%q): %v; want %q", tt.device, err, tt.want)
			}
		})
	}
}

func TestBuildPlanEmbeddedAllowsMultipleInputDevices(t *testing.T) {
	request := Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League of Legends",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream: StreamOptions{
			InputDevices: []string{"/dev/input/event0", "/dev/input/event4"},
		},
	}
	client := Client{Flavor: FlavorEmbedded, Binary: "moonlight"}
	plan, err := BuildPlan(client, request)
	if err != nil {
		t.Fatalf("BuildPlan(): %v", err)
	}
	want := []string{"stream", "-input", "/dev/input/event0", "-input", "/dev/input/event4", "-app", "League of Legends", "pc.local"}
	if !reflect.DeepEqual(plan.Arguments, want) {
		t.Fatalf("arguments = %#v, want %#v", plan.Arguments, want)
	}
	if err := validatePlanArguments(client, plan.Arguments); err != nil {
		t.Fatalf("generated multiple-input arguments rejected: %v", err)
	}
}

func TestStreamOptionsRejectsAmbiguousOrExcessiveInputDevices(t *testing.T) {
	if err := (StreamOptions{
		InputDevice:  "/dev/input/event0",
		InputDevices: []string{"/dev/input/event1"},
	}).Validate(); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("ambiguous input selectors error = %v; want combination rejection", err)
	}
	atLimit := make([]string, maxEmbeddedInputDevices)
	for index := range atLimit {
		atLimit[index] = fmt.Sprintf("/dev/input/event%d", index)
	}
	if err := (StreamOptions{InputDevices: atLimit}).Validate(); err != nil {
		t.Fatalf("input selectors at the Embedded limit were rejected: %v", err)
	}
	tooMany := make([]string, maxEmbeddedInputDevices+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("/dev/input/event%d", index)
	}
	if err := (StreamOptions{InputDevices: tooMany}).Validate(); err == nil || !strings.Contains(err.Error(), "must not exceed") {
		t.Fatalf("excessive input selectors error = %v; want bounded-list rejection", err)
	}
}

func TestStreamOptionsRejectsSDLExclusiveDeviceSelectors(t *testing.T) {
	tests := []struct {
		name    string
		options StreamOptions
		want    string
	}{
		{
			name:    "audio device",
			options: StreamOptions{Platform: "sdl", AudioDevice: "default"},
			want:    "audio device cannot be used with the Embedded SDL platform",
		},
		{
			name:    "single input device",
			options: StreamOptions{Platform: "sdl", InputDevice: "/dev/input/event4"},
			want:    "explicit input devices cannot be used with the Embedded SDL platform",
		},
		{
			name:    "multiple input devices",
			options: StreamOptions{Platform: "sdl", InputDevices: []string{"/dev/input/event0", "/dev/input/event4"}},
			want:    "explicit input devices cannot be used with the Embedded SDL platform",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.options.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("StreamOptions.Validate() error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestBuildDiscoveredInputMappingPlanRequiresDiscovery(t *testing.T) {
	if _, err := BuildDiscoveredInputMappingPlan(Client{Flavor: FlavorEmbedded, Binary: "/fixture/moonlight"}, "/dev/input/event0"); err == nil || !strings.Contains(err.Error(), "not discovered") {
		t.Fatalf("BuildDiscoveredInputMappingPlan() error = %v; want discovery provenance rejection", err)
	}
}

func TestExecuteRunsDiscoveredLocalInputMappingPlan(t *testing.T) {
	client := boundTestClient(t, FlavorEmbedded)
	client.discoveryBinding = bindClient(client)
	plan, err := BuildDiscoveredInputMappingPlan(client, "/dev/input/event0")
	if err != nil {
		t.Fatalf("BuildDiscoveredInputMappingPlan(): %v", err)
	}
	runner := &recordingRunner{}
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err != nil {
		t.Fatalf("Execute(): %v", err)
	}
	if !reflect.DeepEqual(runner.args, plan.Arguments) {
		t.Fatalf("runner args = %#v, want %#v", runner.args, plan.Arguments)
	}
}

func TestExecuteRejectsUnmarkedLocalInputMappingPlan(t *testing.T) {
	client := boundTestClient(t, FlavorEmbedded)
	client.discoveryBinding = bindClient(client)
	plan, err := BuildDiscoveredInputMappingPlan(client, "/dev/input/event0")
	if err != nil {
		t.Fatalf("BuildDiscoveredInputMappingPlan(): %v", err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	var decoded Plan
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	runner := &recordingRunner{}
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, decoded); err == nil || !strings.Contains(err.Error(), "invalid remote plan") {
		t.Fatalf("Execute() decoded plan error = %v; want private local-marker rejection", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for a decoded local plan: %q", runner.name)
	}
}
