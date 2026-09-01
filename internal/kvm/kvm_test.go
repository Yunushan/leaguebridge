package kvm

import (
	"context"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

type fakeEnvironment struct {
	paths map[string]string
}

func (environment fakeEnvironment) LookPath(name string) (string, error) {
	if path := environment.paths[name]; path != "" {
		return path, nil
	}
	return "", os.ErrNotExist
}

type recordingRunner struct {
	called int
	name   string
	args   []string
}

func (runner *recordingRunner) Run(_ context.Context, _ io.Reader, _, _ io.Writer, name string, args ...string) error {
	runner.called++
	runner.name = name
	runner.args = append([]string(nil), args...)
	return nil
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		allowHTTP bool
		want      string
	}{
		{name: "https", endpoint: "https://kvm.lan/"},
		{name: "http opt in", endpoint: "http://192.0.2.10/", allowHTTP: true},
		{name: "missing host", endpoint: "https:///ui", want: "host"},
		{name: "wrong scheme", endpoint: "file://kvm.lan/tmp", want: "https"},
		{name: "http needs opt in", endpoint: "http://kvm.lan/", want: "allow-http"},
		{name: "credentials", endpoint: "https://user:pass@kvm.lan/", want: "credentials"},
		{name: "query", endpoint: "https://kvm.lan/?token=secret", want: "query parameters"},
		{name: "fragment", endpoint: "https://kvm.lan/#ui", want: "fragment"},
		{name: "whitespace", endpoint: " https://kvm.lan/", want: "whitespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpoint(tt.endpoint, tt.allowHTTP)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("ValidateEndpoint() = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateEndpoint() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestDiscoverUsesAllowlistedLaunchers(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment := fakeEnvironment{paths: map[string]string{
		"gio": executable,
	}}
	launcher, err := Discover(context.Background(), environment, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if launcher.Name != "gio" || !reflect.DeepEqual(launcher.Prefix, []string{"open"}) {
		t.Fatalf("launcher = %+v; want gio with fixed open prefix", launcher)
	}
	if _, err := Discover(context.Background(), environment, "sh"); err == nil || !strings.Contains(err.Error(), "unsupported KVM browser launcher") {
		t.Fatalf("unsupported launcher error = %v", err)
	}
}

func TestDiscoverFallsBackToDirectBrowser(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := Discover(context.Background(), fakeEnvironment{paths: map[string]string{
		"firefox": executable,
	}}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if launcher.Name != "firefox" || len(launcher.Prefix) != 0 {
		t.Fatalf("launcher = %+v; want direct firefox with no prefix", launcher)
	}
	plan, err := BuildDiscoveredPlan(launcher, Request{
		Endpoint:                "https://kvm.lan/",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.Arguments, []string{"https://kvm.lan/"}) {
		t.Fatalf("arguments = %#v; want endpoint-only vector", plan.Arguments)
	}
}

func TestDirectBrowserAllowlistRejectsPrefix(t *testing.T) {
	if _, err := BuildPlan(Launcher{
		Name:   "firefox",
		Binary: "/usr/bin/firefox",
		Prefix: []string{"--profile", "/tmp/profile"},
	}, Request{
		Endpoint:                "https://kvm.lan/",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}); err == nil || !strings.Contains(err.Error(), "cannot have a command prefix") {
		t.Fatalf("BuildPlan() error = %v; want direct-browser prefix rejection", err)
	}
}

func TestExecuteRejectsMutationAfterPlanning(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := Discover(context.Background(), fakeEnvironment{paths: map[string]string{"xdg-open": executable}}, "xdg-open")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildDiscoveredPlan(launcher, Request{
		Endpoint:                "https://kvm.lan/",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.Arguments[0] = "https://attacker.invalid/"
	runner := &recordingRunner{}
	if err := Execute(context.Background(), runner, nil, io.Discard, io.Discard, plan); err == nil || !strings.Contains(err.Error(), "argument vector was changed") {
		t.Fatalf("Execute() error = %v, want mutation rejection", err)
	}
	if runner.called != 0 {
		t.Fatalf("runner called %d time(s), want zero", runner.called)
	}
}
