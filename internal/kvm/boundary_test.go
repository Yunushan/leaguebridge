package kvm

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type failingRunner struct{ err error }

func (runner failingRunner) Run(context.Context, io.Reader, io.Writer, io.Writer, string, ...string) error {
	return runner.err
}

func validRequest() Request {
	return Request{Endpoint: "https://kvm.lan/", PhysicalHostConfirmed: true, AcceptUnverifiedHandoff: true}
}

func executableLauncher(t *testing.T, name string) (Launcher, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	launcher, err := Discover(context.Background(), fakeEnvironment{paths: map[string]string{name: path}}, name)
	if err != nil {
		t.Fatalf("Discover() = %v", err)
	}
	if launcher.executableInfo == nil {
		t.Fatal("real executable was not bound during discovery")
	}
	return launcher, path
}

func discoveredPlan(t *testing.T, name string, request Request) (Plan, string) {
	t.Helper()
	launcher, path := executableLauncher(t, name)
	plan, err := BuildDiscoveredPlan(launcher, request)
	if err != nil {
		t.Fatalf("BuildDiscoveredPlan() = %v", err)
	}
	return plan, path
}

func requireError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}

func TestExecuteRunsExactDiscoveredArgv(t *testing.T) {
	plan, path := discoveredPlan(t, "gio", validRequest())
	runner := &recordingRunner{}
	if err := Execute(nil, runner, nil, io.Discard, io.Discard, plan); err != nil { //nolint:staticcheck // nil context defaults to Background.
		t.Fatalf("Execute() = %v", err)
	}
	if runner.called != 1 || runner.name != path || strings.Join(runner.args, " ") != "open https://kvm.lan/" {
		t.Fatalf("runner = %+v", runner)
	}
}

func TestExecuteRejectsRunnerAndContextFailures(t *testing.T) {
	plan, _ := discoveredPlan(t, "xdg-open", validRequest())
	requireError(t, Execute(context.Background(), nil, nil, io.Discard, io.Discard, plan), "nil runner")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireError(t, Execute(ctx, &recordingRunner{}, nil, io.Discard, io.Discard, plan), "canceled KVM handoff")

	sentinel := errors.New("browser exited")
	err := Execute(context.Background(), failingRunner{err: sentinel}, nil, io.Discard, io.Discard, plan)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "handoff failed") {
		t.Fatalf("Execute() = %v, want wrapped runner error", err)
	}
}

func TestExecuteRejectsLauncherReplacementOrRemoval(t *testing.T) {
	if runtime.GOOS != "windows" {
		// Windows resolves file identity lazily from the path, so replacement
		// detection is meaningful only on the supported Linux/BSD clients.
		// Keep the original file alive so the replacement cannot reuse its inode.
		plan, path := discoveredPlan(t, "firefox", validRequest())
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, plan), "changed after discovery")
	}

	removed, removedPath := discoveredPlan(t, "chromium", validRequest())
	if err := os.Remove(removedPath); err != nil {
		t.Fatal(err)
	}
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, removed), "unavailable KVM browser launcher")

	directory, directoryPath := discoveredPlan(t, "brave", validRequest())
	if err := os.Remove(directoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directoryPath, 0o755); err != nil {
		t.Fatal(err)
	}
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, directory), "non-regular")
}

func TestExecuteRejectsNonExecutableLauncher(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no executable permission bit")
	}
	plan, path := discoveredPlan(t, "epiphany", validRequest())
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, plan), "non-executable")
}

func TestExecuteRejectsUnboundOrRelativeLaunchers(t *testing.T) {
	synthetic, err := Discover(context.Background(), fakeEnvironment{paths: map[string]string{"xdg-open": filepath.Join(t.TempDir(), "missing", "xdg-open")}}, "xdg-open")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildDiscoveredPlan(synthetic, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, plan), "not bound by the real environment")

	relative, err := Discover(context.Background(), fakeEnvironment{paths: map[string]string{"xdg-open": "xdg-open"}}, "xdg-open")
	if err != nil {
		t.Fatal(err)
	}
	relativePlan, err := BuildDiscoveredPlan(relative, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, relativePlan), "non-absolute")
}

func TestExecuteRejectsInvalidBoundArgumentVectors(t *testing.T) {
	tests := []struct {
		name      string
		launcher  string
		arguments []string
		want      string
	}{
		{name: "missing endpoint", launcher: "gio", arguments: []string{"open"}, want: "exactly one endpoint"},
		{name: "replaced prefix", launcher: "gio", arguments: []string{"launch", "https://kvm.lan/"}, want: "unexpected command prefix"},
		{name: "unsafe endpoint", launcher: "xdg-open", arguments: []string{"https://kvm.lan/?token=secret"}, want: "query parameters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, _ := discoveredPlan(t, tt.launcher, validRequest())
			plan.Arguments = tt.arguments
			plan.argumentBinding = append([]string(nil), tt.arguments...)
			requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, plan), tt.want)
		})
	}

	plan, _ := discoveredPlan(t, "xdg-open", validRequest())
	plan.Launcher.Name = "sh"
	plan.launcherBinding = bindLauncher(plan.Launcher)
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, plan), "unsupported KVM browser launcher")
}

func TestExecuteRejectsUnvalidatedOrUndiscoveredPlans(t *testing.T) {
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, Plan{}), "unvalidated")

	plan, err := BuildPlan(Launcher{Name: "xdg-open", Binary: "/usr/bin/xdg-open"}, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, Execute(context.Background(), &recordingRunner{}, nil, io.Discard, io.Discard, plan), "not discovered")
}

func TestBuildPlanRequiresAcknowledgementsAndWarnsForHTTP(t *testing.T) {
	launcher := Launcher{Name: "xdg-open", Binary: "/usr/bin/xdg-open"}
	_, err := BuildPlan(Launcher{Name: "xdg-open"}, validRequest())
	requireError(t, err, "path is empty")

	request := validRequest()
	request.PhysicalHostConfirmed = false
	_, err = BuildPlan(launcher, request)
	requireError(t, err, "physical Windows PC or Mac")

	request = validRequest()
	request.AcceptUnverifiedHandoff = false
	_, err = BuildPlan(launcher, request)
	requireError(t, err, "explicit acknowledgement")

	request = validRequest()
	request.Endpoint = "http://192.0.2.10/"
	_, err = BuildPlan(launcher, request)
	requireError(t, err, "allow-http")
	request.AllowHTTP = true
	plan, err := BuildPlan(launcher, request)
	if err != nil {
		t.Fatal(err)
	}
	if last := plan.Warnings[len(plan.Warnings)-1]; !strings.Contains(last, "unencrypted HTTP") {
		t.Fatalf("last warning = %q", last)
	}

	for _, invalid := range []Launcher{
		{Name: "xdg-open", Binary: "/usr/bin/xdg-open", Prefix: []string{"--new"}},
		{Name: "gio", Binary: "/usr/bin/gio"},
		{Name: "sh", Binary: "/bin/sh"},
	} {
		if _, err := BuildPlan(invalid, validRequest()); err == nil {
			t.Fatalf("BuildPlan(%+v) accepted an invalid launcher", invalid)
		}
	}
}

func TestBuildDiscoveredPlanRejectsChangedLauncher(t *testing.T) {
	_, err := BuildDiscoveredPlan(Launcher{Name: "xdg-open", Binary: "/usr/bin/xdg-open"}, validRequest())
	requireError(t, err, "not discovered")

	launcher, _ := executableLauncher(t, "gio")
	for _, mutate := range []func(*Launcher){
		func(l *Launcher) { l.Binary = "/usr/bin/other" },
		func(l *Launcher) { l.Prefix = []string{"launch"} },
		func(l *Launcher) { l.Prefix = nil },
	} {
		changed := launcher
		changed.Prefix = append([]string(nil), launcher.Prefix...)
		mutate(&changed)
		_, err := BuildDiscoveredPlan(changed, validRequest())
		requireError(t, err, "changed after discovery")
	}
}

func TestDiscoverRejectsInvalidSelectionsAndCancellation(t *testing.T) {
	_, err := Discover(context.Background(), nil, "auto")
	requireError(t, err, "environment is nil")

	_, err = Discover(context.Background(), fakeEnvironment{}, "sh -c")
	requireError(t, err, "unsupported KVM browser launcher")

	_, err = Discover(context.Background(), fakeEnvironment{}, "")
	requireError(t, err, "no supported KVM browser launcher")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Discover(ctx, fakeEnvironment{paths: map[string]string{"xdg-open": "/usr/bin/xdg-open"}}, "auto")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover() = %v, want cancellation", err)
	}

	launcher, err := Discover(nil, fakeEnvironment{paths: map[string]string{"sensible-browser": "/usr/bin/sensible-browser"}}, " Sensible-Browser ") //nolint:staticcheck // nil context defaults to Background.
	if err != nil || launcher.Name != "sensible-browser" {
		t.Fatalf("Discover() = %+v, %v", launcher, err)
	}
}
