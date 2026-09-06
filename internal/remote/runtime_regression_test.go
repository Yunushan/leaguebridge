package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/config"
)

// Run a safe stand-in as a real child with the exact Moonlight argv. It never
// contacts a host, parses a test flag as a Moonlight option, or invokes a shell.
func TestMain(m *testing.M) {
	if os.Getenv("LEAGUEBRIDGE_REMOTE_PROCESS_FIXTURE") == "1" {
		if os.Getenv("LEAGUEBRIDGE_REMOTE_FIXTURE_WAIT") == "1" {
			_, _ = io.WriteString(os.Stdout, "fixture-ready\n")
			time.Sleep(time.Minute)
		}
		if os.Getenv("LEAGUEBRIDGE_REMOTE_FIXTURE_QPA") == "1" {
			_, _ = io.WriteString(os.Stdout, os.Getenv("QT_QPA_PLATFORM"))
			os.Exit(0)
		}
		if os.Getenv("LEAGUEBRIDGE_REMOTE_FIXTURE_LARGE") == "1" {
			_, _ = io.WriteString(os.Stdout, strings.Repeat("x", maximumControlOutput)+"\nSuccesfully "+os.Args[1]+"ed\n")
		} else {
			_, _ = io.WriteString(os.Stdout, os.Getenv("LEAGUEBRIDGE_REMOTE_FIXTURE_STDOUT"))
		}
		_, _ = io.WriteString(os.Stderr, os.Getenv("LEAGUEBRIDGE_REMOTE_FIXTURE_STDERR"))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type executableFixtureEnvironment struct {
	RealEnvironment
	executable string
}

func (e executableFixtureEnvironment) LookPath(string) (string, error)   { return e.executable, nil }
func (e executableFixtureEnvironment) flatpakApplicationInstalled() bool { return true }

func TestEmbeddedHostnameLimitAtPlanningAndExecutionValidation(t *testing.T) {
	for _, operation := range []Operation{Pair, Unpair, List, Quit, Stream} {
		for _, length := range []int{116, 117, 122} {
			t.Run(fmt.Sprintf("%s/%d", operation, length), func(t *testing.T) {
				host := strings.Repeat("a", 60) + "." + strings.Repeat("b", length-61)
				request := Request{Operation: operation, Host: host, App: "League", PhysicalHostConfirmed: true, AcceptUnverifiedHandoff: true}
				_, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "/fixture/moonlight"}, request)
				if (err != nil) != (length > 116) {
					t.Fatalf("BuildPlan(host length %d): %v", length, err)
				}
				argv := []string{string(operation), host}
				if operation == Stream {
					argv = []string{"stream", "-app", "League", host}
				}
				if err := validatePlanArguments(Client{Flavor: FlavorEmbedded}, argv); (err != nil) != (length > 116) {
					t.Fatalf("execution validation(host length %d): %v", length, err)
				}
				if operation != Unpair {
					if _, err := BuildPlan(Client{Flavor: FlavorQt, Binary: "/fixture/moonlight-qt"}, request); err != nil {
						t.Fatalf("Qt must retain valid DNS names: %v", err)
					}
				}
			})
		}
	}
}

func TestEmbeddedPairPINAndPortContract(t *testing.T) {
	client := Client{Flavor: FlavorEmbedded, Binary: "/fixture/moonlight"}
	for _, pin := range []string{"", "0000", "0001", "0427", "9999"} {
		request := Request{Operation: Pair, Host: "pc.local:48000", PairingPIN: pin, PhysicalHostConfirmed: true}
		plan, err := BuildPlan(client, request)
		if pin == "0000" {
			if err == nil || validatePlanArguments(client, []string{"pair", "-pin", pin, "pc.local", "-port", "48000"}) == nil {
				t.Fatal("Embedded PIN 0000 must fail both planning and execution validation")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePlanArguments(client, plan.Arguments); err != nil {
			t.Fatalf("valid pair PIN/port rejected: %v", err)
		}
	}
	if _, err := BuildPlan(Client{Flavor: FlavorQt, Binary: "/fixture/qt"}, Request{Operation: Pair, Host: "pc.local", PairingPIN: "0000", PhysicalHostConfirmed: true}); err != nil {
		t.Fatalf("Qt must retain PIN 0000 support: %v", err)
	}
}

func TestEmbeddedControlChecksRealZeroExitProcessOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client, err := Discover(context.Background(), executableFixtureEnvironment{executable: executable}, "moonlight-embedded")
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []Operation{Pair, Unpair} {
		for _, test := range []struct {
			name, stdout, stderr string
			success              bool
		}{
			{"released success", "Succesfully " + string(operation) + "ed\n", "", true},
			{"corrected success", "Successfully " + string(operation) + "ed\n", "", true},
			{"failed zero exit", "", "Failed to " + string(operation) + " to server: fixture rejection\n", false},
			{"empty zero exit", "", "", false},
			{"stderr cannot authorize", "", "Succesfully " + string(operation) + "ed\n", false},
			{"failure overrides success", "Succesfully " + string(operation) + "ed\n", "Failed to " + string(operation) + " to server: fixture rejection\n", false},
			{"truncated", strings.Repeat("x", maximumControlOutput) + "\nSuccesfully " + string(operation) + "ed\n", "", false},
		} {
			t.Run(string(operation)+"/"+test.name, func(t *testing.T) {
				t.Setenv("LEAGUEBRIDGE_REMOTE_PROCESS_FIXTURE", "1")
				if test.name == "truncated" {
					t.Setenv("LEAGUEBRIDGE_REMOTE_FIXTURE_LARGE", "1")
				} else {
					t.Setenv("LEAGUEBRIDGE_REMOTE_FIXTURE_STDOUT", test.stdout)
				}
				t.Setenv("LEAGUEBRIDGE_REMOTE_FIXTURE_STDERR", test.stderr)
				plan, err := BuildDiscoveredPlan(client, Request{Route: config.RouteWindows, Operation: operation, Host: "fixture.invalid", PhysicalHostConfirmed: true})
				if err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				err = Execute(context.Background(), ExecRunner{}, nil, &stdout, &stderr, plan)
				if (err == nil) != test.success {
					t.Fatalf("Execute()=%v; success=%v", err, test.success)
				}
				if stdout.String() != test.stdout || stderr.String() != test.stderr {
					t.Fatal("verification changed live output")
				}
			})
		}
	}
}

// The detector protects its own state while deliberately allowing Write calls
// to overlap. A racy destination such as bytes.Buffer would hide the regression
// behind undefined test behavior instead of reporting the forwarding contract.
type overlapDetectingControlWriter struct {
	mutex      sync.Mutex
	active     int
	overlapped bool
	output     bytes.Buffer
}

func (w *overlapDetectingControlWriter) Write(data []byte) (int, error) {
	w.mutex.Lock()
	w.active++
	w.overlapped = w.overlapped || w.active > 1
	w.mutex.Unlock()
	// Give the other os/exec pipe copier time to enter the same destination.
	time.Sleep(50 * time.Millisecond)
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.active--
	return w.output.Write(data)
}

func TestEmbeddedControlSerializesSharedOutputWithRealChild(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEAGUEBRIDGE_REMOTE_PROCESS_FIXTURE", "1")
	t.Setenv("LEAGUEBRIDGE_REMOTE_FIXTURE_STDERR", "diagnostic\n")
	client, err := Discover(context.Background(), executableFixtureEnvironment{executable: executable}, "moonlight-embedded")
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []Operation{Pair, Unpair} {
		t.Run(string(operation), func(t *testing.T) {
			confirmation := "Succesfully " + string(operation) + "ed\n"
			t.Setenv("LEAGUEBRIDGE_REMOTE_FIXTURE_STDOUT", confirmation)
			plan, err := BuildDiscoveredPlan(client, Request{Route: config.RouteWindows, Operation: operation, Host: "fixture.invalid", PhysicalHostConfirmed: true})
			if err != nil {
				t.Fatal(err)
			}
			output := &overlapDetectingControlWriter{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := Execute(ctx, ExecRunner{}, nil, output, output, plan); err != nil {
				t.Fatal(err)
			}
			output.mutex.Lock()
			defer output.mutex.Unlock()
			if output.overlapped || output.active != 0 {
				t.Fatal("stdout and stderr writes overlapped at their shared destination")
			}
			if got := output.output.String(); got != confirmation+"diagnostic\n" && got != "diagnostic\n"+confirmation {
				t.Fatalf("forwarding changed output: %q", got)
			}
		})
	}
}

func TestExecRunnerReapsCanceledProcess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEAGUEBRIDGE_REMOTE_PROCESS_FIXTURE", "1")
	t.Setenv("LEAGUEBRIDGE_REMOTE_FIXTURE_WAIT", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := &processReadyWriter{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- (ExecRunner{}).Run(ctx, nil, ready, io.Discard, executable, "pair", "fixture.invalid") }()
	select {
	case <-ready.ready:
	case err := <-done:
		t.Fatalf("fixture exited before starting: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("fixture did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("canceled process returned %v, context=%v", err, ctx.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("running child was not reaped after cancellation")
	}
}

type processReadyWriter struct {
	once  sync.Once
	ready chan struct{}
}

func (w *processReadyWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.ready) })
	return len(data), nil
}

func TestQtControlPlatformsAreBoundWithoutPermittingOffscreenStreams(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEAGUEBRIDGE_REMOTE_PROCESS_FIXTURE", "1")
	t.Setenv("LEAGUEBRIDGE_REMOTE_FIXTURE_QPA", "1")
	t.Setenv("QT_QPA_PLATFORM", "unusable-ambient-fixture")
	for _, flavor := range []Flavor{FlavorQt, FlavorFlatpak} {
		selection := "moonlight-qt"
		if flavor == FlavorFlatpak {
			selection = "flatpak"
		}
		client, err := DiscoverForPlatform(context.Background(), executableFixtureEnvironment{executable: executable}, selection, "linux")
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []Operation{Pair, List, Quit, Stream} {
			request := Request{Operation: operation, Host: "fixture.invalid", App: "League", QtPlatform: "offscreen", PhysicalHostConfirmed: true, AcceptUnverifiedHandoff: true}
			plan, err := BuildDiscoveredPlan(client, request)
			if operation == Stream {
				if err == nil {
					t.Fatal("offscreen must never become a streaming backend")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.QtPlatform != "offscreen" {
				t.Fatal("control plan lost explicit backend")
			}
			if err := validatePlanArguments(client, plan.Arguments); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			if err := Execute(context.Background(), ExecRunner{}, nil, &stdout, io.Discard, plan); err != nil {
				t.Fatal(err)
			}
			if stdout.String() != "offscreen" {
				t.Fatalf("control process inherited wrong backend: %q", stdout.String())
			}
		}
	}
}
