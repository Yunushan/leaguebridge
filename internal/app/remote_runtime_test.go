package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/remote"
)

func TestQtExplicitControlBackendReachesChild(t *testing.T) {
	for _, operation := range []string{"pair", "list", "quit"} {
		for _, platform := range []string{"xcb", "offscreen"} {
			t.Run(operation+"/"+platform, func(t *testing.T) {
				a, _, errOut, prober, runner := newTestApp(t)
				useRealRemoteFixture(t, a)
				report := readyClientReport()
				report.Status = probe.StatusFail
				report.Checks[1].Status = probe.StatusFail
				report.Checks[2].Status = probe.StatusFail
				prober.reports[probe.ProfileClient] = report
				args := []string{"remote", operation, "--host", "fixture.invalid", "--confirm-physical-host", "--qt-platform", platform}
				if code := a.Run(context.Background(), args); code != ExitOK {
					t.Fatalf("code=%d stderr=%s", code, errOut.String())
				}
				if !reflect.DeepEqual(runner.qtPlatforms, []string{platform}) {
					t.Fatalf("platforms=%#v", runner.qtPlatforms)
				}
				if deadline, ok := runner.ctx.Deadline(); !ok || time.Until(deadline) > remoteControlTimeout {
					t.Fatal("Qt control lost its finite deadline")
				}
			})
		}
	}
}

func TestQtControlFallbackKeepsRequestedBackend(t *testing.T) {
	a, _, errOut, _, runner := newTestApp(t)
	directory := t.TempDir()
	paths := map[string]string{}
	for _, name := range []string{"moonlight-qt", "moonlight-embedded", "flatpak"} {
		filename := name
		if runtime.GOOS == "windows" {
			filename += ".exe"
		}
		path := filepath.Join(directory, filename)
		if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	// A fixture environment suffices for discovery, but execution requires a
	// real bound executable. Native Qt fails; Embedded must never be started
	// with its incompatible QPA request during automatic recovery.
	t.Setenv("PATH", directory)
	a.RemoteEnv = remote.RealEnvironment{}
	runner.err = errors.New("fixture missing QPA plugin")
	code := a.Run(context.Background(), []string{"remote", "pair", "--host", "fixture.invalid", "--confirm-physical-host", "--qt-platform", "offscreen"})
	if code != ExitInternal || runner.called != 1 || runner.name != paths["moonlight-qt"] {
		t.Fatalf("code=%d calls=%d executable=%s stderr=%s", code, runner.called, runner.name, errOut.String())
	}
}

func TestEmbeddedPairFailureDoesNotReturnSuccess(t *testing.T) {
	a, _, errOut, _, runner := newTestApp(t)
	directory := t.TempDir()
	name := "moonlight-embedded"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	a.RemoteEnv = remote.RealEnvironment{}
	runner.output = "Connecting to fixture.invalid...\n"
	runner.errorOutput = "Failed to pair to server: rejected\n"
	code := a.Run(context.Background(), []string{"remote", "pair", "--client", "moonlight-embedded", "--host", "fixture.invalid", "--confirm-physical-host"})
	if code != ExitInternal || !strings.Contains(errOut.String(), "reported that pair failed") {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
}

func TestKVMPreservesCallerSessionDeadline(t *testing.T) {
	a, _, errOut, _, runner := newTestApp(t)
	directory := t.TempDir()
	name := "firefox"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	a.RemoteEnv = remote.RealEnvironment{}
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	code := a.Run(ctx, []string{"remote", "kvm", "--browser", "firefox", "--url", "https://fixture.invalid", "--confirm-physical-host", "--acknowledge-unverified-handoff"})
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if got, ok := runner.ctx.Deadline(); !ok || !got.Equal(deadline) {
		t.Fatalf("browser deadline=%v; want caller deadline %v", got, deadline)
	}
}
